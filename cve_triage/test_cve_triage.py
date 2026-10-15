import contextlib
import datetime as dt
import gzip
import io
import json
import tempfile
import unittest
from pathlib import Path

import cve_triage as ct

TH = ct.Thresholds()


class JudgeTest(unittest.TestCase):
    def check(self, cvss, epss, kev, expected):
        self.assertEqual(ct.judge(cvss, epss, kev, TH)[0], expected, (cvss, epss, kev))

    def test_kev_is_always_immediate(self):
        self.check(2.0, 0.001, True, ct.IMMEDIATE)
        self.check(None, None, True, ct.IMMEDIATE)

    def test_very_high_epss_is_immediate(self):
        self.check(5.0, 0.5, False, ct.IMMEDIATE)
        self.check(None, 0.9, False, ct.IMMEDIATE)

    def test_act(self):
        self.check(7.0, 0.10, False, ct.ACT)
        self.check(9.8, 0.03, False, ct.ACT)

    def test_review(self):
        self.check(9.8, 0.01, False, ct.REVIEW)   # Criticalは悪用可能性が低くても確認
        self.check(9.8, None, False, ct.REVIEW)   # Critical はEPSS未算出でも確認
        self.check(5.0, 0.2, False, ct.REVIEW)    # EPSSのみ高い
        self.check(None, 0.2, False, ct.REVIEW)

    def test_hold_and_watch(self):
        self.check(None, None, False, ct.HOLD)
        self.check(8.0, None, False, ct.HOLD)     # High + EPSS未算出は保留
        self.check(5.0, None, False, ct.WATCH)    # Medium はEPSS未算出でも経過観察
        self.check(5.0, 0.01, False, ct.WATCH)
        self.check(None, 0.01, False, ct.WATCH)
        self.check(8.0, 0.01, False, ct.WATCH)    # High止まりでEPSSが低い

    def test_missing_data_noted_in_reason(self):
        self.assertIn("EPSS未算出", ct.judge(8.0, None, False, TH)[1])
        self.assertIn("CVSS未付与", ct.judge(None, 0.2, False, TH)[1])


class PickCvssTest(unittest.TestCase):
    @staticmethod
    def entry(version, score, type_):
        return {"type": type_, "cvssData": {"version": version, "baseScore": score,
                                            "baseSeverity": "HIGH", "vectorString": "v"}}

    def test_primary_beats_newer_secondary(self):
        m = {"cvssMetricV40": [self.entry("4.0", 9.0, "Secondary")],
             "cvssMetricV31": [self.entry("3.1", 7.5, "Primary")]}
        self.assertEqual(ct.pick_cvss(m)["version"], "3.1")

    def test_newest_version_among_same_type(self):
        m = {"cvssMetricV2": [self.entry("2.0", 5.0, "Primary")],
             "cvssMetricV31": [self.entry("3.1", 7.5, "Primary")]}
        self.assertEqual(ct.pick_cvss(m)["version"], "3.1")

    def test_v2_severity_is_at_entry_level(self):
        m = {"cvssMetricV2": [{"type": "Primary", "baseSeverity": "MEDIUM",
                               "cvssData": {"version": "2.0", "baseScore": 5.0}}]}
        self.assertEqual(ct.pick_cvss(m)["severity"], "MEDIUM")

    def test_none(self):
        self.assertIsNone(ct.pick_cvss({}))


class EpssTest(unittest.TestCase):
    def test_source_switches_at_100(self):
        self.assertEqual(ct.choose_epss_source(99), "api")
        self.assertEqual(ct.choose_epss_source(100), "csv")

    def test_parse_csv_with_header_comment(self):
        raw = gzip.compress(
            "#model_version:v1,score_date:2026-10-14T12:00:24Z\n"
            "cve,epss,percentile\n"
            "CVE-2021-44228,0.99999,1.00000\n"
            "CVE-1999-0001,0.04753,0.91738\n".encode())
        got = ct.parse_epss_csv(raw, {"CVE-2021-44228", "CVE-2099-0001"})
        self.assertEqual(list(got), ["CVE-2021-44228"])
        self.assertEqual(got["CVE-2021-44228"], {"epss": 0.99999, "percentile": 1.0, "date": "2026-10-14"})


class RowsTest(unittest.TestCase):
    def test_sorted_by_judgement_then_epss(self):
        def cve(id_, score, kev=False):
            return {"cve_id": id_, "published": "", "last_modified": "", "vuln_status": "", "description": "",
                    "cvss": {"score": score} if score else None, "kev": kev, "kev_due_date": None}
        cves = [cve("CVE-A", 5.0), cve("CVE-B", 9.8), cve("CVE-C", 1.0, kev=True)]
        epss = {"CVE-A": {"epss": 0.01, "percentile": 0.5, "date": "d"},
                "CVE-B": {"epss": 0.20, "percentile": 0.9, "date": "d"}}
        rows = ct.build_rows(cves, epss, TH)
        self.assertEqual([r["cve_id"] for r in rows], ["CVE-C", "CVE-B", "CVE-A"])
        self.assertEqual([r["action_required"] for r in rows], ["Y", "Y", "N"])


class ScopeConfigTest(unittest.TestCase):
    def args(self, config=None, *cli):
        """一時ファイルに設定を書き、--config 経由で読ませる(実際の config.json には依存しない)。"""
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "c.json"
            path.write_text(json.dumps(config if config is not None else {}), encoding="utf-8")
            return ct.parse_args(["--config", str(path), *cli])

    def test_default_is_two_days_ago_utc(self):
        a = self.args()
        target = dt.datetime.now(dt.timezone.utc).date() - dt.timedelta(days=2)
        self.assertEqual((a.date, a.end_date), (target, target))

    def test_relative_window_from_config(self):
        a = self.args({"end_days_ago": 2, "window_days": 3})
        today = dt.datetime.now(dt.timezone.utc).date()
        self.assertEqual(a.end_date, today - dt.timedelta(days=2))
        self.assertEqual(a.date, today - dt.timedelta(days=4))

    def test_cli_overrides_config(self):
        a = self.args({"window_days": 5, "min_cvss": 7, "cpe_match": ["cpe:2.3:a:x:y"]},
                      "--date", "2026-10-01", "--min-cvss", "9", "--cpe", "cpe:2.3:a:p:q")
        self.assertEqual((str(a.date), str(a.end_date)), ("2026-10-01", "2026-10-01"))
        self.assertEqual(a.min_cvss, 9)
        self.assertEqual(a.cpe, ["cpe:2.3:a:p:q"])   # 設定ファイルの値を置換する

    def test_thresholds_from_config(self):
        self.assertEqual(self.args({"thresholds": {"epss_high": 0.2}}).epss_high, 0.2)

    def test_invalid_config_is_rejected(self):
        for bad in ({"windw_days": 3}, {"thresholds": {"nope": 1}}):
            with self.assertRaises(SystemExit):
                self.args(bad)
        for bad in ({"window_days": 0}, {"cpe_match": "cpe:2.3:a:x"}, {"min_cvss": 11}, {"min_judgement": "x"}):
            with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                self.args(bad)

    def test_range_over_120_days_is_rejected(self):
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            self.args({"window_days": 121})

    def test_underscore_keys_are_comments(self):
        self.assertEqual(self.args({"_memo": "x", "_cpe_match例": ["a"]}).cpe, [])

    def test_build_filters(self):
        self.assertEqual(ct.build_filters(["cpe:2.3:a:x:y"], ["wordpress"]),
                         [{"virtualMatchString": "cpe:2.3:a:x:y"}, {"keywordSearch": "wordpress"}])
        self.assertEqual(ct.build_filters([], []), [])

    def test_apply_scope(self):
        def cve(id_, score, kev=False):
            return {"cve_id": id_, "cvss": {"score": score} if score is not None else None, "kev": kev}
        cves = [cve("low", 3.0), cve("high", 8.0), cve("none", None), cve("kev_low", 3.0, True)]
        ids = lambda out: [c["cve_id"] for c in out]
        self.assertEqual(ids(ct.apply_scope(cves, 7.0, False)), ["high", "none", "kev_low"])
        self.assertEqual(ids(ct.apply_scope(cves, None, True)), ["kev_low"])
        self.assertEqual(ids(ct.apply_scope(cves, None, False)), ["low", "high", "none", "kev_low"])

    def test_shipped_config_json_is_valid_and_matches_defaults(self):
        cfg = ct.load_config(ct.DEFAULT_CONFIG_PATH)
        self.assertEqual(cfg, ct.DEFAULT_CONFIG)


if __name__ == "__main__":
    unittest.main()

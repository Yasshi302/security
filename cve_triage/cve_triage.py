#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE脅威度判定バッチ

指定日(既定: 前日・UTC)に NVD へ公開(または更新)された CVE を取得し、
CVSS・EPSS・CISA KEV の情報から「対処が必要か」を判定して CSV に出力する。

  * CVE/CVSS/KEV : NVD API 2.0(日付指定で取得)
  * EPSS         : 取得CVE数が 100 件未満なら EPSS 公開API、100 件以上なら日次CSV
  * 標準ライブラリのみで動作(Python 3.9+)
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import gzip
import io
import json
import logging
import logging.handlers
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
EPSS_CSV_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

EPSS_API_MAX_CVES = 100   # 件数がこれ未満ならAPI、以上なら日次CSV
EPSS_API_CHUNK = 50       # API 1リクエストあたりのCVE数(URL長対策)
NVD_PAGE_SIZE = 2000      # NVD API の上限
NVD_MAX_RANGE_DAYS = 120  # NVD API の日付範囲の上限
USER_AGENT = "cve-triage/1.0"
RETRY_STATUS = {403, 429, 500, 502, 503, 504}  # NVDはレート制限超過で403を返す

log = logging.getLogger("cve_triage")

IMMEDIATE, ACT, REVIEW, HOLD, WATCH = "即時対処", "要対処", "要確認", "判定保留", "経過観察"
JUDGEMENT_ORDER = [IMMEDIATE, ACT, REVIEW, HOLD, WATCH]
ACTION_REQUIRED = {IMMEDIATE, ACT}

CSV_COLUMNS = [
    "cve_id", "judgement", "action_required", "reason",
    "cvss_score", "cvss_severity", "cvss_version", "cvss_vector", "cvss_source",
    "epss", "epss_percentile", "epss_date",
    "kev", "kev_due_date",
    "published", "last_modified", "vuln_status", "description", "nvd_url",
]


# ───────────────────────── HTTP ─────────────────────────
def http_get(url: str, headers: dict | None = None, timeout: int = 60, retries: int = 4) -> bytes:
    hdrs = {"User-Agent": USER_AGENT, **(headers or {})}
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=hdrs), timeout=timeout) as res:
                return res.read()
        except urllib.error.HTTPError as e:
            if e.code not in RETRY_STATUS or attempt == retries:
                raise
            reason = f"HTTP {e.code}"
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt == retries:
                raise
            reason = str(e)
        wait = 10 * 2 ** (attempt - 1)
        log.warning("リトライ %d/%d (%s) %d秒待機: %s", attempt, retries, reason, wait, url.split("?")[0])
        time.sleep(wait)
    raise RuntimeError("unreachable")


# ───────────────────────── NVD ─────────────────────────
def build_filters(cpe_match: list[str], keywords: list[str]) -> list[dict]:
    """対象範囲の絞り込み条件をNVD APIのパラメータに変換する。複数指定はOR(結果の和集合)。"""
    return ([{"virtualMatchString": c} for c in cpe_match]
            + [{"keywordSearch": k} for k in keywords])


def fetch_nvd(start: dt.date, end: dt.date, date_type: str, api_key: str | None,
              filters: list[dict] | None = None) -> list[dict]:
    """start〜end(UTC・両端含む)に公開/更新されたCVEを全ページ取得して返す。

    filters が空なら全件、指定があれば条件ごとに検索して重複を除いた和集合を返す。
    """
    prefix = "pub" if date_type == "published" else "lastMod"
    base = {
        f"{prefix}StartDate": f"{start.isoformat()}T00:00:00.000",
        f"{prefix}EndDate": f"{end.isoformat()}T23:59:59.999",
        "resultsPerPage": NVD_PAGE_SIZE,
    }
    headers = {"apiKey": api_key} if api_key else {}
    # レート制限: キー無し 5件/30秒、キー有り 50件/30秒
    interval = 0.7 if api_key else 6.5
    found: dict[str, dict] = {}
    first_request = True
    for extra in filters or [{}]:
        label = next(iter(extra.values())) if extra else "全件"
        index = 0
        while True:
            if not first_request:
                time.sleep(interval)
            first_request = False
            query = urllib.parse.urlencode({**base, **extra, "startIndex": index})
            data = json.loads(http_get(f"{NVD_URL}?{query}", headers, timeout=120))
            vulns = data.get("vulnerabilities", [])
            for v in vulns:
                found.setdefault(v["cve"]["id"], v["cve"])
            index += len(vulns)
            total = data.get("totalResults", 0)
            log.info("NVD取得 [%s] %d/%d 件", label, index, total)
            if not vulns or index >= total:
                break
    return list(found.values())


def pick_cvss(metrics: dict) -> dict | None:
    """採用するCVSSを1つ選ぶ。NVD(Primary)優先、同種ならバージョンの新しい順(4.0 > 3.1 > 3.0 > 2.0)。"""
    ranked = []
    for rank, key in enumerate(("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")):
        for entry in metrics.get(key) or []:
            ranked.append((entry.get("type") != "Primary", rank, entry))
    if not ranked:
        return None
    _, _, entry = min(ranked, key=lambda r: r[:2])
    data = entry["cvssData"]
    return {
        "score": data.get("baseScore"),
        "severity": data.get("baseSeverity") or entry.get("baseSeverity"),  # v2 は entry 直下
        "version": data.get("version"),
        "vector": data.get("vectorString"),
        "source": entry.get("type"),
    }


def parse_cve(cve: dict) -> dict:
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    return {
        "cve_id": cve["id"],
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "vuln_status": cve.get("vulnStatus"),
        "description": " ".join(desc.split()),
        "cvss": pick_cvss(cve.get("metrics") or {}),
        "kev": bool(cve.get("cisaExploitAdd")),
        "kev_due_date": cve.get("cisaActionDue"),
    }


# ───────────────────────── EPSS ─────────────────────────
def choose_epss_source(cve_count: int) -> str:
    return "api" if cve_count < EPSS_API_MAX_CVES else "csv"


def fetch_epss_api(cve_ids: list[str]) -> dict[str, dict]:
    result: dict[str, dict] = {}
    for i in range(0, len(cve_ids), EPSS_API_CHUNK):
        chunk = cve_ids[i:i + EPSS_API_CHUNK]
        query = urllib.parse.urlencode({"cve": ",".join(chunk)}, safe=",")
        data = json.loads(http_get(f"{EPSS_API_URL}?{query}"))
        for row in data.get("data", []):
            result[row["cve"]] = {
                "epss": float(row["epss"]), "percentile": float(row["percentile"]), "date": row.get("date"),
            }
    return result


def parse_epss_csv(gz_bytes: bytes, wanted: set[str]) -> dict[str, dict]:
    """日次CSV(.csv.gz)から対象CVEのスコアだけを抜き出す。先頭の '#model_version:...,score_date:...' 行に対応。"""
    score_date = None
    lines = io.TextIOWrapper(io.BytesIO(gzip.decompress(gz_bytes)), encoding="utf-8")

    def body():
        nonlocal score_date
        for line in lines:
            if line.startswith("#"):
                for part in line[1:].strip().split(","):
                    if part.startswith("score_date:"):
                        score_date = part.split(":", 1)[1][:10]
                continue
            yield line

    result = {}
    for row in csv.DictReader(body()):
        if row["cve"] in wanted:
            result[row["cve"]] = {
                "epss": float(row["epss"]), "percentile": float(row["percentile"]), "date": score_date,
            }
    return result


def fetch_epss_csv(cve_ids: list[str]) -> dict[str, dict]:
    return parse_epss_csv(http_get(EPSS_CSV_URL, timeout=300), set(cve_ids))


# ───────────────────────── 判定 ─────────────────────────
@dataclass
class Thresholds:
    cvss_high: float = 7.0       # CVSS High 以上
    cvss_critical: float = 9.0   # CVSS Critical 以上
    epss_immediate: float = 0.50  # これ以上は即時対処
    epss_high: float = 0.10      # 悪用可能性が高い
    epss_low: float = 0.03       # Critical の足切りライン


def judge(cvss_score: float | None, epss: float | None, kev: bool, th: Thresholds) -> tuple[str, str]:
    """(判定, 理由) を返す。

    即時対処: KEV登録済み、または EPSS >= epss_immediate
    要対処  : CVSS High以上 かつ EPSS高、または CVSS Critical かつ EPSS >= epss_low
    要確認  : EPSS高(CVSS低/未付与)、または CVSS Critical(EPSS低/未算出)
    判定保留: EPSS未算出で、CVSSが High以上 または 未付与(新規公開直後など。翌日以降に再判定)
    経過観察: 上記以外(CVSS High止まりでEPSSが低い場合を含む)

    新規公開CVEはEPSSが低く出やすく、CVSS High以上は全体の6割超を占める。
    「CVSS High かつ EPSS低」まで要確認にすると仕分けにならないため、経過観察としている。
    """
    notes = []
    if cvss_score is None:
        notes.append("CVSS未付与")
    if epss is None:
        notes.append("EPSS未算出")
    suffix = f"[{'・'.join(notes)}]" if notes else ""

    def result(label: str, reason: str) -> tuple[str, str]:
        return label, reason + suffix

    if kev:
        return result(IMMEDIATE, "CISA KEV登録済み(悪用実績あり)")
    if epss is not None and epss >= th.epss_immediate:
        return result(IMMEDIATE, f"EPSS {epss:.1%} が{th.epss_immediate:.0%}以上")

    cvss_high = cvss_score is not None and cvss_score >= th.cvss_high
    cvss_crit = cvss_score is not None and cvss_score >= th.cvss_critical
    epss_high = epss is not None and epss >= th.epss_high

    if cvss_high and epss_high:
        return result(ACT, f"CVSS {cvss_score} かつ EPSS {epss:.1%} がともに高い")
    if cvss_crit and epss is not None and epss >= th.epss_low:
        return result(ACT, f"CVSS {cvss_score}(Critical) かつ EPSS {epss:.1%}")
    if epss_high:
        return result(REVIEW, f"EPSS {epss:.1%} は高いがCVSSは低い/未付与")
    if cvss_crit:
        return result(REVIEW, f"CVSS {cvss_score}(Critical) だがEPSSは低い")
    if epss is None and (cvss_score is None or cvss_high):
        return result(HOLD, "EPSS未算出のため判定できない(翌日以降に再判定を推奨)")
    if cvss_high:
        return result(WATCH, f"CVSS {cvss_score} は高いがEPSSが低い")
    return result(WATCH, "CVSS・EPSSとも閾値未満")


# ───────────────────────── 出力 ─────────────────────────
def build_rows(cves: list[dict], epss_map: dict[str, dict], th: Thresholds) -> list[dict]:
    rows = []
    for c in cves:
        cvss = c["cvss"] or {}
        e = epss_map.get(c["cve_id"])
        label, reason = judge(cvss.get("score"), e["epss"] if e else None, c["kev"], th)
        rows.append({
            "cve_id": c["cve_id"], "judgement": label,
            "action_required": "Y" if label in ACTION_REQUIRED else "N", "reason": reason,
            "cvss_score": cvss.get("score", ""), "cvss_severity": cvss.get("severity") or "",
            "cvss_version": cvss.get("version") or "", "cvss_vector": cvss.get("vector") or "",
            "cvss_source": cvss.get("source") or "",
            "epss": e["epss"] if e else "", "epss_percentile": e["percentile"] if e else "",
            "epss_date": e["date"] if e else "",
            "kev": "Y" if c["kev"] else "N", "kev_due_date": c["kev_due_date"] or "",
            "published": c["published"], "last_modified": c["last_modified"],
            "vuln_status": c["vuln_status"], "description": c["description"],
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{c['cve_id']}",
        })

    def sort_key(r):
        return (JUDGEMENT_ORDER.index(r["judgement"]), -(r["epss"] or 0), -(r["cvss_score"] or 0), r["cve_id"])

    return sorted(rows, key=sort_key)


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8-sig", newline="") as f:  # BOM付き: Excelで文字化けしない
        w = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        w.writeheader()
        w.writerows(rows)
    os.replace(tmp, path)


# ───────────────────────── main ─────────────────────────
def setup_logging(log_dir: Path) -> None:
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    log.setLevel(logging.INFO)
    console = logging.StreamHandler()
    console.setFormatter(fmt)
    log.addHandler(console)
    log_dir.mkdir(parents=True, exist_ok=True)
    fileh = logging.handlers.RotatingFileHandler(
        log_dir / "cve_triage.log", maxBytes=1_000_000, backupCount=5, encoding="utf-8")
    fileh.setFormatter(fmt)
    log.addHandler(fileh)


DEFAULT_CONFIG_PATH = BASE_DIR / "config.json"
DEFAULT_CONFIG = {
    "date_type": "published",      # published=公開日 / modified=最終更新日
    "end_days_ago": 2,             # 取得終了日 = 今日(UTC)のN日前(EPSSの算出待ちを避けるため既定は2日前)
    "window_days": 1,              # 終了日から遡って何日分を取得するか(最大120)
    "cpe_match": [],               # 製品で絞り込み(NVDのvirtualMatchString)。空=全製品
    "keywords": [],                # キーワードで絞り込み(NVDのkeywordSearch)。空=絞らない
    "min_cvss": None,              # CVSSがこの値未満のCVEを除外(KEV・CVSS未付与は除外しない)
    "kev_only": False,             # KEV登録済みのみ
    "min_judgement": WATCH,        # 出力に含める最低判定(経過観察=全件)
    "epss_source": "auto",         # auto / api / csv
    "thresholds": dict(vars(Thresholds())),
}


def load_config(path: Path | None) -> dict:
    """設定ファイル(JSON)を既定値に重ねて返す。path=None なら config.json があれば読む。
    '_' で始まるキーはメモ用として無視する。"""
    cfg = {**DEFAULT_CONFIG, "thresholds": dict(DEFAULT_CONFIG["thresholds"])}
    if path is None:
        path = DEFAULT_CONFIG_PATH
        if not path.exists():
            return cfg
    user = json.loads(path.read_text(encoding="utf-8-sig"))
    user = {k: v for k, v in user.items() if not k.startswith("_")}
    unknown = set(user) - set(DEFAULT_CONFIG)
    if unknown:
        raise ValueError(f"未知の設定項目: {', '.join(sorted(unknown))}")
    th = user.pop("thresholds", {})
    bad = set(th) - set(cfg["thresholds"])
    if bad:
        raise ValueError(f"未知の閾値: {', '.join(sorted(bad))}")
    cfg.update(user)
    cfg["thresholds"].update(th)
    return cfg


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """優先順位: コマンドライン引数 > 設定ファイル(config.json) > 既定値"""
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--config", type=Path, help=f"設定ファイル (既定: {DEFAULT_CONFIG_PATH.name})")
    try:
        cfg = load_config(pre.parse_known_args(argv)[0].config)
    except (OSError, ValueError) as e:  # JSONDecodeError は ValueError のサブクラス
        sys.exit(f"設定ファイルを読み込めません: {e}")
    th = cfg["thresholds"]

    p = argparse.ArgumentParser(description="CVE脅威度判定バッチ(NVD + EPSS)", parents=[pre])
    scope = p.add_argument_group("対象範囲")
    scope.add_argument("--date", type=dt.date.fromisoformat,
                       help="取得開始日 YYYY-MM-DD (UTC)。指定すると end_days_ago/window_days より優先")
    scope.add_argument("--end-date", type=dt.date.fromisoformat, help="取得終了日(含む)。既定: --date と同じ")
    scope.add_argument("--end-days-ago", type=int, default=cfg["end_days_ago"], help="終了日=今日のN日前")
    scope.add_argument("--window-days", type=int, default=cfg["window_days"], help="終了日から遡る日数")
    scope.add_argument("--date-type", choices=["published", "modified"], default=cfg["date_type"],
                       help="日付の基準。published=公開日 / modified=最終更新日")
    scope.add_argument("--cpe", action="append", metavar="CPE",
                       help="製品で絞り込み 例: cpe:2.3:a:apache:http_server (複数指定可・設定ファイルを置換)")
    scope.add_argument("--keyword", action="append", metavar="WORD",
                       help="キーワードで絞り込み (複数指定可・設定ファイルを置換)")
    scope.add_argument("--min-cvss", type=float, default=cfg["min_cvss"], help="この値未満のCVSSを除外")
    scope.add_argument("--kev-only", action=argparse.BooleanOptionalAction, default=cfg["kev_only"],
                       help="KEV登録済みのみ")
    scope.add_argument("--min-judgement", choices=JUDGEMENT_ORDER, default=cfg["min_judgement"],
                       help="出力に含める最低判定。例: 要確認 → 即時対処・要対処・要確認のみ出力")
    p.add_argument("--epss-source", choices=["auto", "api", "csv"], default=cfg["epss_source"],
                   help=f"auto: {EPSS_API_MAX_CVES}件未満ならAPI、以上なら日次CSV")
    p.add_argument("--output-dir", type=Path, default=BASE_DIR / "output")
    p.add_argument("--log-dir", type=Path, default=BASE_DIR / "logs")
    p.add_argument("--cvss-high", type=float, default=th["cvss_high"])
    p.add_argument("--cvss-critical", type=float, default=th["cvss_critical"])
    p.add_argument("--epss-immediate", type=float, default=th["epss_immediate"])
    p.add_argument("--epss-high", type=float, default=th["epss_high"])
    p.add_argument("--epss-low", type=float, default=th["epss_low"])
    args = p.parse_args(argv)

    args.cpe = args.cpe if args.cpe is not None else cfg["cpe_match"]
    args.keyword = args.keyword if args.keyword is not None else cfg["keywords"]
    for name, vals in (("cpe_match", args.cpe), ("keywords", args.keyword)):
        if not isinstance(vals, list) or not all(isinstance(v, str) and v.strip() for v in vals):
            p.error(f"{name} は空でない文字列のリストで指定してください")
    if not (isinstance(args.end_days_ago, int) and args.end_days_ago >= 0):
        p.error("end_days_ago は0以上の整数にしてください")
    if not (isinstance(args.window_days, int) and args.window_days >= 1):
        p.error("window_days は1以上の整数にしてください")
    if args.min_cvss is not None and not 0 <= args.min_cvss <= 10:
        p.error("min_cvss は0〜10で指定してください")
    # argparse の choices は設定ファイル由来の既定値を検証しないため、ここで確認する
    for name, val, allowed in (("min_judgement", args.min_judgement, JUDGEMENT_ORDER),
                               ("date_type", args.date_type, ["published", "modified"]),
                               ("epss_source", args.epss_source, ["auto", "api", "csv"])):
        if val not in allowed:
            p.error(f"{name} は {' / '.join(allowed)} のいずれかにしてください (指定値: {val!r})")

    if args.date is None:
        args.end_date = args.end_date or (
            dt.datetime.now(dt.timezone.utc).date() - dt.timedelta(days=args.end_days_ago))
        args.date = args.end_date - dt.timedelta(days=args.window_days - 1)
    elif args.end_date is None:
        args.end_date = args.date
    if args.end_date < args.date:
        p.error("--end-date は --date 以降にしてください")
    if (args.end_date - args.date).days + 1 > NVD_MAX_RANGE_DAYS:
        p.error(f"NVD APIの制限により期間は最大{NVD_MAX_RANGE_DAYS}日です")
    return args


def apply_scope(cves: list[dict], min_cvss: float | None, kev_only: bool) -> list[dict]:
    """取得後の絞り込み。KEV登録済みはmin_cvssで落とさない。CVSS未付与は判定不能なので残す。"""
    kept = []
    for c in cves:
        if kev_only and not c["kev"]:
            continue
        score = (c["cvss"] or {}).get("score")
        if min_cvss is not None and score is not None and score < min_cvss and not c["kev"]:
            continue
        kept.append(c)
    return kept


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    setup_logging(args.log_dir)
    th = Thresholds(args.cvss_high, args.cvss_critical, args.epss_immediate, args.epss_high, args.epss_low)
    api_key = os.environ.get("NVD_API_KEY") or None
    log.info("開始: %s〜%s (%s) NVD APIキー=%s", args.date, args.end_date, args.date_type,
             "あり" if api_key else "なし")
    log.info("対象範囲: 製品=%s キーワード=%s 最低CVSS=%s KEVのみ=%s 最低判定=%s",
             args.cpe or "全て", args.keyword or "指定なし", args.min_cvss, args.kev_only, args.min_judgement)

    try:
        raw = fetch_nvd(args.date, args.end_date, args.date_type, api_key, build_filters(args.cpe, args.keyword))
        parsed = [parse_cve(c) for c in raw if c.get("vulnStatus") != "Rejected"]
        cves = apply_scope(parsed, args.min_cvss, args.kev_only)
        log.info("対象CVE: %d件 (取得 %d件 / Rejected除外 %d件 / 範囲外 %d件)",
                 len(cves), len(raw), len(raw) - len(parsed), len(parsed) - len(cves))

        ids = [c["cve_id"] for c in cves]
        source = choose_epss_source(len(ids)) if args.epss_source == "auto" else args.epss_source
        epss_map: dict[str, dict] = {}
        if ids:
            log.info("EPSS取得: %s経由", "公開API" if source == "api" else "日次CSV")
            epss_map = fetch_epss_api(ids) if source == "api" else fetch_epss_csv(ids)
            log.info("EPSS取得結果: %d/%d件 (未算出 %d件)", len(epss_map), len(ids), len(ids) - len(epss_map))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as e:
        log.error("取得に失敗しました: %s", e)
        return 1

    rows = build_rows(cves, epss_map, th)
    cutoff = JUDGEMENT_ORDER.index(args.min_judgement)
    rows = [r for r in rows if JUDGEMENT_ORDER.index(r["judgement"]) <= cutoff]
    span =str(args.date) if args.date == args.end_date else f"{args.date}_{args.end_date}"
    out = args.output_dir / f"cve_triage_{span}.csv"
    write_csv(out, rows)

    counts = {label: sum(r["judgement"] == label for r in rows) for label in JUDGEMENT_ORDER}
    log.info("判定結果: %s", " / ".join(f"{k} {v}" for k, v in counts.items()))
    log.info("出力: %s (%d件)", out, len(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())

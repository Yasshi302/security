# cve_triage — CVE脅威度判定バッチ

指定した範囲の CVE を NVD から取得し、CVSS・EPSS・CISA KEV から「対処が必要か」を判定して CSV に出力する。
Python 3.9+ の標準ライブラリのみで動作(インストール不要)。

## データ取得

| 項目 | 取得元 |
|---|---|
| CVE本文・CVSS・KEV登録 | NVD API 2.0(日付指定。2000件/ページで全ページ取得) |
| EPSS | 取得CVEが **100件未満 → EPSS公開API** / **100件以上 → 日次CSV**(`epss_scores-current.csv.gz`) |

- CVSSは NVD(Primary)の値を優先し、無ければ CNA 提供(Secondary)の値を採用。同種ならバージョンの新しい順(4.0 > 3.1 > 3.0 > 2.0)。
- `Rejected` のCVEは除外。
- KEV(CISA Known Exploited Vulnerabilities)は NVD の応答に含まれる `cisaExploitAdd` を使うため、追加のAPI呼び出しは不要。

## 対象範囲の設定

対象範囲は [config.json](config.json) で設定する(コマンドライン引数でも上書き可能。優先順位: **引数 > config.json > 既定値**)。
自動起動のコマンドを変えずに、config.json を編集するだけで範囲を変えられる。

| config.json | 引数 | 内容 | 既定 |
|---|---|---|---|
| `date_type` | `--date-type` | 日付の基準。`published`=公開日 / `modified`=最終更新日 | `published` |
| `end_days_ago` | `--end-days-ago` | 取得終了日 = 今日(UTC)の **N日前** | `2` |
| `window_days` | `--window-days` | 終了日から遡って **何日分** を取得するか(最大120) | `1` |
| — | `--date` `--end-date` | 日付を直接指定(指定時は上の2つより優先)。`--end-date` 省略時は1日分 | — |
| `cpe_match` | `--cpe`(複数可) | **製品で絞り込み**。CPEの前方一致(例: `cpe:2.3:a:apache:http_server`)。空=全製品 | `[]` |
| `keywords` | `--keyword`(複数可) | **キーワードで絞り込み**(説明文など。NVDの `keywordSearch`)。空=絞らない | `[]` |
| `min_cvss` | `--min-cvss` | CVSSがこの値未満のCVEを除外。**KEV登録済み・CVSS未付与は除外しない** | `null` |
| `kev_only` | `--kev-only` / `--no-kev-only` | KEV登録済みのみ | `false` |
| `min_judgement` | `--min-judgement` | 出力に含める最低判定。`要確認` なら 即時対処・要対処・要確認 のみ出力 | `経過観察`(全件) |
| `epss_source` | `--epss-source` | `auto` / `api` / `csv` | `auto` |

- `cpe_match` と `keywords` を複数指定した場合は **OR**(それぞれ検索した結果の和集合、重複は除去)。引数で指定すると config.json の値は置き換わる(追加ではない)。
- `cpe_match` と `keywords` の両方を空にすると期間内の全CVEが対象。
- config.json の `_` で始まるキーはメモとして無視される。未知のキーや不正な値はエラーで停止する(タイプミスで範囲が意図せず変わらないように)。
- 判定の閾値も `thresholds` で変更できる(下記)。

設定例:

```jsonc
// 自社で使っている製品だけを、直近3日分、要確認以上で出力
{ "window_days": 3, "cpe_match": ["cpe:2.3:a:apache:http_server", "cpe:2.3:a:openssl:openssl"], "min_judgement": "要確認" }
```

## 使い方

```bash
python cve_triage.py                          # config.json の設定どおりに実行
python cve_triage.py --date 2026-10-13        # 日付を指定
python cve_triage.py --date 2026-10-01 --end-date 2026-10-07 --cpe cpe:2.3:a:apache   # 期間+製品
python cve_triage.py --config my.json         # 別の設定ファイルを使う
python -m unittest                            # テスト
```

- 環境変数 `NVD_API_KEY` を設定すると NVD のレート制限が緩和される(キー無し: 5件/30秒、有り: 50件/30秒)。キー無しでも動くが、2000件超の日や絞り込み条件が多い場合は時間がかかる。キーは [NVD](https://nvd.nist.gov/developers/request-an-api-key) で無料発行できる。
- 出力: `output/cve_triage_YYYY-MM-DD.csv`(期間指定時は `_開始_終了`)。UTF-8 BOM付きなので Excel でそのまま開ける。0件でもヘッダのみのCSVを出力する。同じ日付で設定を変えて再実行すると上書きされる。
- ログ: `logs/cve_triage.log`(ローテーションあり)。取得失敗時は終了コード 1。

## 判定ルール

上から順に最初に当てはまったものを採用する(閾値は config.json の `thresholds`、または `--cvss-high` `--cvss-critical` `--epss-immediate` `--epss-high` `--epss-low` で変更可)。

| 判定 | 条件(既定値) | `action_required` |
|---|---|---|
| 即時対処 | KEV登録済み、または EPSS ≥ 50% | Y |
| 要対処 | CVSS ≥ 7.0 かつ EPSS ≥ 10%、または CVSS ≥ 9.0 かつ EPSS ≥ 3% | Y |
| 要確認 | EPSS ≥ 10%(CVSS低/未付与)、または CVSS ≥ 9.0(EPSS低/未算出) | N |
| 判定保留 | EPSS未算出で、CVSSが 7.0以上 または 未付与 | N |
| 経過観察 | 上記以外(CVSS High止まりでEPSSが低い場合を含む) | N |

CSVは判定の重い順 → EPSS降順 → CVSS降順で並ぶ。`reason` に判定理由、データ欠損時は `[CVSS未付与]` `[EPSS未算出]` が付く。

### 運用上の注意

- **新規公開直後のCVEはEPSSが未算出のことが多い。** 実測では、前日公開分は約8割でEPSSが未算出、2日前の分は全件算出済みだった。そのため取得終了日の既定を「2日前」にしている(`end_days_ago`)。1にすると新しい情報は早く得られるが「判定保留」が増える。KEV登録済みはEPSSに関係なく判定されるので、早く知りたい場合は `end_days_ago: 1` と `kev_only: true` の別設定を `--config` で併用するとよい。
- 新規公開CVEはEPSSが低く出やすく、CVSS High以上は全体の6割超を占める。「CVSS High かつ EPSS低」まで要確認にすると仕分けにならないため、経過観察としている。
- 判定は一般的な脅威度に基づくもので、自組織の資産・影響範囲は考慮していない。製品で絞り込む場合も、CPEが未登録の新規CVEは取りこぼす可能性がある(キーワードとの併用を推奨)。

## 日次の自動起動

EPSS は毎日 12:00 UTC 頃に更新されるため、朝(JST 10:00 = 01:00 UTC 頃)の実行なら前日分のスコアで判定できる。

**Windows**(タスクスケジューラに登録。登録スクリプトは未実行なので必要に応じて実行する):

```powershell
powershell -ExecutionPolicy Bypass -File register_windows_task.ps1 -Time 10:00
```

**Linux(cron)**:

```cron
0 10 * * * cd /path/to/cve_triage && NVD_API_KEY=xxxx /usr/bin/python3 cve_triage.py
```

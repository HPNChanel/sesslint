# CONTRACT_MAP

Bảy heading hợp đồng CLI, ghép nguyên văn từ bản đồ đã đối chiếu ngày 2026-11-06. Nguồn đã đọc là HEAD `02694d537104659df66cdd084354739f3cccc440`. Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. Phần báo cáo worker không đưa vào file này.

# check-json

Bản đồ JSON stdout/file của lệnh OSS `check`. Nguồn là worktree `D:\FOR_WORK\WORK_PROJECT\sesslint`, HEAD `02694d537104659df66cdd084354739f3cccc440`, nhánh `feat/outcome-guard`. Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` tồn tại và là tổ tiên của HEAD. Worktree không bị đổi nhánh.

`git diff e91d50b2ecea57ef4dd900e3b0b87b14946e847e HEAD` trên các file render JSON của `check` chỉ có `src/sesslint/cli/_output.py`: thêm `"outcome"` vào `_REPORT_COMMANDS` và thêm tên biên `contract`, `target`, `session`. `emit_text` không đổi. `report.py`, `scan.py`, `cli/check.py`, `cli/_render.py`, `cli/_json_errors.py`, `cli/_common.py`, `cli/__init__.py`, `_canonical_codec.py` trùng pin. Dòng trích dưới đây là dòng của HEAD.

`sesslint check` và alias `scan` là cùng lệnh (`src/sesslint/cli/check.py:45-46`). Bốn document JSON có thể ra stdout. Ba document report/skip đi qua `emit_text`. Document lỗi fallback và envelope nội bộ là `print` riêng.

## Schema id

- B01. Report một file hoặc stdin mang field `schema_version` bằng hằng `"sesslint.report/v1"` (`src/sesslint/report.py:39-40`, gán tại `src/sesslint/report.py:918` và `src/sesslint/report.py:2062`). Cùng chuỗi nằm ở `src/sesslint/_version.py:10`. Test CLI: `tests/cli/test_check.py:36`.
- B02. Trên đường CLI thường, `repro.schema_versions` còn ba id: `manifest` = `"sesslint.repair-manifest/v1"` (`src/sesslint/report.py:42-43`, `src/sesslint/report.py:1909`), `report` = `REPORT_SCHEMA_VERSION` (`src/sesslint/report.py:1910`), `session` = literal `"sesslint.session/v1"` (`src/sesslint/report.py:1911`).
- B03. Report thư mục, nhiều path, hoặc `--agent` mang `schema_version` mặc định `"sesslint.scan-report/v1"` (`src/sesslint/scan.py:287`, ghi tại `src/sesslint/scan.py:315`, hằng `src/sesslint/scan.py:327`). Test `--format json` trên thư mục và trên cặp file+thư mục: `tests/cli/test_ac03_lone_surrogate.py:432-443`.
- B04. Document report một file chỉ được chứa khoá trong `KNOWN_REPORT_FIELDS` / `REPORT_ROOT_KEYS` (`src/sesslint/report.py:129-145`). Tập đó có `schema_version`, không có `$id` hay `$schema`. `render_json` chỉ gán các khoá tại `src/sesslint/report.py:2056-2074`. `load_report_schema` đọc file schema (`src/sesslint/report.py:1688-1703`) và không chép khoá nào của file đó vào document.
- B05. Document scan gồm `files`, `root_path`, `schema_version`, `totals`, và `summary` khi có (`src/sesslint/scan.py:312-319`). Không có `$id` hay `$schema`.
- B06. Document `--skip-undetected` không có field schema. Khoá là `findings`, `ok`, `path`, `skipped`, `skipped_reason` (`src/sesslint/cli/_render.py:162-169`). Test: `tests/test_field_regressions.py:263-275`.
- B07. Document lỗi fallback có `code` = `"ERROR"`, `message`, `verdict` = `"error"` (`src/sesslint/cli/_json_errors.py:75-78`). Không có `schema_version`. Test các nhánh `check`/`scan` `--json` và `--format json` khi thất bại: `tests/cli/test_ac03_lone_surrogate.py:304-347`, `tests/cli/test_ac03_lone_surrogate.py:412-416`.
- B08. Envelope lỗi nội bộ có `code` = `"INTERNAL_ERROR"`, `error_id`, `message`, `verdict` = `"error"` (`src/sesslint/api.py:1213-1218`), in khi `args.json` đúng (`src/sesslint/cli/_common.py:46-49`). `main` bật `args.json` khi `wants_json` và stdout còn trống (`src/sesslint/cli/__init__.py:222-228`).
- U01. URL `$id` trong file schema JSON. Python không gán chuỗi URL đó vào output của `check`. UNKNOWN.

## Thứ tự field

`json.dumps(..., sort_keys=True)` quyết định thứ tự khoá object. Mảng giữ thứ tự đã dựng trước lời gọi. Danh sách “thứ tự sort” dưới đây là `sorted` của đúng các chuỗi khoá mà nguồn chèn. Nguồn không ghi một hàm so khoá riêng.

- B09. Report một file: `src/sesslint/report.py:2134`. Scan: `src/sesslint/scan.py:322-324`. Skip: `src/sesslint/cli/_render.py:162-170` (có `sort_keys`, không có `indent`). Lỗi fallback: `src/sesslint/cli/_json_errors.py:78`. Envelope nội bộ: `src/sesslint/cli/_common.py:49`.
- B10. Mảng `findings` của report được sắp bằng `finding_report_sort_key` trước khi dựng JSON (`src/sesslint/report.py:1968-1969`, `src/sesslint/report.py:2046-2055`). Khoá sắp: path slash-forward, line (`None` thành `-1`), ordinal evidence `record_ordinal` (`None` thành `-1`), hạng severity, code, record_id, fingerprint, rồi `related_ids`, message, repairability (`src/sesslint/finding.py:373-408`).
- B11. CLI một file/stdin luôn truyền `repro` (`src/sesslint/cli/_render.py:247-262`). Khoá gốc khi không `--include-content`, thứ tự sort: `assurance`, `counts`, `coverage`, `findings`, `limitation`, `repro`, `schema_version`, `session_id`, `source_fingerprint`, `tool_version`. Tập khoá được chèn tại `src/sesslint/report.py:2056-2071`.
- B12. `--include-content` thêm `content_warning` và `included_content`, cả hai bằng `True` (`src/sesslint/report.py:2072-2074`). Thứ tự sort của gốc khi đã có `repro`: `assurance`, `content_warning`, `counts`, `coverage`, `findings`, `included_content`, `limitation`, `repro`, `schema_version`, `session_id`, `source_fingerprint`, `tool_version`.
- B13. `counts` chèn `by_severity`, `by_code`, `total` (`src/sesslint/report.py:260-266`). Thứ tự sort: `by_code`, `by_severity`, `total`. `by_severity` luôn có bốn khoá `fatal`, `error`, `warning`, `info` theo `REQUIRED_SEVERITIES` (`src/sesslint/report.py:214`, vòng tại `src/sesslint/report.py:263`). Thứ tự sort của bốn khoá đó: `error`, `fatal`, `info`, `warning`. `by_code` được `dict(sorted(...))` lúc dựng (`src/sesslint/report.py:264`, `src/sesslint/report.py:910`).
- B14. `coverage` chèn `adapter`, `performed`, `profile`, `skipped` (`src/sesslint/report.py:410-415`). `performed` là list đã sort (`src/sesslint/report.py:359`). `skipped` sort theo `(check, reason, detail)` (`src/sesslint/report.py:269-270`, `src/sesslint/report.py:372`, `src/sesslint/report.py:414`). Mỗi skip chèn `check`, `detail`, `reason` (`src/sesslint/report.py:310-315`). `adapter` và `profile` có `id`, `version`, và `name` khi nguồn có `name`, rồi `dict(sorted(...))` (`src/sesslint/report.py:404-413`).
- B15. Finding mặc định chèn `code`, `evidence`, `fingerprint`, `remediation`, `repairability`, `severity`, `span` (`src/sesslint/report.py:2011-2019`). `--include-content` thêm `message`, và thêm `record_id` khi `f.source.record_id` đúng (`src/sesslint/report.py:2020-2023`). `span` chèn `path`, `line`, `byte` (`src/sesslint/report.py:1987-1991`); thứ tự sort: `byte`, `line`, `path`.
- B16. Đường `render_json` của `Report` gán `evidence.ordinal` = chỉ số 1-based trong mảng đã sort, nếu khoá `ordinal` chưa có (`src/sesslint/report.py:2006-2007`, `src/sesslint/report.py:2052-2053`). Evidence rỗng vẫn thành object vì có `ordinal` (`src/sesslint/report.py:2013`). Scan gọi `format_finding_content_free(f)` không truyền `ordinal` (`src/sesslint/scan.py:144`), nên evidence scan có thể là `None`.
- B17. Evidence bỏ các khoá `content`, `text`, `payload`, `message`, `prompt` khi không `include_content` (`src/sesslint/report.py:1996-1997`). Chuỗi dài hơn 16 mà tên khoá chứa `"id"` hoặc `"uuid"` (so substring, hạ chữ) bị thay bằng `short_hash` 8 hex (`src/sesslint/report.py:1998-2002`, `src/sesslint/report.py:1825-1827`). Giá trị khác được chép nguyên (`src/sesslint/report.py:2003-2004`). `include_content` bỏ bước lọc đó.
- B18. `repro.to_dict` chèn `adapter`, `cli_version`, `detection`, `platform`, `profile`, `schema_versions` (`src/sesslint/report.py:1874-1881`). `adapter`/`profile` của repro là `name` + `version` (`src/sesslint/report.py:1913-1914`). `detection` là `confidence` + `method` (`src/sesslint/report.py:1915`). `platform` là `architecture`, `os`, `python` (`src/sesslint/report.py:1916-1920`). `schema_versions` là `manifest`, `report`, `session` (B02).
- B19. CLI đặt `detection.method` = `"manual"` khi adapter đã resolve khác `"auto"`, còn lại `"auto"` (`src/sesslint/cli/_render.py:252`). `detection.confidence` trên đường này là `None` (`src/sesslint/cli/_render.py:253`). Test: `tests/cli/test_check.py:121-148`. Ngưỡng `--confidence-min` không được ghi vào `repro.detection.confidence`.
- B20. Scan, thứ tự sort gốc khi có summary: `files`, `root_path`, `schema_version`, `summary`, `totals`. Không summary thì bỏ khoá đó (`src/sesslint/scan.py:312-319`). `totals` chèn `healthy`, `invalid`, `skipped`, `total`, `unreadable`, `unsupported` (`src/sesslint/scan.py:214-223`). `skipped_reasons` chỉ thêm khi có file `skipped` kèm reason; khoá reason đã `sorted` (`src/sesslint/scan.py:293-311`). Test bỏ khoá khi rỗng: `tests/test_scan_schema.py:131-137`.
- B21. Mỗi file scan luôn có `error_count`, `path`, `verdict`, `warning_count` (`src/sesslint/scan.py:123-128`). Thêm `skipped_reason` khi khác `None` (`src/sesslint/scan.py:129-130`), `cache` = `"hit"` khi `cache_hit` (`src/sesslint/scan.py:131-132`), `findings` và `finding_groups` khi có finding (`src/sesslint/scan.py:133-155`). `to_wire` mới mang `session_id`, `tip_id`, `detected_format`, `links` (`src/sesslint/scan.py:158-178`); `to_dict` không chèn các khoá đó.
- B22. `finding_groups` sort theo `(code, kind)` (`src/sesslint/scan.py:145-154`). Mỗi nhóm chèn `code`, `kind`, `count`, `sample_fingerprints`. Mẫu finding cắt theo `max_findings_per_code` (`src/sesslint/scan.py:141-142`, `src/sesslint/scan.py:150-152`).
- B23. Walk thư mục sort `files` theo `FileResult.path` (`src/sesslint/scan.py:1464-1465`). Path hiển thị đi qua `minimize_path` trước khi lưu (`src/sesslint/scan.py:1115`, `src/sesslint/scan.py:891`). Nhiều path: mỗi `scan_path` xong, list gộp sort lại theo `r.path` (`src/sesslint/cli/check.py:491-496`). `--agent`: nối `rep.files` theo thứ tự root, không sort lại toàn cục (`src/sesslint/cli/check.py:372-400`). Thứ tự root: agent được chọn, `claude` rồi `codex` khi `--agent all` (`src/sesslint/cli/check.py:356`, `src/sesslint/api.py:1346-1374`); `archived_sessions` đứng sau root codex khi `--include-archived` (`src/sesslint/api.py:1376-1384`). Root vắng thành một file `skipped` với reason `agent-root-missing` hoặc `agent-root-not-directory` (`src/sesslint/cli/check.py:381-393`). `root_path` agent và multi-path là các path đã minimize, nối bằng `;` (`src/sesslint/cli/check.py:399-400`, `src/sesslint/cli/check.py:492-494`).
- B24. Summary scan được gắn khi `group_by != "none"` hoặc `top > 0` (`src/sesslint/cli/check.py:284-296`). Mặc định `--top` 10 và `--group-by code` (`src/sesslint/cli/check.py:130-145`), nên CLI scan mặc định có `summary`. `--group-by none` cùng `--top 0` để `summary` là `None` và `to_dict` bỏ khoá. Summary chèn `by_code`, `worst_files` (`src/sesslint/scan.py:275-280`). Hàng code: `code`, `count`, `files`, `severity` (`src/sesslint/scan.py:235-241`), thứ tự mảng là hạng severity tăng, count giảm, code tăng (`src/sesslint/scan.py:387-394`). Hàng file: `error_count`, `path`, `warning_count` (`src/sesslint/scan.py:257-261`), thứ tự mảng là error giảm, warning giảm, path tăng (`src/sesslint/scan.py:398-409`). `top` 0 cho `worst_files` rỗng; `group_by none` cho `by_code` rỗng; hai khoá vẫn có trong object summary.
- B25. Skip, thứ tự sort: `findings`, `ok`, `path`, `skipped`, `skipped_reason` (`src/sesslint/cli/_render.py:163-169`). `path` là `minimize_path(display_path)`.
- B26. Lỗi fallback, thứ tự sort: `code`, `message`, `verdict` (`src/sesslint/cli/_json_errors.py:78`). Envelope nội bộ, thứ tự sort: `code`, `error_id`, `message`, `verdict` (`src/sesslint/api.py:1213-1218` với `src/sesslint/cli/_common.py:49`).
- B27. Khoá gốc hoặc khoá finding ngoài allowlist làm `render_json` ném `OperationalError` trước `json.dumps` (`src/sesslint/report.py:2083-2132`). Finding mặc định cấm `text`, `content`, `message`, `payload` (`src/sesslint/report.py:158-160`, `src/sesslint/report.py:2097-2104`).
- U02. `sort_keys` có phụ thuộc locale hay chỉ so sánh mã ký tự: nguồn không nói. UNKNOWN.

## Newline cuối

- B28. `render_json`, `ScanReport.to_json`, `error_document` và envelope nội bộ trả về đúng chuỗi `json.dumps`. Các hàm đó không nối thêm `"\n"` (`src/sesslint/report.py:2134`, `src/sesslint/scan.py:324`, `src/sesslint/cli/_json_errors.py:78`, `src/sesslint/cli/_common.py:49`).
- B29. Không có `-o`: `emit_text` gọi `print(text)` và không truyền `end` (`src/sesslint/cli/_output.py:118-120`). Docstring nói file nhận cùng byte với payload của `print`, cộng newline mà `print` thêm (`src/sesslint/cli/_output.py:111-116`).
- B30. Có `-o`: file nhận `text.encode("utf-8") + b"\n"` (`src/sesslint/cli/_output.py:132-134`). Byte thêm là `0x0A`, không phải `os.linesep`.
- B31. Test `check --json` bắt byte file `-o` bằng stdout mà capsys bắt (`tests/cli/test_output_file.py:28-37`).
- B32. `main` gọi `reconfigure(encoding="utf-8")` trên stdout/stderr kiểu `TextIOWrapper` và không truyền `newline` (`src/sesslint/cli/__init__.py:178-180`).
- U03. `json.dumps` có tự kết thúc bằng newline hay không: nguồn không kiểm. UNKNOWN. Vì vậy nguồn không tự chứng minh “đúng một newline” nếu chuỗi dumps đã có newline.
- U04. Stdout thật của hệ điều hành có dịch `\n` thành CRLF hay không: `reconfigure` không đặt `newline`. Test B31 chạy dưới capsys. UNKNOWN cho console/pipe thật. File `-o` vẫn là UTF-8 cộng một byte `0x0A` (B30).

## In số và Unicode

- B33. Report và scan in bằng `json.dumps(obj, indent=2, sort_keys=True)` (B09). Lời gọi đó không truyền `ensure_ascii`, `allow_nan`, `separators`, `cls`. Codec canonical là hàm khác: `ensure_ascii=False`, `separators=(",", ":")`, `allow_nan=False`, không `indent` (`src/sesslint/_canonical_codec.py:79-90`). `render_json` và `ScanReport.to_json` không gọi codec đó.
- B34. Skip, lỗi fallback và envelope nội bộ cũng không truyền `indent`, `ensure_ascii`, `allow_nan`, `separators` (B09). Ba document này là một object `json.dumps` không `indent`.
- B35. `counts` là `int`: `total` và từng ô severity/code bị từ chối nếu không phải `int` không âm, và `bool` bị loại vì `bool` là lớp con của `int` (`src/sesslint/report.py:231-258`). `totals` scan và các count file là `int` (`src/sesslint/scan.py:201-223`, `src/sesslint/scan.py:123-128`). Test đọc `counts.total` và `by_severity.error` sau `json.loads` (`tests/cli/test_check.py:37-38`).
- B36. `span.byte` là `int` chỉ khi evidence `byte_offset` hoặc `byte` là `int`, không phải `bool`, và `>= 0`; không thì `None` (`src/sesslint/report.py:1980-1991`). `span.line` là `f.source.line` (`src/sesslint/report.py:1989`).
- B37. `content_warning` và `included_content` là `True` (`src/sesslint/report.py:2073-2074`). Sau `json.loads`, test thấy `True` (`tests/report/test_secret_warn.py:53-54`, `tests/report/test_content_free.py:152-153`). Skip: `ok` và `skipped` là `True` (`src/sesslint/cli/_render.py:165-167`, `tests/test_field_regressions.py:271-272`).
- B38. `repro.detection.confidence` trên CLI là `None` (B19). `assurance` là chuỗi `A0`–`A4` (`src/sesslint/report.py:45`), không phải số.
- B39. Evidence không đi qua formatter số riêng (B17). `cache` scan là chuỗi `"hit"`, không phải bool (`src/sesslint/scan.py:132`).
- B40. Path trong report đi qua `minimize_path`: `\` thành `/`, path dưới home thành `~/...`, path khác thành `.._<sha1(parent)[:8]>/<tên>` (`src/sesslint/report.py:1731-1781`). Hàm này không escape `\u`. `render_json` để `home=None` (`src/sesslint/report.py:2033`); CLI không truyền `home` (`src/sesslint/cli/_render.py:258-262`), nên `Path.home()` được dùng (`src/sesslint/report.py:1751`).
- B41. Docstring `Report` nói report không có đồng hồ (`src/sesslint/report.py:433-435`). Document CLI vẫn nhúng `platform.machine()`, `sys.platform`, phiên bản Python và `__version__` trong `repro` (`src/sesslint/report.py:1899-1920`). Byte JSON CLI phụ thuộc máy vì `repro` và vì `Path.home()` trong path.
- B42. `error_document` đưa `message` qua `encode("utf-8", errors="backslashreplace").decode("utf-8")` rồi `json.dumps` (`src/sesslint/cli/_json_errors.py:75-78`). Docstring của hàm gọi kết quả là “One ASCII object”.
- U05. Dạng escape Unicode của `json.dumps` khi không truyền `ensure_ascii` (`\uXXXX` hay UTF-8 thô): nguồn `check` không ghim, test chỉ `json.loads`. UNKNOWN.
- U06. Ngữ pháp float và token `NaN` / `Infinity`: đường `check` không truyền `allow_nan` và không có formatter float. UNKNOWN.
- U07. Chính tả byte của `true` / `false` / `null` và của số nguyên (chữ số, không có `.0`): test `check` chỉ `json.loads`. UNKNOWN.
- U08. Khoảng trắng quanh `:` và `,`: nguồn không truyền `separators`, cả khi `indent=2` và khi không `indent`. UNKNOWN.

## Biến thể theo flag

- B43. `--json` và `-f`/`--format` loại trừ lẫn nhau. Choices của `--format`: `human`, `json`, `sarif`, `html` (`src/sesslint/cli/check.py:114-127`). `_output_format` trả `"json"` khi `args.json`, không thì lấy `output_format`, không có thì `"human"` (`src/sesslint/cli/_common.py:106-110`).
- B44. `SESSLINT_FORMAT` ghi vào `args.output_format` khi CLI không chọn format (`src/sesslint/cli/_context.py:159-181`, `src/sesslint/cli/_context.py:302-313`). Choices của `check` gồm cả `sarif` và `html` (`src/sesslint/cli/_context.py:138-140`). Config không có khoá format (`src/sesslint/cli/_context.py:84-90`). `SESSLINT_FORMAT=json` chọn document JSON. `sarif` và `html` đi nhánh khác (`src/sesslint/cli/_render.py:267-291`, `src/sesslint/cli/check.py:302-321`).
- B45. Một file hoặc `-` stdin đi `_emit_check_report` (`src/sesslint/cli/check.py:405-447`, `src/sesslint/cli/check.py:552-560`). Thư mục đi `check_dir` rồi scan JSON (`src/sesslint/cli/check.py:500-517`). Nhiều path đi scan JSON (`src/sesslint/cli/check.py:462-497`). `--agent` đi scan JSON (`src/sesslint/cli/check.py:351-401`).
- B46. `--agent` ghi đè `skip_undetected=True` trong kwargs (`src/sesslint/cli/check.py:374-376`).
- B47. Trên report một file, `--skip-undetected` và `limitation` bắt đầu bằng `"Unsupported:"` phát document skip (B06) và return 0, trước nhánh `render_json` (`src/sesslint/cli/_render.py:151-187`). Không flag này, cùng limitation vẫn là report `sesslint.report/v1` với `assurance` `A0` (`tests/cli/test_check.py:82-90`, `src/sesslint/cli/_render.py:197-199` rồi `src/sesslint/cli/_render.py:241-265`).
- B48. `--include-content` mặc định `argparse.SUPPRESS` (`src/sesslint/cli/check.py:191-195`). Không nằm trong `_SETTING_SPECS`, nên env/config không bật nó. `render_json` nhận `getattr(args, "include_content", False)` (`src/sesslint/cli/_render.py:260`). Scan gọi `to_json()` không tham số (`src/sesslint/cli/check.py:301`), và `format_finding_content_free` mặc định `include_content=False` (`src/sesslint/report.py:1975`, `src/sesslint/scan.py:144`). Document skip cũng không đọc flag này. Cờ vẫn in cảnh báo ra stderr (`src/sesslint/cli/__init__.py:149-152`).
- B49. `--top` và `--group-by` đổi sự có mặt và nội dung `summary` (B24). `--top` âm trên scan return 2 trước khi in report (`src/sesslint/cli/check.py:286-288`).
- B50. `--max-findings-per-code` vào scan kwargs (`src/sesslint/cli/_scan_args.py:36`) và cắt mẫu (B22). Mặc định config 20 (`src/sesslint/cli/_context.py:104`).
- B51. `--incremental` lần lạnh cho `to_json` bằng lần không cache (`tests/scan/test_incremental.py:47-51`). Lần ấm thêm `"cache": "hit"` (`src/sesslint/scan.py:131-132`, `tests/scan/test_incremental.py:54-63`). Không flag thì không có khoá `cache` (`tests/scan/test_incremental.py:66-70`).
- B52. `-o`/`--output` chuyển byte report vào file (B30). Stdout nhận `wrote <path> (<summary>)` trừ khi `-q` (`src/sesslint/cli/_output.py:141-142`, `tests/cli/test_output_file.py:41-56`).
- B53. `main` không in document lỗi thứ hai sau khi stdout đã có nội dung (`src/sesslint/cli/__init__.py:222-233`). Mã 0 và 130 cũng không nhận `error_document`. Mã khác, JSON được yêu cầu, stdout trống: in `error_document` ra stdout gốc. `SchemaError` trong `check --json` để stdout trống, exit 1, message chứa text lỗi (`tests/cli/test_ac03_lone_surrogate.py:421-428` cùng `src/sesslint/cli/check.py:576-578`).
- B54. `-o` kết hợp `-q` không `print` dòng `wrote`, nên `TrackedStream.nonempty` có thể vẫn sai trong khi file đã có report (`src/sesslint/cli/_output.py:118-142`). Nếu mã thoát khác 0 và 130, điều kiện B53 in `error_document` ra stdout. Không có test ghim tổ hợp exit 1 + `-o` + `-q`. Exit 0 + `-q` để stdout rỗng (`tests/cli/test_output_file.py:50-56`).
- B55. `--progress-json` ghi NDJSON tiến độ bằng `print(..., file=stderr)` (`src/sesslint/cli/_progress.py:1-26`, `src/sesslint/cli/_context.py:66-72`). Report vẫn là `emit_text` trên stdout. Schema từng sự kiện tiến độ nằm ngoài card này.
- B56. Nhánh JSON của report một file không gọi `should_color` (`src/sesslint/cli/_render.py:241-265`). `should_color` trả `False` khi `args.json` (`src/sesslint/cli/_common.py:55-60`); `--format json` không tự bật `args.json`, và nhánh JSON vẫn không nhuộm màu.
- B57. `scan_path` jobs 1 và jobs > 1 cho cùng `to_json` (`tests/scan/test_parallel.py:63-67`). Một file: `--jobs` > 1 chỉ ghi chú stderr (`src/sesslint/cli/check.py:523-524`). Comment CLI nói output report không đổi theo N (`src/sesslint/cli/check.py:146-154`).
- B58. `--seal` không đổi chuỗi `emit_text`. Hash seal nhận `render_json(report)` mặc định: không `repro`, không `include_content` (`src/sesslint/cli/check.py:448-458`, `src/sesslint/cli/check.py:561-572`). Stdout JSON một file có `repro` (B11). `--seal` từ chối nhiều path và thư mục trước khi in report (`src/sesslint/cli/check.py:344-349`, `src/sesslint/cli/check.py:501-506`); các từ chối đó rơi vào document lỗi B07 khi chế độ JSON (`tests/cli/test_ac03_lone_surrogate.py:320-328`).
- B59. `--adapter`, `--profile`, `--select`, `--ignore`, `--baseline` đổi giá trị bên trong report (coverage, repro.method, findings) và được truyền vào `check_file` (`src/sesslint/cli/check.py:526-545`). Chúng không thêm khoá gốc ngoài B11–B12. Adapter resolve từ CLI, rồi `SESSLINT_ADAPTER`, rồi config (`src/sesslint/cli/_context.py:88`, `src/sesslint/cli/_context.py:256-269`) và quyết định `repro.detection.method` (B19).

## Đếm

- Đã dẫn chứng: 59 (B01–B59).
- UNKNOWN: 8 (U01–U08).

# check-text

Bản đồ text human của lệnh OSS `check`. Nguồn là worktree `D:\FOR_WORK\WORK_PROJECT\sesslint`, HEAD `02694d537104659df66cdd084354739f3cccc440`, nhánh `feat/outcome-guard`. Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` là tổ tiên của HEAD (`git merge-base --is-ancestor` thoát 0). Worktree không bị đổi nhánh. `git status --porcelain` trên các file dẫn dưới đây không có dòng.

`git diff e91d50b2ecea57ef4dd900e3b0b87b14946e847e HEAD` trên `cli/_render.py`, `report.py`, `scan.py`, `finding.py`, `cli/_common.py`, `cli/check.py`, `cli/_context.py`, `cli/_options.py`, `cli/_json_errors.py`, `api.py`, `repair/refusals.py` rỗng. Chỉ `src/sesslint/cli/_output.py` lệch: `_REPORT_COMMANDS` thêm `"outcome"`; `_boundaries` thêm tên `contract`, `target`, `session`. Thân `emit_text` không nằm trong diff. Số dòng HEAD của hàm đó là 103–142; trên pin `def emit_text` ở dòng 98, `print(text)` ở 115, `encode` ở 129 (lệch +5 vì hai hunk phía trên). Dòng trích khác là dòng HEAD, trùng pin.

Giả thuyết (đọc nguồn, không sửa): human có hai renderer. Một file và stdin đi `render_human`. Thư mục, nhiều path và `--agent` đi `format_scan_report_human`. Màu là chuỗi ANSI rỗng hoặc bọc một cụm; chữ giữ nguyên. Độ rộng là hằng trong literal. Thứ tự finding là `finding_sort_key`; thứ tự dòng file của scan thư mục là `r.path` sau khi đã minimize. Chỗ nguồn không nói thì ghi UNKNOWN. Không chạy pytest.

`sesslint check` và alias `scan` dùng cùng `run` (`src/sesslint/cli/check.py:45-46`, `src/sesslint/cli/check.py:52-60`). JSON, SARIF và HTML là nhánh khác (`src/sesslint/cli/_render.py:241-292`, `src/sesslint/cli/check.py:299-321`). Bản đồ này là nhánh human.

## Khung một file và stdin

- B01. Một file và `-` stdin gọi `_emit_check_report` (`src/sesslint/cli/check.py:440-447`, `src/sesslint/cli/check.py:552-560`). `--latest` giải một path rồi đi cùng đường một file (`src/sesslint/cli/check.py:224-240`). Thư mục, nhiều path và `--agent` gọi `_emit_scan_rep` (`src/sesslint/cli/check.py:351-401`, `src/sesslint/cli/check.py:464-497`, `src/sesslint/cli/check.py:500-517`).
- B02. `_output_format` trả `"json"` khi `args.json`, không thì `output_format`, không có thì `"human"` (`src/sesslint/cli/_common.py:106-110`). Choices `--format`: `human`, `json`, `sarif`, `html` (`src/sesslint/cli/check.py:114-127`). `--json` và `--format` loại trừ lẫn nhau (`src/sesslint/cli/check.py:114`). `SESSLINT_FORMAT` thắng khi CLI không chọn format (`src/sesslint/cli/_context.py:159-184`). Giá trị mặc định `"human"` không bị `setattr` khi nguồn là default (`src/sesslint/cli/_context.py:302-313`).
- B03. Nhánh human một file gọi `render_human` rồi `emit_text` (`src/sesslint/cli/_render.py:293-304`). CLI không truyền `home` và không truyền `next_action` (`src/sesslint/cli/_render.py:296-301`). `adapter` hiển thị là `FORMAT_DISPLAY_NAMES` của `coverage.adapter["id"]`, thiếu id thì `"canonical"`, id lạ thì chính id đó (`src/sesslint/cli/_render.py:238-239`). Bảng tên: `canonical`, `Claude Code`, `Codex rollout`, `OpenAI Agents` (`src/sesslint/cli/_common.py:21-26`). `profile` hiển thị là `coverage.profile["id"]`, thiếu thì `profile_opt` (`src/sesslint/cli/_render.py:300`).
- B04. Khi `not has_error` và `counts.by_severity["warning"] == 0` và `not ctx.quiet`, chuỗi được ghép `Valid {format_display} session\n` phía trước (`src/sesslint/cli/_render.py:302-303`). `has_error` ở đây là error hoặc fatal, và thêm warning khi `--fail-on warning` (`src/sesslint/cli/_render.py:189-195`). Dòng Valid không có mã màu. `-q` bỏ dòng này; thân `render_human` vẫn đi `emit_text`. Test: `tests/cli/test_quiet_verbose.py:28-37`, `tests/cli/test_check.py:165-176`.
- B05. `render_human` tự tính `has_error` / `has_warning` từ counts và không đọc `fail_on` (`src/sesslint/report.py:2155-2161`). Năm nhánh verdict, cụm in đậm và `files:`:
  - `limitation` bắt đầu `Unsupported:` → chữ `unsupported`, cụm `Unsupported input (format-undetected)`, `H=0 I=0 U=1 R=0 S=0` (`src/sesslint/report.py:2163-2166`).
  - bắt đầu `Skipped:` → `skipped`, `Skipped input (file-too-large)`, `H=0 I=0 U=0 R=0 S=1` (`src/sesslint/report.py:2167-2170`).
  - error hoặc fatal → `invalid`, `Integrity check failed`, `H=0 I=1 U=0 R=0 S=0` (`src/sesslint/report.py:2171-2174`).
  - warning → `healthy with warnings`, `Session is healthy with warnings`, `H=1 I=0 U=0 R=0 S=0` (`src/sesslint/report.py:2175-2178`).
  - còn lại → `healthy`, `Session is healthy`, `H=1 I=0 U=0 R=0 S=0` (`src/sesslint/report.py:2179-2182`).
  Cả năm literal đều ghi `R=0`. Test warning và error: `tests/cli/test_check.py:178-222`.
- B06. `errors` trong meta = error + fatal. `warnings` = warning. Info không cộng vào hai số đó (`src/sesslint/report.py:2160-2161`). Meta là `verdict: {verdict} / errors: {err_cnt} / warnings: {warn_cnt} / files: {files_summary} / profile: {profile} / adapter: {adapter}` (`src/sesslint/report.py:2213-2216`).
- B07. Năm dòng đầu, đúng thứ tự: `[read-only] {cụm verdict} ({meta})`, `Next Action: ...`, `Assurance: {assurance} - {limitation}` (gạch ASCII), `Limitation: {limitation}`, `Source fingerprint: {source_fingerprint}` (`src/sesslint/report.py:2217-2223`). Các `lines.append` còn lại của hàm (`src/sesslint/report.py:2226-2312`) là coverage, Findings, và dòng SL009. Không có append `session_id`, `tool_version`, `schema_version`, count info, hay `related_ids`.
- B08. `Next Action` chọn theo thứ tự if (`src/sesslint/report.py:2184-2211`): unsupported; skipped; có error thì nếu có finding `repairability.value == "deterministic"` thì `Run 'sesslint repair {p} --output <out>'`; không thì nếu có `lossy-explicit` thì thêm `--policy salvage`; không thì câu manual, rồi quét finding đã sort và nối salvage path của rationale đầu tiên có `salvage_path`. Sau error: có SL009 thì câu secret; không thì có warning thì câu review; không thì `No repair needed.` Path của hai nhánh recipe là `hint_path(report.findings[0].source.path)`, tức phần tử đầu của tuple đang lưu (`src/sesslint/report.py:2190-2195`). `build_report` lưu `tuple(sort_findings(...))` (`src/sesslint/report.py:898`, `src/sesslint/report.py:922`). `check_file` và `check_bytes` trả `_check_impl` (`src/sesslint/api.py:119-134`, `src/sesslint/api.py:166`).
- B09. Coverage: `Coverage: {n} checks performed ({danh sách})`. Danh sách là `", ".join(cov.performed)`, rỗng thì `none` (`src/sesslint/report.py:2226-2228`). `performed` đã `tuple(sorted(...))` lúc dựng (`src/sesslint/report.py:359`). Có skip thì dòng `  Skipped ({n}): {check (reason), ...}` (`src/sesslint/report.py:2229-2231`). Mỗi mục là `"{check} ({reason})"`. `detail` không được in. Thứ tự skip là `(check, reason, detail)` (`src/sesslint/report.py:269-270`, `src/sesslint/report.py:372`).
- B10. Có finding thì một dòng trống, rồi `Findings:` (`src/sesslint/report.py:2233-2236`). Mỗi finding năm dòng (`src/sesslint/report.py:2280-2285`):
  - `  [{code}] {title} ({SEVERITY}, {repairability})`. Title là `CODE_REGISTRY[code].name`, thiếu code thì `Integrity finding` (`src/sesslint/report.py:2238`). Severity là `value.upper()`. Repairability là `value`: `deterministic`, `lossy-explicit`, `manual`, `unsupported` (`src/sesslint/codes.py:41-47`).
  - `    Span:        {loc}`.
  - `    Why:         {why}`.
  - `    Fix:         {fix}`.
  - `    Fingerprint: {fingerprint}`.
  Bốn tiền tố Span/Why/Fix/Fingerprint dài 17 ký tự trên literal `src/sesslint/report.py:2282-2285`, nên giá trị bắt đầu ở chỉ số 17.
- B11. `loc` là `minimize_path`, thêm `:{line}` khi line không `None` (`src/sesslint/report.py:2239-2240`). Có cả `byte_offset` và `byte_end`, cả hai là `int` không phải `bool`, `start >= 0` và `end >= start`, thì thêm ` (bytes {start}-{end})` (`src/sesslint/report.py:2241-2257`). Khoá `byte` một mình không đủ cho dòng human.
- B12. Why bắt đầu bằng `f.message` (`src/sesslint/report.py:2259`). SL001 nối thêm ` ({n} further record(s) / {size} may be invisible to vendor loaders)` khi `message_template` không chứa `lone surrogate, e.g.` và hai evidence `following_complete_records`, `following_bytes` là `int` không phải `bool` (`src/sesslint/report.py:2260-2277`). Hàm human không cắt lần hai sau khi nối.
- B13. `make_finding` cắt message đã render quá 500 ký tự: `cut = 500 - len("... [truncated]")` rồi cộng marker (`src/sesslint/finding.py:37-38`, `src/sesslint/finding.py:775-778`). Why in message đã lưu.
- B14. Fix là `get_finding_remediation(..., for_operator=True)` (`src/sesslint/report.py:2278`). Bốn câu (`src/sesslint/report.py:1948-1965`): deterministic `run 'sesslint repair {path}'`; lossy-explicit thêm `--policy salvage`; manual có rationale thì `manual inspection required; automated repair refused: {render}`; manual không rationale thì câu refused không có hậu tố; nhánh còn lại `unsupported defect or structure; automated repair refused` cộng `: {render}` khi có rationale. `render` là `{rationale} (DEMAND: {citation})` và, khi có salvage, `; salvage path: {path đã thay '{path}'}` (`src/sesslint/repair/refusals.py:113-118`). `for_operator=True` dùng `hint_path` (`src/sesslint/report.py:1943-1946`). Span dùng `minimize_path` (`src/sesslint/report.py:2239`).
- B15. `minimize_path` (`src/sesslint/report.py:1731-1781`): chuỗi đã là `~/...`, `~` hoặc `.._` thì giữ. `\` thành `/`. Absolute (kể cả `X:`) thử `~/` theo `relative_to(home)`. Absolute native thử lần nữa sau `resolve()`. Absolute không nằm dưới home thì `.._{sha1(parent)[:8]}/{name}` (`src/sesslint/report.py:1773-1775`). Path tương đối có parent cũng dạng hash đó (`src/sesslint/report.py:1777-1780`). Path tương đối chỉ có tên file thì trả `name` (`src/sesslint/report.py:1781`). `home is None` thì `Path.home()` (`src/sesslint/report.py:1751`).
- B16. `hint_path` (`src/sesslint/report.py:1795-1822`): cùng ba tiền tố thì giữ. Absolute dưới home thành `~/`. Absolute còn lại và mọi path tương đối trả chuỗi đã đổi `\` thành `/`, không băm. Docstring nói hint phải dán được vào shell (`src/sesslint/report.py:1796-1803`). CLI để `home=None` nên cả hai hàm gọi `Path.home()`. Docstring `Report` nói report không có đồng hồ (`src/sesslint/report.py:433-435`). Dòng fingerprint in `source_fingerprint` đã lưu, không thêm đồng hồ (`src/sesslint/report.py:2222`).
- B17. Sau các khối finding, nếu có SL009: một dòng `  SL009 warning - {số record} record(s) contain secret-shaped material (families: {name xN, ...}) - see --json for coordinates/hashes` (`src/sesslint/report.py:2289-2312`). Số record là số cặp `(line, record_ordinal)` khác nhau. Family lấy `secret_family` nếu là `str`, không thì `unknown`. `occurrence_count` được cộng khi là `int` không phải `bool`, không thì cộng 1. Tên family in theo `sorted`. Test cụm chữ: `tests/checks/test_hygiene.py:361-368`.
- B18. `_human_bytes` (`src/sesslint/report.py:1784-1792`): `n < 1024` → `{n} B`; `n < 1024*1024` → `{n/1024:.1f} KiB`; `n < 1024**3` → MiB; còn lại GiB. Ngưỡng đúng bằng 1024 sang bậc kế. Hàm không chặn `n` âm; `n < 1024` nên số âm đi nhánh `{n} B`.
- B19. File quá lớn: limitation `Skipped: file-too-large. No structural conclusion.`, findings rỗng, fingerprint `0` * 64, adapter id `unknown` (`src/sesslint/api.py:250-266`). `build_report` đếm 0 mọi severity (`src/sesslint/report.py:901-914`). Khi không quiet, B04 ghép `Valid unknown session` vì id `unknown` không có trong bảng tên (B03), rồi thân B05 nói `Skipped input (file-too-large)`. Cùng đường còn `ctx.info` ở B60. Format không resolve được: SL302 detection bị loại trước report (`src/sesslint/api.py:358-381`). Limitation là `Unsupported: format-undetected. No structural conclusion.` khi `rep_findings` rỗng, và là `No structural conclusion.` khi còn finding (`src/sesslint/api.py:387-390`). Findings rỗng thì tiền tố `Valid unknown session` và thân `Unsupported input (format-undetected)`. Còn finding thì limitation không bắt đầu bằng `Unsupported:`, nên verdict human đi nhánh error, warning hoặc healthy của B05, và dòng stderr B60 không chạy.

## Khung scan

- B20. `format_scan_report_human` (`src/sesslint/cli/_render.py:25-130`) luôn bắt đầu bằng `[read-only] Scan report for: {root_path}` rồi một dòng Totals theo thứ tự `healthy`, `invalid`, `unsupported`, `unreadable`, `skipped`, `(total=...)` (`src/sesslint/cli/_render.py:33-42`). `total` là tổng năm ô (`src/sesslint/scan.py:209-212`). Renderer không tính lại totals từ `files`.
- B21. `skipped_reason_totals` chỉ đếm verdict `skipped` có reason truthy, rồi `dict(sorted(counts.items()))` (`src/sesslint/scan.py:293-304`). Có bản ghi thì dòng `Skipped reasons: {k}={v}` cách nhau bằng dấu cách, theo thứ tự key đã sort (`src/sesslint/cli/_render.py:44-46`). Có key `max-bytes-cap-exceeded` hoặc `max-files-cap-exceeded` thì thêm `Hint: resource budget exhausted -- raise --max-bytes/--max-files to scan remaining files.` (`src/sesslint/cli/_render.py:47-51`). Test: `tests/cli/test_cli_presentation.py:106-135`.
- B22. Sau khối đầu là `"-" * 80` (`src/sesslint/cli/_render.py:52`). Mỗi file một dòng `  {tag đã đệm} {path}{detail}` (`src/sesslint/cli/_render.py:53-77`). Tag và detail:
  - `healthy` → `[HEALTHY]`, detail rỗng (`src/sesslint/cli/_render.py:54-57`).
  - `invalid` → `[INVALID]`, ` ({error_count} error(s), {warning_count} warning(s))` (`src/sesslint/cli/_render.py:58-61`).
  - `unsupported` → `[UNSUPPORTED]`, ` ({skipped_reason hoặc 'unsupported version'})` (`src/sesslint/cli/_render.py:62-65`).
  - `unreadable` → `[UNREADABLE]`, ` (read error or non-UTF8)` (`src/sesslint/cli/_render.py:66-69`).
  - `else` → `[SKIPPED]`, ` (reason: {skipped_reason})` (`src/sesslint/cli/_render.py:70-73`). `Verdict` là năm literal đó (`src/sesslint/scan.py:57`).
  `cache_hit` truthy thì nối ` [cache-hit]` (`src/sesslint/cli/_render.py:74-75`). Chỗ gán hit lúc đọc cache: `src/sesslint/scan.py:959`. `path` in là `r.path` đã lưu. Walk gán path bằng `minimize_path` (`src/sesslint/scan.py:1115`). Hàm human không gọi `minimize_path` lần nữa và không in Why/Fix từng finding.
- B23. `summary` khác `None` và (`by_code` hoặc `worst_files`) thì thêm gạch 80 (`src/sesslint/cli/_render.py:79-81`). Có `by_code` thì tiêu đề `Findings by code:` và `  {code}  {severity:<8} {count} finding(s) in {files} file(s)` (`src/sesslint/cli/_render.py:82-87`). Có `worst_files` thì `Worst files:` và `  {path}  ({error_count} error(s), {warning_count} warning(s))` (`src/sesslint/cli/_render.py:88-93`). Hai khối không có gạch ở giữa. Summary rỗng cả hai list thì không có khối này.
- B24. CLI gắn summary khi `group_by != "none"` hoặc `top > 0` (`src/sesslint/cli/check.py:284-296`). Mặc định `--top` 10 và `--group-by code` (`src/sesslint/cli/check.py:130-145`). `--top` âm trả trước khi `emit_text` (`src/sesslint/cli/check.py:286-288`). `aggregate_scan` để `by_code` rỗng khi `group_by == "none"`, `worst_files` rỗng khi `top == 0` (`src/sesslint/scan.py:372-410`).
- B25. Có file mang SL009 thì gạch 80 và `  secret-shaped material: {số file} file(s)` (`src/sesslint/cli/_render.py:97-100`). Số đó đếm file, không đếm finding. Test: `tests/checks/test_hygiene.py:406-422`.
- B26. Có SL402 với evidence truthy và `divergence` là `str` thì đếm theo kind (`src/sesslint/cli/_render.py:104-110`). Câu ghép theo thứ tự cố định, không theo thứ tự chèn dict (`src/sesslint/cli/_render.py:113-128`): `{n} session file(s) not listed in vendor index`; `{n} dangling index entry` khi n là 1, không thì `entries`; `malformed index`; `truncated index`. Kind khác được đếm nhưng không có mệnh đề. Dòng là `  index divergence: {các mệnh đề, ngăn bởi ', '} ({hint})`. Hint là `resumable by explicit id; see docs/codes/SL402.md` khi có `file-not-in-index`, không thì `see docs/codes/SL402.md`. `parts` rỗng vẫn in dòng này vì `if kinds` đã đúng.

## Màu

- B27. Bật màu thì các literal là bold `\033[1m`, reset `\033[0m`, đỏ `\033[31m`, lục `\033[32m`, vàng `\033[33m`. Tắt màu thì mọi biến đó là `""` (`src/sesslint/cli/_render.py:27-31`, `src/sesslint/report.py:2149-2153`). Không có mã SGR khác trong hai hàm.
- B28. Một file: cụm verdict là bold, thêm đỏ khi invalid, vàng khi warning, lục khi healthy; unsupported và skipped chỉ bold (`src/sesslint/report.py:2165-2181`). Meta trong ngoặc nằm sau `reset`. Title finding đỏ khi severity `error` hoặc `fatal`, còn lại vàng (`src/sesslint/report.py:2258`, `src/sesslint/report.py:2281`). `[CODE]` và `(SEVERITY, repairability)` nằm ngoài cặp màu.
- B29. Scan: màu bọc đúng `raw_tag`, khoảng đệm nằm sau `reset` (`src/sesslint/cli/_render.py:76`). Healthy lục, invalid đỏ, unsupported vàng, unreadable đỏ, skipped bold (`src/sesslint/cli/_render.py:54-73`). Path và detail không có mã màu.
- B30. `should_color` (`src/sesslint/cli/_common.py:55-68`), đúng thứ tự thoát: `no_color` đúng → False; `args.json` đúng → False; `NO_COLOR` có trong environ và giá trị truthy → False; `color == "never"` → False; `color == "always"` → True; không thì `hasattr(stream, "isatty") and bool(stream.isatty())`. Chuỗi `"0"` là truthy nên `NO_COLOR=0` làm False. Chuỗi rỗng là falsy nên không tắt màu. Biến không có trong environ thì bỏ qua bước đó.
- B31. Cờ: `--color` choices `auto`/`always`/`never`; `--no-color` (`src/sesslint/cli/_options.py:76-93`). Root đặt default; subcommand dùng `SUPPRESS` (`src/sesslint/cli/_options.py:82-91`, `src/sesslint/cli/__init__.py:80`). Test parse: root `--color`/`--no-color` còn trên namespace của `check`/`scan` (`tests/cli/test_cli_flags.py:12-26`); `--color` sau tên lệnh ghi đè root (`tests/cli/test_cli_flags.py:52-61`). `should_color` đọc attribute sau parse. `NO_COLOR=1` vẫn False khi `--color always` (`tests/cli/test_color.py:37-46`, `tests/cli/test_ac03_lone_surrogate.py:252-269`).
- B32. Hai chỗ human gọi `should_color(args, sys.stdout)` (`src/sesslint/cli/_render.py:295`, `src/sesslint/cli/check.py:323`). `main` bọc stdout bằng `TrackedStream` trước dispatch (`src/sesslint/cli/__init__.py:184-192`). `isatty` của wrapper gọi `raw.isatty()` (`src/sesslint/cli/_json_errors.py:34-35`).
- B33. `--color always` khi không có `NO_COLOR` thì stdout human có `\033[` (`tests/cli/test_color.py:25-34`). `--color never` thì không có (`tests/cli/test_color.py:16-22`). Xoá ANSI khỏi bản always cho cùng chữ với never, cả một file (`tests/cli/test_color.py:61-75`) và scan (`tests/cli/test_cli_presentation.py:43-52`, `tests/cli/test_cli_presentation.py:77-95`).
- B34. Nhánh JSON/SARIF/HTML không gọi `render_human` hay `format_scan_report_human`. `should_color` chỉ nhìn `args.json`, không nhìn `output_format`. `--format json` không gán `args.json` (`src/sesslint/cli/_common.py:106-110`). Test `--json` cùng `--color always` không có ANSI (`tests/cli/test_color.py:49-57`).
- B35. Quyết định màu dùng `sys.stdout`, rồi cả chuỗi đã nhuộm được đưa vào `emit_text` (`src/sesslint/cli/_render.py:295-304`, `src/sesslint/cli/check.py:323-329`). Hàm ghi file không xoá ANSI (`src/sesslint/cli/_output.py:132-134`). `ctx.info` và `ctx.warn` in nguyên chuỗi (`src/sesslint/cli/_context.py:51-58`). Các dòng stderr ở mục sau không đi qua `should_color`.

## Độ rộng

- B36. Tag scan đệm bằng `max(0, 20 - len(raw_tag))` (`src/sesslint/cli/_render.py:76`). `len` tính trên tag trần, không tính ANSI. Năm tag: `[HEALTHY]` 9, `[INVALID]` 9, `[UNSUPPORTED]` 13, `[UNREADABLE]` 12, `[SKIPPED]` 9, đều ngắn hơn 20. Dòng là hai dấu cách, field 20, một dấu cách, rồi path. Test nói path bắt đầu ở cột 23 (`tests/cli/test_cli_presentation.py:54-74`, `tests/cli/test_cli_presentation.py:97-103`).
- B37. Gạch scan là 80 ký tự `-`, bốn chỗ: sau header, trước summary khi có summary, trước dòng secret, trước dòng index (`src/sesslint/cli/_render.py:52`, `src/sesslint/cli/_render.py:81`, `src/sesslint/cli/_render.py:99`, `src/sesslint/cli/_render.py:127`).
- B38. Cột severity của by-code là `{row.severity:<8}` (`src/sesslint/cli/_render.py:86`).
- B39. Nhãn finding một file căn bằng khoảng trắng literal, tiền tố dài 17 (B10). Không có hằng tên width.
- B40. `render_human` và `format_scan_report_human` nối dòng bằng `"\n".join` (`src/sesslint/report.py:2314`, `src/sesslint/cli/_render.py:130`). Hai hàm không gọi `get_terminal_size` hay `textwrap`. `_width` trong `src/sesslint/cli/_progress.py:44-66` thuộc dòng tiến độ stderr. `max-width` trong `src/sesslint/html_report.py:42` thuộc HTML.

## Sắp xếp

- B41. Khối Findings sort bằng `finding_report_sort_key`, alias của `finding_sort_key` (`src/sesslint/report.py:1968-1969`, `src/sesslint/report.py:2234`, `src/sesslint/finding.py:411`). Khoá (`src/sesslint/finding.py:373-408`): path đã đổi `\` thành `/`; line `None` thành `-1`; `record_ordinal` là `int` không phải `bool` và `>= 0`, không thì `-1`; hạng severity; code; `record_id` `None` thành `""`; fingerprint; `related_ids`; message; `repairability.value`. Docstring gọi path, code, record_id, fingerprint là lexicographical. Hạng: fatal 0, error 1, warning 2, info 3 (`src/sesslint/finding.py:40-45`). Khoá path của sort không qua `minimize_path`.
- B42. `make_finding` lưu `related_ids` đã `sorted` (`src/sesslint/finding.py:792`). Khoá finding dùng tuple đã lưu.
- B43. Vòng salvage của Next Action sort cùng khoá rồi `break` ở rationale đầu có `salvage_path` (`src/sesslint/report.py:2200-2205`).
- B44. Coverage performed sort lúc dựng (B09). Skip sort theo `(check, reason, detail)` (B09).
- B45. Family SL009 sort theo tên (B17).
- B46. Walk thư mục sort từng directory theo `e.name` (`src/sesslint/scan.py:1092`) và duyệt stack. Trước khi trả report, `file_results.sort(key=lambda r: r.path)` (`src/sesslint/scan.py:1464-1465`). `r.path` là dạng `minimize_path`. SL401 và SL402 thay phần tử tại index, `out` bắt đầu bằng `list(results)` (`src/sesslint/scan.py:1600`, `src/sesslint/scan.py:1671`, `src/sesslint/scan.py:1716`, `src/sesslint/scan.py:1725-1728`). Docstring SL401 nói kết quả đã sort theo path (`src/sesslint/scan.py:1577-1578`).
- B47. Nhánh song song hợp nhất theo thứ tự nộp rồi mới tới sort path (`src/sesslint/scan.py:1388-1389`). Help `--jobs` nói report giống nhau với mọi N (`src/sesslint/cli/check.py:146-154`). Trên `win32`, `jobs = min(jobs, 61)` trước walk (`src/sesslint/scan.py:887-888`). Sort cuối vẫn là B46.
- B48. `--newest` / `--since` sort ứng viên theo `(-mtime_ns, path)` để chọn file (`src/sesslint/scan.py:1288-1301`). Danh sách in ra vẫn qua sort `r.path` ở B46.
- B49. Nhiều path: sau khi nối, `multi_files.sort(key=lambda r: r.path)` (`src/sesslint/cli/check.py:491`). `root_path` là `minimize_path` của từng argument, theo thứ tự argument, nối bằng `;` (`src/sesslint/cli/check.py:492-494`). Một thư mục: `root_path = minimize_path(target)` (`src/sesslint/scan.py:890-891`).
- B50. `--agent` nối `rep.files` theo thứ tự root, không sort lại toàn cục (`src/sesslint/cli/check.py:372-400`). Root: agent được chọn; `all` là `claude` rồi `codex` (`src/sesslint/cli/check.py:356`). `discover_session_roots` đi đúng dãy đó (`src/sesslint/api.py:1337-1374`). `--include-archived` thêm `archived_sessions` ngay sau root codex (`src/sesslint/api.py:1376-1384`). Root vắng là một file `skipped` tại vị trí đó, reason `agent-root-missing` hoặc `agent-root-not-directory` (`src/sesslint/cli/check.py:381-393`). Mỗi `check_dir` đã sort path bên trong (B46).
- B51. `by_code` sort theo `(SEVERITY_ORDER của severity nặng nhất đã thấy, -count, code)` (`src/sesslint/scan.py:387-394`). `worst_files` lấy file có error hoặc warning, sort `(-error_count, -warning_count, path)`, cắt `top` (`src/sesslint/scan.py:397-409`).
- B52. Reason skip của scan sort theo tên reason (B21).

## Nơi ghi và newline

- B53. Hai renderer trả `"\n".join(lines)` và không thêm newline cuối (`src/sesslint/report.py:2314`, `src/sesslint/cli/_render.py:130`).
- B54. Không `-o`: `print(text)` không truyền `end` (`src/sesslint/cli/_output.py:118-120`). Docstring nói file nhận cùng byte với payload của `print`, cộng newline mà `print` thêm (`src/sesslint/cli/_output.py:111-116`).
- B55. Có `-o`: `text.encode("utf-8") + b"\n"` (`src/sesslint/cli/_output.py:132-134`). Byte thêm là `0x0A`. Không quiet thì stdout in `wrote {output} ({summary})` (`src/sesslint/cli/_output.py:141-142`). Summary một file là `{counts.total} finding(s)` (`src/sesslint/cli/_render.py:149`). Summary scan là `{totals.total} file(s)` (`src/sesslint/cli/check.py:298`).
- B56. `main` gọi `reconfigure(encoding="utf-8")` trên stdout/stderr kiểu `TextIOWrapper` và không truyền `newline` (`src/sesslint/cli/__init__.py:178-180`).
- B57. Trên `_output.py` của HEAD, `check` không khai báo `contract`, `target`, `session`. `_boundaries` lấy `getattr` và bỏ giá trị không phải path (`src/sesslint/cli/_output.py:44-50`). Diff so với pin không đổi thân `emit_text`.

## Stderr trên đường render

- B58. `ctx.info` và `ctx.warn` in stderr khi không quiet (`src/sesslint/cli/_context.py:51-58`). `ctx.error` luôn in. Quiet lấy từ `args.quiet` (`src/sesslint/cli/_context.py:316`). Không có khoá quiet trong `_SETTING_SPECS` (`src/sesslint/cli/_context.py:86-106`).
- B59. `--skip-undetected` và limitation bắt đầu `Unsupported:` thì return trước thân human (`src/sesslint/cli/_render.py:151-187`). JSON và SARIF emit document riêng. Nhánh còn lại, gồm human và html, chỉ `ctx.info(f"skipped (format-undetected): {display_path}")`. Không gọi `emit_text`. Quiet thì dòng đó cũng mất. `display_path` một file là `str(target_path)` (`src/sesslint/cli/check.py:556`); stdin là `<stdin>` (`src/sesslint/cli/check.py:444`).
- B60. Không return sớm: limitation `Unsupported:` in `unsupported (format-undetected): use sesslint doctor to inspect supported inputs` (`src/sesslint/cli/_render.py:197-199`). Limitation `Skipped:` in `skipped (file-too-large): increase --max-file-bytes to inspect this file` (`src/sesslint/cli/_render.py:200-201`). Hai dòng này chạy trước khi tách format, rồi human vẫn emit thân B05/B19.
- B61. Với từng finding của report, code `SL302`: nếu evidence là dict và `reason` thuộc `tie`, `low-confidence`, `empty` thì warn câu bảo dùng `--adapter`; nếu `confidences` là dict truthy thì warn `Candidate confidences: {dict}` với `dict(sorted(items))` (`src/sesslint/cli/_render.py:204-218`). Sau đó luôn warn `Format detection error [{code}]: {message}`. Code `SL301` chỉ có dòng error đó (`src/sesslint/cli/_render.py:219-221`). Vòng đi theo thứ tự `report.findings`.
- B62. `resolve_format` khi thành công trả findings rỗng (`src/sesslint/adapters/detect.py:324-325`, `src/sesslint/adapters/detect.py:372-373`). Khi thất bại, reason `empty` tạo SL001 với evidence `empty_input` (`src/sesslint/adapters/detect.py:405-413`). Reason còn lại của kiểu tie/low-confidence tạo một SL302 mang `reason` và `confidences` (`src/sesslint/adapters/detect.py:415-430`). `_check_impl` khi format là `None` bỏ mọi finding code `SL302` rồi return (`src/sesslint/api.py:358-381`). Đường thành công gán `adapter_findings` từ `det_findings` đã rỗng (`src/sesslint/api.py:406`). Vì vậy report CLI một file không còn SL302 detection `tie` / `low-confidence`. Nhánh stderr B61 vẫn nằm trong renderer và chạy khi finding còn lại có đúng evidence. Adapter SL302 còn trong report khi code nằm trong rule được bật (`src/sesslint/api.py:439-476`) và đi vào dòng `Format detection error`.
- B63. Sau vòng đó, nếu đã gặp SL301 hoặc SL302 và path là `<stdin>` hoặc hậu tố `.json` / `.jsonl` (hạ chữ), thì một hint `sesslint bundle` (`src/sesslint/cli/_render.py:223-236`). File: `display_path` đổi `\` thành `/`. Stdin: câu bảo ghi stream ra file. Hậu tố khác không có hint này. Undetected đã loại SL302 (B62) và không còn SL301 thì cờ này không bật; dòng B60 vẫn in.
- B64. Một file với `jobs > 1` in `Note: --jobs is ignored for single-file input.` trước report (`src/sesslint/cli/check.py:523-524`). Quiet bỏ dòng đó (`tests/cli/test_quiet_verbose.py:40-49`).
- B65. `--write-baseline` in `wrote baseline: {count} fingerprint(s) -> {path}` qua `ctx.info` trước khi tách format (`src/sesslint/cli/_common.py:93-103`, `src/sesslint/cli/_render.py:148`, `src/sesslint/cli/check.py:280`).
- B66. `--include-content` làm `main` warn stderr (`src/sesslint/cli/__init__.py:149-152`). `render_human` không có tham số include-content (`src/sesslint/report.py:2137-2145`). Scan human cũng không đọc cờ đó.
- B67. `-v` in `debug:` và dòng elapsed ra stderr (`src/sesslint/cli/_context.py:61-64`, `src/sesslint/cli/__init__.py:159-163`). Hai renderer không đọc `verbose`.

## UNKNOWN

- U01. So sánh `str` của sort finding và sort path có phụ thuộc locale hay không. Docstring nói lexicographical (`src/sesslint/finding.py:379-386`). Nguồn không gọi `locale.strxfrm` hay `casefold`. UNKNOWN.
- U02. Hai finding có cùng đủ 10 thành phần khoá thì thứ tự nào thắng. Khoá không có chỉ số gốc (`src/sesslint/finding.py:397-408`). Nguồn không nói `sorted` ổn định. UNKNOWN.
- U03. Làm tròn đúng giữa của `:.1f` trong `_human_bytes` (`src/sesslint/report.py:1789-1792`). Nguồn không đặt chế độ làm tròn. UNKNOWN.
- U04. Chính tả `str` của dict `confidences` trên dòng stderr B61, gồm cách in float. Nguồn chỉ f-string cái dict (`src/sesslint/cli/_render.py:216-217`). UNKNOWN.
- U05. Stdout console có đổi `\n` thành CRLF hay không. `reconfigure` không đặt `newline` (B56). File `-o` là UTF-8 cộng một byte `0x0A` (B55). UNKNOWN cho console/pipe.
- U06. `raw.isatty()` ném exception thì `should_color` không bắt (`src/sesslint/cli/_common.py:68`, `src/sesslint/cli/_json_errors.py:34-35`). UNKNOWN.
- U07. Terminal có tự ngắt dòng dài hay không. Hai renderer không chèn ngắt theo bề rộng terminal (B40). UNKNOWN cho thiết bị hiển thị.
- U08. `text.encode("utf-8")` khi chuỗi human chứa surrogate lẻ. `emit_text` không đặt `errors=` (`src/sesslint/cli/_output.py:134`). UNKNOWN.

## Đếm

- Đã dẫn chứng: 67 (B01–B67).
- UNKNOWN: 8 (U01–U08).

# triage

Giả thuyết (đọc `02694d537104659df66cdd084354739f3cccc440`, không sửa nhánh): tài liệu JSON là `TriageReport.to_dict` / `to_json`. `next_actions` là bốn nhánh `if/elif` trong `triage()`, không phải bảng tĩnh mã→id. `SL203` và `SL102` chọn nhánh ngoài; `SL301` chỉ đổi `status` thành `unsupported`. `previews[].steps[].action` đi qua recipe rồi `RECIPE_ACTIONS`. Chứng minh bằng file:dòng. Chỗ nguồn im: UNKNOWN. Không chạy pytest.

## Commit đã đọc

| Mục | Giá trị |
|---|---|
| Worktree | `D:\FOR_WORK\WORK_PROJECT\sesslint` |
| Nhánh | `feat/outcome-guard` |
| HEAD đã đọc | `02694d537104659df66cdd084354739f3cccc440` |
| Pin | `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` |
| Checkout | không |

`git status --short` trên các file triage và các file phụ đã trích: rỗng. Byte đã đọc là byte của HEAD.

`git diff --stat` và `--name-status` từ pin tới HEAD cho `src/sesslint/triage.py`, `src/sesslint/cli/triage.py`, `schemas/sesslint.triage.v1.json`, `tests/test_triage.py`, `docs/TRIAGE.md`, `man/sesslint-triage.1`: không có diff.

File phụ duy nhất lệch pin: `src/sesslint/cli/_output.py` (`6` dòng thêm, `1` dòng bớt). Hunk chỉ thêm `"outcome"` vào `_REPORT_COMMANDS` và thêm tên biên `"contract"`, `"target"`, `"session"`. `emit_text` không nằm trong hunk. `preview.py`, `assessment.py`, `planner.py`, `refusals.py`, `registry.py`, ba module recipe, `preconditions.py`, `fingerprint.py`, `api.py`, `report.py`, `finding.py`, `codes.py`, `cli/_common.py`, `cli/__init__.py`, `cli/_json_errors.py`, `source.py`, `state_db.py`, `adapters/detect.py`, `profiles/builtin.py`, `profiles/profile.py`, `_version.py`, `io.py`, `canonical.py`: không có diff so với pin.

`docs/TRIAGE.md` và `man/sesslint-triage.1` không được dùng làm chứng hành vi.

SHA-256 byte HEAD:

| File | SHA-256 |
|---|---|
| `src/sesslint/triage.py` | `a1b695b89ac9fc3142f098d51c9ffba01d2f1a20e9cebe202f6a41e26669029d` |
| `src/sesslint/cli/triage.py` | `752447136a9443f92a2a274985f0ff0eda44d998bb2f78ca1ac56879c3d5f975` |
| `schemas/sesslint.triage.v1.json` | `c0ab67bc6a9ca33d04f0d4830444136f4f0a4bb4d08d5213d1adc46f8bab99e4` |
| `tests/test_triage.py` | `1d9ecc4466e13595e79257a210ca70e3e9e2b42607a7bc9834814c6cd26ad82f` |
| `src/sesslint/preview.py` | `13f05663816b930c1df1d6297740168545b9b702fd3e2abdf67f25df1a54f5a9` |
| `src/sesslint/cli/_output.py` | `32760d5026a321aa640dcc98043fe4b3f0a1dbaa1e9a1fcc5124e551921d736f` |

## Schema `sesslint.triage/v1`

Hằng: `TRIAGE_SCHEMA_VERSION = "sesslint.triage/v1"` tại `src/sesslint/triage.py:26`. `to_dict` ghi khóa `schema_version` tại `src/sesslint/triage.py:62`. Schema JSON khai `"const": "sesslint.triage/v1"` tại `schemas/sesslint.triage.v1.json:9`. `triage.py` không import jsonschema. Test gọi validator trên `to_dict()` tại `tests/test_triage.py:56-57`.

`to_dict` (`src/sesslint/triage.py:60-80`) có đúng các khóa: `schema_version`, `tool_version`, `status`, `source_sha256`, `adapter`, `profile`, `assurance`, `coverage`, `findings`, `finding_count`, `by_code`, `findings_truncated`, `previews`, `impact`, `native_state`, `missing_evidence`, `next_actions`, `limitation`. Schema `required` cùng 18 tên tại `schemas/sesslint.triage.v1.json:7`. `additionalProperties: false` tại `schemas/sesslint.triage.v1.json:6`.

`exit_code` là property (`src/sesslint/triage.py:54-58`). CLI trả số đó (`src/sesslint/cli/triage.py:102`). Khóa `exit_code` không có trong `to_dict`.

`tool_version` là `CLI_VERSION` (`src/sesslint/triage.py:18`, `src/sesslint/triage.py:63`), bằng `"0.5.0"` (`src/sesslint/_version.py:7-8`).

`limitation` là hằng `LIMITATION` (`src/sesslint/triage.py:27-30`, `src/sesslint/triage.py:79`):

`Structural evidence only. Application resume, semantic correctness and external side effects are unverified. No repair or agent command was executed.`

### Byte JSON

`to_json` (`src/sesslint/triage.py:82-83`):

`json.dumps(self.to_dict(), ensure_ascii=True, indent=2, sort_keys=True)`

Không truyền `separators`. Không thêm newline cuối trong chuỗi này. `sort_keys=True` sắp xếp khóa mọi object. Thứ tự mảng giữ nguyên thứ tự xây trong Python.

Quan sát máy này, CPython 3.11.9, `json.dumps(..., ensure_ascii=True, indent=2, sort_keys=True)` cho `{"b":1,"a":[2,3]}` ra chuỗi `repr`:

`'{\n  "a": [\n    2,\n    3\n  ],\n  "b": 1\n}'`

Có space sau dấu hai chấm, xuống dòng `\n`, không có newline cuối. UNKNOWN: mọi bản vá CPython khác có cùng default hay không. Nguồn SessLint không ghi `separators`.

Thứ tự khóa tầng gốc sau `sort_keys`: `adapter`, `assurance`, `by_code`, `coverage`, `finding_count`, `findings`, `findings_truncated`, `impact`, `limitation`, `missing_evidence`, `native_state`, `next_actions`, `previews`, `profile`, `schema_version`, `source_sha256`, `status`, `tool_version`.

CLI chọn chuỗi này khi `_output_format(args) == "json"` (`src/sesslint/cli/triage.py:95-98`). `_output_format`: `--json` thắng, không thì `output_format`, không thì `"human"` (`src/sesslint/cli/_common.py:106-110`). Fold: `--json` > `-f/--format` > `SESSLINT_FORMAT` > human (`src/sesslint/cli/_context.py:165-184`). `output_format` không có khóa config (`src/sesslint/cli/_context.py:84-90`). Giá trị default không được `setattr` (`src/sesslint/cli/_context.py:302-313`).

Stdout: `print(text)` (`src/sesslint/cli/_output.py:119-120`). `main` gọi `reconfigure(encoding="utf-8")` trên `TextIOWrapper`, không đặt `newline` (`src/sesslint/cli/__init__.py:178-180`). Newline stdout theo text stream. UNKNOWN: stream Windows có phải `\r\n` hay không.

`--output`: `text.encode("utf-8") + b"\n"` (`src/sesslint/cli/_output.py:132-134`). LF tường minh trên file. Nếu không quiet, stdout nhận `wrote {output} ({summary})` (`src/sesslint/cli/_output.py:141-142`), summary là `"{finding_count} finding(s)"` (`src/sesslint/cli/triage.py:100`).

`render_human` (`src/sesslint/triage.py:85-113`) là serializer khác. Mặc định CLI là human.

### `status`

Kiểu schema: enum `checked`, `needs-attention`, `blocked`, `unsupported`, `skipped`, `unreadable`, `unstable` (`schemas/sesslint.triage.v1.json:11`).

`triage()` gán đúng các chuỗi đó. Khởi tạo `"unreadable"` (`src/sesslint/triage.py:303`). Khi `report` không phải `None`, nhánh đầu thắng (`src/sesslint/triage.py:304-321`):

| Thứ tự | Điều kiện | `status` |
|---|---|---|
| 1 | `report.limitation.startswith("Skipped:")` hoặc `"cap-exceeded"` thuộc reason của `report.coverage.skipped` | `skipped` |
| 2 | `limitation.startswith("Unsupported:")` hoặc `"SL301"` thuộc `by_code` hoặc `"version-gated"` thuộc skip reasons | `unsupported` |
| 3 | `assessment` không `None` và `not assessment.unchanged()` | `unstable` |
| 4 | `adapter == "unknown"` | `blocked` |
| 5 | có finding `Severity.ERROR` hoặc `Severity.FATAL` | `blocked` nếu `"SL203"` thuộc `by_code`, nếu không thì `needs-attention` |
| 6 | còn lại | `checked` |

Sau đó (`src/sesslint/triage.py:331-335`):

- `state_copy is not None` và `native["status"] != "membership-matches"` và `status == "checked"` → `needs-attention`.
- `assessment` truthy, `status` không thuộc `skipped` / `unsupported` / `unreadable`, và `not assessment.unchanged()` → `status = "unstable"`, `previews = ()`, `impact = {"status": "unverified"}`.

`by_code` lúc này là `dict(sorted(Counter(f.code for f in findings).items()))` trên mọi finding, trước khi cắt 100 (`src/sesslint/triage.py:298-299`).

Nguồn các cờ limitation / skip mà `triage()` chỉ so chuỗi:

- `"Skipped: file-too-large. No structural conclusion."` và skip `reason="cap-exceeded"` (`src/sesslint/api.py:250-263`). Đây là chỗ duy nhất trong `src/` gán limitation bắt đầu bằng `Skipped:`.
- Skip `reason="cap-exceeded"`, `detail="stream limit cap exceeded"` (`src/sesslint/checks/runner.py:208-226`).
- `"Unsupported: format-undetected. No structural conclusion."` khi `resolved_fmt is None` và `rep_findings` rỗng; nếu có finding thì limitation là `"No structural conclusion."` (`src/sesslint/api.py:358-392`).
- Skip `reason="version-gated"` (`src/sesslint/api.py:450-456`, `src/sesslint/checks/runner.py:188-206`).

`unchanged()` (`src/sesslint/assessment.py:36-61`): `readable_snapshot` phải đúng; identity `(st_dev, st_ino, st_size, st_mtime_ns)` (`src/sesslint/assessment.py:20-21`) phải khớp trước, giữa và sau lần đọc; SHA-256 các byte đúng `identity[2]` phải bằng `report.source_fingerprint`. `OSError` → `False`.

### `source_sha256`

`report.source_fingerprint` khi `report` và `assessment` và `assessment.readable_snapshot`; không thì `None` (`src/sesslint/triage.py:426-428`). Schema: `null` hoặc `^[0-9a-f]{64}$` (`schemas/sesslint.triage.v1.json:12`, `schemas/sesslint.triage.v1.json:85`).

`readable_snapshot` (`src/sesslint/assessment.py:114-118`): `data is not None`, `len(data) <= max_file_bytes`, identity trước/sau đọc khớp. File quá cỡ: `data = None` (`src/sesslint/assessment.py:87`) nên snapshot không readable. Report quá cỡ vẫn mang fingerprint `"0" * 64` (`src/sesslint/api.py:250-253`). Triage khi đó để `source_sha256` là `None`.

Khi snapshot readable, `_check_impl` nhận `data` không `None` và fingerprint đi `fingerprint_bytes` (`src/sesslint/api.py:304-305`, `src/sesslint/api.py:362-363`, `src/sesslint/api.py:503`). Hàm đó là `hashlib.sha256(data).hexdigest()` (`src/sesslint/source.py:53-57`).

### `adapter`

`assessment.format` nếu truthy, không thì `"unknown"` (`src/sesslint/triage.py:300`). `format` trên assessment là chuỗi đưa vào `_capture_events`, hoặc `None` khi không capture (`src/sesslint/assessment.py:107-111`). Capture nhận `resolved_fmt` (`src/sesslint/api.py:413-414`).

`resolved_fmt` thành công là một phần tử `SUPPORTED_FORMATS`: `claude-code-jsonl`, `openai-agents`, `codex-rollout`, `canonical` (`src/sesslint/adapters/detect.py:37-49`). Override lạ → `ValueError` (`src/sesslint/adapters/detect.py:307-312`). `"auto"` không return sớm; rơi xuống detect (`src/sesslint/adapters/detect.py:307-323`). Winner là khóa confidence, cũng bốn chuỗi đó (`src/sesslint/adapters/detect.py:227-230`, `src/sesslint/adapters/detect.py:269-272`). Thất bại → `None` (`src/sesslint/adapters/detect.py:327-330`).

Schema enum: `unknown`, `canonical`, `claude-code-jsonl`, `codex-rollout`, `openai-agents` (`schemas/sesslint.triage.v1.json:13`). Chuỗi `"auto"` không được ghi vào `adapter`.

### `profile`

Tham số `profile` sau khi `get_profile(profile)` trả về (`src/sesslint/triage.py:277`, `src/sesslint/triage.py:283-284`, `src/sesslint/triage.py:430`). Tên lạ → `KeyError` (`src/sesslint/profiles/profile.py:108-123`). Registry: `neutral`, `claude-strict`, `openai-strict` (`src/sesslint/profiles/builtin.py:92`, `src/sesslint/profiles/builtin.py:105`, `src/sesslint/profiles/builtin.py:119`, `src/sesslint/profiles/builtin.py:129-132`). Schema chỉ `type: string` (`schemas/sesslint.triage.v1.json:14`).

### `assurance`

`report.assurance` khi có report và `status` không thuộc `unstable`, `skipped`, `unsupported`; không thì `"A0"` (`src/sesslint/triage.py:431-433`). `build_report` từ chối assurance ngoài `A0`–`A4` (`src/sesslint/report.py:46`, `src/sesslint/report.py:882-886`). Schema enum cùng năm mức (`schemas/sesslint.triage.v1.json:15`). Cách `compute_assurance` chọn mức nằm ở `src/sesslint/report.py:68-114`. Triage không tính lại mức đó, trừ ba status bị ép `A0`.

### `coverage`

Có report: `report.coverage.to_dict()` (`src/sesslint/triage.py:434`). Không report: `{"performed": [], "skipped": []}` (cùng dòng).

`Coverage.to_dict` (`src/sesslint/report.py:402-415`): `adapter` và `profile` là object đã `dict(sorted(...))` với `id`, `version`, và `name` khi có. `performed` là list đã sort lúc khởi tạo (`src/sesslint/report.py:359`). `skipped` sort theo `(check, reason, detail)` (`src/sesslint/report.py:269-270`, `src/sesslint/report.py:372`, `src/sesslint/report.py:414`). Mỗi skip là `check`, `detail`, `reason` (`src/sesslint/report.py:310-316`). `detail` luôn có mặt, có thể `""`.

Schema (`schemas/sesslint.triage.v1.json:16-25`): `performed` và `skipped` bắt buộc; `adapter` và `profile` không bắt buộc; skip bắt buộc `check` và `reason`; `detail` không bắt buộc. Reason hợp lệ của `CoverageSkip`: `profile-gated`, `adapter-not-applicable`, `version-gated`, `empty-input`, `cap-exceeded`, `single-doc-fallback`, `deselected` (`src/sesslint/report.py:117-127`).

### `findings`, `finding_count`, `by_code`, `findings_truncated`

`finding_count` = số finding gốc (`src/sesslint/triage.py:436`). `findings` = tối đa `MAX_FINDINGS` (`100`, `src/sesslint/triage.py:31`) phần tử đầu của `report.findings` (`src/sesslint/triage.py:414-422`). `findings_truncated` = `finding_count > len(self.findings)` (`src/sesslint/triage.py:73`). Đúng 100 dòng thì cờ là false.

`report.findings` là `tuple(sort_findings(findings))` (`src/sesslint/report.py:898`). Khóa sort (`src/sesslint/finding.py:373-408`): path slash-normalized, line (`None` → `-1`), `evidence["record_ordinal"]` nếu là int ≥ 0 không phải bool (không thì `-1`), `SEVERITY_ORDER`, code, `record_id` (`None` → `""`), fingerprint, `related_ids`, message, `repairability.value`. `SEVERITY_ORDER`: fatal 0, error 1, warning 2, info 3 (`src/sesslint/finding.py:40-45`). Cắt 100 giữ prefix của thứ tự này.

Mỗi dòng (`src/sesslint/triage.py:415-421`):

| Khóa | Nguồn |
|---|---|
| `code` | `f.code` |
| `severity` | `f.severity.value` |
| `repairability` | `f.repairability.value` |
| `title` | `CODE_REGISTRY[f.code].name` |
| `source_line` | `f.source.line` nếu `f.source` truthy, không thì `None` |

Severity: `fatal`, `error`, `warning`, `info` (`src/sesslint/codes.py:21-27`). Schema cùng enum (`schemas/sesslint.triage.v1.json:32`). Repairability: `deterministic`, `lossy-explicit`, `manual`, `unsupported` (`src/sesslint/codes.py:41-47`). Schema để `type: string` (`schemas/sesslint.triage.v1.json:33`). `title` là `CodeInfo.name` (`src/sesslint/codes.py:139-143`). Code không có trong `CODE_REGISTRY` → `KeyError` trước khi `TriageReport` được trả. CLI bắt `KeyError` và không in tài liệu triage (`src/sesslint/cli/triage.py:92-94`).

`SourceRef.line` là int ≥ 1 hoặc `None` (`src/sesslint/finding.py:138-141`). Schema `source_line`: integer ≥ 1 hoặc null (`schemas/sesslint.triage.v1.json:35`, `schemas/sesslint.triage.v1.json:87`). `findings.maxItems` 100 (`schemas/sesslint.triage.v1.json:28`).

`by_code`: object đếm mọi finding, khóa sort theo mã (`src/sesslint/triage.py:299`, `src/sesslint/triage.py:72`). Schema `counts` không ràng buộc pattern khóa (`schemas/sesslint.triage.v1.json:39`, `schemas/sesslint.triage.v1.json:84`). Pattern `^SL[0-9]{3}$` áp cho `findings[].code`, `blocked_codes[]`, `steps[].code` (`schemas/sesslint.triage.v1.json:86`).

### `previews`

Rỗng trừ khi `assessment` không `None`, `status` thuộc `checked` / `needs-attention` / `blocked`, và `assessment.format` truthy (`src/sesslint/triage.py:322-327`). Khi đó luôn một preview `policy="conservative"`. `policy == "salvage"` thì thêm preview thứ hai. Tham số `policy` khác hai chuỗi này → `ValueError` trước khi có report (`src/sesslint/triage.py:286-287`).

Nhánh `unstable` cuối có thể xoá preview đã dựng (`src/sesslint/triage.py:333-335`).

Schema `maxItems` 2 (`schemas/sesslint.triage.v1.json:41`). Mỗi preview (`src/sesslint/triage.py:178-198`):

| Khóa | Nguồn |
|---|---|
| `policy` | đối số `"conservative"` hoặc `"salvage"` |
| `plan_fingerprint` | `proposal.fingerprint` |
| `source_sha256` | `proposal.source_hash` |
| `step_count` | `len(proposal.steps)` |
| `blocked_count` | `len(proposal.blocked)` |
| `blocked_codes` | `sorted({item.code for item in proposal.blocked})` |
| `kept_events` | `proposal.total_kept` |
| `lost_records` | `proposal.total_lost` |
| `loss_by_class` | `dict(sorted(proposal.loss_accounting.preview.items()))` |
| `steps` | xem dưới |
| `applied` | `False` |

`plan()` được gọi với `acknowledge_side_effects=False` và `input_format=assessment.format` (`src/sesslint/triage.py:168-176`). `source_hash` truyền vào là `assessment.report.source_fingerprint` (cùng chỗ).

`total_kept` / `total_lost` là property của `RepairPlan` đọc `loss_accounting` (`src/sesslint/repair/planner.py:287-294`). `blocked_codes` chỉ là mã, sort chữ. Lý do blocked không được copy vào JSON preview.

`loss_by_class` khởi tạo bằng `discarded-suffix`, `none`, `truncated-projection`, rồi cộng `step.loss` (`src/sesslint/repair/planner.py:935-942`). Plan rỗng vì SL203 dùng cùng ba khóa (`src/sesslint/repair/planner.py:494-499`). Khoá loss được phép: `amputated-branch`, `discarded-suffix`, `none`, `orphan-result`, `projected-orphans`, `torn-record`, `truncated-projection`, `truncated-side-effects` (`src/sesslint/repair/planner.py:47-58`). Khoá lạ → `ValueError` (`src/sesslint/repair/planner.py:773-778`). Ba khóa khởi tạo có mặt cả khi đếm bằng 0. Khoá thêm chỉ khi một step mang chúng.

Fingerprint: `compute_plan_fingerprint(plan_dict)` không truyền `policy=` (`src/sesslint/repair/planner.py:979`, `src/sesslint/repair/fingerprint.py:22-34`). Dict conservative không có khóa `policy`; dict khác có (`src/sesslint/repair/planner.py:966-977`). Codec đang dùng là `_ACTIVE_CODEC` (`src/sesslint/_canonical_codec.py:332`, `src/sesslint/_canonical_codec.py:372-378`). Resolver: `SESSLINT_DISABLE_ACCEL` thuộc `1`/`true`/`yes` → pure Python; nếu không, thử `sesslint._accel` khi `CODEC_INTERFACE_VERSION` khớp; mọi exception → pure Python (`src/sesslint/_canonical_codec.py:310-329`). Repo này không có file `_accel`. Pure Python: SHA-256 hex của canonical JSON, bỏ khóa `fingerprint`, `newline=False`, `ensure_ascii=False`, `separators=(",", ":")` (`src/sesslint/_canonical_codec.py:79-90`, `src/sesslint/_canonical_codec.py:133-144`). Native codec, nếu một bản cài khác cung cấp, UNKNOWN.

`steps[]` do triage dựng (`src/sesslint/triage.py:188-196`): `action` = `d.action`, `code` = `d.reason_code`, `recipe` = `d.recipe`, `source_line` = `d.source_line`. `event_id` và `kind` có trên `PreviewDelta.to_dict` (`src/sesslint/preview.py:67-79`) và không đi vào JSON triage.

`_deltas_for_plan` (`src/sesslint/preview.py:154-185`): `action = RECIPE_ACTIONS.get(step.recipe, "drop")`. `reason_code` = `finding.code` nếu fingerprint khớp, không thì `"SL000"`. `SL000` không có trong `src/sesslint/codes.py`. `source_line` chỉ khi finding có source và line là int ≥ 1, không phải bool. Sort `(seq, action, source_line or 0)`.

Schema `steps.maxItems` 256 (`schemas/sesslint.triage.v1.json:51`). `triage.py` không cắt `steps`. Planner cắt candidate ở `MAX_STEPS = 256` (`src/sesslint/repair/planner.py:43`, `src/sesslint/repair/planner.py:854-913`), rồi có thể append `seq-renumber` (`src/sesslint/repair/planner.py:920-933`). Đường đó làm `len(steps)` thành 257. UNKNOWN: có input thực nào đạt 257 hay không. Test `validate()` sẽ fail schema nếu gặp.

`seq-renumber` dùng `target_finding_fp` sentinel `"-"` (`src/sesslint/repair/planner.py:82-84`, `src/sesslint/repair/planner.py:924`). Fingerprint không khớp finding → `code` JSON là `"SL000"`. Append chỉ khi `input_format == "canonical"` và có step thuộc `EVENT_DROP_RECIPES` (`src/sesslint/repair/planner.py:68-80`, `src/sesslint/repair/planner.py:920`).

Thứ tự step: planner sort candidate `(target_index or 0, recipe, finding_fp)` (`src/sesslint/repair/planner.py:843-852`), gán `seq` bằng enumerate (`src/sesslint/repair/planner.py:856-868`), append `seq-renumber` với `seq=len(final_steps)`. `seq` trên đường này là duy nhất, nên sort delta theo `seq` giữ thứ tự plan.

`applied` luôn `False` (`src/sesslint/triage.py:197`). Schema `const: false` (`schemas/sesslint.triage.v1.json:55`).

### `impact`

Mặc định `{"status": "unverified"}` (`src/sesslint/triage.py:302`). Gán bản mapped trong cùng điều kiện dựng preview (`src/sesslint/triage.py:327`). Nhánh unstable cuối trả lại unverified (`src/sesslint/triage.py:335`).

Mapped (`src/sesslint/triage.py:154-163`): `status` `"mapped"`, `parsed_events`, `affected_events`, `outside_mapped_impact` = `len(events) - len(affected)`, `source_lines` sort tăng rồi cắt `MAX_IMPACT_LINES` (`100`, `src/sesslint/triage.py:32`, `src/sesslint/triage.py:153-159`), `source_lines_truncated`, `unmapped_by_code` = `dict(sorted(...))`, `limitation` = `Outside mapped impact does not mean recoverable or safe to replay.`

Chỉ finding `ERROR` hoặc `FATAL` (`src/sesslint/triage.py:130-132`). Khớp `source.record_id` với `event.id`; nếu không khớp và `source.line` không `None` thì khớp `event.source_line` (`src/sesslint/triage.py:133-136`). Không khớp → `unmapped[code] += 1`. Có khớp thì lan theo `parent_id` tới con (`src/sesslint/triage.py:141-152`). JSON chỉ chứa đếm và dòng đã sort; thứ tự stack không được ghi.

`source_lines` copy `event.source_line` khi không `None`, không kiểm ≥ 1 trong `_impact`. Dataclass `SessionEvent.source_line` không có validator (`src/sesslint/canonical.py:257`). Parser canonical từ chối line < 1 (`src/sesslint/canonical.py:568-572`). Mọi adapter có đi qua parser đó hay không: UNKNOWN. Schema yêu cầu integer ≥ 1 (`schemas/sesslint.triage.v1.json:65`).

### `native_state`

Luôn tính, kể cả ledger unreadable (`src/sesslint/triage.py:328-330`). Object bắt buộc `status` và `detail` (`src/sesslint/triage.py:213-270`). Schema enum status: `not-provided`, `unverified`, `membership-matches`, `membership-mismatch` (`schemas/sesslint.triage.v1.json:71`).

| Điều kiện | status | detail |
|---|---|---|
| `copy is None` | `not-provided` | `Native registry was not inspected.` |
| symlink, hoặc `resolve()` nằm dưới `Path.home()/".codex"` hoặc dưới `CODEX_HOME` nếu biến có mặt | `unverified` | `Provide a closed copy outside agent storage.` |
| `adapter != "codex-rollout"` | `unverified` | `Registry comparison requires a Codex ledger.` |
| không phải regular file, hoặc `st_nlink != 1`, hoặc `st_size > MAX_STATE_DB_BYTES`, hoặc sidecar `-wal` / `-shm` / `-journal` tồn tại hoặc là symlink | `unverified` | `Provide a bounded regular copy without hard links or SQLite sidecars.` |
| digest trước/sau `read_codex_state` khác nhau, sidecar xuất hiện, hoặc `not snapshot.membership_complete` | `unverified` | `Copy is changing, incomplete or unsupported.` |
| `rollout_uuid_from_name(source.name)` là `None` | `unverified` | `No supported rollout identity for comparison.` |
| `(identity, identity)` thuộc `snapshot.thread_rollout_pairs` | `membership-matches` | `Copied registry membership only; live application state is unverified.` |
| cặp đó không thuộc | `membership-mismatch` | cùng câu trên |
| `OSError` hoặc `ValueError` | `unverified` | `Copy could not be inspected.` |

`MAX_STATE_DB_BYTES = 256 * 1024 * 1024` (`src/sesslint/state_db.py:27`). `membership_complete` = `parse_ok and schema_note is None` (`src/sesslint/state_db.py:78-80`).

Identity: regex `([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})` search trên tên file, group 1 lower (`src/sesslint/state_db.py:33-35`, `src/sesslint/state_db.py:45-48`). Docstring nói dạng `rollout-<ts>-<uuid>.jsonl`; thân hàm không kiểm prefix. Cặp registry là `(tid, uuid)` với `tid` giữ nguyên từ cột `id`, uuid lower từ basename `rollout_path` (`src/sesslint/state_db.py:143-159`). So khớp triage là `(identity, identity)` với identity đã lower (`src/sesslint/triage.py:258-266`). `tid` khác chữ hoa/thường với UUID lower thì không khớp.

`read_codex_state(..., immutable=True)` (`src/sesslint/triage.py:247`).

### `missing_evidence`

Thứ tự xây (`src/sesslint/triage.py:336-359`), mảng giữ nguyên:

1. Nếu `status` thuộc `skipped` hoặc `unsupported`: `{code: "coverage", detail: "Applicable checks are incomplete; inspect coverage."}`.
2. Với từng khóa `by_code` (đã sort): nếu `refusal_rationale_for(code)` không `None`, thêm `{code, detail: rationale.rationale}`. Đây là field `rationale`, không phải `render()` (`src/sesslint/repair/refusals.py:113-118`, `src/sesslint/repair/refusals.py:377-379`).
3. Nếu `"SL203"` hoặc `"SL102"` thuộc `by_code`: `{code: "external-state", detail: "Verify actual tool side effects outside this ledger; acknowledgement is not proof."}`.
4. Luôn: `{code: "native-resume", detail: "Validate continuation in the originating application."}`.
5. Nếu `native["status"] != "membership-matches"`: `{code: "native-registry", detail: native["detail"]}`.

Khóa `REFUSAL_REGISTRY` có rationale (`src/sesslint/repair/refusals.py`): `SL001:122`, `SL007:134`, `SL008:142`, `SL009:151`, `SL010:160`, `SL011:169`, `SL101:177`, `SL103:189`, `SL105:197`, `SL106:205`, `SL107:213`, `SL201:224`, `SL202:232`, `SL203:240`, `SL301:248`, `SL302:260`, `SL204:269`, `SL205:277`, `SL206:285`, `SL207:294`, `SL208:303`, `SL303:312`, `SL304:320`, `SL305:328`, `SL306:342`, `SL401:350`, `SL402:358`. Mã không phải khóa → `None`. `SL102` không phải khóa đó; nó chỉ tạo hàng `external-state` ở bước 3. `SL203` tạo cả hàng rationale lẫn `external-state`.

Schema mỗi phần tử bắt buộc `code` và `detail`, `code` là string không pattern SL (`schemas/sesslint.triage.v1.json:72-75`).

## Thứ tự `next_actions`

Schema: mảng `minItems` 1, `maxItems` 3; mỗi phần tử bắt buộc `id`, `detail`, `command`; không additional properties (`schemas/sesslint.triage.v1.json:76-79`).

Bốn nhánh, nhánh đầu thắng, chạy sau mọi gán `status` (`src/sesslint/triage.py:360-413`). `findings` ở nhánh 3 là tuple đầy đủ (`src/sesslint/triage.py:298`), không phải mảng đã cắt 100.

| Nhánh | Điều kiện | Thứ tự phần tử |
|---|---|---|
| 1 | `status` thuộc `skipped`, `unsupported`, `unstable`, `unreadable` | 1. `inspect-source` |
| 2 | `"SL203"` thuộc `by_code` hoặc `"SL102"` thuộc `by_code` | 1. `verify-external-state` 2. `share-evidence` |
| 3 | `findings` không rỗng hoặc `native["status"] == "membership-mismatch"` | 1. `review-findings` 2. `preview-repair` 3. `share-evidence` |
| 4 | còn lại | 1. `native-validation` |

Chuỗi cố định:

| id | detail | command | Dòng |
|---|---|---|---|
| `inspect-source` | `Provide a stable, readable, supported copy within the byte limit.` | `sesslint triage <source>` | `src/sesslint/triage.py:364-367` |
| `verify-external-state` | `Establish whether pending tools changed external state; do not replay them automatically.` | `""` | `src/sesslint/triage.py:372-378` |
| `share-evidence` (nhánh 2) | `Create a content-free support bundle for manual review.` | `sesslint bundle <source>` | `src/sesslint/triage.py:379-383` |
| `review-findings` | `Review codes, coverage and mapped impact before changing a copy.` | `sesslint check <source>` | `src/sesslint/triage.py:387-391` |
| `preview-repair` | `Inspect preconditions and loss; blockers remain unresolved.` | `sesslint repair <source> --dry-run` | `src/sesslint/triage.py:392-396` |
| `share-evidence` (nhánh 3) | `Create a content-free support bundle if the issue remains.` | `sesslint bundle <source>` | `src/sesslint/triage.py:397-401` |
| `native-validation` | `Supported structural checks passed; validate resume separately in the originating application.` | `""` | `src/sesslint/triage.py:405-411` |

`<source>` là chữ cố định trong command, không phải path đã giải. Cùng id `share-evidence` có hai `detail` khác nhau theo nhánh. Không có id nào khác được gán trong `triage.py`.

Nhánh 1 thắng cả khi `by_code` có `SL203` hoặc `SL102`. Ví dụ `SL301` làm `unsupported` ở bước status (nếu chưa `skipped`) thì action là `inspect-source`.

Nhánh 4 không đọc `status`. `blocked`, không finding, không `SL203`/`SL102`, native không phải `membership-mismatch` → vẫn `native-validation`. Một đường vào đó: `adapter == "unknown"` và `findings` rỗng (`src/sesslint/triage.py:316-317` rồi `src/sesslint/triage.py:403-413`).

`checked` bị hạ vì `state_copy` và native `unverified` hoặc `not-provided` là không xảy ra với `not-provided` vì nhánh hạ yêu cầu `state_copy is not None` (`src/sesslint/triage.py:331-332`), và `state_copy is None` cho `not-provided`. `state_copy` có mặt mà native là `unverified`, không finding, không `SL102`/`SL203`: status thành `needs-attention`, action vẫn `native-validation`.

`membership-mismatch` với không `SL102`/`SL203`: nhánh 3, dù finding rỗng.

Warning/info không đẩy status khỏi `checked` (bước 5 chỉ ERROR/FATAL) nhưng finding không rỗng vẫn vào nhánh 3.

Human đánh số từ 1 theo cùng tuple, in `detail` rồi `command` nếu command truthy (`src/sesslint/triage.py:108-111`). Command `""` không được in.

Test: `len(next_actions) <= 3` (`tests/test_triage.py:58`). Fixture có `SL102` thì `next_actions[0]["id"] == "verify-external-state"` (`tests/test_triage.py:237-244`). Test không assert id thứ hai hay hai chuỗi `share-evidence`.

## Mapping mã → action

Không có dict mã SL → `next_actions[].id`. Chỉ ba mã xuất hiện như chữ trong máy action/status:

| Mã | Việc nguồn làm | Action id kết quả |
|---|---|---|
| `SL301` | nếu chưa `skipped`, `status = "unsupported"` (`src/sesslint/triage.py:308-313`) | nhánh 1: `inspect-source` |
| `SL203` | trong bước 5, ERROR/FATAL → `status = "blocked"` (`src/sesslint/triage.py:318-319`); thuộc `by_code` thì nhánh 2 (`src/sesslint/triage.py:369-384`) | `verify-external-state` rồi `share-evidence` (detail "manual review"), trừ khi status đã ở nhánh 1 |
| `SL102` | không tự gán `blocked`; thuộc `by_code` thì cùng nhánh 2 (`src/sesslint/triage.py:369`) | cùng cặp, trừ khi status đã ở nhánh 1 |

Mọi mã khác: không có id riêng. Chúng đi nhánh 3 khi còn trong `findings`, hoặc không đổi action nếu finding rỗng và native không `membership-mismatch`. Severity ERROR/FATAL của chúng, khi tới bước 5 và không có `SL203`, đặt `needs-attention` (`src/sesslint/triage.py:318-319`).

### `steps[].action` (khác `next_actions`)

Chuỗi action của một step là `RECIPE_ACTIONS.get(recipe, "drop")` (`src/sesslint/preview.py:155`). Bảng (`src/sesslint/preview.py:29-42`):

| recipe | action |
|---|---|
| `terminal-suffix-discard` | `discard-tail` |
| `torn-terminal-record-discard` | `discard-tail` |
| `torn-compaction-project` | `discard-tail` |
| `side-effect-unknown-truncate` | `discard-tail` |
| `identical-duplicate-collapse` | `dedupe` |
| `duplicate-projection-removal` | `dedupe` |
| `identical-duplicate-drop` | `dedupe` |
| `proven-unique-parent-restore` | `relink` |
| `compaction-projection-reunion` | `relink` |
| `orphan-result-drop` | `drop` |
| `torn-record-excision` | `drop` |
| `unresolvable-branch-amputate` | `drop` |
| `seq-renumber` | `normalize` |

Recipe không có trong bảng → action `"drop"` (cùng dòng 155). Comment ở `src/sesslint/preview.py:59` liệt kê `drop | relink | discard-tail | dedupe | normalize`.

`recipes_for(code)` trả recipe đã đăng ký mà `code` thuộc `handles`, theo thứ tự insert (`src/sesslint/repair/registry.py:74-76`). `plan()` đăng ký: conservative, rồi salvage, rồi SL002 (`src/sesslint/repair/planner.py:462-465`). Ba chỗ `register_recipe` trong `src/` là `src/sesslint/repair/recipes_conservative.py:1012`, `src/sesslint/repair/recipes_salvage.py:644`, `src/sesslint/repair/recipes_sl002.py:121`.

Thứ tự insert và handles:

| Thứ tự | recipe | handles | action | Dòng handles |
|---|---|---|---|---|
| 1 | `terminal-suffix-discard` | `SL005` | `discard-tail` | `src/sesslint/repair/recipes_conservative.py:925-927` |
| 2 | `identical-duplicate-collapse` | `SL003` | `dedupe` | `src/sesslint/repair/recipes_conservative.py:935-937` |
| 3 | `proven-unique-parent-restore` | `SL004` | `relink` | `src/sesslint/repair/recipes_conservative.py:945-947` |
| 4 | `compaction-projection-reunion` | `SL108` | `relink` | `src/sesslint/repair/recipes_conservative.py:955-957` |
| 5 | `duplicate-projection-removal` | `SL104` | `dedupe` | `src/sesslint/repair/recipes_conservative.py:965-967` |
| 6 | `identical-duplicate-drop` | `SL003` | `dedupe` | `src/sesslint/repair/recipes_conservative.py:975-977` |
| 7 | `seq-renumber` | không mã | `normalize` | `src/sesslint/repair/recipes_conservative.py:985-987` |
| 8 | `unresolvable-branch-amputate` | `SL005`, `SL006` | `drop` | `src/sesslint/repair/recipes_salvage.py:577-579` |
| 9 | `torn-compaction-project` | `SL108` | `discard-tail` | `src/sesslint/repair/recipes_salvage.py:586-588` |
| 10 | `side-effect-unknown-truncate` | `SL102` | `discard-tail` | `src/sesslint/repair/recipes_salvage.py:595-597` |
| 11 | `orphan-result-drop` | `SL101` | `drop` | `src/sesslint/repair/recipes_salvage.py:604-606` |
| 12 | `torn-record-excision` | `SL001` | `drop` | `src/sesslint/repair/recipes_salvage.py:614-616` |
| 13 | `torn-terminal-record-discard` | `SL002` | `discard-tail` | `src/sesslint/repair/recipes_sl002.py:105-107` |

`seq-renumber` có `handles=()` nên `recipes_for` không trả nó. Planner tự append. `code` của step đó là `"SL000"`.

Chọn recipe: first-match trên `available_recipes` (`src/sesslint/repair/planner.py:655-674`). `check_preconditions` trả precondition fail đầu tiên (`src/sesslint/repair/preconditions.py:572-588`). Không match → blocked, không có step (`src/sesslint/repair/planner.py:676-692`).

Cổng trước khi thử precondition (`src/sesslint/repair/planner.py:563-634`): repairability `unsupported` → blocked `repairability-unsupported`; `unknown` → `repairability-unknown`; không recipe → `no-recipe`; conservative và mọi recipe `salvage_only` → `needs-salvage-policy`; repairability `lossy-explicit` hoặc `salvage` khi policy không phải salvage → `needs-salvage-policy`; `manual` bị blocked `repairability-manual` trừ khi policy là salvage và có recipe `salvage_only`. Các reason này không có field trong JSON triage; chúng chỉ quyết định có step hay chỉ tăng `blocked_count` / `blocked_codes`.

Có finding `SL203` → plan không step, mọi finding sorted bị blocked reason `"SL203-refusal"` (`src/sesslint/repair/planner.py:486-525`). `should_abstain_from_repair` thêm reason `"SL203 present"` khi có finding mã `SL203` rồi return (`src/sesslint/policy/abstention.py:429-432`). Reason salvage dạng `side-effect-...` không làm nhánh rỗng đó chạy.

Triage luôn `acknowledge_side_effects=False` (`src/sesslint/triage.py:174`). Precondition cùng tên trả `bool(ctx.acknowledge_side_effects)` (`src/sesslint/repair/preconditions.py:352-354`). Ba recipe salvage khai báo precondition đó: `side-effect-unknown-truncate`, `orphan-result-drop`, `torn-record-excision` (`src/sesslint/repair/recipes_salvage.py:598`, `src/sesslint/repair/recipes_salvage.py:607`, `src/sesslint/repair/recipes_salvage.py:617`). Với `policy="salvage"`, `salvage_policy` qua (`src/sesslint/repair/preconditions.py:346-348`) rồi `acknowledge_side_effects` fail → blocked reason `needs-acknowledgement` (`src/sesslint/repair/planner.py:679-680`). Với conservative, nếu mọi recipe của mã đều `salvage_only`, dừng sớm `needs-salvage-policy` (`src/sesslint/repair/planner.py:595-603`). Hệ quả trên triage: `SL102`, `SL101`, `SL001` không thành step. `SL005` và `SL006` chỉ có recipe salvage_only trong bảng handles ở trên, nên conservative blocked `needs-salvage-policy` trước precondition. Salvage vẫn thử recipe; kết quả precondition `no_prior_safe_tool_after_cut` / `branch_has_no_checkpoint` / các tên khác: UNKNOWN ở mức pass/fail từng input. Hàm tồn tại; bảng kết quả theo fixture không được suy từ tên.

Conservative, recipe có `affected_region`: `check_step_scope` fail thì blocked, reason là `refusal_reason` hoặc `"side-effect-scope-unproven"` (`src/sesslint/repair/planner.py:784-815`). Bộ reason của `check_step_scope`: UNKNOWN trong bản đồ này (chưa liệt kê từng return). Conservative, recipe không `affected_region`: nếu `must_abstain(...).abstain` thì blocked `"side-effect-abstention"` (`src/sesslint/repair/planner.py:534`, `src/sesslint/repair/planner.py:816-827`). `must_abstain` abstain khi có `SL203`, hoặc khi một event kind thuộc `tool_call` / `tool_use` / `tool_result` có side effect khác `"none"` (`src/sesslint/policy/abstention.py:42-43`, `src/sesslint/policy/abstention.py:478-494`).

`cap-overflow`: candidate sau 256 bị blocked, không thành step (`src/sesslint/repair/planner.py:906-912`).

Step loss theo tên recipe (`src/sesslint/repair/planner.py:732-771`): `terminal-suffix-discard` → `discarded-suffix`; `unresolvable-branch-amputate` → `amputated-branch`; `torn-compaction-project` → `projected-orphans`; `side-effect-unknown-truncate` → `truncated-side-effects`; `orphan-result-drop` → `orphan-result`; `torn-record-excision` → `torn-record`; recipe `lossy` còn lại → `{"none": 0}`. Recipe không lossy không vào các nhánh đó giữ `step_loss` khởi tạo `{}` (`src/sesslint/repair/planner.py:733`). `seq-renumber` dùng `loss={}` (`src/sesslint/repair/planner.py:929`).

## Tham số CLI đi vào tài liệu

API `triage()` mặc định `format=None`, `profile="neutral"`, `policy="conservative"`, `state_copy=None`, `max_file_bytes=DEFAULT_MAX_FILE_BYTES` (`src/sesslint/triage.py:273-280`). `DEFAULT_MAX_FILE_BYTES = 100 * 1024 * 1024` (`src/sesslint/io.py:47`).

CLI `run` truyền `getattr(args, "adapter", None)`, `getattr(args, "profile", "neutral")`, `getattr(args, "policy", "conservative")`, `args.state_copy`, `args.max_file_bytes` (`src/sesslint/cli/triage.py:84-91`). `build_context` ghi default `adapter="auto"` và `profile="neutral"` vì giá trị default không `None` (`src/sesslint/cli/_context.py:88-89`, `src/sesslint/cli/_context.py:302-313`). `policy` default `None` không được ghi (`src/sesslint/cli/_context.py:92`); `getattr` trong `run` thành `"conservative"`. Config khóa `policy` được fold cho lệnh `triage` (`src/sesslint/cli/_context.py:111-117`, `src/sesslint/cli/_context.py:197-199`). Không có env var cho `policy` (`env_var` là `None` trong spec).

`"auto"` sau resolve không thành `adapter` JSON, như mục adapter.

`--include-content` → stderr `Error: triage does not support --include-content.`, exit 2, không có `TriageReport` (`src/sesslint/cli/triage.py:79-81`). Path và `--latest` cùng lúc hoặc cùng thiếu → `Error: choose a file OR --agent claude|codex --latest.`, exit 2 (`src/sesslint/cli/triage.py:73-78`). `OSError`, `ValueError`, `KeyError` từ `triage()` / discovery → `Error: triage input/discovery/options could not be resolved.`, exit 2 (`src/sesslint/cli/triage.py:92-94`). `ctx.error` in stderr (`src/sesslint/cli/_context.py:47-49`).

Khi exit không thuộc `(0, 130)`, `wants_json` đúng, và stdout còn rỗng, `main` in `error_document` (`src/sesslint/cli/__init__.py:232-233`). Object đó là `code` `"ERROR"`, `message`, `verdict` `"error"` (`src/sesslint/cli/_json_errors.py:75-78`). `message` là prefix stderr đã track, hoặc `"Command failed"`. Đây không phải `sesslint.triage/v1`.

Exception khác, stdout còn rỗng, JSON: `build_internal_error_envelope` (`src/sesslint/cli/__init__.py:221-228`, `src/sesslint/cli/_common.py:45-49`). Khóa `code` `"INTERNAL_ERROR"`, `error_id`, `message`, `verdict` `"error"` (`src/sesslint/api.py:1205-1218`). `error_id` dùng `secrets.token_hex(4)` (`src/sesslint/cli/_common.py:45`). Không tất định. Không phải tài liệu triage.

`KeyboardInterrupt` / `OperationCancelled` → exit 130, stderr, không tài liệu triage (`src/sesslint/cli/__init__.py:207-214`).

`TriageReport.exit_code`: `unreadable` → 2; `checked` → 0; mọi status còn lại → 1 (`src/sesslint/triage.py:54-58`). Bảng exit đầy đủ thuộc card khác; các dòng trên là property và đường CLI đã trích.

## UNKNOWN

- Newline stdout của `print(text)` khi stream là `\r\n`.
- Default `separators` của `json.dumps` trên mọi bản Python khác CPython 3.11.9 đã quan sát.
- Native `sesslint._accel` có cùng digest fingerprint với pure Python hay không, khi bản cài có module đó.
- Có input nào làm `steps` dài 257 hay không.
- Mọi `SessionEvent.source_line` từ adapter có ≥ 1 hay không.
- Pass/fail của từng precondition theo từng fixture (`no_prior_safe_tool_after_cut`, `branch_has_no_checkpoint`, và các tên precondition khác chưa được lập bảng).
- Bộ reason trả về từ `check_step_scope`.
- Bảng phủ định “mọi mã SL không có recipe”. Chỉ các `handles` đã liệt kê được đăng ký trong `src/`.

## Bằng chứng bất biến

- Fail-closed: chỗ nguồn không nói được ghi UNKNOWN ở mục trên. Không bịa id action, không bịa bảng mã→id.
- Thứ tự: `next_actions` và `missing_evidence` theo thứ tự nhánh/`by_code` đã trích; `sort_keys` chỉ sắp khóa object.
- Byte: `to_json` dùng `sort_keys=True`, `ensure_ascii=True`, `indent=2` (`src/sesslint/triage.py:83`). `triage.py` không import `datetime`, `random`, `secrets`. `CODEX_HOME` và `Path.home()` chỉ ảnh hưởng `native_state` khi có `state_copy` (`src/sesslint/triage.py:219-222`).
- Content-free: command dùng chữ `<source>`; dòng finding không copy payload (`src/sesslint/triage.py:415-421`).
- Không sửa Python. Không chạy pytest/cargo/Docker. Pin và HEAD giống nhau trên file triage đã nêu.

# sarif

Bản đồ document SARIF 2.1.0 của OSS `sesslint check` / alias `scan`. Nguồn là worktree `D:\FOR_WORK\WORK_PROJECT\sesslint`, HEAD `02694d537104659df66cdd084354739f3cccc440`, nhánh `feat/outcome-guard`. Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` là tổ tiên của HEAD (`git merge-base --is-ancestor`, exit 0). Worktree không bị checkout. Blob `src/sesslint/sarif.py` tại pin và tại HEAD cùng là `88bd1ff35dc39840537034a9f904f39fa2e5fb37`. `git diff --name-status` pin…HEAD trên `sarif.py`, `tests/test_sarif.py`, `cli/_render.py`, `cli/check.py`, `cli/_json_errors.py`, `cli/_common.py`, `cli/_context.py`, `codes.py`, `report.py`, `finding.py`, `scan.py`, `checks/hygiene.py`, `_version.py`, `tests/test_wave1_correctness.py`, `tests/test_field_regressions.py`, `tests/checks/test_hygiene.py`, `tests/cli/test_env_precedence.py`, `tests/report/test_delivery_guidance.py` chỉ báo `M src/sesslint/cli/_output.py`. Diff đó thêm `"outcome"` vào `_REPORT_COMMANDS` (`src/sesslint/cli/_output.py:21-23`) và thêm tên biên `contract`, `target`, `session` (`src/sesslint/cli/_output.py:44-46`). `emit_text` không nằm trong diff. Dòng trích dưới đây là dòng của HEAD. File `sarif.py` trên đĩa: 151 dòng LF, sha256 `4d0486958ccdf9150141f8692c3949c24b7958f42488534d3f61c0be90975b50`.

`build_sarif` dựng dict. `render_sarif` là `json.dumps` của dict đó. CLI đưa chuỗi đó vào `emit_text`.

## Cấu trúc document

- B01. Hằng: `SARIF_VERSION` = `"2.1.0"` (`src/sesslint/sarif.py:25`), `SARIF_SCHEMA` = `"https://json.schemastore.org/sarif-2.1.0.json"` (`src/sesslint/sarif.py:26`), `TOOL_INFORMATION_URI` = `"https://github.com/HPNChanel/sesslint"` (`src/sesslint/sarif.py:27`). `_RULE_HELP_BASE` nối URI đó với `"/blob/main/docs/codes"` (`src/sesslint/sarif.py:28`).
- B02. Dict gốc có ba khoá: `$schema` = `SARIF_SCHEMA`, `version` = `SARIF_VERSION`, `runs` = một list một phần tử (`src/sesslint/sarif.py:118-133`). Test CLI: `version` bằng `"2.1.0"` (`tests/test_sarif.py:30`).
- B03. Phần tử `runs[0]` có `tool` và `results` (`src/sesslint/sarif.py:122-132`). `tool` có một khoá `driver` (`src/sesslint/sarif.py:123-129`).
- B04. `driver` gán `name` = `"SessLint"`, `version` = đối số `tool_version` nguyên chuỗi (không `strip` trong `sarif.py`), `informationUri` = `TOOL_INFORMATION_URI`, `rules` = `_rule_objects()` (`src/sesslint/sarif.py:124-128`).
- B05. `results` là `[_result_object(f) for f in findings]` (`src/sesslint/sarif.py:131`). List rỗng khi `findings` rỗng. Rules vẫn là cả registry. Test file sạch: `results == []`, exit 0 (`tests/test_sarif.py:46-50`).
- B06. Mỗi result có `ruleId` = `finding.code`, `level` = `_LEVEL_MAP[finding.severity]`, `message` = `{"text": finding.message}`, `locations` = một phần tử, `partialFingerprints` (`src/sesslint/sarif.py:103-109`).
- B07. Location có `physicalLocation.artifactLocation.uri` (`src/sesslint/sarif.py:83-86`). Khi `finding.source.line is not None`, thêm `physicalLocation.region` = `{"startLine": finding.source.line}` (`src/sesslint/sarif.py:88-89`). `SourceRef.line` là `None` hoặc `int >= 1`, và `bool` bị loại (`src/sesslint/finding.py:128`, `src/sesslint/finding.py:138-142`).
- B08. `partialFingerprints` luôn có `"sesslint/finding-fingerprint"` = `finding.fingerprint` (`src/sesslint/sarif.py:91-93`). `Finding` chỉ giữ fingerprint khớp `^[0-9a-f]{16}$` (`src/sesslint/finding.py:47`, `src/sesslint/finding.py:243-248`).
- B09. Khoá `"sesslint/secret-match-sha256"` được thêm khi `finding.evidence` là `Mapping`, `evidence["match_sha256"]` là `list`, và list sau khi lọc còn ít nhất một `str` (`src/sesslint/sarif.py:94-101`). Giá trị là `",".join` của các `str` đó sau `sorted` (`src/sesslint/sarif.py:97-101`). Phần tử không phải `str` bị bỏ. `tuple` không phải `list` nên không vào nhánh này.
- B10. `render_sarif` trả `json.dumps(build_sarif(...), indent=2, sort_keys=True)` (`src/sesslint/sarif.py:137-143`). Lời gọi không truyền `ensure_ascii`, `separators`, `allow_nan`, `cls`. `scan_report_sarif` nối `file_result.findings` theo thứ tự `scan_report.files` rồi gọi `render_sarif` (`src/sesslint/sarif.py:146-151`). Hàm này không đọc `summary`, `totals`, `root_path`, `verdict`, `skipped_reason`.
- B11. Module docstring nói document cho GitHub code scanning, content-free, rules sort theo id, results theo thứ tự finding mà report đã cố định (FR-094), `helpUri` không bị fetch (`src/sesslint/sarif.py:1-11`). Import của file là `json`, `Mapping`/`Sequence`, `Any`/`Final`, `CODE_REGISTRY`/`Severity`, `Finding`, `minimize_path`, `ScanReport` (`src/sesslint/sarif.py:16-23`). Kết quả result theo code là list comprehension B05, không có lời gọi `sort_findings` trong `sarif.py`.
- B12. `message.text` là `finding.message` đã render, không phải `message_template` và không phải `CodeInfo.summary`. `make_finding` format template với `line` và `record_id`, cắt ở 500 ký tự bằng `"... [truncated]"` (`src/sesslint/finding.py:36-38`, `src/sesslint/finding.py:775-778`, `src/sesslint/finding.py:818-827`). `Finding.message` phải qua `enforce_content_free_text` (`src/sesslint/finding.py:228-237`).
- B13. SL009 ghi `match_sha256` là `sorted(agg.digests)[:16]` (`src/sesslint/checks/hygiene.py:52`, `src/sesslint/checks/hygiene.py:475`). Mỗi digest là `hashlib.sha256(secret_bytes).hexdigest()` (`src/sesslint/checks/hygiene.py:420`). SARIF sort lại các `str` đó rồi nối bằng dấu phẩy (B09). Test: result SL009 có level `"warning"` và có khoá digest (`tests/checks/test_hygiene.py:396-403`).

## Rule metadata

`_rule_objects` lặp `sorted(CODE_REGISTRY)` và mỗi rule lấy field từ `CodeInfo` (`src/sesslint/sarif.py:42-60`, `src/sesslint/codes.py:138-148`). Registry literal có 35 `CodeInfo` (`src/sesslint/codes.py:3-8`, `src/sesslint/codes.py:151-569`). Test: `len(rules) == 35` và id đã sort (`tests/test_sarif.py:32-34`).

Mỗi rule có `id` = `info.code`, `name` = `info.name`, `shortDescription.text` = `info.summary`, `defaultConfiguration.level` = `_LEVEL_MAP[info.default_severity]`, `helpUri` = `{_RULE_HELP_BASE}/{info.code}.md`, `properties.category` = `info.category`, `properties.repairability` = `info.default_repairability.value` (`src/sesslint/sarif.py:46-58`). `override_policy` là field của `CodeInfo` (`src/sesslint/codes.py:148`) và không có mặt trong dict rule.

`_LEVEL_MAP`: `FATAL` và `ERROR` → `"error"`, `WARNING` → `"warning"`, `INFO` → `"note"` (`src/sesslint/sarif.py:30-35`). Giá trị enum severity là `"fatal"`, `"error"`, `"warning"`, `"info"` (`src/sesslint/codes.py:24-27`). Giá trị repairability là `"deterministic"`, `"lossy-explicit"`, `"manual"`, `"unsupported"` (`src/sesslint/codes.py:44-47`). 35 default trong registry dùng `deterministic`, `manual`, `unsupported`. `LOSSY_EXPLICIT` có trong enum; không có `CodeInfo` nào ở `src/sesslint/codes.py:151-569` gán default đó.

`defaultConfiguration.level` lấy severity mặc định của mã. `results[].level` lấy `finding.severity` (B06). Hai nguồn khác nhau: policy của SL003 nói detector đổi duplicate xung đột sang error (`src/sesslint/codes.py:184-187`).

`helpUri` mẫu: `https://github.com/HPNChanel/sesslint/blob/main/docs/codes/` + mã + `.md` (B01 + `src/sesslint/sarif.py:54`). Test output chứa `docs/codes/{code}.md` với `code` là `SL009` hoặc `SL402` (`tests/report/test_delivery_guidance.py:24-25`).

Cột `level` trong bảng là `_LEVEL_MAP` của `default_severity`. Cột dòng là khối `CodeInfo` chứa `name`, `summary`, `default_severity`, `default_repairability`, `category`.

| id | name | severity | level | repairability | category | dòng |
| --- | --- | --- | --- | --- | --- | --- |
| SL001 | Malformed record | error | error | manual | syntax | `src/sesslint/codes.py:152-158` |
| SL002 | Torn terminal record | error | error | deterministic | syntax | `src/sesslint/codes.py:164-172` |
| SL003 | Duplicate event ID | warning | warning | deterministic | identity | `src/sesslint/codes.py:177-183` |
| SL004 | Missing parent | error | error | manual | graph | `src/sesslint/codes.py:189-195` |
| SL005 | Parent cycle | fatal | error | unsupported | graph | `src/sesslint/codes.py:198-204` |
| SL006 | Disconnected branch | warning | warning | manual | graph | `src/sesslint/codes.py:209-215` |
| SL007 | Ambiguous session head | warning | warning | manual | graph | `src/sesslint/codes.py:220-226` |
| SL008 | Non-monotonic timestamp | warning | warning | manual | graph | `src/sesslint/codes.py:229-235` |
| SL009 | Persisted secret material | warning | warning | manual | structure | `src/sesslint/codes.py:241-247` |
| SL010 | Interleaved writer markers | warning | warning | manual | structure | `src/sesslint/codes.py:253-262` |
| SL011 | Record size anomaly | info | note | manual | structure | `src/sesslint/codes.py:268-274` |
| SL101 | Orphan tool result | error | error | manual | pairing | `src/sesslint/codes.py:280-286` |
| SL102 | Dangling tool call | error | error | manual | pairing | `src/sesslint/codes.py:292-298` |
| SL103 | Reused tool-call ID | error | error | manual | pairing | `src/sesslint/codes.py:303-309` |
| SL104 | Multiple tool results | error | error | manual | pairing | `src/sesslint/codes.py:315-321` |
| SL105 | Tool result precedes call | error | error | manual | pairing | `src/sesslint/codes.py:326-332` |
| SL106 | Cross-branch tool pairing | error | error | manual | pairing | `src/sesslint/codes.py:337-343` |
| SL107 | Provider adjacency violation | warning | warning | manual | pairing | `src/sesslint/codes.py:348-354` |
| SL108 | Compaction split pair | warning | warning | manual | pairing | `src/sesslint/codes.py:359-365` |
| SL201 | Checkpoint/history divergence | error | error | manual | checkpoint | `src/sesslint/codes.py:370-376` |
| SL202 | Accepted terminal output not durable | error | error | manual | checkpoint | `src/sesslint/codes.py:379-385` |
| SL203 | Unknown side-effect state | error | error | manual | checkpoint | `src/sesslint/codes.py:390-396` |
| SL204 | Token usage arithmetic inconsistency | warning | warning | manual | accounting | `src/sesslint/codes.py:402-408` |
| SL205 | Compaction coverage gap | warning | warning | manual | checkpoint | `src/sesslint/codes.py:411-417` |
| SL206 | Durable-prefix boundary violation | warning | warning | manual | checkpoint | `src/sesslint/codes.py:423-433` |
| SL207 | Context-pressure projection | warning | warning | manual | accounting | `src/sesslint/codes.py:439-449` |
| SL208 | Compaction snapshot divergence | warning | warning | manual | checkpoint | `src/sesslint/codes.py:456-465` |
| SL301 | Unsupported format version | error | error | unsupported | compatibility | `src/sesslint/codes.py:471-477` |
| SL302 | Unknown critical record | error | error | manual | compatibility | `src/sesslint/codes.py:480-488` |
| SL303 | Duplicate JSON key | warning | warning | manual | compatibility | `src/sesslint/codes.py:491-497` |
| SL304 | Mid-file schema drift | warning | warning | manual | compatibility | `src/sesslint/codes.py:503-509` |
| SL305 | Provider-incompatible record shape | warning | warning | manual | compatibility | `src/sesslint/codes.py:515-524` |
| SL306 | Unknown non-linking metadata | info | note | manual | compatibility | `src/sesslint/codes.py:531-537` |
| SL401 | Unresolved cross-file link | warning | warning | manual | linkage | `src/sesslint/codes.py:542-548` |
| SL402 | Session index divergence | warning | warning | manual | linkage | `src/sesslint/codes.py:554-563` |

Thứ tự mảng `rules` là `sorted(CODE_REGISTRY)` (`src/sesslint/sarif.py:44`). Các khoá là 35 mã trong bảng. Với so sánh từng ký tự của các chuỗi ASCII đó, thứ tự là SL001, SL002, SL003, SL004, SL005, SL006, SL007, SL008, SL009, SL010, SL011, SL101, SL102, SL103, SL104, SL105, SL106, SL107, SL108, SL201, SL202, SL203, SL204, SL205, SL206, SL207, SL208, SL301, SL302, SL303, SL304, SL305, SL306, SL401, SL402. Nguồn không ghi sẵn list đã sort. So sánh có phụ thuộc locale hay không: U01.

Test level: rule SL003 → `"warning"`, SL101 → `"error"`, mọi level nằm trong `{"error","warning","note"}` (`tests/test_sarif.py:88-96`). Fixture `orphan_output.jsonl`: một result, `ruleId` `"SL101"`, `level` `"error"`, exit 1 (`tests/test_sarif.py:18-43`).

## URI

- B14. `_artifact_uri` nhận `finding.source.path` (`src/sesslint/sarif.py:85`). `SourceRef` đã `strip` và đổi `\` thành `/` trước khi finding tồn tại (`src/sesslint/finding.py:133-136`). `_artifact_uri` đổi `\` thành `/` lần nữa (`src/sesslint/sarif.py:73`).
- B15. `is_abs` khi chuỗi bắt đầu bằng `"/"`, hoặc `len > 1` và ký tự index 1 là `":"`, hoặc bắt đầu bằng `"~/"` (`src/sesslint/sarif.py:74`). Đúng thì `safe_path = minimize_path(p_str)` không truyền `home`. Sai thì `safe_path = p_str` (`src/sesslint/sarif.py:75`).
- B16. Chuỗi cuối là từng byte UTF-8 của `safe_path`: byte thuộc `_URI_PATH_SAFE` giữ nguyên dưới dạng `chr(byte)`, byte khác thành `"%{byte:02X}"` (`src/sesslint/sarif.py:76-79`). Tập an toàn là các byte của `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~/` (`src/sesslint/sarif.py:37-39`). `02X` là hex hoa hai chữ số.
- B17. Test ghim một path tương đối: `"folder name/#?-%-ä.jsonl"` → `"folder%20name/%23%3F-%25-%C3%A4.jsonl"` (`tests/test_wave1_correctness.py:281-295`). Test cấu trúc cấm `\` trong uri của fixture SL101 (`tests/test_sarif.py:41-42`).
- B18. `minimize_path` khi chuỗi là `str` và bắt đầu bằng `"~/"`, bằng `"~"`, hoặc bắt đầu bằng `".._"` thì trả nguyên (`src/sesslint/report.py:1739-1741`). Nhánh này chạy cho URI đã là `"~/..."`. Dạng `".._<8hex>/name"` không thoả B15 nên `_artifact_uri` không gọi `minimize_path` lần hai.
- B19. Path qua B15 mà không trả sớm ở B18 (`/` đầu hoặc dấu `:` ở index 1) đi vào nhánh `is_abs` của `minimize_path` (`src/sesslint/report.py:1745`, `src/sesslint/report.py:1753-1775`). `home` mặc định là `Path.home()` (`src/sesslint/report.py:1751`). Dưới home: `"~"` hoặc `"~/" + rel.as_posix()` (`src/sesslint/report.py:1753-1758`). Nếu native absolute (`Path.is_absolute()` hoặc bắt đầu `/`), thử `resolve()` rồi `relative_to` home đã resolve (`src/sesslint/report.py:1762-1769`). Comment nói absolute kiểu ngoại (`"D:/x"` trên POSIX) không được `resolve()` vì sẽ gắn cwd (`src/sesslint/report.py:1746-1749`). Còn lại: `".._" + sha1(parent UTF-8).hexdigest()[:8] + "/" + name` (`src/sesslint/report.py:10`, `src/sesslint/report.py:1773-1775`). Parent được đổi `\` thành `/` trước khi hash.
- B20. Nhãn path mà loader ghi vào `SourceRef`, trước khi SARIF mã hoá: canonical dùng `_canonical_source_label` — `bytes` → `"<bytes>"`, path → `str(Path).replace("\\","/")`, stream → `str(getattr(path,"name","<stream>")).replace("\\","/")` (`src/sesslint/adapters/canonical.py:931-937`). Ba adapter kia cùng ba nhánh: `src/sesslint/adapters/claude_code.py:429-434` và `src/sesslint/adapters/claude_code.py:453-454`, `src/sesslint/adapters/openai_agents.py:549-554` và `src/sesslint/adapters/openai_agents.py:584-585`, `src/sesslint/adapters/codex_rollout.py:1332-1337` và `src/sesslint/adapters/codex_rollout.py:1366-1367`. Detect dùng `str(Path).replace("\\","/")` (`src/sesslint/adapters/detect.py:304-305`).
- B21. `check` file đã resolve format dựng `SourceSnapshot(data, display_path)` (`src/sesslint/api.py:409`). `name` của snapshot là `str(Path(path))` (`src/sesslint/adapters/load.py:60-62`). `display_path` là `virtual_path` nếu có, không thì `str(target_path)` (`src/sesslint/api.py:212`). CLI file truyền `target_path` vào `check_file` (`src/sesslint/cli/check.py:533-534`). CLI stdin gọi `check_bytes` (`src/sesslint/cli/check.py:415-428`); default `virtual_path` là `"<stdin>"` (`src/sesslint/api.py:140`). Ký tự cụ thể của `str(Path("<stdin>"))` không được ghim trong nguồn. U04.
- B22. Scan thư mục đánh giá file bằng `display_path=minimize_path(file_path)` (`src/sesslint/scan.py:426-428`). Finding I/O sớm dùng `SourceRef(path=display_path)` (ví dụ `src/sesslint/scan.py:480-485`). Loader nhận `file_path` khi `data is None` (`src/sesslint/scan.py:604-606`). Check trong scan nhận `source_path_str`, và `source_path_str` là `str(file_path)` khi `data is None` (`src/sesslint/scan.py:456`, `src/sesslint/scan.py:650-655`). Hai nhóm path đó vào `_artifact_uri` riêng: path đã minimize dạng `".._"` không bị minimize lần hai (B18); path tuyệt đối còn dấu `:` hoặc `/` thì bị minimize (B15, B19).

## Thứ tự field và thứ tự result

`sort_keys=True` sắp khoá object (B10). Mảng giữ thứ tự dựng sẵn. Danh sách “thứ tự sort” dưới đây là so sánh từng ký tự của đúng các chuỗi khoá mà `build_sarif` / `_rule_objects` / `_result_object` chèn. Nguồn không ghi hàm so khoá riêng. U01.

- B23. Gốc, thứ tự sort: `$schema`, `runs`, `version`.
- B24. `runs[0]`: `results`, `tool`. `tool`: `driver`. `driver`: `informationUri`, `name`, `rules`, `version`.
- B25. Rule: `defaultConfiguration`, `helpUri`, `id`, `name`, `properties`, `shortDescription`. `shortDescription`: `text`. `defaultConfiguration`: `level`. `properties`: `category`, `repairability`.
- B26. Result: `level`, `locations`, `message`, `partialFingerprints`, `ruleId`. `message`: `text`. Location: `physicalLocation`. `physicalLocation` khi có region: `artifactLocation`, `region`. `artifactLocation`: `uri`. `region`: `startLine`.
- B27. `partialFingerprints` một khoá: `sesslint/finding-fingerprint`. Khi có digest: `sesslint/finding-fingerprint` rồi `sesslint/secret-match-sha256` (`"finding"` đứng trước `"secret"` sau tiền tố `sesslint/`).
- B28. Mảng `runs` một phần tử (B02). Mảng `rules` theo B của mục rule. Mảng `locations` một phần tử (B06). Mảng `results` là thứ tự đối số `findings` (B05, B11).
- B29. Một file hoặc stdin: CLI truyền `report.findings` (`src/sesslint/cli/_render.py:267-273`). `build_report` gán `findings` bằng `tuple(sort_findings(findings))` trước khi trả report (`src/sesslint/report.py:898`, `src/sesslint/report.py:917-922`). `check_file` đi qua `build_report` (`src/sesslint/api.py:508-516`). Khoá sort FR-094: path slash-forward, line (`None` → `-1`), `evidence["record_ordinal"]` nếu là `int` không phải `bool` và `>= 0` không thì `-1`, hạng severity fatal < error < warning < info, code, record_id (`None` → `""`), fingerprint, `related_ids`, message, repairability (`src/sesslint/finding.py:373-408`). `related_ids` và message có trong khoá sort; chúng không có field riêng trong result SARIF (B06).
- B30. Scan SARIF không sort finding. `to_dict` của `FileResult` sort bằng `finding_report_sort_key` (`src/sesslint/scan.py:137`); `scan_report_sarif` không gọi `to_dict`. Trong một file, list lưu là `adapter_findings + check_findings` rồi thành tuple (`src/sesslint/scan.py:663-668`). SL401 nối finding theo thứ tự link của từng file; docstring nói file đã sort theo path (`src/sesslint/scan.py:1577-1578`, `src/sesslint/scan.py:1642-1668`). SL402 nối tiếp (`src/sesslint/scan.py:1721-1727`, `src/sesslint/scan.py:1953-1960`).
- B31. `scan_path` sort `file_results` theo `r.path` sau khi duyệt, kể cả nhánh pool (`src/sesslint/scan.py:1464-1465`). `r.path` là path đã `minimize_path` (`src/sesslint/scan.py:428`, `src/sesslint/scan.py:1115`). Pool `map` rồi `from_wire` giữ thứ tự finding trong wire (`src/sesslint/scan.py:1423-1427`, `src/sesslint/scan.py:195`). File `skipped` mặc định `findings=()` nên không thêm result (`src/sesslint/scan.py:104`).
- B32. Nhiều path: mỗi `scan_path` xong, list gộp sort lại theo `r.path` (`src/sesslint/cli/check.py:475-495`). `--agent`: `merged_files.extend(rep.files)` theo thứ tự `roots`, không sort lại toàn cục (`src/sesslint/cli/check.py:356-378`, `src/sesslint/cli/check.py:399-401`). `requested` là `("claude","codex")` khi `--agent all`, không thì một tên (`src/sesslint/cli/check.py:356`). `discover_session_roots` đi theo `selected`; `codex` với `include_archived` thêm `archived_sessions` ngay sau root codex (`src/sesslint/api.py:1346-1384`). Root vắng là `FileResult` skipped, không có finding (`src/sesslint/cli/check.py:380-392`).

## Đường ra CLI

- B33. Choices `--format` của `check`/`scan`: `human`, `json`, `sarif`, `html` (`src/sesslint/cli/check.py:45-46`, `src/sesslint/cli/check.py:120-126`). `--json` và `--format` loại trừ nhau (`src/sesslint/cli/check.py:114-119`). Test tổ hợp `--json --format sarif` raises `SystemExit` code 2 (`tests/test_sarif.py:65-68`). Lệnh khác dùng choices `human`/`json` (`src/sesslint/cli/_options.py:279-290`).
- B34. `_output_format`: `args.json` thì `"json"`, không thì `output_format` hoặc `"human"` (`src/sesslint/cli/_common.py:106-110`). `SESSLINT_FORMAT` được gán khi CLI không chọn format; choices lấy từ subparser (`src/sesslint/cli/_context.py:26`, `src/sesslint/cli/_context.py:159-181`, `src/sesslint/cli/_context.py:302-313`). Config không có khoá format (`src/sesslint/cli/_context.py:84-90`). Test: `--format sarif` thắng `SESSLINT_FORMAT=json` và stdout chứa `"$schema"` (`tests/cli/test_env_precedence.py:114-121`).
- B35. Một file / stdin, format sarif, sau nhánh skip: `render_sarif(report.findings, tool_version=report.tool_version)` (`src/sesslint/cli/_render.py:267-276`). `report.tool_version` đến từ `CLI_VERSION` rồi `strip` (`src/sesslint/api.py:511`, `src/sesslint/report.py:921`). `CLI_VERSION` là `__version__` = `"0.5.0"` (`src/sesslint/_version.py:7-8`). Package gán `__version__ = CLI_VERSION` (`src/sesslint/__init__.py:149`).
- B36. `--skip-undetected` và `limitation` bắt đầu bằng `"Unsupported:"`: format sarif gọi `render_sarif((), tool_version=__version__)` và `return 0` (`src/sesslint/cli/_render.py:151-187`). Import `__version__` ở `src/sesslint/cli/_render.py:12`. Test: version `"2.1.0"`, có `runs`, exit 0 (`tests/test_field_regressions.py:278-288`).
- B37. Thư mục, nhiều path, `--agent`: `scan_report_sarif(scan_rep, tool_version=__version__)` (`src/sesslint/cli/check.py:302-310`, import `src/sesslint/cli/check.py:10`). Summary được gắn vào `scan_rep` trước khi chọn format (`src/sesslint/cli/check.py:284-296`) và không được `scan_report_sarif` đọc (B10). `--top` âm return 2 trước khi emit (`src/sesslint/cli/check.py:286-288`).
- B38. File trong scan mà không detect được: `skip_undetected` trả `FileResult` skipped không finding (`src/sesslint/scan.py:568-572`). Result SARIF của file đó không xuất hiện. Đây là document scan (B37), không phải document rỗng của B36.
- B39. Exit một file sau khi emit SARIF là `exit_code` đã tính từ count: error/fatal, hoặc warning khi `--fail-on warning` (`src/sesslint/cli/_render.py:189-195`, `src/sesslint/cli/_render.py:277`). Limitation `"Unsupported:"` đặt exit bằng `int(fail_on_unsupported)` trước nhánh format (`src/sesslint/cli/_render.py:197-198`). Scan emit xong rồi return 1 khi `totals.invalid > 0`, hoặc unsupported nếu `fail_on_unsupported`, hoặc `unreadable > 0`, hoặc `--fail-on warning` và tổng `warning_count` > 0; không thì 0 (`src/sesslint/cli/check.py:331-339`).
- B40. `wants_json` đúng khi `args.json` hoặc `output_format == "json"` hoặc token/env chọn `"json"` (`src/sesslint/cli/_json_errors.py:50-72`). `output_format` `"sarif"` không thoả `== "json"`. `error_document` chỉ được in ở `main` khi `wants_json` và stdout trống và code khác 0, 130 (`src/sesslint/cli/__init__.py:232-233`). `_handle_internal_error` in envelope JSON khi `args.json`, không thì một dòng stderr (`src/sesslint/cli/_common.py:46-51`).
- B41. `--include-content` không có trong chữ ký `render_sarif` (`src/sesslint/sarif.py:137-140`). Nhánh sarif không đọc flag đó (`src/sesslint/cli/_render.py:267-276`). `--seal` một file emit report trước, rồi hash `render_json(report)` (`src/sesslint/cli/check.py:552-572`). `--seal` từ chối nhiều path và thư mục trước emit (`src/sesslint/cli/check.py:344-349`, `src/sesslint/cli/check.py:501-506`).
- B42. Không `-o`: `emit_text` gọi `print(text)` và không truyền `end` (`src/sesslint/cli/_output.py:118-120`). Có `-o`: file nhận `text.encode("utf-8") + b"\n"` (`src/sesslint/cli/_output.py:132-134`). Docstring nói file nhận byte của `print` cộng newline mà `print` thêm (`src/sesslint/cli/_output.py:111-116`). `main` `reconfigure(encoding="utf-8")` không truyền `newline` (`src/sesslint/cli/__init__.py:178-180`).
- B43. Progress NDJSON ghi stderr (`src/sesslint/cli/_progress.py:1-4`, `src/sesslint/cli/_progress.py:26`). Chuỗi SARIF là đối số `emit_text` trên stdout hoặc file `-o` (B42).
- B44. `render_sarif` không gọi codec canonical. Codec đó dùng `separators=(",", ":")`, `ensure_ascii=False`, `allow_nan=False`, không `indent` (`src/sesslint/_canonical_codec.py:84-90`).
- B45. Hai lần `check --format sarif` trên cùng fixture cho cùng stdout trong test (`tests/test_sarif.py:71-76`). Test content-free của fixture SL101 cấm các substring `"payload"`, `"tool_calls"`, `"arguments"` trong cả document (`tests/test_sarif.py:79-85`).
- B46. Rule list không nhận `--select` / `--ignore` / baseline: `_rule_objects` không có tham số (mục rule). `check` gọi `apply_rule_selection` (`src/sesslint/api.py:219`) rồi lọc `adapter_findings` theo `enabled_rules` (`src/sesslint/api.py:441`) và lọc baseline (`src/sesslint/api.py:477-480`). Scan gọi `apply_rule_selection` (`src/sesslint/scan.py:901`), lấy `enabled_rules` (`src/sesslint/scan.py:532-536`), lọc adapter (`src/sesslint/scan.py:633`) và baseline (`src/sesslint/scan.py:664-667`).

## UNKNOWN

- U01. `sort_keys` và `sorted` có phụ thuộc locale hay chỉ so mã ký tự: nguồn không nói.
- U02. Khoảng trắng `json.dumps` khi `indent=2` mà không truyền `separators`, và dạng escape Unicode khi không truyền `ensure_ascii`: nguồn không ghim. Test SARIF dùng `json.loads` hoặc so cả chuỗi stdout với chính nó (B45).
- U03. `allow_nan` và chính tả số của `json.dumps`: lời gọi không truyền các tham số đó. Dict SARIF chèn `str`, `int` (`startLine`), `list`, `dict`. Nguồn không có test chính tả byte của số nguyên trong file SARIF.
- U04. URI vàng cho `"<stdin>"`, `"<bytes>"`, `"<stream>"`, và cho path tuyệt đối sau `minimize_path`: nguồn không ghi chuỗi kỳ vọng. Quy tắc B14–B22 là phần được ghi. `str(Path("<stdin>"))` không được ghim (B21).
- U05. Stdout có đúng một `0x0A` và console Windows có dịch `\n` thành CRLF hay không: `print` không truyền `end`, `reconfigure` không truyền `newline` (B42). File `-o` là UTF-8 cộng một byte `0x0A` (B42).
- U06. Hai giá trị `--jobs` có cho cùng byte SARIF hay không: `sarif.py` không đọc `jobs`. `scan_path` sort file theo `r.path` trước khi trả `ScanReport` (B31). Nguồn SARIF không có test so byte giữa `jobs=1` và `jobs>1`.

## Đếm

- Đã dẫn chứng: 46 (B01–B46).
- UNKNOWN: 6 (U01–U06).
- Bảng rule: 35 hàng, mỗi hàng một khoảng dòng `codes.py`.

# exit

Bản đồ điều kiện ra exit `0`, `1`, `2`, `130` và stderr lỗi. Nguồn là worktree `D:\FOR_WORK\WORK_PROJECT\sesslint`, HEAD `02694d537104659df66cdd084354739f3cccc440`. Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` tồn tại và là tổ tiên của HEAD (`git merge-base --is-ancestor` thoát 0). Worktree không bị đổi nhánh.

`python -m sesslint` bọc giá trị `main()` bằng `SystemExit` (`src/sesslint/__main__.py:18`). Số trong bảng là số `main` hoặc lệnh con trả về, trừ khi ô Exit ghi UNKNOWN. `check` và alias `scan` dùng cùng `run` (`src/sesslint/cli/_registry.py:69`).

Stderr được gọi là content-free chỉ khi cả dòng là literal trong nguồn, hoặc phần nội suy là token kín mà cùng hàm đã liệt kê (`source`/`target`, tên lệnh đã xoá, số nguyên của cờ). Dòng nội suy exception, path, message finding, problem của contract, hoặc chi tiết seal: ô stderr ghi UNKNOWN. Nguồn không chứng minh phần nội suy không chứa payload.

`src/sesslint/completion.py:135` nhúng `return 0` trong script bash sinh ra. Đó là exit của shell completion, không phải exit tiến trình Python của SessLint.

## Lệch so với pin

`git diff --name-only e91d50b2ecea57ef4dd900e3b0b87b14946e847e HEAD` trên các file gán exit của CLI, `precheck.py`, `triage.py`, `hook_event.py`, `progress.py`, `mcp_server.py`, `__main__.py` không có tên file. Các file đó trùng pin.

Khác pin, trong vùng exit:

- `src/sesslint/cli/outcome.py` và `src/sesslint/outcome/report.py` là file mới. Mọi exit của lệnh `outcome` không có ở pin.
- `src/sesslint/cli/_registry.py` đăng ký lệnh `outcome`. Không thêm literal exit.
- `src/sesslint/cli/_output.py` không đổi các `CliError(2)` hay chuỗi stderr. Diff thêm `"outcome"` vào `_REPORT_COMMANDS` và thêm tên biên `contract`, `target`, `session`. Lệnh `outcome` vì vậy đi qua các guard exit 2 đã có.

## Văn bản mô tả, không phải lệnh trả

Epilog ghi nghĩa, không tự trả số (`src/sesslint/cli/__init__.py:42-50`): `0` phiên sạch, cũng là verify đạt hoặc dry-run sinh plan; `1` phiên có finding, cũng là verify thất bại hoặc repair bị từ chối; `2` lỗi công cụ, cũng là usage, cờ sai, hoặc I/O. `README.md:494-499` lặp ba nghĩa đó và thêm `130` cho Ctrl+C hoặc hủy hợp tác. Producer của `130` là `main`, ở mục dưới. `progress.py:19-20` cũng viết cancelled CLI exits 130. `docs/MIGRATING_0_5.md:80` viết cancellation remains exit 130.

## Bảng

Trong ô stderr, `\|` là dấu `|` của chuỗi nguồn.

| Điều kiện | Exit | Dẫn chứng | stderr |
|---|---|---|---|
| Không có subcommand: in help ra stdout rồi trả | 2 | `src/sesslint/cli/__init__.py:138-140` | không có dòng lỗi; help ở stdout |
| Token argv không bắt đầu bằng `-` nằm trong `REMOVED_COMMANDS`: in hint rồi `return code`; `code` đã gán 2 và nhánh này không gán lại | 2 | `src/sesslint/cli/__init__.py:98-106`, `src/sesslint/cli/__init__.py:187`, `src/sesslint/cli/__init__.py:193-196`, `src/sesslint/cli/_registry.py:43-51` | `Error: 'validate-session' was removed in 0.5.0; use: sesslint check --adapter canonical PATH`; `Error: 'baseline' was removed in 0.5.0; use: v1 baselines still load via 'sesslint check --baseline OLD.json'; regenerate v2 with 'sesslint check PATH --write-baseline NEW.json'`; `Error: 'formats' was removed in 0.5.0; use: sesslint doctor  (or: sesslint version --json)`; `Error: 'init-hooks' was removed in 0.5.0; use: sesslint hook --init [--agent claude\|codex\|all]` |
| Hint cờ đã xoá hoặc `--format` kèm tên adapter: in hint rồi parse tiếp. Hint không trả số. Nếu parse ném `SystemExit`, số tiến trình UNKNOWN | UNKNOWN | `src/sesslint/cli/__init__.py:110-125`, `src/sesslint/cli/__init__.py:197-199`, `src/sesslint/cli/__init__.py:204-206`, `src/sesslint/cli/_registry.py:53-64` | literal `hint: '--format' now selects the output format; use '--adapter <name>'`; hoặc `hint: '<flag>' was removed in 0.5.0; use <replacement>` với flag và replacement lấy từ `REMOVED_FLAGS` |
| `args.command` không có trong `build_dispatch()` | 0 | `src/sesslint/cli/__init__.py:154-157` | không |
| Lệnh có trong dispatch: trả nguyên giá trị `command.run` | số của `run` | `src/sesslint/cli/__init__.py:161` | theo lệnh con |
| `CliError` trong `_dispatch`: in `err.message`, trả `err.exit_code`. Mọi `CliError(` trong `src/sesslint` truyền 2; các chỗ gọi nằm ở các hàng guard bên dưới | 2 | `src/sesslint/cli/__init__.py:164-169`, `src/sesslint/cli/_errors.py:14-17` | đúng `message` của từng `CliError` |
| `KeyboardInterrupt` tới `main` | 130 | `src/sesslint/cli/__init__.py:207-210` | `Operation cancelled by user` |
| `OperationCancelled` tới `main` | 130 | `src/sesslint/cli/__init__.py:211-214` | `Operation cancelled` |
| `FileNotFoundError` tới `main`: in `Error: {err}`, `return code`. Biến `code` gán 2 lúc vào `main`; nhánh này không gán lại. `_dispatch` ném thì phép gán `code = _dispatch` không hoàn tất | 2 | `src/sesslint/cli/__init__.py:187`, `src/sesslint/cli/__init__.py:215-217` | UNKNOWN (`Error: {err}`) |
| `CliError` thoát khỏi `_dispatch`: in message, trả `err.exit_code` | số truyền vào `CliError` | `src/sesslint/cli/__init__.py:218-221` | đúng `message` |
| Exception khác tới `main`: `_handle_internal_error`. `CliError` bị ném lại cho handler trên. Nhánh còn lại trả 2. ID có dạng `ERR-` + 8 hex; docstring gọi ID là content-free | 2 | `src/sesslint/cli/__init__.py:222-228`, `src/sesslint/cli/_common.py:29-52` | người: UNKNOWN vì dòng là `Operational error [{error_id}]: {err}`. JSON: không stderr; envelope in stdout, `message` là `str(err)` (`src/sesslint/api.py:1213-1218`) |
| `SystemExit` (gồm `--help`, `--version`, `parser.error`, `ArgumentTypeError`): gán biến cục bộ rồi `raise`. Biến cục bộ = `err.code` nếu là int, 0 nếu `None`, 1 nếu kiểu khác. Biến đó chỉ để cổng JSON trong `finally`, không được trả. Nguồn không ghi số argparse đặt vào `SystemExit` | UNKNOWN | `src/sesslint/cli/__init__.py:75-79`, `src/sesslint/cli/__init__.py:204-206`, `src/sesslint/cli/__init__.py:232-233` | UNKNOWN. `finally` có thể in JSON ra stdout, không đổi exit: message là prefix stderr hoặc literal `Command failed` |
| `parser.error(...)` tại check stdin, check file, bundle, verify thiếu path. Các dòng này không gán số | UNKNOWN | `src/sesslint/cli/check.py:433`, `src/sesslint/cli/check.py:550`, `src/sesslint/cli/bundle.py:106`, `src/sesslint/cli/verify.py:95`, `src/sesslint/cli/__init__.py:204-206` | UNKNOWN |
| Validator argparse ném `ArgumentTypeError`. Nguồn không gán số exit | UNKNOWN | `src/sesslint/cli/_options.py:17-19`, `src/sesslint/cli/_options.py:28-32`, `src/sesslint/cli/outcome.py:34-36`, `src/sesslint/cli/__init__.py:204-206` | UNKNOWN |
| `SESSLINT_FORMAT` không thuộc choices của lệnh | 2 | `src/sesslint/cli/_context.py:176-180` | UNKNOWN (template `Invalid SESSLINT_FORMAT=<giá trị>: choose from <choices>`, có giá trị env) |
| `load_config` ném `ConfigError` | 2 | `src/sesslint/cli/_context.py:214-217`, `src/sesslint/config.py:119`, `src/sesslint/config.py:159-164`, `src/sesslint/config.py:171`, `src/sesslint/config.py:176`, `src/sesslint/config.py:182-183`, `src/sesslint/config.py:187`, `src/sesslint/config.py:190`, `src/sesslint/config.py:198`, `src/sesslint/config.py:203-204`, `src/sesslint/config.py:234-239`, `src/sesslint/config.py:252`, `src/sesslint/config.py:254`, `src/sesslint/config.py:259` | UNKNOWN (`Error: {err}`; message ConfigError có path và có thể có giá trị) |
| `SESSLINT_ADAPTER` không thuộc adapter hỗ trợ | 2 | `src/sesslint/cli/_context.py:260-268` | UNKNOWN (template có giá trị env) |
| `SESSLINT_PROFILE` không thuộc profile đã đăng ký | 2 | `src/sesslint/cli/_context.py:270-278` | UNKNOWN (template có giá trị env) |
| Output hoặc baseline là symlink hoặc hard link | 2 | `src/sesslint/cli/_output.py:72-73` | `Error: --output/--write-baseline must not be a link alias` |
| Output hoặc baseline trùng path input | 2 | `src/sesslint/cli/_output.py:74-78` | `Error: --output/--write-baseline must not be an input path` |
| Output nằm trong thư mục input | 2 | `src/sesslint/cli/_output.py:79-80` | `Error: --output must not replace an artifact inside an input directory` |
| `OSError` hoặc `RuntimeError` khi kiểm tra an toàn output | 2 | `src/sesslint/cli/_output.py:99-100` | `Error: output safety could not be established` |
| `OSError` khi ghi report | 2 | `src/sesslint/cli/_output.py:139-140` | UNKNOWN (`Error: cannot write report to {output}: {err}`) |
| `check`: `--latest` mà agent không phải `claude` hoặc `codex` | 2 | `src/sesslint/cli/check.py:226-229` | `Error: --latest requires --agent claude or --agent codex.` |
| `check`: `--latest` kèm path positional | 2 | `src/sesslint/cli/check.py:230-232` | `Error: positional paths cannot be combined with --latest.` |
| `check`: `latest_session` ném `OSError` hoặc `FileNotFoundError` | 2 | `src/sesslint/cli/check.py:235-239` | UNKNOWN (`Error: {err}`) |
| `check`: không agent và không path: in help ra stderr | 2 | `src/sesslint/cli/check.py:246-248` | UNKNOWN (help do argparse sinh, không phải literal lỗi) |
| `check`: `ValueError` khi dựng baseline hoặc scan kwargs | 2 | `src/sesslint/cli/check.py:251-259`, `src/sesslint/cli/_common.py:80-84` | UNKNOWN (`Error: {err}`) |
| `check` scan: `--top` không `None` và `< 0` | 2 | `src/sesslint/cli/check.py:284-288` | `Error: --top must be >= 0, got ` + số nguyên cờ |
| `check` scan: `totals.invalid > 0`, hoặc `fail_on_unsupported` và `totals.unsupported > 0`, hoặc `totals.unreadable > 0`, hoặc `fail_on == "warning"` và tổng warning của các file `> 0` | 1 | `src/sesslint/cli/check.py:331-338` | không có dòng lỗi của nhánh này |
| `check` scan: phủ định điều kiện hàng trên | 0 | `src/sesslint/cli/check.py:339` | không |
| `check`: `--seal` khi có agent hoặc số path khác 1 | 2 | `src/sesslint/cli/check.py:344-349` | `Error: --seal applies to single-file checks only (one artifact per line; scans are not sealed).` |
| `check --agent`: `ValueError` hoặc `KeyError` | 2 | `src/sesslint/cli/check.py:394-397` | UNKNOWN (`Error: {err_msg}`) |
| `check`: `-` kèm path khác | 2 | `src/sesslint/cli/check.py:405-408` | `Error: '-' (stdin) cannot be combined with other paths.` |
| `check` stdin: `ValueError`/`KeyError` mà `str(err)` chứa `not permitted by profile` | 2 | `src/sesslint/cli/check.py:429-432` | UNKNOWN (`str(err)`) |
| `check` stdin: `SesslintError` | 1 | `src/sesslint/cli/check.py:434-436` | UNKNOWN (`Validation error [{err.code}]: {err}`) |
| `check` stdin: exception khác trong khối đọc stdin | 2 | `src/sesslint/cli/check.py:437-438`, `src/sesslint/cli/_common.py:52` | như hàng internal error |
| `check` nhiều path: một path không tồn tại và không phải symlink | 2 | `src/sesslint/cli/check.py:465-468` | UNKNOWN (`Error: Path not found: {p}`) |
| `check` nhiều path: `ValueError` hoặc `KeyError` từ `scan_path` | 2 | `src/sesslint/cli/check.py:476-481` | UNKNOWN (`Error: {err_msg}`) |
| `check` thư mục kèm `--seal` | 2 | `src/sesslint/cli/check.py:500-506` | `Error: --seal applies to single-file checks only (one artifact per line; directory scans are not sealed).` |
| `check` thư mục: `ValueError` hoặc `KeyError` | 2 | `src/sesslint/cli/check.py:510-515` | UNKNOWN (`Error: {err_msg}`) |
| `check` một path không tồn tại | 2 | `src/sesslint/cli/check.py:519-521` | UNKNOWN (`Error: Path not found: {target_path}`) |
| `check` file: `ValueError`/`KeyError` mà `str(err)` chứa `not permitted by profile` | 2 | `src/sesslint/cli/check.py:546-549` | UNKNOWN (`str(err)`) |
| `check` file: `SesslintError` | 1 | `src/sesslint/cli/check.py:576-578` | UNKNOWN (`Validation error [{err.code}]: {err}`) |
| `check` file: `FileNotFoundError` từ `check_file` | 2 | `src/sesslint/cli/check.py:579-581` | UNKNOWN (`Error: {err}`) |
| `check` file: exception khác | 2 | `src/sesslint/cli/check.py:582-583`, `src/sesslint/cli/_common.py:52` | như hàng internal error |
| `check` một file hoặc stdin, `--skip-undetected` và `limitation` bắt đầu bằng `Unsupported:` | 0 | `src/sesslint/cli/_render.py:151-187` | không có dòng lỗi; nhánh text gọi `ctx.info`, bị `--quiet` nuốt |
| `check` một file hoặc stdin, không đi nhánh skip trên: `exit_code` = 1 khi count severity `error` hoặc `fatal` `> 0`; nếu `fail_on == "warning"` thì thêm count `warning` `> 0`; không thì 0 | 0 hoặc 1 | `src/sesslint/cli/_render.py:189-195`, `src/sesslint/cli/_options.py:169-176` | không phải nhánh lỗi |
| Cùng đường trên, `limitation` bắt đầu bằng `Unsupported:`: gán đè `exit_code = int(fail_on_unsupported)`. Flag là `store_true`. Help nói Exit 1. Dòng gán không viết literal 0 hay 1 | int(flag); literal UNKNOWN | `src/sesslint/cli/_render.py:197-198`, `src/sesslint/cli/_options.py:258-261` | không lỗi; `ctx.info` một câu unsupported |
| Cùng đường, `limitation` bắt đầu bằng `Skipped:`: không đổi `exit_code` vừa tính | 0 hoặc 1 như hàng finding | `src/sesslint/cli/_render.py:200-201` | không lỗi; `ctx.info` một câu file-too-large |
| Bốn nhánh format json, sarif, html, human của report một file trả `exit_code` đã tính | số đã tính | `src/sesslint/cli/_render.py:266`, `src/sesslint/cli/_render.py:277`, `src/sesslint/cli/_render.py:292`, `src/sesslint/cli/_render.py:305` | không thêm |
| `check` stdin hoặc file: nếu seal trả int thì dùng số đó, không thì dùng rc của report | số seal hoặc rc | `src/sesslint/cli/check.py:450-460`, `src/sesslint/cli/check.py:563-574` | theo seal |
| `--seal` được bật và `SealError` hoặc `OSError` | 2 | `src/sesslint/cli/_seal.py:42-48`, `src/sesslint/cli/_seal.py:74-76` | UNKNOWN (`Error: seal failed: {err}`) |
| `--seal` vắng hoặc append thành công: trả `None`, caller giữ exit của mình | không đổi | `src/sesslint/cli/_seal.py:46-48`, `src/sesslint/cli/_seal.py:77-78` | không lỗi; `ctx.info` dòng `sealed:` |
| `repair`: `--apply-plan` kèm override CLI của policy, profile, hoặc adapter | 2 | `src/sesslint/cli/repair.py:173-184` | `Error: --apply-plan is authoritative for the exported plan; remove override(s): ` + danh sách cờ |
| `repair`: `--apply-plan` kèm `--plan-out` | 2 | `src/sesslint/cli/repair.py:185-190` | `Error: --plan-out cannot be combined with --apply-plan (no plan is recomputed to export).` |
| `repair --preview` kèm output, plan, plan-out, batch, hoặc `--emit` khác `auto` | 2 | `src/sesslint/cli/repair.py:205-222` | `Error: --preview writes nothing; incompatible with ` + danh sách xung đột |
| Batch repair có `-` | 2 | `src/sesslint/cli/repair.py:228-231` | `Error: '-' (stdin) cannot be combined with other repair inputs.` |
| Batch repair kèm `--seal` | 2 | `src/sesslint/cli/repair.py:232-237` | `Error: --seal applies to single-file repair only (batch modes produce no single subject artifact).` |
| Batch repair kèm `--output` | 2 | `src/sesslint/cli/repair.py:238-242` | `Error: --output applies to single-file repair; batch modes use --output-dir.` |
| Batch repair kèm `--apply-plan` hoặc `--plan-out` | 2 | `src/sesslint/cli/repair.py:243-248` | `Error: --apply-plan/--plan-out are single-file options; batch computes plans internally per file.` |
| Batch repair thiếu `--output-dir` | 2 | `src/sesslint/cli/repair.py:249-251` | `Error: batch repair requires --output-dir.` |
| Batch: không đọc được scan report (`OSError`, `ValueError`, `KeyError`) | 2 | `src/sesslint/cli/repair.py:274-279` | UNKNOWN (`Error: cannot read scan report: {err}`) |
| Batch: profile không lấy được (`KeyError`, `ValueError`) | 2 | `src/sesslint/cli/repair.py:290-295` | UNKNOWN (`Error: {err_msg}`) |
| Batch: exception từ `repair_many` | 2 | `src/sesslint/cli/repair.py:311-312`, `src/sesslint/cli/_common.py:52` | như hàng internal error |
| Batch xong: `refused == 0` và `skipped == 0`. Path scan không resolve được được thêm hàng `skipped` trước phép trả | 0 | `src/sesslint/cli/repair.py:314-325` | không lỗi của nhánh này |
| Batch xong: `refused != 0` hoặc `skipped != 0` | 1 | `src/sesslint/cli/repair.py:325` | không lỗi của nhánh này |
| Repair không batch và không có path | 2 | `src/sesslint/cli/repair.py:327-332` | `Error: repair requires a source path, or batch inputs (multiple paths, directories, or --from-scan with --output-dir).` |
| `--seal` khi plan-only hoặc preview | 2 | `src/sesslint/cli/repair.py:338-343` | `Error: --seal requires a completed repair — incompatible with --dry-run, plan-only export, or --preview (nothing is produced).` |
| Không plan-only, không preview, thiếu `--output` | 2 | `src/sesslint/cli/repair.py:344-348` | `Error: --output is required unless --dry-run, --plan-out, or --preview is specified.` |
| Stdin repair dài hơn `DEFAULT_MAX_FILE_BYTES` | 2 | `src/sesslint/cli/repair.py:363-367`, `src/sesslint/io.py:47` | `Error: stdin exceeds maximum supported size (` + số hằng + ` bytes).` |
| Path repair là thư mục | 2 | `src/sesslint/cli/repair.py:372-374` | UNKNOWN (`Error: repair operates on a single session file, not a directory: {src_path}`) |
| Path repair không phải file | 2 | `src/sesslint/cli/repair.py:375-377` | UNKNOWN (`Error: Source file not found: {src_path}`) |
| `--adapter` không thuộc `VALID_FORMAT_OPTIONS` | 2 | `src/sesslint/cli/repair.py:389-391` | UNKNOWN (`Error: Unsupported format option: {format_opt}`) |
| Profile repair không lấy được | 2 | `src/sesslint/cli/repair.py:397-402` | UNKNOWN (`Error: {err_msg}`) |
| Preview: `FileNotFoundError` hoặc `OSError` | 2 | `src/sesslint/cli/repair.py:417-419` | UNKNOWN (`File error: {err}`) |
| Preview: `ValueError` hoặc `KeyError` | 2 | `src/sesslint/cli/repair.py:420-423` | UNKNOWN (`Error: {err_msg}`) |
| Preview: `SesslintError` | 2 | `src/sesslint/cli/repair.py:424-426` | UNKNOWN (`Error: {err}`) |
| Preview: exception khác | 2 | `src/sesslint/cli/repair.py:427-428`, `src/sesslint/cli/_common.py:52` | như hàng internal error |
| Preview in xong: `preview_doc.refused` đúng | 1 | `src/sesslint/cli/repair.py:434` | không |
| Preview in xong: `preview_doc.refused` sai | 0 | `src/sesslint/cli/repair.py:434` | không |
| Ghi `--plan-out` ném `OSError` | 2 | `src/sesslint/cli/repair.py:474-476` | UNKNOWN (`Error writing plan to {args.plan_out}: {err}`) |
| Plan-only sau khi in plan, kể cả khi có blocked finding trên stdout | 0 | `src/sesslint/cli/repair.py:515-525` | không lỗi của lệnh trả này |
| Có `--seal` mà manifest là `None` sau repair | 2 | `src/sesslint/cli/repair.py:557-561` | `Error: --seal requires a completed repair with a manifest.` |
| Seal của repair trả int | số đó | `src/sesslint/cli/repair.py:562-575`, `src/sesslint/cli/_seal.py:74-76` | UNKNOWN nếu là lỗi seal |
| Repair có manifest và seal không trả số | 0 | `src/sesslint/cli/repair.py:576` | nếu `declared_loss` khác rỗng thì có stderr UNKNOWN (`Declared loss: ` + các mục + ` (salvage repair — see manifest for detail)`), `src/sesslint/cli/repair.py:535-540`; dòng đó không chọn exit |
| `VendorRepairRefused` | 2 | `src/sesslint/cli/repair.py:577-582` | UNKNOWN (`Error: {err}`) |
| `PlanTampered`, `Abstained`, `PolicyMismatch`, `OutputInvalid`, `RepairRefused`, hoặc `PlanSourceMismatch` | 1 | `src/sesslint/cli/repair.py:583-609` | người: UNKNOWN (`Repair refused [{err_code}]: {err}`). JSON: document ra stdout, không qua `ctx.error` |
| Repair: `ValueError` hoặc `KeyError` | 2 | `src/sesslint/cli/repair.py:610-615` | UNKNOWN (`Error: {err_msg}`) |
| Repair: `FileNotFoundError` | 2 | `src/sesslint/cli/repair.py:616-618` | UNKNOWN (`File error: {err}`) |
| Repair: `SesslintError` | 2 | `src/sesslint/cli/repair.py:619-623` | UNKNOWN (`Error: {err}`) |
| Repair: exception khác | 2 | `src/sesslint/cli/repair.py:624-625`, `src/sesslint/cli/_common.py:52` | như hàng internal error |
| `verify` thiếu source hoặc repaired: `parser.error`, không gán số | UNKNOWN | `src/sesslint/cli/verify.py:94-95` | UNKNOWN |
| `verify` in xong và seal không trả số: `verdict.ok` đúng | 0 | `src/sesslint/cli/verify.py:137-139` | không |
| `verify` in xong và seal không trả số: `verdict.ok` sai | 1 | `src/sesslint/cli/verify.py:137-139` | không |
| `verify`: seal trả int | số đó | `src/sesslint/cli/verify.py:126-138` | theo seal |
| `verify`: `FileNotFoundError` hoặc `OSError` | 2 | `src/sesslint/cli/verify.py:140-142` | UNKNOWN (`Verify I/O error: {err}`) |
| `verify`: exception khác | 2 | `src/sesslint/cli/verify.py:143-144`, `src/sesslint/cli/_common.py:52` | như hàng internal error |
| `diff`: `DiffInputError` | 2 | `src/sesslint/cli/diff.py:85-87` | UNKNOWN (`Error: {err}`) |
| `diff`: `ValueError` | 2 | `src/sesslint/cli/diff.py:88-90` | UNKNOWN (`Error: {err}`) |
| `diff`: `identical` đúng | 0 | `src/sesslint/cli/diff.py:97` | không |
| `diff`: `identical` sai | 1 | `src/sesslint/cli/diff.py:97` | không |
| `doctor`: `ConfigError` | 2 | `src/sesslint/cli/doctor.py:73-75` | UNKNOWN (`Error: {err}`) |
| `doctor`: report phát được. `doctor.py` không có `return 1` | 0 | `src/sesslint/cli/doctor.py:76-80` | không |
| `triage` CLI: không đúng một trong hai dạng “một file” hoặc “`--latest` và `--agent`” | 2 | `src/sesslint/cli/triage.py:73-78` | `Error: choose a file OR --agent claude\|codex --latest.` |
| `triage` CLI: `--include-content` | 2 | `src/sesslint/cli/triage.py:79-81` | `Error: triage does not support --include-content.` |
| `triage()` hoặc `latest_session` ném `OSError`, `ValueError`, hoặc `KeyError` | 2 | `src/sesslint/cli/triage.py:82-94` | `Error: triage input/discovery/options could not be resolved.` |
| `triage` CLI còn lại: trả `TriageReport.exit_code` | số của property | `src/sesslint/cli/triage.py:102`, `src/sesslint/triage.py:54-58` | không thêm |
| Triage `status == "unreadable"`: giá trị đầu, và giữ vậy khi `assess_source` ném `OSError` nên report là `None` | 2 | `src/sesslint/triage.py:295-303`, `src/sesslint/triage.py:56-57` | không ở CLI; hàm nuốt `OSError` rồi vẫn emit report |
| Triage `status == "checked"` | 0 | `src/sesslint/triage.py:320-321`, `src/sesslint/triage.py:58` | không |
| Triage status khác hai giá trị trên. Chuỗi được gán: `skipped`, `unsupported`, `unstable`, `blocked`, `needs-attention` | 1 | `src/sesslint/triage.py:304-335`, `src/sesslint/triage.py:58` | không |
| `hook --init` | 0 | `src/sesslint/cli/hook.py:99-107` | không |
| `hook` còn lại: trả `HookResult.exit_code`. Docstring nói exit 2 không được phát. `hook.py` và `hook_event.py` không gán 2 | 0 hoặc 1 | `src/sesslint/cli/hook.py:30-32`, `src/sesslint/cli/hook.py:128` | không stderr lỗi; stdout là dòng hoặc JSON mà docstring gọi content-free (`src/sesslint/hook_event.py:102-109`) |
| Hook payload quá lớn, JSON hỏng, payload không phải object, `hook_event_name` hoặc `cwd` sai kiểu, không có `transcript_path`, transcript không phải file, `OSError` khi stat hoặc check, quá ngân sách byte, limitation `Unsupported:` hoặc `Skipped:`, hoặc exception còn lại | 0 | `src/sesslint/hook_event.py:116-125`, `src/sesslint/hook_event.py:161-223` | không |
| Hook không finding | 0 | `src/sesslint/hook_event.py:225-234` | không |
| Hook có finding, `fail_on == "warning"` | 1 | `src/sesslint/hook_event.py:240-256`, `src/sesslint/cli/hook.py:73-80` | không |
| Hook có finding, `fail_on == "error"`, và có severity `error` hoặc `fatal` | 1 | `src/sesslint/hook_event.py:243-256` | không |
| Hook có finding, `fail_on` là `None`, `"never"`, hoặc `"error"` mà không có severity `error`/`fatal` | 0 | `src/sesslint/hook_event.py:240-256` | không |
| `export` thiếu `--output` | 2 | `src/sesslint/cli/export.py:53-55` | `Error: --output is required for export.` |
| `export`: path không phải file | 2 | `src/sesslint/cli/export.py:56-58` | UNKNOWN (`Error: Source file not found: {args.path}`) |
| `export`: `ExportRefused` | 1 | `src/sesslint/cli/export.py:69-71` | UNKNOWN (`Export refused [{err.code}]: {err}`) |
| `export`: `FileNotFoundError` | 2 | `src/sesslint/cli/export.py:72-74` | UNKNOWN (`File error: {err}`) |
| `export`: exception khác | 2 | `src/sesslint/cli/export.py:75-76`, `src/sesslint/cli/_common.py:52` | như hàng internal error |
| `export` thành công | 0 | `src/sesslint/cli/export.py:86` | không |
| `bundle`: path không tồn tại | 2 | `src/sesslint/cli/bundle.py:79-81` | UNKNOWN (`Error: Path not found: {target_bundle_path}`) |
| `bundle`: path là thư mục | 2 | `src/sesslint/cli/bundle.py:82-87` | UNKNOWN (câu `Error: Path is a directory...` có path) |
| `bundle`: `ValueError`/`KeyError` chứa `not permitted by profile` | 2 | `src/sesslint/cli/bundle.py:102-105` | UNKNOWN (`str(err)`) |
| `bundle`: `FileNotFoundError` | 2 | `src/sesslint/cli/bundle.py:107-109` | UNKNOWN (`Error: {err}`) |
| `bundle`: exception khác | 2 | `src/sesslint/cli/bundle.py:110-111`, `src/sesslint/cli/_common.py:52` | như hàng internal error |
| `bundle`: `share_advisory` khác `None` và `--strict-share` | 1 | `src/sesslint/cli/bundle.py:117-127` | không phải `ctx.error`; `ctx.warn` có count và tên family, UNKNOWN với payload |
| `bundle`: ghi file output ném exception | 2 | `src/sesslint/cli/bundle.py:140-142` | UNKNOWN (`Error writing bundle to {out_path}: {err}`) |
| `bundle`: ghi file xong, hoặc không có `--output` và đã in JSON | 0 | `src/sesslint/cli/bundle.py:148`, `src/sesslint/cli/bundle.py:152` | không lỗi |
| `stats`: `--agent` kèm path | 2 | `src/sesslint/cli/stats.py:75-78` | `Error: --agent cannot be combined with explicit paths.` |
| `stats`: `--agent` mà không có root tồn tại | 2 | `src/sesslint/cli/stats.py:80-83` | UNKNOWN (`Error: no existing session roots found for agent '{agent}'.`; agent là choice CLI) |
| `stats`: không path và không agent | 2 | `src/sesslint/cli/stats.py:85-87` | `Error: stats requires at least one path or --agent.` |
| `stats`: `ValueError` | 2 | `src/sesslint/cli/stats.py:95-97` | UNKNOWN (`Error: {err}`) |
| `stats`: report phát được. `stats.py` không có `return 1` | 0 | `src/sesslint/cli/stats.py:104` | không |
| `watch`: `--agent` kèm path | 2 | `src/sesslint/cli/watch.py:72-75` | `Error: --agent cannot be combined with explicit paths.` |
| `watch`: `--agent` mà không có root tồn tại | 2 | `src/sesslint/cli/watch.py:77-80` | UNKNOWN (cùng template agent như stats) |
| `watch`: không path và không agent | 2 | `src/sesslint/cli/watch.py:81-83` | `Error: watch requires at least one path or --agent.` |
| `watch`: một path không tồn tại | 2 | `src/sesslint/cli/watch.py:84-87` | UNKNOWN (`Error: Path not found: {wp}`) |
| `watch`: `OperationCancelled` bị bắt trong `run` | 0 | `src/sesslint/cli/watch.py:107-108` | không. Exception không tới `main`, nên không thành 130 |
| `watch`: `ValueError` | 2 | `src/sesslint/cli/watch.py:109-111` | UNKNOWN (`Error: {err}`) |
| `watch`: `KeyboardInterrupt` bị bắt trong `run` | 0 | `src/sesslint/cli/watch.py:112-113` | không. Help nói Ctrl+C exits cleanly (`src/sesslint/cli/watch.py:26`) và không ghi số. `progress.py:19-20` và `README.md:499` viết 130; hàm này trả 0 |
| `watch`: `watch()` trả bình thường | 0 | `src/sesslint/cli/watch.py:114` | không |
| `seal`: `SealError` | 2 | `src/sesslint/cli/seal.py:50-54` | UNKNOWN (`Error: {err}`) |
| `seal`: `divergence is None` | 0 | `src/sesslint/cli/seal.py:73` | không |
| `seal`: có divergence | 1 | `src/sesslint/cli/seal.py:68-73` | UNKNOWN (`divergence at line {line}: {kind} — {detail}`) |
| `version` | 0 | `src/sesslint/cli/version.py:49` | không |
| `completion`: `ValueError` | 2 | `src/sesslint/cli/completion.py:35-37` | UNKNOWN (`Error: {err}`) |
| `completion`: in script xong | 0 | `src/sesslint/cli/completion.py:38` | không |
| `mcp`: `run` trả nguyên `serve`. EOF của stdin | 0 | `src/sesslint/cli/mcp.py:30-33`, `src/sesslint/mcp_server.py:344-349` | không |
| `mcp`: `KeyboardInterrupt` không bị `serve` bắt, nên tới `main` | 130 | `src/sesslint/mcp_server.py:344-365`, `src/sesslint/cli/__init__.py:207-210` | `Operation cancelled by user`. Help nói Ctrl+C exits cleanly và không ghi số (`src/sesslint/cli/mcp.py:25`) |
| `outcome`: `ContractError` | 2 | `src/sesslint/cli/outcome.py:133-137` | dòng `Error: invalid outcome contract:` là literal; mỗi dòng `  - {problem}` UNKNOWN |
| `outcome`: `OSError` khi đọc contract | 2 | `src/sesslint/cli/outcome.py:138-140` | `Error: outcome contract could not be read.` |
| `outcome --explain` kèm `--source` hoặc `--target` | 2 | `src/sesslint/cli/outcome.py:141-144` | `Error: --explain reads only the contract; drop --source/--target.` |
| `outcome --explain` không kèm hai cờ đó, sau khi in | 0 | `src/sesslint/cli/outcome.py:141-146` | không |
| `outcome` thiếu `--source` hoặc `--target` | 2 | `src/sesslint/cli/outcome.py:147-149` | `Error: outcome needs --source and --target snapshots (or --explain).` |
| `outcome`: `SnapshotError` | 2 | `src/sesslint/cli/outcome.py:163-165` | UNKNOWN (`Error: {role} snapshot: {err}`; role chỉ là `source` hoặc `target`) |
| `outcome`: `OSError` khi đọc snapshot | 2 | `src/sesslint/cli/outcome.py:166-168` | `Error: source snapshot could not be read.` hoặc `Error: target snapshot could not be read.` |
| `outcome`: không có `--as-of` và target không có `observed_at` | 2 | `src/sesslint/cli/outcome.py:170-173` | `Error: pass --as-of or --target-observed-at; the wall clock is never used.` |
| `outcome`: `EvaluationError` | 2 | `src/sesslint/cli/outcome.py:174-178`, `src/sesslint/outcome/engine.py:162-163` | UNKNOWN (`Error: {err}`) |
| `outcome`: `evaluation.outcome == "VERIFIED"` | 0 | `src/sesslint/cli/outcome.py:4-7`, `src/sesslint/cli/outcome.py:193`, `src/sesslint/outcome/report.py:82-95`, `src/sesslint/outcome/engine.py:27` | không |
| `outcome`: outcome khác `VERIFIED`. Docstring liệt kê `VIOLATED`, `PENDING`, `INCONCLUSIVE`, `NOT_APPLICABLE`, `NOT_EVALUATED`. Property trả 1 cho mọi giá trị không bằng `VERIFIED` | 1 | `src/sesslint/cli/outcome.py:4-7`, `src/sesslint/outcome/report.py:94-95`, `src/sesslint/outcome/engine.py:28-39` | không |
| `session_dimension` nuốt `OSError` và `ValueError`, không đặt exit. Exit của lệnh vẫn là property trên | không đổi | `src/sesslint/outcome/report.py:58-61`, `src/sesslint/cli/outcome.py:193` | không |
| Trường `PrecheckResult.exit_code`, không phải status tiến trình CLI. `FileNotFoundError`, `PermissionError`, `IsADirectoryError`, `OSError` | 2 | `src/sesslint/precheck.py:35-36`, `src/sesslint/precheck.py:105-111` | API không in stderr |
| Precheck: `ValueError`, `KeyError`, `TypeError`, `AttributeError` | 2 | `src/sesslint/precheck.py:112-118` | API không in stderr |
| Precheck: limitation bắt đầu bằng `Unsupported:` hoặc `Skipped:`, hoặc finding `SL301`/`SL302` | 1 | `src/sesslint/precheck.py:120-129` | API không in stderr |
| Precheck: count `error` hoặc `fatal` `> 0` | 1 | `src/sesslint/precheck.py:131-142` | API không in stderr |
| Precheck: có warning, không rơi các nhánh trên | 0 | `src/sesslint/precheck.py:144-152` | API không in stderr |
| Precheck: không warning | 0 | `src/sesslint/precheck.py:154-160` | API không in stderr |
| MCP `sesslint_precheck` chép `res.exit_code` vào JSON. `serve` vẫn chỉ trả 0 khi EOF | trường 0, 1, hoặc 2; tiến trình 0 khi EOF | `src/sesslint/mcp_server.py:230-243`, `src/sesslint/mcp_server.py:349` | không phải stderr tiến trình |

# progress

Bản đồ NDJSON `--progress-json` và hủy (CancellationToken / exit 130). Nguồn là worktree `D:\FOR_WORK\WORK_PROJECT\sesslint`, HEAD `02694d537104659df66cdd084354739f3cccc440`, nhánh `feat/outcome-guard`. Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` tồn tại và là tổ tiên của HEAD. Worktree không bị đổi nhánh.

`git diff e91d50b2ecea57ef4dd900e3b0b87b14946e847e HEAD` trên `progress.py`, `cli/_progress.py`, `cli/_context.py`, `cli/_options.py`, `cli/__init__.py`, `cli/check.py`, `cli/repair.py`, `cli/_scan_args.py`, `cli/_json_errors.py`, `cli/watch.py`, `api.py`, `scan.py`, `batch.py`, `watch.py`, `repair/executor.py`, `tests/cli/test_progress_json.py`, `tests/test_progress.py`, `tests/test_cancel.py` trống. Dòng trích dưới đây là dòng của HEAD, trùng pin.

## Cờ CLI và kênh

- B01. `--progress-json` là `store_true` trên subparser `check` (alias `scan`) và `repair` (`src/sesslint/cli/_options.py:265-271`, gắn tại `src/sesslint/cli/check.py:129` và `src/sesslint/cli/repair.py:96`). Help: NDJSON trên stderr, stdout là kênh kết quả. `scan` là alias của `check` (`src/sesslint/cli/check.py:45-46`, `src/sesslint/cli/_registry.py:69`).
- B02. Cùng hàm thêm `--no-progress` `store_true` (`src/sesslint/cli/_options.py:272-276`). Hai cờ không nằm trong `mutually_exclusive_group`.
- B03. Các lệnh khác trong `COMMANDS` không gọi `add_progress_json_option` (`src/sesslint/cli/_registry.py:68-80`). `getattr(args, "progress_json", False)` khi cờ vắng là `False` (`src/sesslint/cli/_context.py:69`).
- B04. `progress_json` / `no_progress` không có trong `_SETTING_SPECS` (`src/sesslint/cli/_context.py:86-106`). Env/config không gán hai cờ này.
- B05. `CliContext.progress_callback` chọn callback theo thứ tự: `--progress-json` → `ndjson_progress_cb(self.stderr)`; không thì `--quiet` hoặc `--no-progress` → `None`; không thì stderr `isatty()` → `TtyProgress`; không thì `None` (`src/sesslint/cli/_context.py:66-79`). `--progress-json` thắng `--quiet` và `--no-progress`.
- B06. `check.run` và `repair.run` lấy callback một lần rồi truyền xuống API (`src/sesslint/cli/check.py:250-261`, `src/sesslint/cli/repair.py:172`, `src/sesslint/cli/_scan_args.py:43`). `build_scan_kwargs` không có khoá `cancel_token`.
- B07. NDJSON ghi bằng `print(json.dumps(...), file=out, flush=True)` (`src/sesslint/cli/_progress.py:17-28`). `out` mặc định `sys.stderr`; CLI truyền `ctx.stderr` (`src/sesslint/cli/_context.py:72`). Docstring: stdout là kênh kết quả, mọi byte tiến độ ra stderr, chỉ counter — không content, không full path (`src/sesslint/cli/_progress.py:1-4`).
- B08. `build_context` gán `stderr=sys.stderr` (`src/sesslint/cli/_context.py:315-321`). `main` bọc stderr bằng `TrackedStream` trước `_dispatch` (`src/sesslint/cli/__init__.py:185-202`). `TrackedStream.write` chuyển tiếp toàn bộ chuỗi sang `raw`; giới hạn 8192 chỉ cắt bản sao diagnostic, không cắt byte ra stderr (`src/sesslint/cli/_json_errors.py:13-32`, `src/sesslint/cli/__init__.py:185`).
- B09. `print` không truyền `end`, nên dùng `end` mặc định `"\n"` (`src/sesslint/cli/_progress.py:26`). `flush=True` từng dòng. Test CLI đọc stderr theo `splitlines` rồi `json.loads` từng dòng (`tests/cli/test_progress_json.py:21-24`).
- B10. `TtyProgress` không phải NDJSON: `\r` một dòng, throttle 0.1s, không in `item`, `finish()` xoá dòng (`src/sesslint/cli/_progress.py:31-66`). `ndjson_progress_cb` không có `finish`. `check`/`repair` gọi `finish` trong `finally` nếu có (`src/sesslint/cli/check.py:263-266`, `src/sesslint/cli/repair.py:626-629`).
- B11. Không `--progress-json`, stderr capsys (không TTY) rỗng (`tests/cli/test_progress_json.py:36-43`). Có cờ: report JSON vẫn trên stdout (`tests/cli/test_progress_json.py:31-33`, `tests/cli/test_progress_json.py:55-57`).
- B12. `main` `reconfigure(encoding="utf-8")` stdout/stderr `TextIOWrapper` và không truyền `newline` (`src/sesslint/cli/__init__.py:178-180`).

## Schema sự kiện

- B13. `ProgressEvent` là `@dataclass(frozen=True)` với `phase: str`, `completed: int`, `total: int | None = None`, `item: str | None = None` (`src/sesslint/progress.py:31-49`). Test gán thuộc tính sau khi tạo bị `AttributeError` (`tests/test_progress.py:38-41`).
- B14. `to_dict` luôn chèn `phase` rồi `completed`; thêm `total` khi `total is not None`; thêm `item` khi `item is not None` (`src/sesslint/progress.py:51-58`). `None` bị bỏ, không thành JSON `null`. Test: đủ bốn khoá, và `{completed, phase}` khi thiếu total/item (`tests/test_progress.py:29-35`).
- B15. NDJSON gọi `json.dumps(event.to_dict(), sort_keys=True)` không `indent`, không `ensure_ascii`, không `separators`, không `allow_nan` (`src/sesslint/cli/_progress.py:26`). Thứ tự khoá trên dây sau `sort_keys`: `completed`, rồi `item` nếu có, rồi `phase`, rồi `total` nếu có.
- B16. Không có `$id`, `$schema`, `schema_version` trên sự kiện. Chỉ các khoá B14. Test CLI cấm `"/" ` và `"\\"` trong `item` khi có (`tests/cli/test_progress_json.py:60-70`). Test API: mọi value `to_dict` là `str` hoặc `int` (`tests/test_progress.py:170-175`).
- B17. Hợp đồng thư viện: event chỉ counter và toạ độ (phase, completed/total, basename hoặc step id), không record content; emission không đổi output bytes hay thứ tự finding (`src/sesslint/progress.py:9-15`). Test dump report/scan/repair giống nhau với và không callback (`tests/test_progress.py:152-167`).
- B18. `emit` / `emit_progress` no-op khi callback `None` (`src/sesslint/progress.py:97-104`, alias `src/sesslint/api.py:50`).

## Thứ tự sự kiện `check` một file / stdin

- B19. Đường hạnh phúc `_check_impl` lần lượt: `check:detect` completed=1, `check:load` completed=2, `check:analyze` completed=3, `check:report` completed=4; mọi event `total=4` (`src/sesslint/api.py:352-355`, `src/sesslint/api.py:443-446`, `src/sesslint/api.py:481-484`, `src/sesslint/api.py:504-507`). Test API và CLI cùng thứ tự phase (`tests/test_progress.py:44-54`, `tests/cli/test_progress_json.py:25-30`). Test API: `completed` `[1,2,3,4]` (`tests/test_progress.py:53-54`).
- B20. `item` một file là `target_path.name`; stdin/`check_bytes` là `virtual_path` (mặc định `"<stdin>"`) (`src/sesslint/api.py:212-213`, `src/sesslint/api.py:140`, `src/sesslint/cli/check.py:415-422`). Test: `item` không chứa `os.sep` hay `"/"` (`tests/test_progress.py:57-63`).
- B21. Lỗi encoding/NUL trước detect: chỉ emit `check:report` completed=4 rồi return, không detect/load/analyze (`src/sesslint/api.py:317-321`).
- B22. Detect xong `format is None`: đã emit `check:detect`, rồi emit `check:report` completed=4 và return, không load/analyze (`src/sesslint/api.py:352-380`). Test: event đầu `check:detect`, event cuối `check:report` completed=4 (`tests/test_progress.py:66-71`).
- B23. File quá `max_file_bytes`: `return build_report(...)` không `emit` (`src/sesslint/api.py:250-267`).
- B24. `FileNotFoundError` trước mọi emit (`src/sesslint/api.py:216-217`).
- B25. `check_token` sau emit detect, sau emit load, sau emit analyze; không có `check_token` trước detect, không có sau emit report (`src/sesslint/api.py:356`, `src/sesslint/api.py:447`, `src/sesslint/api.py:485`). Token đã `cancel()` trước `check_file` vẫn chạy detect rồi raise ở check sau detect (`src/sesslint/api.py:352-356`, `tests/test_progress.py:88-92`).
- B26. CLI một file và stdin truyền `progress_cb`, không truyền `cancel_token` (`src/sesslint/cli/check.py:415-428`, `src/sesslint/cli/check.py:533-545`).

## Thứ tự sự kiện `scan` / thư mục / nhiều path

- B27. Thư mục: mỗi file được inspect emit một `ProgressEvent(phase="scan")`; `total` là `None` vì không pre-walk (`src/sesslint/scan.py:841-843`, emit `src/sesslint/scan.py:1337-1345` cache-hit, `src/sesslint/scan.py:1378-1386` tuần tự, `src/sesslint/scan.py:1449-1457` jobs>1). `completed` là `scanned_count` tăng sau mỗi file inspect. Test CLI/API: mọi phase `"scan"`, `completed` = `1..N`, API `total is None` (`tests/cli/test_progress_json.py:46-54`, `tests/test_progress.py:74-79`).
- B28. File bị skip/special không emit (docstring `src/sesslint/scan.py:841-843`). Nhánh skip (hardlink, cap, exclude, newest, since, file-too-large, builtin names) `continue` trước `emit`. Root FIFO/socket/device return `ScanReport` trước `check_token` và trước `emit` (`src/sesslint/scan.py:991-1005`).
- B29. `scan_path` một file (không phải dir): một event `phase="scan", completed=1, total=1, item=target.name` sau inspect (`src/sesslint/scan.py:1039-1042`).
- B30. `scan_bytes`: `check_token` rồi inspect rồi emit `phase="scan", completed=1, total=1, item=virtual_path` (`src/sesslint/scan.py:2140-2172`). CLI stdin dùng `check_bytes` (phase `check:*`), không gọi `scan_bytes` (`src/sesslint/cli/check.py:409-422`; `scan_bytes` không có call site trong `src` ngoài định nghĩa).
- B31. CLI thư mục: `check_dir(..., **scan_kwargs)` có `progress_cb`, không `cancel_token` (`src/sesslint/cli/check.py:508-511`, `src/sesslint/cli/_scan_args.py:29-52`). Nhiều path: mỗi path một `scan_path` độc lập rồi gộp (`src/sesslint/cli/check.py:475-477`) — `completed` reset theo từng `scan_path`. `--agent`: mỗi root một `check_dir` (`src/sesslint/cli/check.py:372-377`) — `completed` cũng reset theo root.
- B32. `jobs>1`: emit lúc merge `pool.map`, thứ tự submission `pending_files`, không phải thứ tự sort report (`src/sesslint/scan.py:1388-1457`, sort sau `src/sesslint/scan.py:1464-1465`). `worker_cfg` không có `cancel_token` hay `progress_cb` (`src/sesslint/scan.py:1396-1407`). `check_token` mỗi kết quả worker (`src/sesslint/scan.py:1424`). `finally`: `pool.shutdown(wait=False, cancel_futures=True)` (`src/sesslint/scan.py:1458-1459`).
- B33. `check_token` lúc root file (`src/sesslint/scan.py:1007`), mỗi directory entry (`src/sesslint/scan.py:1113`), mỗi candidate trước inspect (`src/sesslint/scan.py:1292`). Hủy giữa `_scan_single_file` không có check trong hàm đó. Test hủy mid-scan: callback `cancel()` trên event đầu, event đó đã emit rồi raise (`tests/test_progress.py:95-102`).

## Thứ tự sự kiện `repair` / batch

- B34. `api.repair`: `repair:load` completed=1, `repair:plan` completed=2, rồi (trong `execute`) `repair:step` mỗi bước, rồi `repair:execute` completed=3, `repair:done` completed=4; stage `total=4`, `item=src.name` (`src/sesslint/api.py:758-761`, `src/sesslint/api.py:805-808`, `src/sesslint/api.py:828-835` dry-run, `src/sesslint/api.py:857-864` thật). Test: đầu `repair:load`, cuối `repair:done`, có `repair:plan` và `repair:execute` (`tests/test_progress.py:105-113`).
- B35. `execute` mỗi recipe: `check_token` rồi `apply` rồi emit `phase="repair:step", completed=step_idx+1, total=len(sorted_steps), item=step.recipe` (`src/sesslint/repair/executor.py:655-718`). Test: số event step = `len(plan.steps)`, `total` = số step (`tests/test_progress.py:114-116`).
- B36. `check_token` đầu `repair` trước load (`src/sesslint/api.py:736`), sau load (`src/sesslint/api.py:762`), sau plan (`src/sesslint/api.py:809`). Token đã cancel trước `repair` raise trước event load. `execute` `check_token` trước publish, trước mọi ghi (`src/sesslint/repair/executor.py:960-962`).
- B37. Dry-run vẫn emit `repair:execute` và `repair:done` sau `execute(..., dry_run=True)` (`src/sesslint/api.py:812-836`). Plan 0 bước: vòng step không emit `repair:step`.
- B38. `apply_plan` gọi lại `repair(..., plan=plan_obj, progress_cb=..., cancel_token=...)` (`src/sesslint/api.py:1013-1025`). CLI `apply_plan`/`repair` truyền `progress_cb`, không `cancel_token` (`src/sesslint/cli/repair.py:482-513`).
- B39. `repair_many`: mỗi file, `check_token` rồi emit `repair:batch` với `completed=idx` (0-based), `total=len(files)`, `item=src.name`; sau vòng emit `completed=total, item=None` (`src/sesslint/batch.py:249-255`, `src/sesslint/batch.py:374-377`). File eligible gọi `api.apply_plan(..., progress_cb=progress_cb, cancel_token=cancel_token)` (`src/sesslint/batch.py:311-319`) — NDJSON xen `repair:batch` với `repair:load`/`plan`/`step`/`execute`/`done`. CLI batch truyền `progress_cb`, không `cancel_token` (`src/sesslint/cli/repair.py:298-309`).

## CancellationToken

- B40. `CancellationToken` dùng `threading.Event`; `cancel()` `set()`; `is_cancelled` là `is_set()`; `throw_if_cancelled` raise `OperationCancelled("operation cancelled")` khi set (`src/sesslint/progress.py:69-91`). Docstring: `cancel()` từ thread khác (`src/sesslint/progress.py:72-73`).
- B41. `check_token(None)` no-op; token không None thì `throw_if_cancelled` (`src/sesslint/progress.py:107-110`).
- B42. `OperationCancelled` subclass `Exception` (không phải `BaseException`/`KeyboardInterrupt`) (`src/sesslint/progress.py:61-66`).
- B43. `src/` không có lời gọi `CancellationToken(` — CLI và runtime không tạo token. `src/sesslint/cli/` không có chuỗi `cancel_token`. Check/repair CLI không truyền token xuống API (B26, B31, B38, B39).
- B44. `watch` thư viện nhận `cancel_token` và `throw_if_cancelled` đầu mỗi vòng poll (`src/sesslint/watch.py:140-176`). CLI `watch` không truyền token (`src/sesslint/cli/watch.py:100-106`).

## Exit 130 và thông điệp stderr

- B45. `main` bắt `KeyboardInterrupt`: `print("Operation cancelled by user", file=sys.stderr)` rồi `return 130` (`src/sesslint/cli/__init__.py:207-210`). Test human/json/repair patch `KeyboardInterrupt` → 130 và chuỗi đó trên stderr (`tests/test_cancel.py:25-33`, `tests/test_cancel.py:36-43`, `tests/test_cancel.py:61-66`).
- B46. `main` bắt `OperationCancelled`: `print("Operation cancelled", file=sys.stderr)` rồi `return 130` (`src/sesslint/cli/__init__.py:211-214`). Test inject `OperationCancelled` (và `KeyboardInterrupt`) bằng patch `_dispatch` → 130, stdout rỗng, stderr chứa `"cancelled"` (`tests/cli/test_ac03_lone_surrogate.py:492-499`). Chuỗi raise là `"operation cancelled"` (`src/sesslint/progress.py:91`); chuỗi CLI khác hoa/thường và không có `"by user"`.
- B47. `finally` của `main` chỉ in `error_document` khi `code not in (0, 130)` và JSON được yêu cầu và stdout trống (`src/sesslint/cli/__init__.py:230-233`). 130 không nhận envelope lỗi JSON. Test: 130 + stdout rỗng (`tests/cli/test_ac03_lone_surrogate.py:496-498`). Human interrupt: stdout rỗng (`tests/test_cancel.py:33`).
- B48. `KeyboardInterrupt` là `BaseException`, không bị `except Exception` trong `check`/`repair`. `OperationCancelled` là `Exception`. Nhánh CLI một file/stdin: `except Exception` → `_handle_internal_error` exit 2 (`src/sesslint/cli/check.py:437-438`, `src/sesslint/cli/check.py:582-583`, `src/sesslint/cli/_common.py:29-39`). Nhánh thư mục/nhiều path/`--agent`: `check_dir`/`scan_path` chỉ bắt `ValueError`/`KeyError` rồi `return` trước `try` của một file (`src/sesslint/cli/check.py:351-401`, `src/sesslint/cli/check.py:464-517`, `src/sesslint/cli/check.py:529`) — `OperationCancelled` từ các nhánh đó đi tới `main` B46. `repair.run` (kể cả batch) `except Exception` → `_handle_internal_error` (`src/sesslint/cli/repair.py:311-312`, `src/sesslint/cli/repair.py:624-625`). CLI không truyền token nên đường token không chạy trên CLI; Ctrl+C đi B45.
- B49. `watch.run` bắt `OperationCancelled` và `KeyboardInterrupt` rồi `return 0` (`src/sesslint/cli/watch.py:107-113`). Không phải 130. `watch` không có `--progress-json` (B03).
- B50. Không có `signal.signal` / SIGINT trong `src/sesslint` (grep `signal.` không có handler). Ctrl+C là `KeyboardInterrupt` của interpreter, không phải `token.cancel()`.
- B51. Docstring `progress`: cancel hợp tác, `OperationCancelled` đi cùng cleanup với `KeyboardInterrupt` (không output dở, source không đổi); CLI vẫn exit 130 qua interrupt handling sẵn có (`src/sesslint/progress.py:16-20`).
- B52. `execute` `except BaseException` lúc publish: gỡ manifest/output dở rồi `raise` (`src/sesslint/repair/executor.py:1056-1068`). `check_token` trước publish nên cancel bằng token trước ghi thì không vào nhánh ghi (`src/sesslint/repair/executor.py:960-962`). Test API: cancel tại `repair:step` hoặc `repair:plan` không để lại output, manifest, hay `.sesslint-tmp*` (`tests/test_progress.py:119-149`). Test CLI `KeyboardInterrupt` lúc `planner.plan`: không output/manifest/tmp (`tests/test_cancel.py:54-74`).
- B53. Help exit codes chỉ liệt kê 0/1/2 (`src/sesslint/cli/__init__.py:42-51`). 130 không có trong epilog.

## UNKNOWN

- U01. `json.dumps` không truyền `ensure_ascii` / `separators` / `allow_nan`. Nguồn sesslint không ghim escape Unicode (`\uXXXX` hay UTF-8 thô) hay khoảng trắng quanh `:` / `,`. UNKNOWN.
- U02. `reconfigure` không đặt `newline`. Byte `\n` của `print` trên console/pipe Windows có thành CRLF hay không: nguồn không ghim. UNKNOWN cho stderr OS. Test capsys đọc dòng logic, không ghim CRLF.
- U03. `json.dumps` có tự thêm newline hay không: nguồn không kiểm. UNKNOWN. B09 vẫn đúng là `print` không tắt `end`.
- U04. SIGINT giữa `print` một dòng NDJSON có để lại dòng JSON dở trên stderr hay không: nguồn không xử lý. UNKNOWN.
- U05. CLI có nhận `CancellationToken` từ ngoài (env, flag, fd) hay không: không có API CLI cho token. UNKNOWN cho tích hợp UI ngoài `api.*`.
- U06. Worker `jobs>1` đã chạy xong trong process con khi parent `check_token` raise: nguồn shutdown `cancel_futures=True` nhưng không mô tả file nào worker đã inspect. UNKNOWN cho tập file đã phân tích trong process con.
- U07. `scan_bytes(..., item=virtual_path)` khi caller truyền path có `/`: nguồn ghi nguyên `virtual_path` (`src/sesslint/scan.py:2171`). CLI không gọi hàm này. UNKNOWN cho caller API tùy ý vs luật basename của `check_file`.
- U08. `TtyProgress` dùng `time.monotonic` (`src/sesslint/cli/_progress.py:48`). Không thuộc dây `--progress-json`. Có TTY + không `--progress-json` có emit NDJSON không: B05 nói không. UNKNOWN cho byte TTY (ngoài card).

## Đếm

- Đã dẫn chứng: 53 (B01–B53).
- UNKNOWN: 8 (U01–U08).

# limits

Bản đồ `sesslint version --json` và mọi hằng giới hạn kích thước file / dòng / độ sâu trong `io`, `scan`, `adapters`. Nguồn: worktree `D:\FOR_WORK\WORK_PROJECT\sesslint`, HEAD `02694d537104659df66cdd084354739f3cccc440`, nhánh `feat/outcome-guard`. Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` là tổ tiên của HEAD (`git merge-base --is-ancestor` exit 0). `git diff` pin…HEAD trên `_version.py`, `cli/version.py`, `io.py`, `scan.py`, `adapters/` rỗng — dòng trích dưới đây đúng cả hai hash. Worktree không bị checkout/đổi nhánh.

Giá trị cột «giá trị» là vế phải đúng như nguồn viết. Không tính ra số thập phân nếu nguồn không viết số đó. UNKNOWN khi nguồn không nêu giá trị.

Giả thuyết (Prompt 5): `version --json` in đúng dict của `get_version_info()`; adapter không đặt trần file/dòng/độ sâu riêng mà dùng `ReaderLimits` từ `io.py`; `scan` thêm trần số file và tổng byte. Chứng minh: mỗi hàng có `file:dòng`; hàng không có số trong nguồn thì UNKNOWN.

## version --json

`sesslint version --json` gọi `get_version_info()` rồi `print(json.dumps(info, indent=2, sort_keys=True))` (`src/sesslint/cli/version.py:33-36`). Test ghim `json.loads(stdout) == get_version_info()` (`tests/cli/test_formats_version.py:62-77`). Không có file schema `version` trong `schemas/` (OSS-SCH-01); Python không gán `$id`/`$schema`/`schema_version` vào object này.

### Trường gốc

| id | hằng / khoá | giá trị | file:dòng |
|---|---|---|---|
| V01 | `cli` | `CLI_VERSION` → `__version__` = `"0.5.0"` | `src/sesslint/_version.py:7-8`, gán `src/sesslint/_version.py:30` |
| V02 | `schema_session` | `"sesslint.session/v1"` (`SESSION_SCHEMA_VERSION`) | `src/sesslint/_version.py:9`, gán `:31` |
| V03 | `schema_report` | `"sesslint.report/v1"` (`REPORT_SCHEMA_VERSION`) | `src/sesslint/_version.py:10`, gán `:32` |
| V04 | `schema_manifest` | `"sesslint.repair-manifest/v1"` (`MANIFEST_SCHEMA_VERSION`) | `src/sesslint/_version.py:11`, gán `:33` |
| V05 | `adapters` | `dict(ADAPTER_VERSIONS)` | `src/sesslint/_version.py:13-18`, gán `:34` |
| V06 | `profiles` | `dict(PROFILE_VERSIONS)` | `src/sesslint/_version.py:20-24`, gán `:35` |

Sáu khoá trên là toàn bộ object (`src/sesslint/_version.py:29-36`). Test khói bắt đủ sáu khoá (`tests/test_smoke_release.py:31-36`).

### Khoá lồng `adapters` / `profiles`

| id | hằng / khoá | giá trị | file:dòng |
|---|---|---|---|
| V07 | `adapters["canonical"]` | `"1.0.0"` | `src/sesslint/_version.py:14` |
| V08 | `adapters["claude-code-jsonl"]` | `"1.0.0"` | `src/sesslint/_version.py:15` |
| V09 | `adapters["codex-rollout"]` | `"1.0.0"` | `src/sesslint/_version.py:16` |
| V10 | `adapters["openai-agents"]` | `"1.0.0"` | `src/sesslint/_version.py:17` |
| V11 | `profiles["neutral"]` | `"1.0.0"` | `src/sesslint/_version.py:21` |
| V12 | `profiles["claude-strict"]` | `"1.0.0"` | `src/sesslint/_version.py:22` |
| V13 | `profiles["openai-strict"]` | `"1.0.0"` | `src/sesslint/_version.py:23` |

Bốn adapter và ba profile là toàn bộ hai dict. Human mode in cùng các khoá, sort `items()` (`src/sesslint/cli/version.py:38-48`). Test khói bắt `canonical`, `claude-code-jsonl`, `openai-agents` và ba profile; không assert `codex-rollout` (`tests/test_smoke_release.py:38-46`) — nguồn vẫn có khoá đó (V09).

### In JSON

| id | hằng / hành vi | giá trị | file:dòng |
|---|---|---|---|
| V14 | `json.dumps` kwargs | `indent=2`, `sort_keys=True` | `src/sesslint/cli/version.py:36` |
| V15 | `ensure_ascii` / `allow_nan` / `separators` / `cls` | không truyền | `src/sesslint/cli/version.py:36` |
| V16 | kênh | `print(...)` stdout; không ghi stderr trên đường thành công | `src/sesslint/cli/version.py:36`; test `tests/cli/test_streams.py:37-44` |
| V17 | thứ tự khoá gốc sau `sort_keys` | nguồn không liệt kê thứ tự; `sort_keys=True` trên đúng sáu chuỗi V01–V06 | `src/sesslint/cli/version.py:36` |

### Trường không có trong object

Nguồn không chèn `schema_scan`, `schema_version`, `$id`, `$schema`, `tool_version`, phiên bản `sesslint.scan-report/v1`, hay bất kỳ hằng giới hạn I/O (`src/sesslint/_version.py:29-36`). `SCAN_REPORT` schema sống ở module scan, không đi vào `version --json` (`src/sesslint/scan.py:287` — ngoài object version).

## Kích thước file / dòng / độ sâu

### io — hằng đặt tên

| id | hằng | giá trị | file:dòng |
|---|---|---|---|
| L01 | `DEFAULT_MAX_LINE_BYTES` | `8 * 1024 * 1024` | `src/sesslint/io.py:45` |
| L02 | `DEFAULT_MAX_DEPTH` | `100` | `src/sesslint/io.py:46` |
| L03 | `DEFAULT_MAX_FILE_BYTES` | `100 * 1024 * 1024` | `src/sesslint/io.py:47` |
| L04 | `ReaderLimits.max_line_bytes` (mặc định) | `DEFAULT_MAX_LINE_BYTES` | `src/sesslint/io.py:63` |
| L05 | `ReaderLimits.max_depth` (mặc định) | `DEFAULT_MAX_DEPTH` | `src/sesslint/io.py:64` |
| L06 | `ReaderLimits.max_file_bytes` (mặc định) | `DEFAULT_MAX_FILE_BYTES` | `src/sesslint/io.py:65` |
| L07 | `ReaderLimits.max_records` (mặc định) | `None` | `src/sesslint/io.py:66` |
| L08 | `DEFAULT_READER_LIMITS` | `ReaderLimits()` → L04–L07 | `src/sesslint/io.py:102` |

Comment trên L01: «8 MiB per-line bound» và «100 MB whole-file cap» (`src/sesslint/io.py:41-44`). Comment cùng dòng L03: `# 100 MB` (`src/sesslint/io.py:47`). Nguồn không viết số thập phân của `8 * 1024 * 1024`.

`check_nesting_depth`: container gốc bắt đầu `depth = 1`; vượt khi `depth > max_depth` (`src/sesslint/io.py:366-386`). Đọc dòng: `readline(max_line_bytes + 1)` rồi `len(chunk) > max_line_bytes` (`src/sesslint/io.py:1122`, `:1137`, `:1287`, `:1301`). Đọc file: `file_size > max_file_bytes` hoặc `total_bytes_read > max_file_bytes` (`src/sesslint/io.py:1102`, `:1127`, `:1261`, `:1293`).

### scan — hằng đặt tên + tham số kích thước

| id | hằng | giá trị | file:dòng |
|---|---|---|---|
| L09 | `DEFAULT_MAX_FILES` | `10000` | `src/sesslint/scan.py:59` |
| L10 | `DEFAULT_MAX_BYTES` | `1024 * 1024 * 1024` | `src/sesslint/scan.py:60` |
| L11 | `scan_path.max_files` (mặc định) | `DEFAULT_MAX_FILES` | `src/sesslint/scan.py:815` |
| L12 | `scan_path.max_bytes` (mặc định) | `DEFAULT_MAX_BYTES` | `src/sesslint/scan.py:816` |
| L13 | `scan_path.max_file_bytes` (mặc định) | `DEFAULT_MAX_FILE_BYTES` (từ `io`) | `src/sesslint/scan.py:32`, `:832` |
| L14 | `_scan_single_source.max_file_bytes` (mặc định) | `DEFAULT_MAX_FILE_BYTES` | `src/sesslint/scan.py:423`, `:449` |
| L15 | `scan_bytes.max_file_bytes` (mặc định) | `DEFAULT_MAX_FILE_BYTES` | `src/sesslint/scan.py:2105` |
| L16 | `scan_bytes.max_input_bytes` (mặc định) | `None` | `src/sesslint/scan.py:2104` |
| L17 | `_walk_rollout_files.max_files` (mặc định) | `200_000` | `src/sesslint/scan.py:1521` |

Comment L10: `# 1GB` (`src/sesslint/scan.py:60`). `scan` không định nghĩa `DEFAULT_MAX_LINE_BYTES` / `DEFAULT_MAX_DEPTH`; khi dựng `ReaderLimits` chỉ ghi `max_file_bytes` (`src/sesslint/scan.py:606`) nên dòng/độ sâu giữ L01/L02.

Áp trần walk: `file_size > max_file_bytes` → `skipped_reason="file-too-large"` (`src/sesslint/scan.py:1304-1307`); `scanned_count + len(pending_files) >= max_files` → `"max-files-cap-exceeded"` (`:1311-1318`); `cumulative_bytes + file_size > max_bytes` → `"max-bytes-cap-exceeded"` (`:1322-1329`). `_walk_rollout_files`: `seen > max_files` thì `return None` (fail-closed, không đoán) (`src/sesslint/scan.py:1541-1543`). `max_input_bytes is not None` thì `max_file_bytes = min(max_file_bytes, max_input_bytes)` (`src/sesslint/scan.py:2119-2120`).

### adapters — không có trần file/dòng/độ sâu riêng

Không có `DEFAULT_MAX_LINE_BYTES` / `DEFAULT_MAX_DEPTH` / `DEFAULT_MAX_FILE_BYTES` trong `src/sesslint/adapters/`. Mọi loader dùng `DEFAULT_READER_LIMITS` hoặc `ReaderLimits` từ `io`.

| id | hằng / chỗ dùng | giá trị | file:dòng |
|---|---|---|---|
| L18 | `claude_code` `effective_limits` | `limits if limits is not None else DEFAULT_READER_LIMITS` | `src/sesslint/adapters/claude_code.py:423` |
| L19 | `codex_rollout` `effective_limits` | như L18 | `src/sesslint/adapters/codex_rollout.py:1326` |
| L20 | `openai_agents` `effective_limits` | như L18 | `src/sesslint/adapters/openai_agents.py:543` |
| L21 | `canonical` `effective_limits` | như L18 | `src/sesslint/adapters/canonical.py:975` |
| L22 | `load.read_source_snapshot` | so `DEFAULT_MAX_FILE_BYTES`; đọc `DEFAULT_MAX_FILE_BYTES + 1` | `src/sesslint/adapters/load.py:73-79` |
| L23 | `load.snapshot_input` | fallback path nếu `len(data) > DEFAULT_MAX_FILE_BYTES` | `src/sesslint/adapters/load.py:87-88` |
| L24 | `SNIFF_BYTES` | `65536` | `src/sesslint/adapters/detect.py:34` |

Docstring `detect_format` gọi `SNIFF_BYTES` là «64KB» (`src/sesslint/adapters/detect.py:135`). Đọc sniff: `stream.read(SNIFF_BYTES)` (`:159`); bytes: `data[:SNIFF_BYTES]` (`:184`).

Áp L01–L03 trong adapter (giá trị lấy từ `limits.*`, không hằng mới): file `claude_code.py:442-445`, `codex_rollout.py:1346-1355`, `openai_agents.py:564-573`, `canonical.py:996-1005` / `:1033-1044`; dòng `claude_code.py:479-492`, `codex_rollout.py:1436-1444`, `openai_agents.py:943-951`; độ sâu `claude_code.py:788`, `codex_rollout.py:1276`, `openai_agents.py:755` / `:1171`, `canonical.py:1139` / `:1462`. Canonical JSONL: payload đi `check_nesting_depth(..., max_depth - 1)` khi shape common (`src/sesslint/adapters/canonical.py:1714-1717`).

## Hằng I/O khác trong io / scan / adapters

Không phải kích thước-file / dòng / độ sâu. Ghi để khỏi sót; không đếm vào tiêu chí «mọi hằng kích thước/dòng/độ sâu».

| id | hằng | giá trị | loại | file:dòng |
|---|---|---|---|---|
| C01 | `_MAX_DUP_KEYS_PER_RECORD` | `16` | số khoá trùng / record | `src/sesslint/io.py:424` |
| C02 | `_CHUNK_DRAIN_SIZE` | `65536` | chunk drain dòng quá dài | `src/sesslint/io.py:49`; dùng `:1306` |
| C03 | `_PROBE_CHUNK_BYTES` | `1024 * 1024` | chunk probe encoding; comment `# 1 MiB` | `src/sesslint/io.py:104` |
| C04 | `_MMAP_MIN_BYTES` | `4 * 1024 * 1024` | cổng mmap; comment `# 4 MiB` | `src/sesslint/io.py:171` |
| C05 | `_MMAP_MIN_LINE_BYTES` | `65536` | cổng mmap; comment `# 64 KiB avg line` | `src/sesslint/io.py:172` |
| C06 | `_MMAP_SNIFF_BYTES` | `65536` | mẫu đầu mmap; comment `# head sample` | `src/sesslint/io.py:173` |
| C07 | `_RECORD_ID_REGEX` bound | `{1,200}` | độ dài capture `id` | `src/sesslint/io.py:48` |
| C08 | cắt `record_id` | `200` | `len(candidate) > 200` → `[:200]` | `src/sesslint/io.py:400-401`, `:413-414` |
| C09 | `FileResult.max_findings_per_code` | `20` | số finding / mã | `src/sesslint/scan.py:113` |
| C10 | `scan_path.max_findings_per_code` | `20` | như C09 | `src/sesslint/scan.py:836` |
| C11 | `scan_bytes.max_findings_per_code` | `20` | như C09 | `src/sesslint/scan.py:2107` |
| C12 | `summarize_scan.top` | `10` | số hàng worst-file | `src/sesslint/scan.py:351` |
| C13 | `MAX_PROJECTED_RUN_STATE_KEYS` | `32` | số khoá projection | `src/sesslint/adapters/openai_agents.py:148` |
| C14 | `MAX_PROJECTED_CHECKPOINTS` | `8` | số checkpoint projection | `src/sesslint/adapters/openai_agents.py:149` |
| C15 | `MAX_CROSS_LINKS` | `16` | số link / file | `src/sesslint/adapters/links.py:16` |
| C16 | `MAX_DRIFT_TRANSITIONS` | `8` | số chuyển drift / file | `src/sesslint/adapters/drift.py:39` |
| C17 | `GUARDIAN_SNAPSHOT_ITEM_CAP` | `512` | số item snapshot | `src/sesslint/adapters/codex_rollout.py:170` |
| C18 | `_GUARDIAN_ID_MAX` | `256` | độ dài id guardian | `src/sesslint/adapters/codex_rollout.py:171` |
| C19 | `max_event_findings` (local) | `1000` | số finding canonical | `src/sesslint/adapters/canonical.py:1020` |
| C20 | `CONFIDENCE_MIN` | `0.55` | ngưỡng detect | `src/sesslint/adapters/detect.py:32` |
| C21 | `MARGIN_MIN` | `0.15` | ngưỡng detect | `src/sesslint/adapters/detect.py:33` |
| C22 | `EPSILON` | `1e-9` | hòa detect | `src/sesslint/adapters/detect.py:35` |

### Literal không đặt tên (cùng module)

| id | chỗ | giá trị | file:dòng |
|---|---|---|---|
| N01 | `detect_canonical` decode head | `data[:65536]` | `src/sesslint/adapters/canonical.py:233` |
| N02 | `detect_openai_agents` decode head | `data[:4096]` | `src/sesslint/adapters/openai_agents.py:368` |
| N03 | `detect_codex_rollout` decode head | `data[:4096]` | `src/sesslint/adapters/codex_rollout.py:343` |
| N04 | `links` độ dài `target` | `512` (`len(target) > 512`) | `src/sesslint/adapters/links.py:94` |
| N05 | `UnknownMetadataTracker` | `32` (`len(self._groups) >= 32`); docstring «at most 32» | `src/sesslint/adapters/metadata.py:77`, `:84` |
| N06 | `canonical` timestamp mẫu | `256` (`len(validated_timestamps) < 256`) | `src/sesslint/adapters/canonical.py:503` |
| N07 | `codex` `gh_type` | `64` (`len(gh_type) <= 64`) | `src/sesslint/adapters/codex_rollout.py:905` |

`detect_claude_code` không cắt `[:N]` thêm; nó nhận `head_bytes` đã giới hạn `SNIFF_BYTES` (L24). N01 trùng số với L24 nhưng là literal riêng, không tham chiếu `SNIFF_BYTES`.

Không có hằng tên `MAX_LINES` / `DEFAULT_MAX_LINES` / `max_line_count` trong `io.py`, `scan.py`, hay `adapters/*.py`. Trần «dòng» là byte/dòng (L01), không phải số dòng.

## Ngoài io / scan / adapters (không thuộc card; không sửa)

| id | hằng | giá trị | file:dòng |
|---|---|---|---|
| O01 | `canonical.MAX_NON_STREAMING_BYTES` | `100 * 1024 * 1024` | `src/sesslint/canonical.py:24` |
| O02 | `canonical.MAX_PAYLOAD_DEPTH` | `100` | `src/sesslint/canonical.py:25` |
| O03 | `_SETTING_SPECS` `max_files` | `10000` | `src/sesslint/cli/_context.py:101` |
| O04 | `_SETTING_SPECS` `max_bytes` | `1024 * 1024 * 1024` | `src/sesslint/cli/_context.py:102` |
| O05 | `_SETTING_SPECS` `max_file_bytes` | `100 * 1024 * 1024` | `src/sesslint/cli/_context.py:103` |
| O06 | `_SETTING_SPECS` `max_findings_per_code` | `20` | `src/sesslint/cli/_context.py:104` |
| O07 | `build_scan_kwargs` fallback `max_files` | `10000` | `src/sesslint/cli/_scan_args.py:32` |
| O08 | `build_scan_kwargs` fallback `max_bytes` | `1024 * 1024 * 1024` | `src/sesslint/cli/_scan_args.py:33` |
| O09 | CLI `--max-files` help | chuỗi `"default: 10000"`; argparse `default=None` | `src/sesslint/cli/check.py:103-107` |
| O10 | CLI `--max-bytes` help | chuỗi `"default: 1GB"`; argparse `default=None` | `src/sesslint/cli/check.py:109-113` |
| O11 | CLI `--max-file-bytes` help | chuỗi `"default: 104857600"`; argparse `default=None` | `src/sesslint/cli/_options.py:247-250` |

O01/O02 cùng biểu thức với L03/L02 nhưng là hằng khác module. O03–O08 lặp số của L09/L10/L03/C09 bằng literal, không import hằng `scan`/`io`. O11 là chỗ duy nhất nguồn viết số thập phân `104857600` (help CLI, không phải `io.py`).

`doctor` dump `ReaderLimits()` thành `max_line_bytes` / `max_depth` / `max_file_bytes` / `max_records` (`src/sesslint/doctor.py:403-408`) — đó là `doctor --json`, không phải `version --json`.

## UNKNOWN

| id | câu hỏi | lý do |
|---|---|---|
| U01 | `json.dumps` có tự thêm newline cuối không | `version.py:36` không nối `"\n"`; `print` thêm newline theo mặc định CPython. Nguồn không ghim byte stdout. |
| U02 | dạng escape Unicode / `ensure_ascii` | V15: không truyền `ensure_ascii`. Test chỉ `json.loads`. |
| U03 | `sort_keys` có phụ thuộc locale không | V17: nguồn không nói. |
| U04 | tích số thập phân của `8 * 1024 * 1024` | L01 chỉ ghi biểu thức. Comment «8 MiB». Không viết `8388608`. |
| U05 | tích số thập phân của `100 * 1024 * 1024` trong `io.py` | L03 chỉ ghi biểu thức + comment `# 100 MB`. Số `104857600` chỉ có ở help CLI (O11), không ở `io.py`. |
| U06 | tích số thập phân của `1024 * 1024 * 1024` | L10 chỉ ghi biểu thức + comment `# 1GB`. |
| U07 | `SNIFF_BYTES` «64KB» là 65536 hay 64000 | L24 giá trị `65536`; docstring `:135` viết «64KB». Nguồn không viết `64 * 1024`. |
| U08 | N01 `[:65536]` có phải `SNIFF_BYTES` không | hai chỗ cùng số, không alias. |
| U09 | N02/N03 `4096` quan hệ với L24 | nguồn không nói. |

## Đếm

- Trường `version --json` đã dẫn: 17 (V01–V17).
- Hằng kích thước/dòng/độ sâu (+ chỗ áp adapter): 24 (L01–L24).
- Hằng I/O khác trong phạm vi module: 22 (C01–C22).
- Literal không tên: 7 (N01–N07).
- Ngoài phạm vi (chỉ ghi nhận): 11 (O01–O11).
- UNKNOWN: 9 (U01–U09).
- Mọi hàng V/L/C/N/O đều có `file:dòng`. U không có giá trị bịa.

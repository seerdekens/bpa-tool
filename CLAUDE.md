# CLAUDE.md

Context for AI assistants and developers working on this repository.

## What this is

A small web app that sends a PAN-OS or Panorama config (XML) to the **Strata Cloud Manager Posture API** and displays the BPA report.
The project is meant for international use: the user interface, log messages, error messages, code comments and documentation are all in **English**. Keep it that way.

## Architecture

- `app.py` is a single FastAPI file, deliberately without a database. Each request is a `Task` that runs in a background thread.
  State lives in memory (`TASKS`) and is mirrored to `data/index.json`. Reports are stored as `data/<id>.report.json`.
- `static/index.html` is the entire frontend in one file: vanilla JS, no framework, **no build step**. Keep it that way.
- The frontend polls `/api/reports` while a task is running.
- Dates and numbers are formatted with the browser's locale (`toLocaleString()` without a fixed locale).

## API flow (`run_task`)

1. Token: `POST https://auth.apps.paloaltonetworks.com/oauth2/access_token` with basic auth (client id and secret), `grant_type=client_credentials` and `scope=tsg_id:<TSG>`. The token is cached per (client, tsg).
2. `POST {API_BASE}/reports/config-file-upload` with body `{"delete_after_processing": bool}`. Returns `task_id` and `upload_url`.
   On HTTP 429 (at most 5 active jobs), the tool waits and retries.
3. `PUT upload_url` with headers `Content-Type: text/plain` and `Content-Encoding: gzip`.
   The official docs send **raw** XML with that gzip header, and that is the default. `BPA_UPLOAD_GZIP=1` actually gzips the body.
4. Poll `GET {API_BASE}/reports/{task_id}/bpa-result` (`_poll_and_download`). Documented statuses: 202, `QUEUED`, `IN_PROGRESS`, `COMPLETED` or `FAILED`.
   The real API also returns undocumented ones, such as `UPLOAD_COMPLETE` ("waiting for BPA processing to start"). Rule: **any status that is not a failure keeps polling**; the tool only stops when the response has a report URL, contains the report itself (`best_practices`), or fails. Never treat an unknown status as a finished report.
5. Download the report from `result.report_url`. In practice the link is sometimes in `custom_check_url`, so `_find_report_url` checks several places.
   A gzip body is detected by its magic bytes and unpacked.

`POST /api/reports/{id}/resume` (button "Fetch result again") polls and downloads again for a task that already exists at Palo Alto Networks (`remote_id`), without uploading the config again. Use it after a time-out or a broken report.

The documentation on pan.dev sometimes differs from what the API actually does. Be tolerant when parsing, and prefer adding fallbacks over making assumptions.

## Report structure

```
best_practices → <domain: device|network|policies|objects…> → <object type> → [ { configuration, warnings[], notes, summary_remediation } ]
warning = { check_id, check_name, check_type (Critical|High|Warning|Informational), check_message,
            check_passed, check_excluded, remediation, failed_fields, defined_by, severity }
```

`extractRows()` in the frontend flattens this into rows: `{type, cat, object, kind, ctx, ruleCount, location, check, check_id, severity, state, message, failed, cfg, idx}`.
`state` is `pass`, `fail` or `excepted`. The function is deliberately generic. Unknown structures fall back to the "Raw JSON" tab.

What a result refers to (`describeObject()`):

- **`object`**: a named object (security rule, profile, zone…). `configuration.name` is the name; rules get context from `from`/`to`/`action`/`application`.
- **`rulebase`**: the configuration has no name but a `*_rules` list (`security_rules`, `decryption_rules`…). The check applies to the rulebase as a whole (for example "there must be a rule that blocks QUIC"), so there is no single rule to point at. One rulebase per location: `vsys1`, `shared`, `predefined` or an empty location.
- **`settings`**: a group of device settings without a name (`device_setup_*`, `log_settings_*`, `dynamic_updates`, `user_id`).

Profiles are linked to the rules that use them (`computeUsage()` and `USAGE_FIELDS`): security rules reference profiles by name in `profile_anti_spyware`, `profile_url_filtering`, `log_setting` and so on (profile groups are already resolved into these fields); decryption rules use `profile`. A result on a profile gets `usedBy` (rule names). Objects in location `predefined` are Palo Alto's read-only built-in objects: a finding on one only matters if a rule uses it, so show that clearly and sort such results last.

`failed_fields` (a dict, or `null`) holds the exact settings that fail the check and their current value, for example `{"service": ["any"]}` or `{"permitted_ip": []}`. Keys can be dotted paths. Values are often lists of named entries (for example DNS security categories with their action); `renderFailed()` shows those per entry by name instead of as JSON. This is the most useful information for the user: always show it next to a failing result.

Don't use the configuration field `type` as the object type: on some objects it is a setting (for example the management interface). The grouping key in the report is the object type.

## Developing and testing locally

```bash
pip install -r requirements.txt
BPA_MOCK=1 uvicorn app:app --reload --port 8000     # fictional report, no credentials needed
```

- **Mock mode:** `_mock_report()` generates a fictional report in the same structure as the real API, including rulebases, rule context and `failed_fields`, with the config kept consistent with the failing settings. **Never** use real customer reports or configs as test data or in screenshots: they contain rule names, object names and network details.
- **Testing the real API path without credentials:** run a fake server with FastAPI and point `PAN_AUTH_URL` and `PAN_API_BASE` at it. This lets you test 202, 404, 429, `custom_check_url` and gzip reports too.
- **Checking the UI:** test at 1280, 1440 and 1920 px. Below 1520 px the layout switches to a more compact table.

## UI style

- Dark theme: navy background (`--bg`, `--panel`), teal (`--teal`) as the primary accent and lavender (`--lav`) as the secondary accent.
- Severity colours: Critical `--crit`, High `--high`, Warning `--wrn`, Informational `--inf`. Severity is shown with chevron icons: double for Critical and High, single for the others.
- Light and dark themes: all colours are CSS variables on `:root` (dark) and `:root[data-theme="light"]`. Don't hardcode colours in CSS or SVG markup; add a variable to both themes. The only exception is the chart palette in JS (`SEV_COLOR`, `ST_COLOR`, `catColors`), which is vivid enough for both themes. The theme is stored in `localStorage` (`bpa.theme`) and defaults to `prefers-color-scheme`.
- The footer credits the author (Steven Eerdekens, with LinkedIn and X links). Keep it.
- Do not use Palo Alto Networks logos or brand elements.

## Conventions

- No secrets in the repository: `.env` and `data/` are in `.gitignore`. `.env.example` contains placeholders only.
- The client secret must never reach the frontend. `/api/settings` only says *whether* server credentials are set.
- Configs are sensitive. Delete them locally after upload, unless `BPA_KEEP_CONFIG=1`.
- Python 3.10+ with type hints. Keep dependencies minimal (`fastapi`, `uvicorn`, `httpx`, `python-multipart`).

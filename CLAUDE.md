# CLAUDE.md

Context voor AI-assistenten en ontwikkelaars die aan deze repository werken.

## Wat dit is

Een kleine webapp die een PAN-OS- of Panorama-config (XML) naar de **Strata Cloud Manager Posture API** stuurt en het BPA-rapport toont.
De gebruikersinterface is **Nederlandstalig**. Houd teksten, logberichten en foutmeldingen in het Nederlands.

## Architectuur

- `app.py` is één FastAPI-bestand, met bewust geen database. Elke aanvraag is een `Task` die in een achtergrondthread loopt.
  De status staat in geheugen (`TASKS`) en wordt gespiegeld naar `data/index.json`. Rapporten staan in `data/<id>.report.json`.
- `static/index.html` is de hele frontend in één bestand: vanilla JS, geen framework, **geen build-stap**. Houd dat zo.
- De frontend pollt `/api/reports` zolang er een taak loopt.

## API-flow (`run_task`)

1. Token: `POST https://auth.apps.paloaltonetworks.com/oauth2/access_token` met basic auth (client id en secret), `grant_type=client_credentials` en `scope=tsg_id:<TSG>`. Het token wordt per (client, tsg) gecachet.
2. `POST {API_BASE}/reports/config-file-upload` met body `{"delete_after_processing": bool}`. Geeft `task_id` en `upload_url` terug.
   Bij HTTP 429 (maximaal 5 actieve jobs) wacht de tool en probeert hij opnieuw.
3. `PUT upload_url` met headers `Content-Type: text/plain` en `Content-Encoding: gzip`.
   De officiële docs sturen **ruwe** XML met die gzip-header, en dat is de standaard. `BPA_UPLOAD_GZIP=1` gzipt de body echt.
4. `GET {API_BASE}/reports/{task_id}/bpa-result` pollen. Statussen: 202, `QUEUED`, `IN_PROGRESS`, `COMPLETED` of `FAILED`.
5. Rapport downloaden via `result.report_url`. In de praktijk staat de link soms in `custom_check_url`, en `_find_report_url` zoekt op meerdere plaatsen.
   Een gzip-body wordt herkend aan de magic bytes en uitgepakt.

De documentatie op pan.dev wijkt soms af van wat de API echt doet. Wees tolerant bij het parsen en voeg liever fallbacks toe dan aannames.

## Structuur van het rapport

```
best_practices → <domein: device|network|policies|objects…> → <objecttype> → [ { configuration, warnings[], notes, summary_remediation } ]
warning = { check_id, check_name, check_type (Critical|High|Warning|Informational), check_message,
            check_passed, check_excluded, remediation, failed_fields, defined_by, severity }
```

`extractRows()` in de frontend maakt hier platte rijen van: `{type, cat, object, location, check, check_id, severity, state, message}`.
`state` is `pass`, `fail` of `excepted`. De functie is bewust generiek. Onbekende structuren vallen terug op de tab "Ruwe JSON".

## Lokaal ontwikkelen en testen

```bash
pip install -r requirements.txt
BPA_MOCK=1 uvicorn app:app --reload --port 8000     # fictief rapport, geen credentials nodig
```

- **Mock-modus:** `_mock_report()` maakt een fictief rapport in dezelfde structuur als de echte API. Gebruik **nooit** echte klantrapporten of -configs als testdata of in screenshots: ze bevatten regelnamen, objectnamen en netwerkdetails.
- **Het echte API-pad testen zonder credentials:** start een nep-server met FastAPI en zet `PAN_AUTH_URL` en `PAN_API_BASE` daarnaar. Zo test je ook 202, 404, 429, `custom_check_url` en gzip-rapporten.
- **De UI controleren:** test op 1280, 1440 en 1920 px. Onder 1520 px schakelt de layout naar een compactere tabel.

## Stijl van de UI

- Donker thema: navy achtergrond (`--bg`, `--panel`), teal (`--teal`) als primair accent en lavendel (`--lav`) als secundair accent.
- Severitykleuren: Critical `--crit`, High `--high`, Warning `--wrn`, Informational `--inf`. Severity wordt getoond met chevron-iconen: dubbel voor Critical en High, enkel voor de andere.
- Gebruik geen logo's of merkelementen van Palo Alto Networks.

## Afspraken

- Geen geheimen in de repository: `.env` en `data/` staan in `.gitignore`. `.env.example` bevat alleen placeholders.
- De client secret mag nooit naar de frontend. `/api/settings` geeft alleen terug *of* er server-credentials zijn.
- Configs zijn gevoelig. Verwijder ze lokaal na de upload, tenzij `BPA_KEEP_CONFIG=1`.
- Python 3.10+ en type hints. Houd dependencies minimaal (`fastapi`, `uvicorn`, `httpx`, `python-multipart`).

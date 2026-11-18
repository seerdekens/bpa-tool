"""
PAN-OS / Panorama BPA via de Strata Cloud Manager Posture API
-------------------------------------------------------------
Webapp die een NGFW- of Panorama-configuratie (XML) aanneemt en via de
Posture API een Best Practice Assessment laat uitvoeren.

API-flow (https://pan.dev/scm/api/config/posture-management/checks/):
  1. OAuth2 token via auth.apps.paloaltonetworks.com (client credentials + TSG ID)
  2. POST /posture/checks/v1/reports/config-file-upload  -> task_id + upload_url
  3. PUT  <upload_url>  (Content-Type: text/plain, Content-Encoding: gzip)
  4. GET  /posture/checks/v1/reports/{task_id}/bpa-result -> pollen tot COMPLETED
  5. GET  result.report_url (of custom_check_url)        -> JSON rapport
"""

from __future__ import annotations

import gzip
import json
import os
import re
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

# --------------------------------------------------------------------------- #
# Configuratie
# --------------------------------------------------------------------------- #
AUTH_URL = os.getenv(
    "PAN_AUTH_URL", "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
)
API_BASE = os.getenv(
    "PAN_API_BASE", "https://api.strata.paloaltonetworks.com/posture/checks/v1"
)
DEFAULT_CLIENT_ID = os.getenv("PAN_CLIENT_ID", "")
DEFAULT_CLIENT_SECRET = os.getenv("PAN_CLIENT_SECRET", "")
DEFAULT_TSG_ID = os.getenv("PAN_TSG_ID", "")
MOCK = os.getenv("BPA_MOCK", "0") == "1"
UPLOAD_GZIP = os.getenv("BPA_UPLOAD_GZIP", "0") == "1"  # body echt gzippen?
KEEP_CONFIG = os.getenv("BPA_KEEP_CONFIG", "0") == "1"  # lokale kopie bewaren?
POLL_INTERVAL = float(os.getenv("BPA_POLL_INTERVAL", "5"))
POLL_TIMEOUT = float(os.getenv("BPA_POLL_TIMEOUT", "900"))
QUEUE_TIMEOUT = float(os.getenv("BPA_QUEUE_TIMEOUT", "600"))  # wachten bij HTTP 429
DATA_DIR = Path(os.getenv("BPA_DATA_DIR", "./data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

ACTIVE_STATES = {"QUEUED", "IN_PROGRESS", "PENDING", "PROCESSING", "RUNNING", "ACCEPTED"}
DONE_STATES = {"COMPLETED", "SUCCESS", "COMPLETED_WITH_SUCCESS"}
FAIL_STATES = {"FAILED", "ERROR", "COMPLETED_WITH_ERROR"}


# --------------------------------------------------------------------------- #
# Config-analyse (enkel ter info / als label)
# --------------------------------------------------------------------------- #
def inspect_config(path: Path) -> dict[str, Any]:
    info: dict[str, Any] = {"type": "firewall", "version": None, "hostname": None}
    stack: list[str] = []
    try:
        for event, elem in ET.iterparse(str(path), events=("start", "end")):
            if event == "start":
                stack.append(elem.tag)
                if len(stack) == 1:
                    if elem.tag != "config":
                        raise ValueError("Root-element is geen <config>: dit is geen PAN-OS-configuratie.")
                    info["version"] = elem.get("detail-version") or elem.get("version")
                elif len(stack) == 2 and elem.tag == "panorama":
                    info["type"] = "panorama"
            else:
                if "/".join(stack) == "config/devices/entry/deviceconfig/system/hostname":
                    info["hostname"] = (elem.text or "").strip() or None
                stack.pop()
                if len(stack) <= 2:
                    elem.clear()
    except ET.ParseError as exc:
        raise ValueError(f"Ongeldige XML: {exc}") from exc
    return info


# --------------------------------------------------------------------------- #
# API-hulpfuncties
# --------------------------------------------------------------------------- #
_token_cache: dict[tuple[str, str], tuple[str, float]] = {}
_token_lock = threading.Lock()


def get_token(client_id: str, client_secret: str, tsg_id: str) -> str:
    key = (client_id, tsg_id)
    with _token_lock:
        cached = _token_cache.get(key)
        if cached and cached[1] > time.time() + 60:
            return cached[0]
        r = httpx.post(
            AUTH_URL,
            auth=(client_id, client_secret),
            data={"grant_type": "client_credentials", "scope": f"tsg_id:{tsg_id}"},
            timeout=30,
        )
        if r.status_code != 200:
            raise RuntimeError(f"Authenticatie mislukt ({r.status_code}): {_err_text(r)}")
        body = r.json()
        token = body["access_token"]
        _token_cache[key] = (token, time.time() + int(body.get("expires_in", 900)))
        return token


def _err_text(r: httpx.Response) -> str:
    """Haal een leesbare foutmelding uit een Palo Alto error-body."""
    try:
        body = r.json()
        errs = body.get("_errors") or []
        if errs:
            parts = []
            for e in errs:
                msg = e.get("message", "")
                det = "; ".join(e.get("details") or []) if isinstance(e.get("details"), list) else e.get("details")
                parts.append(f"{e.get('code', '')} {msg} {('— ' + det) if det else ''}".strip())
            return " | ".join(parts)
        for k in ("error_description", "message", "error", "detail"):
            if body.get(k):
                return str(body[k])
    except Exception:  # noqa: BLE001
        pass
    return r.text[:600]


def _raise_for(r: httpx.Response, what: str) -> None:
    if r.status_code >= 400:
        hint = ""
        if r.status_code in (401, 403):
            hint = " — controleer de rol van het service account en de TSG ID."
        raise RuntimeError(f"{what} mislukt ({r.status_code}): {_err_text(r)}{hint}")


def _find_status(data: dict[str, Any]) -> str:
    st = data.get("status")
    if not st and isinstance(data.get("data"), dict):
        st = data["data"].get("status")
    return str(st or "").upper()


def _find_report_url(data: dict[str, Any]) -> str | None:
    """De API zet de link niet altijd op dezelfde plek; zoek op de bekende plaatsen."""
    containers = [data.get("result") or {}, data.get("data") or {}, data]
    for c in containers:
        if not isinstance(c, dict):
            continue
        for k in ("report_url", "custom_check_url", "download_url", "download-url", "url"):
            v = c.get(k)
            if isinstance(v, str) and v.startswith("http"):
                return v
    return None


def _decode_report(content: bytes) -> bytes:
    if content[:2] == b"\x1f\x8b":
        content = gzip.decompress(content)
    return content


# --------------------------------------------------------------------------- #
# Taken
# --------------------------------------------------------------------------- #
@dataclass
class Task:
    id: str
    filename: str
    label: str
    info: dict[str, Any]
    delete_after: bool
    status: str = "QUEUED"
    remote_id: str | None = None
    error: str | None = None
    log: list[dict[str, Any]] = field(default_factory=list)
    created: float = field(default_factory=time.time)
    finished: float | None = None

    def add(self, msg: str, level: str = "info") -> None:
        self.log.append({"t": time.time(), "level": level, "msg": msg})

    def public(self) -> dict[str, Any]:
        d = {k: getattr(self, k) for k in (
            "id", "filename", "label", "info", "delete_after", "status", "remote_id",
            "error", "log", "created", "finished")}
        d["has_report"] = (DATA_DIR / f"{self.id}.report.json").exists()
        return d


TASKS: dict[str, Task] = {}
_index_lock = threading.Lock()


def run_task(task: Task, cfg_path: Path, creds: dict[str, str]) -> None:
    try:
        if MOCK:
            _run_mock(task)
            return

        task.status = "AUTHENTICATING"
        task.add("Access token ophalen…")
        tok = lambda: get_token(creds["client_id"], creds["client_secret"], creds["tsg_id"])  # noqa: E731
        hdr = lambda: {"Authorization": f"Bearer {tok()}", "Accept": "application/json"}  # noqa: E731
        tok()

        with httpx.Client(timeout=120) as client:
            # 1. Upload-taak aanmaken (max. 5 actieve jobs -> 429)
            task.status = "REQUESTING"
            task.add("Upload-taak aanmaken (POST /reports/config-file-upload)…")
            deadline = time.time() + QUEUE_TIMEOUT
            while True:
                r = client.post(f"{API_BASE}/reports/config-file-upload", headers=hdr(),
                                json={"delete_after_processing": task.delete_after})
                if r.status_code != 429:
                    break
                if time.time() > deadline:
                    raise RuntimeError("Limiet van 5 actieve BPA-jobs bereikt; probeer later opnieuw.")
                task.add("Limiet van 5 actieve jobs bereikt — wachten op een vrije plaats…", "warn")
                time.sleep(20)
            _raise_for(r, "Upload-taak aanmaken")
            body = r.json()
            task.remote_id = body.get("task_id") or body.get("id")
            upload_url = body.get("upload_url") or body.get("upload-url")
            if not task.remote_id or not upload_url:
                raise RuntimeError(f"Onverwacht antwoord: {json.dumps(body)[:400]}")
            task.add(f"Taak aangemaakt: {task.remote_id}")

            # 2. Config uploaden naar de signed URL
            task.status = "UPLOADING"
            raw = cfg_path.read_bytes()
            payload = gzip.compress(raw) if UPLOAD_GZIP else raw
            task.add(f"Configuratie uploaden ({len(raw) / 1_048_576:.1f} MB)…")
            r = client.put(upload_url, content=payload, timeout=900, headers={
                "Content-Type": "text/plain", "Content-Encoding": "gzip"})
            _raise_for(r, "Upload")
            task.add("Upload voltooid.")
            if not KEEP_CONFIG:
                cfg_path.unlink(missing_ok=True)

            # 3. Pollen
            task.status = "PROCESSING"
            deadline = time.time() + POLL_TIMEOUT
            last, not_found = None, 0
            while True:
                r = client.get(f"{API_BASE}/reports/{task.remote_id}/bpa-result", headers=hdr())
                if r.status_code == 202:
                    status, data = "ACCEPTED", {}
                elif r.status_code == 404 and not_found < 6:
                    not_found += 1
                    status, data = "PENDING", {}
                else:
                    _raise_for(r, "Status opvragen")
                    data = r.json()
                    status = _find_status(data)
                msg = data.get("message") if isinstance(data, dict) else None
                line = status + (f" — {msg}" if msg else "")
                if line != last:
                    task.add(f"Status: {line}")
                    last = line
                if status in DONE_STATES:
                    break
                if status in FAIL_STATES:
                    raise RuntimeError(f"BPA-verwerking mislukt: {msg or json.dumps(data)[:400]}")
                if status not in ACTIVE_STATES:
                    # Geen herkenbare status: misschien zit het rapport rechtstreeks in de body
                    if isinstance(data, dict) and data and not _find_report_url(data):
                        task.add("Antwoord bevat geen status; inhoud wordt als rapport bewaard.", "warn")
                        (DATA_DIR / f"{task.id}.report.json").write_text(json.dumps(data))
                        task.status = "DONE"
                        return
                    if _find_report_url(data):
                        break
                if time.time() > deadline:
                    raise RuntimeError("Time-out bij wachten op het rapport.")
                time.sleep(POLL_INTERVAL)

            # 4. Rapport downloaden
            task.status = "DOWNLOADING"
            url = _find_report_url(data)
            if not url:
                raise RuntimeError(f"Geen download-URL in het antwoord: {json.dumps(data)[:400]}")
            task.add("Rapport downloaden…")
            r = client.get(url, timeout=600)
            _raise_for(r, "Rapport downloaden")
            content = _decode_report(r.content)
            json.loads(content)  # valideren
            (DATA_DIR / f"{task.id}.report.json").write_bytes(content)
            task.add(f"Rapport opgeslagen ({len(content) / 1024:.0f} kB).")

        task.status = "DONE"
    except Exception as exc:  # noqa: BLE001
        task.status = "FAILED"
        task.error = str(exc)
        task.add(str(exc), "error")
    finally:
        if not KEEP_CONFIG:
            cfg_path.unlink(missing_ok=True)
        task.finished = time.time()
        _save_index()


def _run_mock(task: Task) -> None:
    for st, msg in [("AUTHENTICATING", "Access token ophalen… (mock)"),
                    ("REQUESTING", "Upload-taak aanmaken… (mock)"),
                    ("UPLOADING", "Configuratie uploaden… (mock)"),
                    ("PROCESSING", "Status: QUEUED"),
                    ("PROCESSING", "Status: IN_PROGRESS — Analyzing security rules..."),
                    ("DOWNLOADING", "Status: COMPLETED")]:
        task.status = st
        task.add(msg)
        time.sleep(0.5)
    task.remote_id = str(uuid.uuid4())
    (DATA_DIR / f"{task.id}.report.json").write_text(json.dumps(_mock_report(), indent=1))
    task.add("Rapport opgeslagen (mock).")
    task.status = "DONE"


def _mock_report() -> dict[str, Any]:
    """Fictief voorbeeldrapport in dezelfde structuur als de Posture API (best_practices → domein → objecttype)."""
    import random
    rnd = random.Random(7)
    # domein -> objecttype -> (objectnamen, [(check, severity, uitleg)])
    spec = {
        "policies": {
            "security_rule": (
                ["allow-web", "allow-dns", "any-any-temp", "dmz-to-lan", "vpn-users", "guest-internet",
                 "mgmt-access", "backup-srv", "iot-cloud", "partner-api"],
                [("Allow rules should specify applications (App-ID).", "Critical",
                  "Rules based on ports instead of App-ID allow any application on that port."),
                 ("Allow rules should have a security profile group attached.", "Critical",
                  "Without threat profiles, allowed traffic is not inspected for exploits or malware."),
                 ("Service should not be 'any' in allow rules.", "High",
                  "Restrict allowed services to the application defaults or explicit ports."),
                 ("Log at session end should be enabled.", "Warning",
                  "Session-end logging provides visibility for investigation and reporting."),
                 ("Security rules should have a description.", "Informational",
                  "Descriptions help reviewers understand why a rule exists.")]),
            "security_rulebase": (
                ["rulebase"],
                [("Block inbound traffic from known malicious IP addresses.", "High",
                  "Use external dynamic lists with known malicious IP addresses."),
                 ("Enable logging on the interzone-default rule.", "Informational",
                  "Denied traffic is otherwise invisible in the logs.")]),
        },
        "objects": {
            "anti_spyware_profile": (
                ["default", "strict-AS"],
                [("Enable DNS sinkhole in the anti-spyware profile.", "Critical",
                  "Sinkholing identifies infected hosts that resolve malicious domains."),
                 ("Block critical, high and medium severity spyware.", "High",
                  "Command-and-control traffic should be blocked, not only alerted.")]),
            "url_filtering_profile": (
                ["default", "corp-url"],
                [("Block known malicious URL categories.", "Critical",
                  "Malware, phishing and command-and-control categories should be blocked."),
                 ("Log the full URL, not only the container page.", "Informational",
                  "Full URL logging improves investigations.")]),
        },
        "network": {
            "zone_protection_profile": (
                ["zp-untrust"],
                [("Enable reconnaissance protection.", "Warning",
                  "Detects and blocks port scans and host sweeps."),
                 ("Enable packet-based attack protection.", "Warning",
                  "Drops malformed and spoofed packets.")]),
            "interface_management_profile": (
                ["mgmt-ping", "allow-https"],
                [("Do not allow HTTP or Telnet on management profiles.", "High",
                  "Unencrypted management protocols expose credentials.")]),
        },
        "device": {
            "device_setup_management": (
                ["fw-demo-01"],
                [("Restrict management access to permitted IP addresses.", "Critical",
                  "Management access should only be possible from trusted networks."),
                 ("Enable minimum password complexity.", "High",
                  "Enforce strong passwords for local administrators."),
                 ("Configure an NTP server.", "Warning",
                  "Accurate time is required for log correlation.")]),
            "dynamic_updates": (
                ["updates"],
                [("Schedule antivirus updates hourly.", "Warning",
                  "Frequent updates shorten the window of exposure.")]),
        },
    }
    out: dict[str, Any] = {}
    cid = 100
    for domain, types in spec.items():
        out[domain] = {}
        for otype, (names, checks) in types.items():
            ids = list(range(cid, cid + len(checks)))
            cid += len(checks)
            objs = []
            for n in names:
                warns = []
                for check_id, (cn, sev, msg) in zip(ids, checks):
                    passed = rnd.random() > 0.38
                    excl = not passed and rnd.random() < 0.12
                    warns.append({"check_id": check_id, "check_name": cn, "check_type": sev,
                                  "check_message": msg, "check_passed": passed, "check_excluded": excl,
                                  "defined_by": "Predefined", "severity": ""})
                objs.append({"configuration": {"uuid": str(uuid.UUID(int=rnd.getrandbits(128))),
                                               "name": n, "location": "vsys1"},
                             "warnings": warns, "notes": None, "summary_remediation": {}})
            out[domain][otype] = objs
    return {"best_practices": out, "version": "1",
            "information": {"platform": "ngfw", "PanOS_version": "11.2.0", "note": "Fictief voorbeeldrapport (mock)"}}


def _save_index() -> None:
    with _index_lock:
        idx = {tid: t.public() for tid, t in TASKS.items()}
        (DATA_DIR / "index.json").write_text(json.dumps(idx, indent=1))


def _load_index() -> None:
    p = DATA_DIR / "index.json"
    if not p.exists():
        return
    for tid, d in json.loads(p.read_text()).items():
        legacy = d.get("meta", {})  # rapporten van de oude AIOps-versie
        label = d.get("label") or f"{legacy.get('model', '')} {legacy.get('serial', '')}".strip() or d["filename"]
        info = d.get("info") or {"type": "panorama" if legacy.get("model") == "Panorama" else "firewall",
                                 "version": legacy.get("version")}
        t = Task(id=tid, filename=d["filename"], label=label, info=info,
                 delete_after=d.get("delete_after", True), status=d["status"],
                 remote_id=d.get("remote_id"), error=d.get("error"), log=d.get("log", []),
                 created=d.get("created", 0), finished=d.get("finished"))
        if t.status not in ("DONE", "FAILED"):
            t.status, t.error = "FAILED", "Onderbroken door herstart van de server."
        TASKS[tid] = t


_load_index()

# --------------------------------------------------------------------------- #
# Web-API
# --------------------------------------------------------------------------- #
app = FastAPI(title="BPA Report Generator")
STATIC = Path(__file__).parent / "static"


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/api/settings")
def settings() -> dict[str, Any]:
    return {"mock": MOCK, "api_base": API_BASE,
            "server_credentials": bool(DEFAULT_CLIENT_ID and DEFAULT_CLIENT_SECRET and DEFAULT_TSG_ID)}


async def _save_upload(file: UploadFile, dest: Path) -> None:
    with dest.open("wb") as fh:
        while chunk := await file.read(1 << 20):
            fh.write(chunk)


@app.post("/api/inspect")
async def inspect(file: UploadFile = File(...)) -> dict[str, Any]:
    tmp = DATA_DIR / f"inspect-{uuid.uuid4().hex}.xml"
    try:
        await _save_upload(file, tmp)
        return inspect_config(tmp)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    finally:
        tmp.unlink(missing_ok=True)


@app.post("/api/reports")
async def create_report(
    file: UploadFile = File(...),
    label: str = Form(""),
    delete_after_processing: bool = Form(True),
    client_id: str = Form(""),
    client_secret: str = Form(""),
    tsg_id: str = Form(""),
) -> dict[str, Any]:
    creds = {"client_id": client_id or DEFAULT_CLIENT_ID,
             "client_secret": client_secret or DEFAULT_CLIENT_SECRET,
             "tsg_id": tsg_id or DEFAULT_TSG_ID}
    if not MOCK and not all(creds.values()):
        raise HTTPException(400, "Client ID, Client Secret en TSG ID zijn vereist.")

    tid = uuid.uuid4().hex[:12]
    cfg_path = DATA_DIR / f"{tid}.config.xml"
    await _save_upload(file, cfg_path)
    try:
        info = inspect_config(cfg_path)
    except ValueError as exc:
        cfg_path.unlink(missing_ok=True)
        raise HTTPException(400, str(exc)) from exc

    label = label.strip() or info.get("hostname") or (file.filename or "config")
    task = Task(id=tid, filename=file.filename or "config.xml", label=label, info=info,
                delete_after=delete_after_processing)
    task.add(f"Bestand ontvangen: {task.filename}")
    TASKS[tid] = task
    _save_index()
    threading.Thread(target=run_task, args=(task, cfg_path, creds), daemon=True).start()
    return task.public()


@app.get("/api/reports")
def list_reports() -> list[dict[str, Any]]:
    return sorted((t.public() for t in TASKS.values()), key=lambda t: -t["created"])


@app.get("/api/reports/{tid}")
def get_report(tid: str) -> dict[str, Any]:
    if tid not in TASKS:
        raise HTTPException(404, "Onbekende taak")
    return TASKS[tid].public()


@app.get("/api/reports/{tid}/json")
def get_report_json(tid: str, download: bool = False):
    p = DATA_DIR / f"{tid}.report.json"
    if tid not in TASKS or not p.exists():
        raise HTTPException(404, "Rapport niet beschikbaar")
    if download:
        t = TASKS[tid]
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", t.label)[:60]
        name = f"BPA_{safe}_{time.strftime('%Y%m%d', time.localtime(t.created))}.json"
        return FileResponse(p, media_type="application/json", filename=name)
    return JSONResponse(json.loads(p.read_text()))


@app.delete("/api/reports/{tid}")
def delete_report(tid: str) -> dict[str, str]:
    TASKS.pop(tid, None)
    for suffix in (".config.xml", ".report.json"):
        (DATA_DIR / f"{tid}{suffix}").unlink(missing_ok=True)
    _save_index()
    return {"deleted": tid}


app.mount("/static", StaticFiles(directory=STATIC), name="static")

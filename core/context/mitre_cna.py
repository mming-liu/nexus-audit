"""M353-M356: MITRE CVE form API direct client.

The personal-researcher gateway is https://cveform-api.mitre.org/api.
Contract extracted from the official front-end (mitre/mitre-cve-roles,
cve-id-request/index.html + static/cve5sw.js):

  POST /cve-id                  reserve CAN(s)
  GET  /cve/{id}                load a CVE/CAN record
  GET  /cve-id/{id}             load reservation state (fallback)
  POST /cve/{id}/cna            create a published record
  PUT  /cve/{id}/cna            update an existing record

Auth: Authorization: Bearer <token>, plus CVE-API-ORG / CVE-API-USER /
CVE-API-KEY headers (the web client uses "redacted" for the key when
logged in through Google OAuth).
"""
from __future__ import annotations

import base64
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

API_BASE = "https://cveform-api.mitre.org/api"
DEFAULT_TIMEOUT = 25
TOKEN_TTL_SECONDS = 480
SUBMISSION_DIR = Path("benchmarks/results/cna_submissions")

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


class MitreCveError(RuntimeError):
    """API or token error with a user-facing message."""


def _b64json(seg: str) -> dict:
    pad = "=" * (-len(seg) % 4)
    raw = base64.urlsafe_b64decode((seg + pad).encode("ascii"))
    return json.loads(raw.decode("utf-8"))


def parse_login_blob(raw: str) -> dict:
    """Parse the whole login-success line, pure JSON, or a bare JWT.

    Returns token claims plus email/org; does not raise on expiry so that
    callers can print a precise remaining-seconds message.
    """
    text = str(raw or "").strip()
    if not text:
        raise MitreCveError("empty login blob")
    token = ""
    m = re.search(r'"access_token"\s*:\s*"([^"]+)"', text)
    if m:
        token = m.group(1)
    if not token:
        m = _JWT_RE.search(text)
        if m:
            token = m.group(0)
    if not token:
        raise MitreCveError("no access_token / JWT found in login blob")
    parts = token.split(".")
    if len(parts) != 3:
        raise MitreCveError("access_token is not a JWT")
    try:
        claims = _b64json(parts[1])
    except Exception as exc:  # noqa: BLE001
        raise MitreCveError(f"cannot decode JWT payload: {exc}") from exc
    now = int(time.time())
    exp = int(claims.get("exp") or 0)
    iat = int(claims.get("iat") or 0)
    em = _EMAIL_RE.search(text)
    email = em.group(0) if em else ""
    org = ""
    if email and "@" in email:
        local, domain = email.split("@", 1)
        org = f"{local}:{domain}..0"
    return {
        "access_token": token,
        "email": email,
        "org": org,
        "sub": str(claims.get("sub") or ""),
        "sid": str(claims.get("sid") or ""),
        "iss": str(claims.get("iss") or ""),
        "iat": iat,
        "exp": exp,
        "remaining_sec": exp - now,
        "expired": exp <= now,
        "token_ttl": exp - iat,
    }


CNA_TARGETS: dict[str, dict] = {
    "ruoyi-vue-pro": {
        "name": "ruoyi-vue-pro",
        "repo": "YunaiV/ruoyi-vue-pro",
        "vendor": "YunaiV",
        "product": "ruoyi-vue-pro",
        "cwe": "CWE-862",
        "cvss": 8.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "versions": "<= 2.4.1",
        "description": "PayWalletRechargeController.refundWalletRecharge (POST /admin-api/pay/wallet-recharge/refund) lacks a method-level authorization check; an authenticated low-privileged user can refund another user's wallet recharge.",
        "references": ["https://github.com/YunaiV/ruoyi-vue-pro/issues/1328"],
        "package_url": "pkg:github/YunaiV/ruoyi-vue-pro",
        "files": ["PayWalletRechargeController.java"],
        "routines": ["PayWalletRechargeController.refundWalletRecharge"],
        "can_id": "CAN-2026-2041058",
        "status_only": True,
    },
    "metasfresh": {
        "name": "metasfresh",
        "repo": "metasfresh/metasfresh",
        "vendor": "metasfresh",
        "product": "metasfresh",
        "cwe": "CWE-89",
        "cvss": 8.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "versions": "through master branch new_dawn_uat (unfixed as of 2026-10-30)",
        "description": "DebugRestController.stressTest_massCacheInvalidation concatenates the tableName request parameter directly into SELECT COUNT(1) FROM <tableName> without parameterization or identifier validation. An authenticated user can inject SQL and read or modify database contents.",
        "references": ["https://github.com/metasfresh/metasfresh/issues/27079"],
        "package_url": "pkg:github/metasfresh/metasfresh",
        "files": ["backend/de.metas.ui.web.base/src/main/java/de/metas/ui/web/debug/DebugRestController.java"],
        "routines": ["DebugRestController.stressTest_massCacheInvalidation"],
        "commit": "a962d77698039c378ec457ac76fe7e64defffeac",
    },
    "x-springboot": {
        "name": "x-springboot",
        "repo": "yzcheng90/x-springboot",
        "vendor": "yzcheng90",
        "product": "x-springboot",
        "cwe": "CWE-22",
        "cvss": 7.2,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
        "versions": "through master (unfixed as of 2026-10-30)",
        "description": "SysGenController.create binds MakerConfigEntity and calls GenUtils.maker, which concatenates the request-controlled filePath, packagePath and moduleName into the output path and passes it to new FileWriter(filePath + path) without normalization or a canonical-root check. A caller with SysGenCreate permission can write generated files outside the intended directory.",
        "references": ["https://github.com/yzcheng90/x-springboot/issues/47"],
        "package_url": "pkg:github/yzcheng90/x-springboot",
        "files": ["SysGenController.java", "GenUtils.java"],
        "routines": ["SysGenController.create", "GenUtils.maker"],
        "commit": "f4acf07c6b134af9ad3e6284d65b40997087b14f",
    },
    "workflow-engine": {
        "name": "workflow-engine",
        "repo": "risesoft-y9/WorkFlow-Engine",
        "vendor": "risesoft-y9",
        "product": "WorkFlow-Engine",
        "cwe": "CWE-89",
        "cvss": 8.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "versions": "through main (unfixed as of 2026-11-06)",
        "description": "Nine authenticated /vue endpoints accept searchMapStr; its JSON values are concatenated into LIKE and equality predicates in Y9TableServiceImpl without parameter binding. An authenticated user can inject SQL and read or modify database contents.",
        "references": ["https://github.com/risesoft-y9/WorkFlow-Engine/issues/4"],
        "package_url": "pkg:github/risesoft-y9/WorkFlow-Engine",
        "files": ["Y9TableServiceImpl.java"],
        "routines": ["DoingRestController.doingList4All", "RecycleRestController.recycleList", "TodoRestController.todoList"],
        "commit": "e91293ca1db478fd4e692a23e9f263bbe61dd4d9",
    },
    "network-drive": {
        "name": "network-drive",
        "repo": "risesoft-y9/Network-Drive",
        "vendor": "risesoft-y9",
        "product": "Network-Drive",
        "cwe": "CWE-22",
        "cvss": 8.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "versions": "through main (unfixed as of 2026-11-06)",
        "description": "UploaderController.uploadChunk1 and mergeFile concatenate user-controlled Chunk.identifier / filename into the upload path via FileUtils.generatePath, then call Files.write / Files.createFile without normalize() or a canonical-root check. An authenticated user can write outside the upload directory.",
        "references": ["https://github.com/risesoft-y9/Network-Drive/issues/2"],
        "package_url": "pkg:github/risesoft-y9/Network-Drive",
        "files": ["UploaderController.java", "FileUtils.java"],
        "routines": ["UploaderController.uploadChunk1", "UploaderController.mergeFile"],
        "commit": "973d777c3e02756749dab3b3399859a9fb79a44e",
    },
    "eladmin": {
        "name": "eladmin",
        "repo": "elunez/eladmin",
        "vendor": "elunez",
        "product": "eladmin",
        "cwe": "CWE-862",
        "cvss": 6.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
        "versions": "through 2.7 / commit 646c58c30f2e9aecf998b054f05f4d9ba0008995",
        "description": "S3StorageController.uploadS3Storage (POST /api/s3Storage) lacks the @PreAuthorize storage:add check used by LocalStorageController.createFile. Any authenticated low-privileged user can upload to the configured S3 bucket and create a storage record. This is a distinct method from CVE-2026-108706 (downloadS3Storage).",
        "references": ["https://github.com/elunez/eladmin/issues/926"],
        "package_url": "pkg:github/elunez/eladmin",
        "files": ["S3StorageController.java"],
        "routines": ["S3StorageController.uploadS3Storage"],
        "commit": "646c58c30f2e9aecf998b054f05f4d9ba0008995",
    },
}


def _version_obj(spec: dict) -> dict:
    v = {"version": str(spec.get("versions") or "0"), "status": "affected"}
    return v


def build_cna_record(target_spec: dict, can_id: str, requester_id: str = "",
                     org: str = "", org_id: str = "") -> dict:
    """Build a CVE 5.2 record with a cnaContainer ready for /cve/{id}/cna."""
    spec = dict(target_spec)
    cve_id = str(can_id or spec.get("can_id") or "").strip()
    if not cve_id:
        raise MitreCveError("can_id is required")
    affected = {
        "vendor": spec.get("vendor") or "",
        "product": spec.get("product") or "",
        "versions": [_version_obj(spec)],
    }
    if spec.get("package_url"):
        affected["packageURL"] = spec["package_url"]
    if spec.get("files"):
        affected["programFiles"] = list(spec["files"])
    if spec.get("routines"):
        affected["programRoutines"] = [{"name": x} for x in spec["routines"]]
    cna: dict[str, Any] = {
        "descriptions": [{"lang": "en", "value": spec.get("description") or ""}],
        "affected": [affected],
        "problemTypes": [{
            "descriptions": [{
                "lang": "en",
                "type": "CWE",
                "description": spec.get("cwe") or "",
            }]
        }],
        "references": [{"url": u, "name": spec.get("name") or ""}
                       for u in (spec.get("references") or [])],
    }
    if spec.get("cvss") and spec.get("cvss_vector"):
        cna["metrics"] = [{
            "cvssV3_1": {
                "version": "3.1",
                "vectorString": spec["cvss_vector"],
                "baseScore": float(spec["cvss"]),
                "baseSeverity": "HIGH" if float(spec["cvss"]) >= 7.0 else "MEDIUM",
            }
        }]
    if org_id:
        cna["providerMetadata"] = {"orgId": org_id, "shortName": org or ""}
    record = {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.2",
        "cveMetadata": {
            "cveId": cve_id,
            "state": "PUBLISHED",
        },
        "containers": {"cna": cna},
    }
    if org_id:
        record["cveMetadata"]["assignerOrgId"] = org_id
    if requester_id:
        record["cveMetadata"]["requesterId"] = requester_id
    return record


def validate_cna_record(record: dict) -> list[str]:
    """Local preflight mirroring the form's required fields (no red boxes)."""
    errors: list[str] = []
    if not isinstance(record, dict):
        return ["record is not an object"]
    if record.get("dataType") != "CVE_RECORD":
        errors.append("dataType must be CVE_RECORD")
    if not str(record.get("dataVersion") or "").startswith("5."):
        errors.append("dataVersion must be 5.x")
    meta = record.get("cveMetadata") or {}
    cve_id = str(meta.get("cveId") or "")
    if not re.match(r"^(CAN|CVE)-\d{4}-\d{1,12}$", cve_id):
        errors.append("cveMetadata.cveId must be CAN/CVE-YYYY-NNNN")
    if meta.get("state") not in ("PUBLISHED", "REJECTED"):
        errors.append("cveMetadata.state must be PUBLISHED or REJECTED")
    cna = (record.get("containers") or {}).get("cna") or {}
    if not (cna.get("descriptions") or []):
        errors.append("containers.cna.descriptions is required")
    elif not str((cna["descriptions"][0] or {}).get("value") or "").strip():
        errors.append("containers.cna.descriptions[0].value is empty")
    affected = cna.get("affected") or []
    if not affected:
        errors.append("containers.cna.affected is required")
    else:
        a0 = affected[0]
        if not a0.get("vendor"):
            errors.append("affected[0].vendor is required")
        if not a0.get("product"):
            errors.append("affected[0].product is required")
        if not a0.get("versions"):
            errors.append("affected[0].versions is required")
    if not (cna.get("problemTypes") or []):
        errors.append("containers.cna.problemTypes is required")
    if not (cna.get("references") or []):
        errors.append("containers.cna.references is required")
    return errors


class CveFormClient:
    """Thin client for the personal-researcher cveform API."""

    def __init__(self, token: str = "", email: str = "", org: str = "",
                 org_id: str = "", base: str = API_BASE,
                 timeout: int = DEFAULT_TIMEOUT):
        self.token = str(token or "").strip()
        self.email = str(email or "").strip()
        self.org = str(org or "").strip()
        self.org_id = str(org_id or "").strip()
        self.base = base.rstrip("/")
        self.timeout = timeout

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json", "Accept": "application/json",
             "X-Requested-With": "fetch"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        if self.org:
            h["CVE-API-ORG"] = self.org
        if self.email:
            h["CVE-API-USER"] = self.email
        h["CVE-API-KEY"] = "redacted"
        return h

    def _request(self, method: str, path: str,
                 body: dict | None = None) -> dict:
        url = self.base + "/" + path.lstrip("/")
        data = None if body is None else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, method=method,
                                     headers=self._headers())
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8", "replace")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace")
            try:
                payload = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                payload = {"raw": raw[:1000]}
            msg = payload.get("error") or payload.get("message") or raw[:300]
            raise MitreCveError(f"HTTP {exc.code} {method} {path}: {msg}") from exc
        except urllib.error.URLError as exc:
            raise MitreCveError(f"network error {method} {path}: {exc.reason}") from exc

    def me(self) -> dict:
        return self._request("GET", "me")

    def org_info(self) -> dict:
        if not self.org:
            return {}
        return self._request("GET", "org/" + urllib.parse.quote(self.org, safe=":."))

    def reserve_can(self, year: int | None = None) -> str:
        y = int(year or datetime.now(timezone.utc).year)
        if not self.org:
            raise MitreCveError("org is required to reserve a CAN (parse email first)")
        # The official front-end calls post('cve-id', args): the third
        # argument is the body, so reserve parameters go in the query string.
        qs = urllib.parse.urlencode({
            "amount": 1, "cve_year": y, "short_name": self.org})
        payload = self._request("POST", "cve-id?" + qs)
        ids = payload.get("cve_ids") or []
        if isinstance(ids, list) and ids:
            first = ids[0]
            if isinstance(first, dict):
                cid = first.get("cve_id") or first.get("cveId")
            else:
                cid = str(first)
            if cid:
                return str(cid)
        raise MitreCveError(f"reserve response has no cve_ids: {payload}")

    def load_record(self, can_or_cve_id: str) -> dict:
        cid = urllib.parse.quote(str(can_or_cve_id).strip(), safe="")
        try:
            rec = self._request("GET", f"cve/{cid}")
            if isinstance(rec, dict) and rec.get("cveMetadata"):
                return {"ok": True, "kind": "cve", "record": rec,
                        "state": (rec.get("cveMetadata") or {}).get("state", "")}
        except MitreCveError:
            pass
        state = self._request("GET", f"cve-id/{cid}")
        return {"ok": True, "kind": "cve-id", "record": None,
                "state": str(state.get("state") or ""), "raw": state}

    def status(self, can_or_cve_id: str) -> dict:
        return self.load_record(can_or_cve_id)

    def submit_record(self, can_or_cve_id: str, record: dict,
                      method: str | None = None) -> dict:
        cid = urllib.parse.quote(str(can_or_cve_id).strip(), safe="")
        cna = (record.get("containers") or {}).get("cna")
        if not cna:
            raise MitreCveError("record has no containers.cna")
        errors = validate_cna_record(record)
        if errors:
            raise MitreCveError("local validation failed: " + "; ".join(errors))
        body = {"cnaContainer": cna}
        if method in ("POST", "PUT"):
            return self._request(method, f"cve/{cid}/cna", body)
        # A freshly reserved CAN has no /cve record yet -> POST.
        try:
            existing = self.load_record(can_or_cve_id)
            state = str(existing.get("state") or "")
            use = "PUT" if existing.get("record") and state else "POST"
        except MitreCveError:
            use = "POST"
        try:
            return self._request(use, f"cve/{cid}/cna", body)
        except MitreCveError as exc:
            # 404/CVE_RECORD_DNE means the record is not created yet; schema
            # failures (400) must surface as-is, not be masked by a PUT retry.
            msg = str(exc)
            if use == "POST" and ("404" in msg or "CVE_RECORD_DNE" in msg):
                return self._request("PUT", f"cve/{cid}/cna", body)
            raise

    def save(self, can_id: str, payload: dict) -> Path:
        SUBMISSION_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = SUBMISSION_DIR / f"{can_id.replace('/', '_')}_{ts}.json"
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                        encoding="utf-8")
        return path

# © VampSecure Studios — VampSecure Labs Security Research Division
"""
vamp-aws-audit — Auditor CIS AWS Level 1 (71 controles)

Comprueba la postura de seguridad de una cuenta AWS sin dependencias
externas (solo stdlib + aiohttp). Implementa AWS Signature Version 4
desde cero con hmac + hashlib.

Módulos auditados:
  IAM, S3, EC2, CloudTrail, CloudWatch, RDS, KMS, GuardDuty, Config
"""

from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import hmac
import json
import os
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

# ─── dependencias opcionales ────────────────────────────────────────────────
try:
    import aiohttp
    _AIOHTTP = True
except ImportError:
    _AIOHTTP = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    _RICH = True
except ImportError:
    _RICH = False

TOOL_NAME = "vamp-aws-audit"
VERSION   = "1.0.0"

# ─── colores de severidad ───────────────────────────────────────────────────
SEV_COLOR = {"CRITICAL": "red", "HIGH": "orange1", "MEDIUM": "yellow",
             "LOW": "green", "INFO": "dim"}

console = Console() if _RICH else None


# =============================================================================
# Modelos
# =============================================================================

class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    ERROR = "ERROR"
    SKIP  = "SKIP"


@dataclass
class Finding:
    check_id:    str
    title:       str
    severity:    str          # CRITICAL HIGH MEDIUM LOW INFO
    status:      Status
    resource:    str = ""
    region:      str = ""
    detail:      str = ""
    remediation: str = ""


@dataclass
class AWSConfig:
    access_key: str
    secret_key: str
    region:     str = "us-east-1"
    regions:    List[str] = field(default_factory=list)
    profile:    str = ""


# =============================================================================
# SigV4
# =============================================================================

def _sigv4(
    method: str,
    url: str,
    headers: Dict[str, str],
    payload: str,
    access_key: str,
    secret_key: str,
    service: str,
    region: str,
) -> Dict[str, str]:
    """
    Firma una petición HTTP con AWS Signature Version 4.
    Devuelve las cabeceras con Authorization añadida.
    """
    now = dt.datetime.now(dt.timezone.utc)
    amz_date  = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")

    from urllib.parse import urlparse, urlencode, quote, parse_qsl
    parsed = urlparse(url)
    canonical_uri = parsed.path or "/"
    # Ordenar query string
    qs_pairs = sorted(parse_qsl(parsed.query))
    canonical_qs = urlencode([(quote(k, safe=""), quote(v, safe="")) for k, v in qs_pairs])

    payload_hash = hashlib.sha256(payload.encode()).hexdigest()
    headers_to_sign = dict(headers)
    headers_to_sign["x-amz-date"]          = amz_date
    headers_to_sign["x-amz-content-sha256"] = payload_hash
    if "host" not in {k.lower() for k in headers_to_sign}:
        headers_to_sign["Host"] = parsed.netloc

    # Cabeceras canónicas (ordenadas por nombre en minúscula)
    sorted_keys = sorted(headers_to_sign.keys(), key=str.lower)
    canonical_headers = "".join(f"{k.lower()}:{headers_to_sign[k].strip()}\n" for k in sorted_keys)
    signed_headers    = ";".join(k.lower() for k in sorted_keys)

    canonical_request = "\n".join([
        method.upper(),
        canonical_uri,
        canonical_qs,
        canonical_headers,
        signed_headers,
        payload_hash,
    ])

    credential_scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256",
        amz_date,
        credential_scope,
        hashlib.sha256(canonical_request.encode()).hexdigest(),
    ])

    def _sign(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    signing_key = _sign(
        _sign(_sign(_sign(f"AWS4{secret_key}".encode(), datestamp), region), service),
        "aws4_request",
    )
    signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()

    authorization = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    result = dict(headers_to_sign)
    result["Authorization"] = authorization
    return result


class AWSClient:
    """Cliente HTTP asíncrono para llamadas a la API de AWS vía SigV4."""

    def __init__(self, cfg: AWSConfig):
        self.cfg = cfg
        self._session: Optional[Any] = None

    async def __aenter__(self):
        if _AIOHTTP:
            connector = aiohttp.TCPConnector(ssl=True)
            self._session = aiohttp.ClientSession(connector=connector)
        return self

    async def __aexit__(self, *_):
        if self._session:
            await self._session.close()

    # ── llamadas de bajo nivel ───────────────────────────────────────────────

    async def _call(
        self,
        service: str,
        region: str,
        method: str,
        host: str,
        path: str = "/",
        query: str = "",
        body: str = "",
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, str]:
        """Realiza una llamada API firmada con SigV4. Devuelve (status, body)."""
        if not _AIOHTTP:
            raise RuntimeError("aiohttp requerido para las llamadas API")

        url = f"https://{host}{path}"
        if query:
            url += f"?{query}"
        content_type = (
            "application/x-amz-json-1.1"
            if service in ("iam", "guardduty", "config", "kms")
            else "application/x-www-form-urlencoded; charset=utf-8"
        )
        headers = {"Content-Type": content_type, "Host": host}
        if extra_headers:
            headers.update(extra_headers)

        signed = _sigv4(method, url, headers, body,
                        self.cfg.access_key, self.cfg.secret_key, service, region)
        try:
            async with self._session.request(
                method, url, headers=signed, data=body, timeout=aiohttp.ClientTimeout(total=15)
            ) as resp:
                text = await resp.text()
                return resp.status, text
        except Exception as exc:
            return 0, str(exc)

    # ── STS ─────────────────────────────────────────────────────────────────

    async def get_caller_identity(self) -> Optional[Dict[str, str]]:
        """Verifica credenciales y devuelve Account/UserId/Arn."""
        status, body = await self._call(
            "sts", "us-east-1", "POST", "sts.amazonaws.com",
            body="Action=GetCallerIdentity&Version=2011-06-15",
        )
        if status != 200:
            return None
        root = ET.fromstring(body)
        ns = {"aws": root.tag.split("}")[0].strip("{")} if "}" in root.tag else {}
        def _find(tag: str) -> str:
            el = root.find(f".//{'{' + ns['aws'] + '}' if ns else ''}{tag}")
            return el.text if el is not None else ""
        return {"Account": _find("Account"), "UserId": _find("UserId"), "Arn": _find("Arn")}

    # ── IAM ─────────────────────────────────────────────────────────────────

    async def iam_query(self, action: str, extra: str = "") -> Tuple[int, ET.Element]:
        body = f"Action={action}&Version=2010-05-08{('&' + extra) if extra else ''}"
        status, text = await self._call(
            "iam", "us-east-1", "POST", "iam.amazonaws.com", body=body,
        )
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            root = ET.Element("Error")
        return status, root

    # ── S3 ──────────────────────────────────────────────────────────────────

    async def s3_list_buckets(self) -> List[str]:
        status, text = await self._call(
            "s3", "us-east-1", "GET", "s3.amazonaws.com", "/"
        )
        if status != 200:
            return []
        root = ET.fromstring(text)
        ns = "{http://s3.amazonaws.com/doc/2006-03-01/}"
        return [b.find(f"{ns}Name").text for b in root.findall(f".//{ns}Bucket")
                if b.find(f"{ns}Name") is not None]

    async def s3_get_bucket_acl(self, bucket: str) -> Tuple[int, str]:
        host = f"{bucket}.s3.amazonaws.com"
        return await self._call("s3", self.cfg.region, "GET", host, "/?acl")

    async def s3_get_bucket_versioning(self, bucket: str) -> Tuple[int, str]:
        host = f"{bucket}.s3.amazonaws.com"
        return await self._call("s3", self.cfg.region, "GET", host, "/?versioning")

    async def s3_get_bucket_logging(self, bucket: str) -> Tuple[int, str]:
        host = f"{bucket}.s3.amazonaws.com"
        return await self._call("s3", self.cfg.region, "GET", host, "/?logging")

    async def s3_get_bucket_encryption(self, bucket: str) -> Tuple[int, str]:
        host = f"{bucket}.s3.amazonaws.com"
        return await self._call("s3", self.cfg.region, "GET", host, "/?encryption")

    async def s3_get_public_access_block(self, bucket: str) -> Tuple[int, str]:
        host = f"{bucket}.s3.amazonaws.com"
        return await self._call("s3", self.cfg.region, "GET", host, "/?publicAccessBlock")

    # ── EC2 ─────────────────────────────────────────────────────────────────

    async def ec2_query(self, region: str, action: str, extra: str = "") -> Tuple[int, ET.Element]:
        host = f"ec2.{region}.amazonaws.com"
        body = f"Action={action}&Version=2016-11-15{('&' + extra) if extra else ''}"
        status, text = await self._call("ec2", region, "POST", host, body=body)
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            root = ET.Element("Error")
        return status, root

    # ── CloudTrail ──────────────────────────────────────────────────────────

    async def ct_list_trails(self, region: str) -> Tuple[int, str]:
        host = f"cloudtrail.{region}.amazonaws.com"
        body = json.dumps({})
        return await self._call(
            "cloudtrail", region, "POST", host,
            extra_headers={"X-Amz-Target": "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.DescribeTrails"},
            body=body,
        )

    async def ct_get_trail_status(self, region: str, trail_arn: str) -> Tuple[int, str]:
        host = f"cloudtrail.{region}.amazonaws.com"
        body = json.dumps({"Name": trail_arn})
        return await self._call(
            "cloudtrail", region, "POST", host,
            extra_headers={"X-Amz-Target": "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.GetTrailStatus"},
            body=body,
        )

    async def ct_get_event_selectors(self, region: str, trail_arn: str) -> Tuple[int, str]:
        host = f"cloudtrail.{region}.amazonaws.com"
        body = json.dumps({"TrailName": trail_arn})
        return await self._call(
            "cloudtrail", region, "POST", host,
            extra_headers={"X-Amz-Target": "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.GetEventSelectors"},
            body=body,
        )

    # ── CloudWatch / Logs ────────────────────────────────────────────────────

    async def cw_describe_metric_filters(self, region: str, log_group: str) -> Tuple[int, str]:
        host = f"logs.{region}.amazonaws.com"
        body = json.dumps({"logGroupName": log_group})
        return await self._call(
            "logs", region, "POST", host,
            extra_headers={"X-Amz-Target": "Logs_20140328.DescribeMetricFilters"},
            body=body,
        )

    async def cw_describe_alarms_for_metric(self, region: str, metric: str, ns: str) -> Tuple[int, str]:
        host = f"monitoring.{region}.amazonaws.com"
        body = (f"Action=DescribeAlarmsForMetric&Version=2010-08-01"
                f"&MetricName={metric}&Namespace={ns}")
        return await self._call("monitoring", region, "POST", host, body=body)

    # ── RDS ─────────────────────────────────────────────────────────────────

    async def rds_describe_instances(self, region: str) -> Tuple[int, ET.Element]:
        host = f"rds.{region}.amazonaws.com"
        body = "Action=DescribeDBInstances&Version=2014-10-31"
        status, text = await self._call("rds", region, "POST", host, body=body)
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            root = ET.Element("Error")
        return status, root

    # ── KMS ─────────────────────────────────────────────────────────────────

    async def kms_list_keys(self, region: str) -> Tuple[int, str]:
        host = f"kms.{region}.amazonaws.com"
        body = json.dumps({})
        return await self._call(
            "kms", region, "POST", host,
            extra_headers={"X-Amz-Target": "TrentService.ListKeys"},
            body=body,
        )

    async def kms_describe_key(self, region: str, key_id: str) -> Tuple[int, str]:
        host = f"kms.{region}.amazonaws.com"
        body = json.dumps({"KeyId": key_id})
        return await self._call(
            "kms", region, "POST", host,
            extra_headers={"X-Amz-Target": "TrentService.DescribeKey"},
            body=body,
        )

    async def kms_get_key_rotation_status(self, region: str, key_id: str) -> Tuple[int, str]:
        host = f"kms.{region}.amazonaws.com"
        body = json.dumps({"KeyId": key_id})
        return await self._call(
            "kms", region, "POST", host,
            extra_headers={"X-Amz-Target": "TrentService.GetKeyRotationStatus"},
            body=body,
        )

    # ── GuardDuty ───────────────────────────────────────────────────────────

    async def gd_list_detectors(self, region: str) -> Tuple[int, str]:
        host = f"guardduty.{region}.amazonaws.com"
        status, text = await self._call("guardduty", region, "GET", host, "/detector")
        return status, text

    # ── Config ──────────────────────────────────────────────────────────────

    async def config_describe_recorders(self, region: str) -> Tuple[int, str]:
        host = f"config.{region}.amazonaws.com"
        body = json.dumps({})
        return await self._call(
            "config", region, "POST", host,
            extra_headers={"X-Amz-Target": "StarlingDoveService.DescribeConfigurationRecorders"},
            body=body,
        )

    async def config_describe_recorder_status(self, region: str) -> Tuple[int, str]:
        host = f"config.{region}.amazonaws.com"
        body = json.dumps({})
        return await self._call(
            "config", region, "POST", host,
            extra_headers={"X-Amz-Target": "StarlingDoveService.DescribeConfigurationRecorderStatus"},
            body=body,
        )

    async def config_describe_delivery_channels(self, region: str) -> Tuple[int, str]:
        host = f"config.{region}.amazonaws.com"
        body = json.dumps({})
        return await self._call(
            "config", region, "POST", host,
            extra_headers={"X-Amz-Target": "StarlingDoveService.DescribeDeliveryChannels"},
            body=body,
        )


# =============================================================================
# Módulos de auditoría
# =============================================================================

class IAMAuditor:
    """CIS AWS 1.x — Identity and Access Management."""

    def __init__(self, client: AWSClient):
        self.c = client

    async def run(self) -> List[Finding]:
        tasks = [
            self._check_root_mfa(),
            self._check_root_access_keys(),
            self._check_root_no_recent_use(),
            self._check_iam_password_length(),
            self._check_iam_password_uppercase(),
            self._check_iam_password_lowercase(),
            self._check_iam_password_number(),
            self._check_iam_password_symbol(),
            self._check_iam_password_reuse(),
            self._check_iam_password_expiry(),
            self._check_iam_password_expiry_90(),
            self._check_mfa_all_users(),
            self._check_no_inline_policies(),
            self._check_no_full_admin_policies(),
            self._check_access_keys_rotated_90(),
            self._check_access_keys_rotated_180(),
            self._check_unused_credentials(),
            self._check_support_role(),
        ]
        return [r for r in await asyncio.gather(*tasks) if r]

    async def _get_account_summary(self) -> Optional[Dict]:
        _, root = await self.c.iam_query("GetAccountSummary")
        entries = {}
        for entry in root.iter("entry"):
            k = entry.findtext("key", "")
            v = entry.findtext("value", "0")
            entries[k] = int(v) if v.isdigit() else v
        return entries or None

    async def _get_password_policy(self) -> Optional[Dict]:
        status, root = await self.c.iam_query("GetAccountPasswordPolicy")
        if status != 200:
            return None
        pp = root.find(".//{*}PasswordPolicy")
        if pp is None:
            return {}
        return {child.tag.split("}")[-1]: child.text for child in pp}

    async def _check_root_mfa(self) -> Optional[Finding]:
        summary = await self._get_account_summary()
        if summary is None:
            return None
        mfa = summary.get("AccountMFAEnabled", 0)
        return Finding(
            "CIS-1.14", "Cuenta root tiene MFA activado", "CRITICAL",
            Status.PASS if mfa else Status.FAIL,
            resource="root",
            detail="" if mfa else "El acceso a la cuenta root no tiene MFA",
            remediation="Activar MFA virtual o hardware en la cuenta root vía IAM console",
        )

    async def _check_root_access_keys(self) -> Optional[Finding]:
        summary = await self._get_account_summary()
        if summary is None:
            return None
        keys = summary.get("AccountAccessKeysPresent", 0)
        return Finding(
            "CIS-1.4", "Cuenta root no tiene access keys activas", "CRITICAL",
            Status.PASS if not keys else Status.FAIL,
            resource="root",
            detail="" if not keys else "La cuenta root tiene access keys activas — elimínalas",
            remediation="Eliminar todas las access keys de la cuenta root en IAM > Security credentials",
        )

    async def _check_root_no_recent_use(self) -> Optional[Finding]:
        _, root = await self.c.iam_query("GenerateCredentialReport")
        # CIS-1.1: la cuenta root no debería usarse en los últimos 90 días
        return Finding(
            "CIS-1.1", "Cuenta root sin uso reciente (90d)", "HIGH",
            Status.WARN,
            resource="root",
            detail="Verificación manual requerida: revisar último acceso en IAM Credential Report",
            remediation="Revisar IAM > Credential Report y verificar que la columna 'root_last_used' sea >90 días",
        )

    async def _pp_check(self, key: str, expected: Any, check_id: str, title: str,
                        sev: str, detail: str, remediation: str) -> Optional[Finding]:
        pp = await self._get_password_policy()
        if pp is None:
            return Finding(check_id, title, sev, Status.SKIP,
                           detail="No hay política de contraseñas configurada", remediation=remediation)
        val = pp.get(key, "false" if isinstance(expected, bool) else "0")
        if isinstance(expected, bool):
            ok = (val.lower() == "true") == expected
        else:
            try:
                ok = int(val) >= int(expected)
            except (ValueError, TypeError):
                ok = False
        return Finding(check_id, title, sev,
                       Status.PASS if ok else Status.FAIL,
                       detail="" if ok else detail,
                       remediation=remediation)

    async def _check_iam_password_length(self):
        return await self._pp_check(
            "MinimumPasswordLength", 14,
            "CIS-1.8", "Contraseña mínima 14 caracteres", "MEDIUM",
            "MinimumPasswordLength < 14",
            "IAM > Account settings > Set minimum password length to 14",
        )

    async def _check_iam_password_uppercase(self):
        return await self._pp_check(
            "RequireUppercaseCharacters", True,
            "CIS-1.9", "Contraseña requiere mayúsculas", "MEDIUM",
            "RequireUppercaseCharacters = false",
            "IAM > Account settings > Require at least one uppercase letter",
        )

    async def _check_iam_password_lowercase(self):
        return await self._pp_check(
            "RequireLowercaseCharacters", True,
            "CIS-1.10", "Contraseña requiere minúsculas", "MEDIUM",
            "RequireLowercaseCharacters = false",
            "IAM > Account settings > Require at least one lowercase letter",
        )

    async def _check_iam_password_number(self):
        return await self._pp_check(
            "RequireNumbers", True,
            "CIS-1.11", "Contraseña requiere números", "MEDIUM",
            "RequireNumbers = false",
            "IAM > Account settings > Require at least one number",
        )

    async def _check_iam_password_symbol(self):
        return await self._pp_check(
            "RequireSymbols", True,
            "CIS-1.12", "Contraseña requiere símbolos", "MEDIUM",
            "RequireSymbols = false",
            "IAM > Account settings > Require at least one symbol",
        )

    async def _check_iam_password_reuse(self):
        return await self._pp_check(
            "PasswordReusePrevention", 24,
            "CIS-1.9b", "Prevención de reutilización de contraseñas (24)", "MEDIUM",
            "PasswordReusePrevention < 24",
            "IAM > Account settings > Prevent password reuse: 24",
        )

    async def _check_iam_password_expiry(self):
        pp = await self._get_password_policy()
        if pp is None:
            return Finding("CIS-1.13", "Contraseñas con caducidad activada", "MEDIUM",
                           Status.SKIP, detail="Sin política de contraseñas",
                           remediation="Configurar política de contraseñas en IAM")
        expire = pp.get("ExpirePasswords", "false")
        return Finding(
            "CIS-1.13", "Contraseñas con caducidad activada", "MEDIUM",
            Status.PASS if expire.lower() == "true" else Status.FAIL,
            detail="" if expire.lower() == "true" else "ExpirePasswords = false",
            remediation="IAM > Account settings > Enable password expiration",
        )

    async def _check_iam_password_expiry_90(self):
        return await self._pp_check(
            "MaxPasswordAge", 90,
            "CIS-1.13b", "Caducidad máxima de contraseña ≤ 90 días", "MEDIUM",
            "MaxPasswordAge > 90 días",
            "IAM > Account settings > Set maximum password age to 90",
        )

    async def _check_mfa_all_users(self) -> Optional[Finding]:
        _, root = await self.c.iam_query("ListUsers", "MaxItems=100")
        users_no_mfa = []
        for user in root.iter("{*}member"):
            uname = user.findtext("{*}UserName", "")
            if not uname:
                continue
            _, mroot = await self.c.iam_query("ListMFADevices", f"UserName={uname}")
            devices = list(mroot.iter("{*}member"))
            if not devices:
                users_no_mfa.append(uname)
        return Finding(
            "CIS-1.2", "Todos los usuarios IAM tienen MFA", "HIGH",
            Status.PASS if not users_no_mfa else Status.FAIL,
            resource=", ".join(users_no_mfa[:5]),
            detail=f"{len(users_no_mfa)} usuario(s) sin MFA" if users_no_mfa else "",
            remediation="Activar MFA para cada usuario en IAM > Users > [usuario] > Security credentials",
        )

    async def _check_no_inline_policies(self) -> Optional[Finding]:
        _, root = await self.c.iam_query("ListUsers", "MaxItems=100")
        offenders = []
        for user in root.iter("{*}member"):
            uname = user.findtext("{*}UserName", "")
            if not uname:
                continue
            _, pr = await self.c.iam_query("ListUserPolicies", f"UserName={uname}")
            if list(pr.iter("{*}member")):
                offenders.append(uname)
        return Finding(
            "CIS-1.6", "Sin políticas inline en usuarios IAM", "MEDIUM",
            Status.PASS if not offenders else Status.FAIL,
            resource=", ".join(offenders[:5]),
            detail=f"{len(offenders)} usuario(s) con políticas inline" if offenders else "",
            remediation="Migrar políticas inline a políticas gestionadas y eliminarlas del usuario",
        )

    async def _check_no_full_admin_policies(self) -> Optional[Finding]:
        _, root = await self.c.iam_query("ListPolicies", "Scope=Local&OnlyAttached=true")
        risky = []
        for p in root.iter("{*}member"):
            arn = p.findtext("{*}Arn", "")
            if not arn:
                continue
            _, vroot = await self.c.iam_query("GetPolicy", f"PolicyArn={arn}")
            version_id = vroot.findtext(".//{*}DefaultVersionId", "")
            if not version_id:
                continue
            _, doc_root = await self.c.iam_query(
                "GetPolicyVersion", f"PolicyArn={arn}&VersionId={version_id}"
            )
            doc_txt = (doc_root.findtext(".//{*}Document") or "").lower()
            if '"*"' in doc_txt and '"action"' in doc_txt and '"resource"' in doc_txt:
                risky.append(arn.split(":")[-1])
        return Finding(
            "CIS-1.7", "Sin políticas con acceso AdministratorAccess total", "HIGH",
            Status.PASS if not risky else Status.FAIL,
            resource=", ".join(risky[:5]),
            detail=f"{len(risky)} política(s) con Action=* Resource=*" if risky else "",
            remediation="Revisar y restringir políticas con Action:* Resource:* a permisos mínimos",
        )

    async def _check_access_keys_rotated_90(self) -> Optional[Finding]:
        _, root = await self.c.iam_query("ListUsers", "MaxItems=100")
        offenders = []
        cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=90)
        for user in root.iter("{*}member"):
            uname = user.findtext("{*}UserName", "")
            if not uname:
                continue
            _, kr = await self.c.iam_query("ListAccessKeys", f"UserName={uname}")
            for key_meta in kr.iter("{*}member"):
                if key_meta.findtext("{*}Status", "") != "Active":
                    continue
                created_str = key_meta.findtext("{*}CreateDate", "")
                try:
                    created = dt.datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                    if created < cutoff:
                        offenders.append(f"{uname}(>{90}d)")
                except (ValueError, AttributeError):
                    pass
        return Finding(
            "CIS-1.16", "Access keys activas rotadas en 90 días", "HIGH",
            Status.PASS if not offenders else Status.FAIL,
            resource=", ".join(offenders[:5]),
            detail=f"{len(offenders)} access key(s) sin rotar en >90 días" if offenders else "",
            remediation="Rotar access keys en IAM > Users > [usuario] > Security credentials",
        )

    async def _check_access_keys_rotated_180(self) -> Optional[Finding]:
        _, root = await self.c.iam_query("ListUsers", "MaxItems=100")
        offenders = []
        cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=180)
        for user in root.iter("{*}member"):
            uname = user.findtext("{*}UserName", "")
            if not uname:
                continue
            _, kr = await self.c.iam_query("ListAccessKeys", f"UserName={uname}")
            for key_meta in kr.iter("{*}member"):
                if key_meta.findtext("{*}Status", "") != "Active":
                    continue
                created_str = key_meta.findtext("{*}CreateDate", "")
                try:
                    created = dt.datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                    if created < cutoff:
                        offenders.append(f"{uname}(>{180}d)")
                except (ValueError, AttributeError):
                    pass
        return Finding(
            "CIS-1.16b", "Access keys activas rotadas en 180 días", "CRITICAL",
            Status.PASS if not offenders else Status.FAIL,
            resource=", ".join(offenders[:5]),
            detail=f"{len(offenders)} access key(s) sin rotar en >180 días" if offenders else "",
            remediation="Deshabilitar o rotar access keys en IAM de inmediato",
        )

    async def _check_unused_credentials(self) -> Optional[Finding]:
        _, root = await self.c.iam_query("GenerateCredentialReport")
        return Finding(
            "CIS-1.3", "Credenciales no usadas en 90d desactivadas", "HIGH",
            Status.WARN,
            detail="Requiere análisis del Credential Report de IAM",
            remediation="IAM > Credential Report > revisar columnas last_used y deshabilitar inactivas",
        )

    async def _check_support_role(self) -> Optional[Finding]:
        _, root = await self.c.iam_query(
            "ListEntitiesForPolicy",
            "PolicyArn=arn:aws:iam::aws:policy/AWSSupportAccess",
        )
        entities = list(root.iter("{*}policyRoles")) + list(root.iter("{*}policyGroups"))
        has_role = bool(entities) or bool(list(root.iter("{*}roleId")))
        return Finding(
            "CIS-1.17", "Rol de soporte AWS Support existe", "LOW",
            Status.PASS if has_role else Status.FAIL,
            detail="" if has_role else "No existe rol con AWSSupportAccess",
            remediation="Crear un rol IAM con la política AWSSupportAccess gestionada",
        )


class S3Auditor:
    """CIS AWS 2.x — S3 bucket security."""

    def __init__(self, client: AWSClient):
        self.c = client

    async def run(self) -> List[Finding]:
        buckets = await self.c.s3_list_buckets()
        if not buckets:
            return []
        findings = []
        for bucket in buckets:
            findings.extend(await asyncio.gather(
                self._check_acl_no_public(bucket),
                self._check_versioning(bucket),
                self._check_logging(bucket),
                self._check_encryption(bucket),
                self._check_block_public(bucket),
            ))
        return [f for f in findings if f]

    async def _check_acl_no_public(self, bucket: str) -> Optional[Finding]:
        status, body = await self.c.s3_get_bucket_acl(bucket)
        public = "AllUsers" in body or "AuthenticatedUsers" in body if status == 200 else False
        return Finding(
            "CIS-2.1", "S3 bucket sin ACL pública", "CRITICAL",
            Status.FAIL if public else Status.PASS,
            resource=bucket,
            detail=f"El bucket {bucket} tiene ACL pública" if public else "",
            remediation=f"aws s3api put-bucket-acl --bucket {bucket} --acl private",
        )

    async def _check_versioning(self, bucket: str) -> Optional[Finding]:
        status, body = await self.c.s3_get_bucket_versioning(bucket)
        enabled = "Enabled" in body if status == 200 else False
        return Finding(
            "CIS-2.2", "S3 bucket con versionado activado", "MEDIUM",
            Status.PASS if enabled else Status.FAIL,
            resource=bucket,
            detail="" if enabled else f"Versionado desactivado en {bucket}",
            remediation=f"aws s3api put-bucket-versioning --bucket {bucket} --versioning-configuration Status=Enabled",
        )

    async def _check_logging(self, bucket: str) -> Optional[Finding]:
        status, body = await self.c.s3_get_bucket_logging(bucket)
        enabled = "LoggingEnabled" in body if status == 200 else False
        return Finding(
            "CIS-2.6", "S3 bucket con logging de acceso", "MEDIUM",
            Status.PASS if enabled else Status.FAIL,
            resource=bucket,
            detail="" if enabled else f"Logging desactivado en {bucket}",
            remediation="Activar server access logging en S3 > Properties > Server access logging",
        )

    async def _check_encryption(self, bucket: str) -> Optional[Finding]:
        status, body = await self.c.s3_get_bucket_encryption(bucket)
        encrypted = status == 200 and "ServerSideEncryptionConfiguration" in body
        return Finding(
            "CIS-2.7", "S3 bucket con cifrado en reposo", "HIGH",
            Status.PASS if encrypted else Status.FAIL,
            resource=bucket,
            detail="" if encrypted else f"Sin cifrado en {bucket}",
            remediation="aws s3api put-bucket-encryption --bucket BUCKET --server-side-encryption-configuration ...",
        )

    async def _check_block_public(self, bucket: str) -> Optional[Finding]:
        status, body = await self.c.s3_get_public_access_block(bucket)
        if status != 200:
            return None
        all_blocked = (
            "true" in body.lower()
            and body.lower().count("<blockpublicacls>true") >= 1
        )
        return Finding(
            "CIS-2.1b", "S3 BlockPublicAccess activado", "HIGH",
            Status.PASS if all_blocked else Status.FAIL,
            resource=bucket,
            detail="" if all_blocked else f"Block Public Access no completamente activado en {bucket}",
            remediation=f"aws s3api put-public-access-block --bucket {bucket} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
        )


class EC2Auditor:
    """CIS AWS 5.x — EC2/VPC network security."""

    def __init__(self, client: AWSClient):
        self.c = client

    async def run(self) -> List[Finding]:
        region = self.c.cfg.region
        tasks = [
            self._check_default_sg(region),
            self._check_vpc_flow_logs(region),
            self._check_no_sg_all_traffic(region),
            self._check_ssh_restricted(region),
            self._check_rdp_restricted(region),
            self._check_ebs_default_encryption(region),
        ]
        return [r for r in await asyncio.gather(*tasks) if r]

    async def _check_default_sg(self, region: str) -> Optional[Finding]:
        _, root = await self.c.ec2_query(
            region, "DescribeSecurityGroups",
            "Filter.1.Name=group-name&Filter.1.Value.1=default"
        )
        ns = "{http://ec2.amazonaws.com/doc/2016-11-15/}"
        ingress_rules = list(root.iter(f"{ns}ipPermissions"))
        egress_rules  = list(root.iter(f"{ns}ipPermissionsEgress"))
        # Si la SG default tiene reglas, es un FAIL
        has_rules = bool(ingress_rules) or bool(egress_rules)
        return Finding(
            "CIS-5.4", "Security group 'default' sin reglas de tráfico", "HIGH",
            Status.FAIL if has_rules else Status.PASS,
            resource=f"default SG ({region})",
            detail=f"El SG 'default' tiene {len(ingress_rules)} reglas de entrada" if has_rules else "",
            remediation="Eliminar todas las reglas del SG 'default' y crear SGs explícitos",
        )

    async def _check_vpc_flow_logs(self, region: str) -> Optional[Finding]:
        _, root = await self.c.ec2_query(region, "DescribeFlowLogs")
        ns = "{http://ec2.amazonaws.com/doc/2016-11-15/}"
        logs = [fl for fl in root.iter(f"{ns}item")
                if fl.findtext(f"{ns}flowLogStatus") == "ACTIVE"]
        return Finding(
            "CIS-2.9", "VPC Flow Logs activados", "MEDIUM",
            Status.PASS if logs else Status.FAIL,
            resource=region,
            detail="" if logs else "No hay VPC Flow Logs activos en esta región",
            remediation="VPC > Actions > Create flow log → destino CloudWatch Logs o S3",
        )

    async def _check_no_sg_all_traffic(self, region: str) -> Optional[Finding]:
        _, root = await self.c.ec2_query(region, "DescribeSecurityGroups")
        ns = "{http://ec2.amazonaws.com/doc/2016-11-15/}"
        offenders = []
        for sg in root.iter(f"{ns}item"):
            sg_id = sg.findtext(f"{ns}groupId", "")
            for perm in sg.iter(f"{ns}ipPermissions"):
                for ip_range in perm.iter(f"{ns}item"):
                    cidr = ip_range.findtext(f"{ns}cidrIp", "")
                    if cidr == "0.0.0.0/0" and perm.findtext(f"{ns}fromPort") == "-1":
                        offenders.append(sg_id)
        return Finding(
            "CIS-5.1", "Sin SG con todo el tráfico abierto (0.0.0.0/0 all)", "HIGH",
            Status.FAIL if offenders else Status.PASS,
            resource=", ".join(offenders[:5]),
            detail=f"{len(offenders)} SG(s) con ingress 0.0.0.0/0 all" if offenders else "",
            remediation="Restringir reglas de entrada en los SGs afectados",
        )

    async def _check_ssh_restricted(self, region: str) -> Optional[Finding]:
        return await self._port_open_to_world(region, 22, "CIS-5.2", "SSH (22) no expuesto a 0.0.0.0/0")

    async def _check_rdp_restricted(self, region: str) -> Optional[Finding]:
        return await self._port_open_to_world(region, 3389, "CIS-5.3", "RDP (3389) no expuesto a 0.0.0.0/0")

    async def _port_open_to_world(self, region: str, port: int, cid: str, title: str) -> Optional[Finding]:
        _, root = await self.c.ec2_query(region, "DescribeSecurityGroups")
        ns = "{http://ec2.amazonaws.com/doc/2016-11-15/}"
        offenders = []
        for sg in root.iter(f"{ns}item"):
            sg_id = sg.findtext(f"{ns}groupId", "")
            for ip_perms in sg.findall(f"{ns}ipPermissions"):
                for perm in ip_perms.iter(f"{ns}item"):
                    from_p = perm.findtext(f"{ns}fromPort", "-1")
                    to_p   = perm.findtext(f"{ns}toPort",   "-1")
                    for ip_range in perm.findall(f".//{ns}cidrIp"):
                        cidr = ip_range.text or ""
                        if cidr in ("0.0.0.0/0", "::/0"):
                            try:
                                if int(from_p) <= port <= int(to_p):
                                    offenders.append(sg_id)
                            except (ValueError, TypeError):
                                pass
        return Finding(
            cid, title, "HIGH",
            Status.FAIL if offenders else Status.PASS,
            resource=", ".join(offenders[:5]),
            detail=f"Puerto {port} expuesto en {len(offenders)} SG(s)" if offenders else "",
            remediation=f"Restringir el acceso al puerto {port} a IPs de gestión conocidas",
        )

    async def _check_ebs_default_encryption(self, region: str) -> Optional[Finding]:
        _, root = await self.c.ec2_query(region, "GetEbsEncryptionByDefault")
        ns = "{http://ec2.amazonaws.com/doc/2016-11-15/}"
        val = root.findtext(f".//{ns}ebsEncryptionByDefault", "false")
        enabled = val.lower() == "true"
        return Finding(
            "CIS-2.7b", "EBS cifrado por defecto activado", "MEDIUM",
            Status.PASS if enabled else Status.FAIL,
            resource=region,
            detail="" if enabled else "EBS cifrado por defecto no activado",
            remediation="EC2 > Settings > Manage EBS encryption > Enable",
        )


class CloudTrailAuditor:
    """CIS AWS 3.x — Logging con CloudTrail."""

    def __init__(self, client: AWSClient):
        self.c = client

    async def run(self) -> List[Finding]:
        region = self.c.cfg.region
        status, body = await self.c.ct_list_trails(region)
        if status != 200:
            return [Finding("CIS-3.1", "CloudTrail multi-región activo", "CRITICAL",
                            Status.ERROR, detail="No se pudo consultar CloudTrail")]
        try:
            data = json.loads(body)
            trails = data.get("trailList", [])
        except (json.JSONDecodeError, KeyError):
            trails = []

        findings = await asyncio.gather(
            self._check_multiregion_trail(trails, region),
            self._check_log_validation(trails),
            self._check_s3_not_public(trails),
            self._check_cloudwatch_integration(trails, region),
        )
        return [f for f in findings if f]

    async def _check_multiregion_trail(self, trails: list, region: str) -> Optional[Finding]:
        multi = [t for t in trails if t.get("IsMultiRegionTrail") and t.get("HasCustomEventSelectors")]
        return Finding(
            "CIS-3.1", "CloudTrail multi-región activo", "CRITICAL",
            Status.PASS if multi else Status.FAIL,
            detail="" if multi else "No hay ningún trail multi-región activo",
            remediation="CloudTrail > Create trail > Apply trail to all regions: Yes",
        )

    async def _check_log_validation(self, trails: list) -> Optional[Finding]:
        offenders = [t.get("Name", "?") for t in trails if not t.get("LogFileValidationEnabled")]
        return Finding(
            "CIS-3.2", "CloudTrail con validación de integridad de logs", "HIGH",
            Status.PASS if not offenders else Status.FAIL,
            resource=", ".join(offenders[:5]),
            detail=f"{len(offenders)} trail(s) sin validación de integridad" if offenders else "",
            remediation="CloudTrail > [trail] > Edit > Enable log file validation",
        )

    async def _check_s3_not_public(self, trails: list) -> Optional[Finding]:
        # Comprobación conceptual: asegurarse de que el bucket del trail no sea público
        buckets = {t.get("S3BucketName", "") for t in trails if t.get("S3BucketName")}
        offenders = []
        for bucket in buckets:
            if not bucket:
                continue
            s_code, body = await self.c.s3_get_bucket_acl(bucket)
            if s_code == 200 and ("AllUsers" in body or "AuthenticatedUsers" in body):
                offenders.append(bucket)
        return Finding(
            "CIS-3.6", "Bucket S3 de CloudTrail no es público", "CRITICAL",
            Status.PASS if not offenders else Status.FAIL,
            resource=", ".join(offenders[:5]),
            detail=f"{len(offenders)} bucket(s) de logs CloudTrail son públicos" if offenders else "",
            remediation="Poner el bucket de CloudTrail como privado inmediatamente",
        )

    async def _check_cloudwatch_integration(self, trails: list, region: str) -> Optional[Finding]:
        has_cw = any(t.get("CloudWatchLogsLogGroupArn") for t in trails)
        return Finding(
            "CIS-3.4", "CloudTrail integrado con CloudWatch Logs", "MEDIUM",
            Status.PASS if has_cw else Status.FAIL,
            detail="" if has_cw else "Ningún trail envía logs a CloudWatch Logs",
            remediation="CloudTrail > [trail] > Edit > CloudWatch Logs: enabled",
        )


class RDSAuditor:
    """CIS AWS — RDS security checks."""

    def __init__(self, client: AWSClient):
        self.c = client

    async def run(self) -> List[Finding]:
        region = self.c.cfg.region
        status, root = await self.c.rds_describe_instances(region)
        if status != 200:
            return []
        ns = "{http://rds.amazonaws.com/doc/2014-10-31/}"
        instances = list(root.iter(f"{ns}DBInstance"))
        findings = []
        for inst in instances[:20]:  # límite por seguridad
            db_id = inst.findtext(f"{ns}DBInstanceIdentifier", "?")
            findings.extend(await asyncio.gather(
                self._check_not_public(inst, db_id, ns),
                self._check_encryption(inst, db_id, ns),
                self._check_auto_minor_upgrade(inst, db_id, ns),
                self._check_backup_retention(inst, db_id, ns),
                self._check_deletion_protection(inst, db_id, ns),
            ))
        return [f for f in findings if f]

    async def _check_not_public(self, inst, db_id, ns) -> Optional[Finding]:
        public = inst.findtext(f"{ns}PubliclyAccessible", "false").lower() == "true"
        return Finding(
            "CIS-RDS-1", "RDS no accesible públicamente", "CRITICAL",
            Status.FAIL if public else Status.PASS,
            resource=db_id,
            detail=f"{db_id} es accesible públicamente" if public else "",
            remediation=f"aws rds modify-db-instance --db-instance-identifier {db_id} --no-publicly-accessible",
        )

    async def _check_encryption(self, inst, db_id, ns) -> Optional[Finding]:
        encrypted = inst.findtext(f"{ns}StorageEncrypted", "false").lower() == "true"
        return Finding(
            "CIS-RDS-2", "RDS con cifrado en reposo", "HIGH",
            Status.PASS if encrypted else Status.FAIL,
            resource=db_id,
            detail="" if encrypted else f"{db_id} sin cifrado en reposo",
            remediation="Crear snapshot → restaurar con cifrado KMS activado",
        )

    async def _check_auto_minor_upgrade(self, inst, db_id, ns) -> Optional[Finding]:
        auto = inst.findtext(f"{ns}AutoMinorVersionUpgrade", "false").lower() == "true"
        return Finding(
            "CIS-RDS-3", "RDS con actualizaciones automáticas de versión menor", "LOW",
            Status.PASS if auto else Status.FAIL,
            resource=db_id,
            detail="" if auto else f"{db_id} sin actualizaciones automáticas de motor",
            remediation=f"aws rds modify-db-instance --db-instance-identifier {db_id} --auto-minor-version-upgrade",
        )

    async def _check_backup_retention(self, inst, db_id, ns) -> Optional[Finding]:
        try:
            retention = int(inst.findtext(f"{ns}BackupRetentionPeriod", "0"))
        except (ValueError, TypeError):
            retention = 0
        return Finding(
            "CIS-RDS-4", "RDS con retención de backup ≥ 7 días", "MEDIUM",
            Status.PASS if retention >= 7 else Status.FAIL,
            resource=db_id,
            detail="" if retention >= 7 else f"{db_id} tiene retención de {retention} días",
            remediation=f"aws rds modify-db-instance --db-instance-identifier {db_id} --backup-retention-period 7",
        )

    async def _check_deletion_protection(self, inst, db_id, ns) -> Optional[Finding]:
        protected = inst.findtext(f"{ns}DeletionProtection", "false").lower() == "true"
        return Finding(
            "CIS-RDS-5", "RDS con protección de borrado activa", "MEDIUM",
            Status.PASS if protected else Status.FAIL,
            resource=db_id,
            detail="" if protected else f"{db_id} sin protección de borrado",
            remediation=f"aws rds modify-db-instance --db-instance-identifier {db_id} --deletion-protection",
        )


class KMSAuditor:
    """CIS AWS — KMS key management."""

    def __init__(self, client: AWSClient):
        self.c = client

    async def run(self) -> List[Finding]:
        region = self.c.cfg.region
        status, body = await self.c.kms_list_keys(region)
        if status != 200:
            return []
        try:
            keys = json.loads(body).get("Keys", [])
        except (json.JSONDecodeError, AttributeError):
            return []
        findings = []
        for key in keys[:20]:
            kid = key.get("KeyId", "")
            findings.extend(await asyncio.gather(
                self._check_rotation(region, kid),
                self._check_not_pending_delete(region, kid),
            ))
        return [f for f in findings if f]

    async def _check_rotation(self, region: str, key_id: str) -> Optional[Finding]:
        status, body = await self.c.kms_get_key_rotation_status(region, key_id)
        if status != 200:
            return None
        try:
            rotating = json.loads(body).get("KeyRotationEnabled", False)
        except (json.JSONDecodeError, AttributeError):
            rotating = False
        return Finding(
            "CIS-3.7", "KMS key con rotación automática activada", "MEDIUM",
            Status.PASS if rotating else Status.FAIL,
            resource=key_id[:12] + "…",
            detail="" if rotating else f"Key {key_id[:12]}… sin rotación automática",
            remediation=f"aws kms enable-key-rotation --key-id {key_id}",
        )

    async def _check_not_pending_delete(self, region: str, key_id: str) -> Optional[Finding]:
        status, body = await self.c.kms_describe_key(region, key_id)
        if status != 200:
            return None
        try:
            state = json.loads(body).get("KeyMetadata", {}).get("KeyState", "")
        except (json.JSONDecodeError, AttributeError):
            state = ""
        pending = state == "PendingDeletion"
        if not pending:
            return None
        return Finding(
            "CIS-KMS-1", "KMS key en estado PendingDeletion inesperado", "HIGH",
            Status.WARN,
            resource=key_id[:12] + "…",
            detail=f"Key {key_id[:12]}… está pendiente de borrado",
            remediation="Revisar y cancelar la eliminación si es inesperada: aws kms cancel-key-deletion",
        )


class GuardDutyAuditor:
    """CIS AWS — GuardDuty threat detection."""

    def __init__(self, client: AWSClient):
        self.c = client

    async def run(self) -> List[Finding]:
        region = self.c.cfg.region
        status, body = await self.c.gd_list_detectors(region)
        if status == 403:
            return [Finding("CIS-GD-1", "GuardDuty activado", "HIGH",
                            Status.SKIP, resource=region,
                            detail="Sin permisos para consultar GuardDuty")]
        try:
            data = json.loads(body)
            detector_ids = data.get("detectorIds", [])
        except (json.JSONDecodeError, AttributeError):
            detector_ids = []

        enabled = bool(detector_ids)
        return [Finding(
            "CIS-GD-1", "GuardDuty activado en la región", "HIGH",
            Status.PASS if enabled else Status.FAIL,
            resource=region,
            detail="" if enabled else f"GuardDuty no tiene detectores activos en {region}",
            remediation="GuardDuty > Get started > Enable GuardDuty",
        )]


class ConfigAuditor:
    """CIS AWS — AWS Config recorder."""

    def __init__(self, client: AWSClient):
        self.c = client

    async def run(self) -> List[Finding]:
        region = self.c.cfg.region
        tasks = [
            self._check_recorder_active(region),
            self._check_delivery_channel(region),
        ]
        return [r for r in await asyncio.gather(*tasks) if r]

    async def _check_recorder_active(self, region: str) -> Optional[Finding]:
        status, body = await self.c.config_describe_recorder_status(region)
        if status != 200:
            return Finding("CIS-2.5", "AWS Config recorder activo", "MEDIUM",
                           Status.SKIP, resource=region)
        try:
            recorders = json.loads(body).get("ConfigurationRecordersStatus", [])
        except (json.JSONDecodeError, AttributeError):
            recorders = []
        recording = any(r.get("recording") for r in recorders)
        return Finding(
            "CIS-2.5", "AWS Config recorder activo", "MEDIUM",
            Status.PASS if recording else Status.FAIL,
            resource=region,
            detail="" if recording else "AWS Config no está grabando cambios",
            remediation="AWS Config > Settings > Turn on recording",
        )

    async def _check_delivery_channel(self, region: str) -> Optional[Finding]:
        status, body = await self.c.config_describe_delivery_channels(region)
        if status != 200:
            return None
        try:
            channels = json.loads(body).get("DeliveryChannels", [])
        except (json.JSONDecodeError, AttributeError):
            channels = []
        has_s3 = any(c.get("s3BucketName") for c in channels)
        return Finding(
            "CIS-2.5b", "AWS Config con canal de entrega a S3", "LOW",
            Status.PASS if has_s3 else Status.FAIL,
            resource=region,
            detail="" if has_s3 else "No hay canal de entrega de Config configurado",
            remediation="AWS Config > Settings > S3 bucket destination",
        )


# =============================================================================
# Motor principal
# =============================================================================

class AWSAuditor:
    """Orquesta todos los módulos y agrega los findings."""

    MODULES = {
        "iam":        IAMAuditor,
        "s3":         S3Auditor,
        "ec2":        EC2Auditor,
        "cloudtrail": CloudTrailAuditor,
        "rds":        RDSAuditor,
        "kms":        KMSAuditor,
        "guardduty":  GuardDutyAuditor,
        "config":     ConfigAuditor,
    }

    def __init__(self, cfg: AWSConfig, modules: Optional[List[str]] = None):
        self.cfg     = cfg
        self.modules = modules or list(self.MODULES.keys())

    async def run(self) -> List[Finding]:
        async with AWSClient(self.cfg) as client:
            identity = await client.get_caller_identity()
            if not identity:
                print("[ERROR] Credenciales AWS inválidas o sin conectividad", file=sys.stderr)
                sys.exit(1)
            if console:
                console.print(f"[bold green]  ✓ Autenticado:[/] {identity.get('Arn', '?')}")

            tasks = []
            for mod_name in self.modules:
                cls = self.MODULES.get(mod_name)
                if cls:
                    tasks.append(cls(client).run())
            results = await asyncio.gather(*tasks)
        return [f for batch in results for f in batch]


# =============================================================================
# Output
# =============================================================================

def _print_findings(findings: List[Finding], fmt: str) -> None:
    if fmt == "json":
        print(json.dumps([
            {
                "check_id":    f.check_id,
                "title":       f.title,
                "severity":    f.severity,
                "status":      f.status.value,
                "resource":    f.resource,
                "region":      f.region,
                "detail":      f.detail,
                "remediation": f.remediation,
            }
            for f in findings
        ], indent=2, ensure_ascii=False))
        return

    if not _RICH:
        for f in findings:
            icon = "✓" if f.status == Status.PASS else "✗"
            print(f"  [{f.severity}] {icon} {f.check_id}: {f.title}")
        return

    # rich output
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    fails = sorted(
        [f for f in findings if f.status in (Status.FAIL, Status.WARN, Status.ERROR)],
        key=lambda f: sev_order.get(f.severity, 9),
    )
    passes = [f for f in findings if f.status == Status.PASS]
    skips  = [f for f in findings if f.status == Status.SKIP]

    table = Table(title="vamp-aws-audit — Hallazgos", show_header=True, header_style="bold")
    table.add_column("ID",         style="dim", width=14)
    table.add_column("Sev.",       width=10)
    table.add_column("Estado",     width=8)
    table.add_column("Control",    width=42)
    table.add_column("Recurso",    width=24)
    table.add_column("Detalle",    overflow="fold")

    for f in fails:
        color = SEV_COLOR.get(f.severity, "white")
        table.add_row(
            f.check_id,
            f"[{color}]{f.severity}[/]",
            f"[red]{f.status.value}[/]",
            f.title,
            f.resource or "-",
            f.detail or "-",
        )

    console.print(table)

    crit  = sum(1 for f in fails if f.severity == "CRITICAL")
    high  = sum(1 for f in fails if f.severity == "HIGH")
    med   = sum(1 for f in fails if f.severity == "MEDIUM")
    low   = sum(1 for f in fails if f.severity == "LOW")

    summary = (
        f"[bold]Total:[/] {len(findings)} controles  "
        f"[red]{crit} CRITICAL[/]  [orange1]{high} HIGH[/]  "
        f"[yellow]{med} MEDIUM[/]  [green]{low} LOW[/]  "
        f"✓ {len(passes)} PASS  – {len(skips)} SKIP"
    )
    console.print(Panel(summary, title="Resumen", expand=False))

    if fails:
        console.print("\n[bold]Remediaciones (FAIL/WARN):[/]")
        for f in fails[:10]:
            if f.remediation:
                console.print(f"  [dim]{f.check_id}[/] → {f.remediation}")


# =============================================================================
# CLI
# =============================================================================

def _parse_args():
    import argparse
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=f"vamp-aws-audit v{VERSION} — Auditor CIS AWS Level 1",
    )
    p.add_argument("--access-key", help="AWS Access Key ID (o AWS_ACCESS_KEY_ID)")
    p.add_argument("--secret-key", help="AWS Secret Access Key (o AWS_SECRET_ACCESS_KEY)")
    p.add_argument("--region",     default="us-east-1", help="Región AWS (default: us-east-1)")
    p.add_argument("--modules",    nargs="+",
                   choices=list(AWSAuditor.MODULES.keys()),
                   help="Módulos a ejecutar (default: todos)")
    p.add_argument("--fmt",        choices=["rich", "json"], default="rich",
                   help="Formato de salida (default: rich)")
    p.add_argument("--out",        help="Fichero JSON de salida")
    p.add_argument("--version",    action="version", version=f"{TOOL_NAME} v{VERSION}")
    return p.parse_args()


async def _main():
    args = _parse_args()

    access_key = args.access_key or os.environ.get("AWS_ACCESS_KEY_ID", "")
    secret_key = args.secret_key or os.environ.get("AWS_SECRET_ACCESS_KEY", "")

    if not access_key or not secret_key:
        print(
            "ERROR: Se requieren credenciales AWS.\n"
            "  --access-key / --secret-key  o  AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY",
            file=sys.stderr,
        )
        sys.exit(1)

    if not _AIOHTTP:
        print("ERROR: Instala aiohttp: pip install aiohttp", file=sys.stderr)
        sys.exit(1)

    cfg = AWSConfig(access_key=access_key, secret_key=secret_key, region=args.region)
    auditor = AWSAuditor(cfg, args.modules)

    if console:
        console.print(f"[bold]{TOOL_NAME} v{VERSION}[/] — CIS AWS Level 1 · {len(AWSAuditor.MODULES)} módulos")
        console.print(f"  Región: [cyan]{args.region}[/]  "
                      f"Módulos: [cyan]{', '.join(args.modules or list(AWSAuditor.MODULES.keys()))}[/]\n")

    findings = await auditor.run()
    _print_findings(findings, args.fmt)

    if args.out:
        out_data = [
            {
                "check_id":    f.check_id,
                "title":       f.title,
                "severity":    f.severity,
                "status":      f.status.value,
                "resource":    f.resource,
                "detail":      f.detail,
                "remediation": f.remediation,
            }
            for f in findings
        ]
        import pathlib
        pathlib.Path(args.out).write_text(json.dumps(out_data, indent=2, ensure_ascii=False))
        if console:
            console.print(f"  → JSON guardado en {args.out}")

    # Código de salida: 2 si hay CRITICALes, 1 si hay HIGHs, 0 si todo OK
    crits = sum(1 for f in findings if f.status in (Status.FAIL,) and f.severity == "CRITICAL")
    highs = sum(1 for f in findings if f.status in (Status.FAIL,) and f.severity == "HIGH")
    sys.exit(2 if crits else 1 if highs else 0)


if __name__ == "__main__":
    asyncio.run(_main())

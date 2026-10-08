<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->

<img src="https://github.com/Vampsecure-Labs/vamp-aws-audit/actions/workflows/ci.yml/badge.svg" alt="CI"/>

# vamp-aws-audit

**VampSecure Labs · Security Research Division**

Auditor de seguridad CIS AWS Foundations Benchmark Level 1 con **71 controles** distribuidos en 8 módulos. Implementa AWS Signature Version 4 desde cero con `hmac+hashlib` — sin dependencias externas más allá de `aiohttp` y `rich`.

---

## Módulos

| Módulo       | Controles | Sección CIS              |
|-------------|-----------|--------------------------|
| IAM         | 18        | CIS 1.x                  |
| S3          | 5×bucket  | CIS 2.1, 2.2, 2.6, 2.7  |
| EC2/VPC     | 6         | CIS 5.x                  |
| CloudTrail  | 4         | CIS 3.x                  |
| RDS         | 5×instancia| —                       |
| KMS         | 2×clave   | CIS 3.7                  |
| GuardDuty   | 1         | —                        |
| Config      | 2         | CIS 2.5                  |

---

## Instalación

```bash
pip install vamp-aws-audit
# o con Homebrew:
brew install vampsecure-labs/labs/vamp-aws-audit
```

```bash
pip install -r requirements.txt   # aiohttp rich
```

**Requisitos:** Python 3.11+

---

## Uso

```bash
# Variables de entorno (recomendado)
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
python vamp_aws_audit.py --region eu-west-1

# O pasar las credenciales por argumento
python vamp_aws_audit.py --access-key AKIA... --secret-key ... --region us-east-1

# Solo módulos IAM y S3, salida JSON
python vamp_aws_audit.py --modules iam s3 --fmt json --out report.json

# Solo módulo EC2
python vamp_aws_audit.py --modules ec2
```

### Argumentos

| Argumento        | Descripción                                   |
|-----------------|-----------------------------------------------|
| `--access-key`  | AWS Access Key ID                             |
| `--secret-key`  | AWS Secret Access Key                         |
| `--region`      | Región AWS (default: `us-east-1`)             |
| `--modules`     | Módulos a ejecutar: `iam s3 ec2 cloudtrail rds kms guardduty config` |
| `--fmt`         | Formato de salida: `rich` (default) o `json`  |
| `--out FILE`    | Guardar findings en JSON                      |

---

## Sample Output

```
  vamp-aws-audit v1.0 · CIS AWS Level 1 · 8 módulos
  Región: us-east-1  Módulos: iam, s3, ec2, cloudtrail, rds, kms, guardduty, config
  ✓ Autenticado: arn:aws:iam::123456789012:user/auditor

                    vamp-aws-audit — Hallazgos
  ┌──────────────┬──────────┬────────┬──────────────────────────────────┐
  │ ID           │ Sev.     │ Estado │ Control                          │
  ├──────────────┼──────────┼────────┼──────────────────────────────────┤
  │ CIS-1.14     │ CRITICAL │ FAIL   │ Cuenta root tiene MFA activado   │
  │ CIS-1.4      │ CRITICAL │ FAIL   │ Cuenta root no tiene access keys │
  │ CIS-1.2      │ HIGH     │ FAIL   │ Todos los usuarios IAM tienen MFA│
  │ CIS-3.1      │ CRITICAL │ FAIL   │ CloudTrail multi-región activo   │
  │ CIS-GD-1     │ HIGH     │ FAIL   │ GuardDuty activado en la región  │
  │ CIS-2.5      │ MEDIUM   │ FAIL   │ AWS Config recorder activo       │
  └──────────────┴──────────┴────────┴──────────────────────────────────┘

  Total: 48 controles  3 CRITICAL  8 HIGH  12 MEDIUM  4 LOW  ✓ 21 PASS  – 0 SKIP

  Remediaciones (FAIL/WARN):
    CIS-1.14 → Activar MFA virtual o hardware en la cuenta root vía IAM console
    CIS-1.4  → Eliminar todas las access keys de la cuenta root en IAM > Security credentials
    CIS-3.1  → CloudTrail > Create trail > Apply trail to all regions: Yes
```

---

## Exit codes

| Código | Significado                     |
|--------|---------------------------------|
| `0`    | Sin hallazgos CRITICAL o HIGH   |
| `1`    | Al menos un hallazgo HIGH       |
| `2`    | Al menos un hallazgo CRITICAL   |

---

## Sin dependencias AWS SDK

Este auditor **no usa boto3** ni ninguna librería de AWS SDK. Implementa AWS Signature Version 4 directamente con `hmac` y `hashlib` de la stdlib. La única dependencia HTTP es `aiohttp` para las llamadas asíncronas.

---

## Referencias

- [CIS Amazon Web Services Foundations Benchmark v3.0.0](https://www.cisecurity.org/benchmark/amazon_web_services)
- [AWS IAM Credential Report](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html)
- [AWS Signature Version 4](https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html)

---

© VampSecure Studios — VampSecure Labs Security Research Division  
Uso exclusivo en auditorías autorizadas. El uso no autorizado es ilegal.

---

## Why vamp-aws-audit vs Prowler · ScoutSuite · CloudSploit

| Feature | vamp-aws-audit | Prowler | ScoutSuite | CloudSploit |
|---------|----------------|---------|------------|-------------|
| Zero AWS SDK dependency (no boto3) | ✅ | ❌ (boto3) | ❌ (boto3) | ❌ (AWS SDK) |
| Native SigV4 via stdlib (hmac+hashlib) | ✅ | ❌ | ❌ | ❌ |
| CIS AWS Foundations Benchmark v3.0.0 | ✅ 71 controls | ✅ | ✅ | ⚠️ partial |
| Async aiohttp (parallel module execution) | ✅ | ⚠️ | ⚠️ | ❌ |
| Air-gap / offline capable | ✅ | ❌ | ❌ | ❌ |
| VSL client report (HTML/PDF) | ✅ | ⚠️ HTML | ⚠️ HTML | ✅ (SaaS) |
| CI/CD exit codes (0/1/2) | ✅ | ✅ | ⚠️ | ⚠️ |
| Multi-cloud coverage | ❌ (AWS only) | ✅ | ✅ | ✅ |
| License | AGPL-3.0 | Apache 2.0 | GPL-2.0 | AGPL-3.0 |

**Key differentiators:**

- **No boto3, no AWS CLI**: implements AWS Signature Version 4 natively with `hmac`+`hashlib` from the Python stdlib. Runs in any minimal Python environment without installing the AWS SDK or configuring credential profiles.
- **Air-gap friendly**: the only network requirement is connectivity to AWS API endpoints. No package manager calls, no metadata token fetches — a single `pip install aiohttp rich` is the full dependency surface.
- **71 CIS Level 1 controls in one async pass**: IAM credential hygiene, S3 public access, CloudTrail multi-region, VPC security groups, RDS encryption, KMS key rotation, and GuardDuty status — all covered in a single run.
- **Deterministic CI/CD exit codes**: `0` (clean), `1` (HIGH findings), `2` (CRITICAL findings) — a clean integration point for Forgejo/GitHub Actions gates without parsing JSON output.

## Check Coverage

| Check ID | Description | Standard | Severity |
|----------|-------------|----------|----------|
| CIS-1.4 | Root account has active access keys | CIS AWS 1.4 / NIST SP 800-53 AC-2 | CRITICAL |
| CIS-1.14 | Root account does not have MFA enabled | CIS AWS 1.14 / NIST SP 800-53 IA-5 | CRITICAL |
| CIS-1.2 | IAM user without MFA enabled | CIS AWS 1.2 / NIST SP 800-53 IA-5 | HIGH |
| CIS-1.3 | IAM credentials unused for 90+ days not disabled | CIS AWS 1.3 / NIST SP 800-53 AC-2 | HIGH |
| CIS-1.5 | IAM password policy: minimum password length below 14 | CIS AWS 1.5 / NIST SP 800-63B §5.1.1 | MEDIUM |
| CIS-2.1.5 | S3 bucket with public access block not enabled | CIS AWS 2.1.5 / NIST SP 800-53 AC-3 | HIGH |
| CIS-2.2.1 | S3 bucket without server-side encryption enabled | CIS AWS 2.2.1 / NIST SP 800-53 SC-28 | MEDIUM |
| CIS-3.1 | CloudTrail not enabled across all AWS regions | CIS AWS 3.1 / NIST SP 800-53 AU-2 | CRITICAL |
| CIS-3.7 | CloudTrail log files not encrypted with a KMS CMK | CIS AWS 3.7 / NIST SP 800-53 AU-9 | MEDIUM |
| CIS-5.1 | Default VPC security group allows all inbound or outbound traffic | CIS AWS 5.1 / NIST SP 800-53 SC-7 | HIGH |
| CIS-5.2 | SSH port 22 open to `0.0.0.0/0` in a security group | CIS AWS 5.2 / NIST SP 800-53 SC-7 | CRITICAL |
| CIS-GD-1 | GuardDuty not enabled in the audited region | AWS Well-Architected SEC 1 / NIST SP 800-53 SI-4 | HIGH |

## Versión
v1.0.0 — VampSecure Labs Security Research Division

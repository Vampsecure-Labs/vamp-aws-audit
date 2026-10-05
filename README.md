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

## Versión
v1.0.0 — VampSecure Labs Security Research Division

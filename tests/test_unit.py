# © VampSecure Studios — VampSecure Labs Security Research Division
"""
Tests unitarios para vamp-aws-audit.

Ejecutar: pytest tests/test_unit.py -v -m "not integration"
"""
import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from vamp_aws_audit import (
    AWSConfig,
    AWSClient,
    Finding,
    Status,
    IAMAuditor,
    S3Auditor,
    EC2Auditor,
    RDSAuditor,
    KMSAuditor,
    GuardDutyAuditor,
    ConfigAuditor,
    _sigv4,
    AWSAuditor,
)


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def cfg():
    return AWSConfig(
        access_key="FAKEACCESSKEYFORTESTS01",
        secret_key="FakeSeCrEtKeYf0rTeStS1234567890000000",
        region="us-east-1",
    )


@pytest.fixture
def client(cfg):
    return AWSClient(cfg)


# ─────────────────────────────────────────────────────────────────────────────
# SigV4
# ─────────────────────────────────────────────────────────────────────────────

class TestSigV4:
    def test_genera_authorization_header(self):
        hdrs = _sigv4(
            "POST", "https://sts.amazonaws.com/",
            {"Host": "sts.amazonaws.com"},
            "Action=GetCallerIdentity&Version=2011-06-15",
            "FAKEKEY00000000000001",
            "FakeSeCrEtKeYfOrUnItTest1234567890",
            "sts", "us-east-1",
        )
        assert "Authorization" in hdrs
        assert hdrs["Authorization"].startswith("AWS4-HMAC-SHA256 Credential=")

    def test_incluye_x_amz_date(self):
        hdrs = _sigv4(
            "GET", "https://s3.amazonaws.com/",
            {"Host": "s3.amazonaws.com"},
            "",
            "FAKEKEY00000000000001",
            "FakeSeCrEtKeYfOrUnItTest1234567890",
            "s3", "us-east-1",
        )
        assert "x-amz-date" in hdrs

    def test_incluye_payload_hash(self):
        hdrs = _sigv4(
            "POST", "https://iam.amazonaws.com/",
            {"Host": "iam.amazonaws.com"},
            "Action=ListUsers",
            "FAKEKEY00000000000001",
            "FakeSeCrEtKeYfOrUnItTest1234567890",
            "iam", "us-east-1",
        )
        assert "x-amz-content-sha256" in hdrs

    def test_signed_headers_en_authorization(self):
        hdrs = _sigv4(
            "POST", "https://sts.amazonaws.com/",
            {"Host": "sts.amazonaws.com"},
            "Action=GetCallerIdentity",
            "FAKEKEY00000000000001",
            "FakeSeCrEtKeYfOrUnItTest1234567890",
            "sts", "us-east-1",
        )
        auth = hdrs["Authorization"]
        assert "SignedHeaders=" in auth
        assert "Signature=" in auth


# ─────────────────────────────────────────────────────────────────────────────
# AWSConfig
# ─────────────────────────────────────────────────────────────────────────────

class TestAWSConfig:
    def test_region_default(self):
        c = AWSConfig(access_key="K", secret_key="S")
        assert c.region == "us-east-1"

    def test_custom_region(self):
        c = AWSConfig(access_key="K", secret_key="S", region="eu-west-1")
        assert c.region == "eu-west-1"


# ─────────────────────────────────────────────────────────────────────────────
# Finding
# ─────────────────────────────────────────────────────────────────────────────

class TestFinding:
    def test_finding_pass(self):
        f = Finding("CIS-1.4", "Título", "CRITICAL", Status.PASS)
        assert f.status == Status.PASS

    def test_finding_fail(self):
        f = Finding("CIS-1.4", "Título", "CRITICAL", Status.FAIL, detail="detalle")
        assert f.detail == "detalle"

    def test_finding_defaults(self):
        f = Finding("X", "T", "LOW", Status.SKIP)
        assert f.resource == ""
        assert f.region   == ""
        assert f.remediation == ""


# ─────────────────────────────────────────────────────────────────────────────
# IAMAuditor
# ─────────────────────────────────────────────────────────────────────────────

class TestIAMAuditor:
    def _make_client(self, cfg):
        return AWSClient(cfg)

    @pytest.mark.asyncio
    async def test_root_mfa_activado(self, cfg):
        client = self._make_client(cfg)
        import xml.etree.ElementTree as ET
        xml_body = """
        <GetAccountSummaryResponse>
          <GetAccountSummaryResult>
            <SummaryMap>
              <entry><key>AccountMFAEnabled</key><value>1</value></entry>
            </SummaryMap>
          </GetAccountSummaryResult>
        </GetAccountSummaryResponse>"""
        with patch.object(client, "_call", new=AsyncMock(return_value=(200, xml_body))):
            auditor = IAMAuditor(client)
            finding = await auditor._check_root_mfa()
        assert finding is not None
        assert finding.status == Status.PASS

    @pytest.mark.asyncio
    async def test_root_mfa_desactivado(self, cfg):
        client = self._make_client(cfg)
        xml_body = """
        <GetAccountSummaryResponse>
          <GetAccountSummaryResult>
            <SummaryMap>
              <entry><key>AccountMFAEnabled</key><value>0</value></entry>
            </SummaryMap>
          </GetAccountSummaryResult>
        </GetAccountSummaryResponse>"""
        with patch.object(client, "_call", new=AsyncMock(return_value=(200, xml_body))):
            auditor = IAMAuditor(client)
            finding = await auditor._check_root_mfa()
        assert finding is not None
        assert finding.status == Status.FAIL
        assert finding.severity == "CRITICAL"

    @pytest.mark.asyncio
    async def test_root_access_keys_presentes_es_fail(self, cfg):
        client = self._make_client(cfg)
        xml_body = """
        <GetAccountSummaryResponse>
          <GetAccountSummaryResult>
            <SummaryMap>
              <entry><key>AccountAccessKeysPresent</key><value>1</value></entry>
            </SummaryMap>
          </GetAccountSummaryResult>
        </GetAccountSummaryResponse>"""
        with patch.object(client, "_call", new=AsyncMock(return_value=(200, xml_body))):
            auditor = IAMAuditor(client)
            finding = await auditor._check_root_access_keys()
        assert finding.status == Status.FAIL

    @pytest.mark.asyncio
    async def test_password_policy_min_length_pass(self, cfg):
        client = self._make_client(cfg)
        xml_body = """
        <GetAccountPasswordPolicyResponse>
          <GetAccountPasswordPolicyResult>
            <PasswordPolicy>
              <MinimumPasswordLength>14</MinimumPasswordLength>
            </PasswordPolicy>
          </GetAccountPasswordPolicyResult>
        </GetAccountPasswordPolicyResponse>"""
        with patch.object(client, "_call", new=AsyncMock(return_value=(200, xml_body))):
            auditor = IAMAuditor(client)
            finding = await auditor._check_iam_password_length()
        assert finding.status == Status.PASS

    @pytest.mark.asyncio
    async def test_password_policy_min_length_fail(self, cfg):
        client = self._make_client(cfg)
        xml_body = """
        <GetAccountPasswordPolicyResponse>
          <GetAccountPasswordPolicyResult>
            <PasswordPolicy>
              <MinimumPasswordLength>8</MinimumPasswordLength>
            </PasswordPolicy>
          </GetAccountPasswordPolicyResult>
        </GetAccountPasswordPolicyResponse>"""
        with patch.object(client, "_call", new=AsyncMock(return_value=(200, xml_body))):
            auditor = IAMAuditor(client)
            finding = await auditor._check_iam_password_length()
        assert finding.status == Status.FAIL


# ─────────────────────────────────────────────────────────────────────────────
# S3Auditor
# ─────────────────────────────────────────────────────────────────────────────

class TestS3Auditor:
    @pytest.mark.asyncio
    async def test_lista_buckets_vacia(self, cfg):
        client = AWSClient(cfg)
        with patch.object(client, "s3_list_buckets", new=AsyncMock(return_value=[])):
            auditor = S3Auditor(client)
            findings = await auditor.run()
        assert findings == []

    @pytest.mark.asyncio
    async def test_bucket_publico_es_critical(self, cfg):
        client = AWSClient(cfg)
        acl_body = """
        <AccessControlPolicy>
          <AccessControlList>
            <Grant><Grantee xsi:type="Group">
              <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>
            </Grantee></Grant>
          </AccessControlList>
        </AccessControlPolicy>"""
        with patch.object(client, "s3_get_bucket_acl", new=AsyncMock(return_value=(200, acl_body))):
            auditor = S3Auditor(client)
            finding = await auditor._check_acl_no_public("mi-bucket")
        assert finding.status == Status.FAIL
        assert finding.severity == "CRITICAL"

    @pytest.mark.asyncio
    async def test_bucket_sin_cifrado_es_fail(self, cfg):
        client = AWSClient(cfg)
        with patch.object(client, "s3_get_bucket_encryption", new=AsyncMock(return_value=(404, ""))):
            auditor = S3Auditor(client)
            finding = await auditor._check_encryption("mi-bucket")
        assert finding.status == Status.FAIL

    @pytest.mark.asyncio
    async def test_bucket_con_cifrado_es_pass(self, cfg):
        client = AWSClient(cfg)
        enc_body = "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>"
        with patch.object(client, "s3_get_bucket_encryption", new=AsyncMock(return_value=(200, enc_body))):
            auditor = S3Auditor(client)
            finding = await auditor._check_encryption("mi-bucket")
        assert finding.status == Status.PASS


# ─────────────────────────────────────────────────────────────────────────────
# EC2Auditor
# ─────────────────────────────────────────────────────────────────────────────

class TestEC2Auditor:
    @pytest.mark.asyncio
    async def test_ssh_abierto_es_fail(self, cfg):
        client = AWSClient(cfg)
        xml_body = """
        <DescribeSecurityGroupsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
          <securityGroupInfo>
            <item>
              <groupId>sg-12345678</groupId>
              <ipPermissions>
                <item>
                  <fromPort>22</fromPort>
                  <toPort>22</toPort>
                  <ipRanges>
                    <item><cidrIp>0.0.0.0/0</cidrIp></item>
                  </ipRanges>
                </item>
              </ipPermissions>
            </item>
          </securityGroupInfo>
        </DescribeSecurityGroupsResponse>"""
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml_body)
        with patch.object(client, "ec2_query", new=AsyncMock(return_value=(200, root))):
            auditor = EC2Auditor(client)
            finding = await auditor._check_ssh_restricted("us-east-1")
        assert finding.status == Status.FAIL

    @pytest.mark.asyncio
    async def test_ebs_cifrado_por_defecto_pass(self, cfg):
        client = AWSClient(cfg)
        xml_body = """
        <GetEbsEncryptionByDefaultResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
          <ebsEncryptionByDefault>true</ebsEncryptionByDefault>
        </GetEbsEncryptionByDefaultResponse>"""
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml_body)
        with patch.object(client, "ec2_query", new=AsyncMock(return_value=(200, root))):
            auditor = EC2Auditor(client)
            finding = await auditor._check_ebs_default_encryption("us-east-1")
        assert finding.status == Status.PASS


# ─────────────────────────────────────────────────────────────────────────────
# RDSAuditor
# ─────────────────────────────────────────────────────────────────────────────

class TestRDSAuditor:
    @pytest.mark.asyncio
    async def test_rds_publico_es_critical(self, cfg):
        client = AWSClient(cfg)
        xml_body = """
        <DescribeDBInstancesResponse xmlns="http://rds.amazonaws.com/doc/2014-10-31/">
          <DescribeDBInstancesResult>
            <DBInstances>
              <DBInstance>
                <DBInstanceIdentifier>db-prod</DBInstanceIdentifier>
                <PubliclyAccessible>true</PubliclyAccessible>
                <StorageEncrypted>true</StorageEncrypted>
                <AutoMinorVersionUpgrade>true</AutoMinorVersionUpgrade>
                <BackupRetentionPeriod>7</BackupRetentionPeriod>
                <DeletionProtection>true</DeletionProtection>
              </DBInstance>
            </DBInstances>
          </DescribeDBInstancesResult>
        </DescribeDBInstancesResponse>"""
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml_body)
        with patch.object(client, "rds_describe_instances", new=AsyncMock(return_value=(200, root))):
            auditor = RDSAuditor(client)
            findings = await auditor.run()
        public_finding = next((f for f in findings if f.check_id == "CIS-RDS-1"), None)
        assert public_finding is not None
        assert public_finding.status == Status.FAIL

    @pytest.mark.asyncio
    async def test_rds_backup_menor_7_dias_es_fail(self, cfg):
        client = AWSClient(cfg)
        xml_body = """
        <DescribeDBInstancesResponse xmlns="http://rds.amazonaws.com/doc/2014-10-31/">
          <DescribeDBInstancesResult>
            <DBInstances>
              <DBInstance>
                <DBInstanceIdentifier>db-dev</DBInstanceIdentifier>
                <PubliclyAccessible>false</PubliclyAccessible>
                <StorageEncrypted>true</StorageEncrypted>
                <AutoMinorVersionUpgrade>true</AutoMinorVersionUpgrade>
                <BackupRetentionPeriod>3</BackupRetentionPeriod>
                <DeletionProtection>true</DeletionProtection>
              </DBInstance>
            </DBInstances>
          </DescribeDBInstancesResult>
        </DescribeDBInstancesResponse>"""
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml_body)
        with patch.object(client, "rds_describe_instances", new=AsyncMock(return_value=(200, root))):
            auditor = RDSAuditor(client)
            findings = await auditor.run()
        backup_finding = next((f for f in findings if f.check_id == "CIS-RDS-4"), None)
        assert backup_finding is not None
        assert backup_finding.status == Status.FAIL


# ─────────────────────────────────────────────────────────────────────────────
# KMSAuditor
# ─────────────────────────────────────────────────────────────────────────────

class TestKMSAuditor:
    @pytest.mark.asyncio
    async def test_sin_keys_retorna_lista_vacia(self, cfg):
        client = AWSClient(cfg)
        with patch.object(client, "kms_list_keys", new=AsyncMock(return_value=(200, '{"Keys": []}'))):
            auditor = KMSAuditor(client)
            findings = await auditor.run()
        assert findings == []

    @pytest.mark.asyncio
    async def test_key_sin_rotacion_es_fail(self, cfg):
        client = AWSClient(cfg)
        key_id = "aaaaaaaa-0000-0000-0000-000000000001"
        with patch.object(client, "kms_list_keys",
                          new=AsyncMock(return_value=(200, json.dumps({"Keys": [{"KeyId": key_id}]})))):
            with patch.object(client, "kms_get_key_rotation_status",
                              new=AsyncMock(return_value=(200, '{"KeyRotationEnabled": false}'))):
                with patch.object(client, "kms_describe_key",
                                  new=AsyncMock(return_value=(200, '{"KeyMetadata": {"KeyState": "Enabled"}}'))):
                    auditor = KMSAuditor(client)
                    findings = await auditor.run()
        rotation_finding = next((f for f in findings if f.check_id == "CIS-3.7"), None)
        assert rotation_finding is not None
        assert rotation_finding.status == Status.FAIL


# ─────────────────────────────────────────────────────────────────────────────
# GuardDutyAuditor
# ─────────────────────────────────────────────────────────────────────────────

class TestGuardDutyAuditor:
    @pytest.mark.asyncio
    async def test_sin_detectores_es_fail(self, cfg):
        client = AWSClient(cfg)
        with patch.object(client, "gd_list_detectors",
                          new=AsyncMock(return_value=(200, '{"detectorIds": []}'))):
            auditor = GuardDutyAuditor(client)
            findings = await auditor.run()
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL

    @pytest.mark.asyncio
    async def test_con_detector_es_pass(self, cfg):
        client = AWSClient(cfg)
        with patch.object(client, "gd_list_detectors",
                          new=AsyncMock(return_value=(200, '{"detectorIds": ["abc123"]}'))):
            auditor = GuardDutyAuditor(client)
            findings = await auditor.run()
        assert findings[0].status == Status.PASS


# ─────────────────────────────────────────────────────────────────────────────
# ConfigAuditor
# ─────────────────────────────────────────────────────────────────────────────

class TestConfigAuditor:
    @pytest.mark.asyncio
    async def test_recorder_inactivo_es_fail(self, cfg):
        client = AWSClient(cfg)
        payload = json.dumps({"ConfigurationRecordersStatus": [{"recording": False}]})
        with patch.object(client, "config_describe_recorder_status",
                          new=AsyncMock(return_value=(200, payload))):
            with patch.object(client, "config_describe_delivery_channels",
                              new=AsyncMock(return_value=(200, '{"DeliveryChannels": []}'))):
                auditor = ConfigAuditor(client)
                findings = await auditor.run()
        recorder_f = next((f for f in findings if f.check_id == "CIS-2.5"), None)
        assert recorder_f is not None
        assert recorder_f.status == Status.FAIL

    @pytest.mark.asyncio
    async def test_recorder_activo_es_pass(self, cfg):
        client = AWSClient(cfg)
        payload = json.dumps({"ConfigurationRecordersStatus": [{"recording": True}]})
        with patch.object(client, "config_describe_recorder_status",
                          new=AsyncMock(return_value=(200, payload))):
            with patch.object(client, "config_describe_delivery_channels",
                              new=AsyncMock(return_value=(200, '{"DeliveryChannels": [{"s3BucketName": "my-bucket"}]}'))):
                auditor = ConfigAuditor(client)
                findings = await auditor.run()
        recorder_f = next((f for f in findings if f.check_id == "CIS-2.5"), None)
        assert recorder_f is not None
        assert recorder_f.status == Status.PASS


# ─────────────────────────────────────────────────────────────────────────────
# AWSAuditor
# ─────────────────────────────────────────────────────────────────────────────

class TestAWSAuditor:
    def test_modulos_disponibles(self):
        assert "iam" in AWSAuditor.MODULES
        assert "s3"  in AWSAuditor.MODULES
        assert "ec2" in AWSAuditor.MODULES
        assert "cloudtrail" in AWSAuditor.MODULES
        assert "rds" in AWSAuditor.MODULES
        assert "kms" in AWSAuditor.MODULES
        assert "guardduty" in AWSAuditor.MODULES
        assert "config" in AWSAuditor.MODULES

    def test_8_modulos(self):
        assert len(AWSAuditor.MODULES) == 8

    def test_filtro_de_modulos(self, cfg):
        auditor = AWSAuditor(cfg, ["iam", "s3"])
        assert auditor.modules == ["iam", "s3"]

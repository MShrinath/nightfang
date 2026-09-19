"""Cloud Testing Agent - AWS, Azure, GCP infrastructure security testing."""
import asyncio
import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.config import EngagementConfig, AgentConfig
from ..core.scope import ScopeValidator
from ..core.memory import MemoryManager, Finding, Asset, TimelineEvent
from ..core.telegram_bot import TelegramBot
from .base import BaseAgent, ToolResult

logger = logging.getLogger(__name__)


class CloudTestingAgent(BaseAgent):
    """Cloud infrastructure security testing - AWS, Azure, GCP misconfigurations."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = "SCANNER-CLOUD"
        self.role = "Cloud Security Tester"
        self.tools_required = [
            'aws', 'az', 'gcloud', 'prowler', 'scoutsuite', 'cloudsploit',
            'pacu', 'enumerate-iam', 's3scanner', 'awscli', 'jq'
        ]
        self.hitl_required = True
        self.hitl_checkpoints = [
            "Before ANY cloud exploitation attempt",
            "Before modifying IAM policies or roles",
            "Before accessing storage buckets with write permissions",
            "Before invoking serverless functions",
            "Before accessing cloud metadata via SSRF",
            "Before running Prowler/ScoutSuite with write access"
        ]
        self.max_runtime_minutes = 90

    async def run(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Execute cloud security testing."""
        self.log_event("cloud_testing", "Starting cloud infrastructure security testing", "started")

        credentials = inputs.get('credentials', [])
        scope = inputs.get('scope_definition', {})

        # Get cloud config from technique_config
        tech_config = self.config.rules.technique_config.get('cloud_testing', {})
        aws_regions = tech_config.get('aws_regions', 'us-east-1,us-west-2,eu-west-1').split(',')
        azure_subs = tech_config.get('azure_subscriptions', '').split(',')
        gcp_projects = tech_config.get('gcp_projects', '').split(',')

        results = {
            'aws_findings': [],
            'azure_findings': [],
            'gcp_findings': [],
            'storage_findings': [],
            'iam_findings': [],
            'serverless_findings': [],
            'metadata_findings': [],
            'compliance_findings': []
        }

        # AWS Testing
        if await self._check_aws_creds(credentials):
            results['aws_findings'].extend(await self._test_aws(aws_regions, credentials))

        # Azure Testing
        if await self._check_azure_creds(credentials):
            results['azure_findings'].extend(await self._test_azure(azure_subs, credentials))

        # GCP Testing
        if await self._check_gcp_creds(credentials):
            results['gcp_findings'].extend(await self._test_gcp(gcp_projects, credentials))

        # SSRF-based metadata testing (no creds needed)
        web_endpoints = inputs.get('web_endpoints_list', [])
        if web_endpoints:
            results['metadata_findings'].extend(await self._test_metadata_ssrf(web_endpoints))

        # Automated scanners
        if await self.check_tool('prowler'):
            results['compliance_findings'].extend(await self._run_prowler(aws_regions))

        if await self.check_tool('scoutsuite'):
            results['compliance_findings'].extend(await self._run_scoutsuite(credentials))

        total_findings = sum(len(v) for v in results.values() if isinstance(v, list))
        self.log_event("cloud_testing", f"Cloud testing complete. Total findings: {total_findings}", "completed")
        return results

    async def _check_aws_creds(self, credentials: List[Dict]) -> bool:
        """Check if AWS credentials are available."""
        for cred in credentials:
            if cred.get('role') in ['aws_admin', 'aws_readonly', 'api_consumer']:
                if cred.get('api_key') and cred.get('api_secret'):
                    return True
        # Check environment
        import os
        return bool(os.environ.get('AWS_ACCESS_KEY_ID') and os.environ.get('AWS_SECRET_ACCESS_KEY'))

    async def _check_azure_creds(self, credentials: List[Dict]) -> bool:
        """Check if Azure credentials are available."""
        import os
        return bool(os.environ.get('AZURE_TENANT_ID') and os.environ.get('AZURE_CLIENT_ID'))

    async def _check_gcp_creds(self, credentials: List[Dict]) -> bool:
        """Check if GCP credentials are available."""
        import os
        return bool(os.environ.get('GOOGLE_APPLICATION_CREDENTIALS') or os.environ.get('GCP_PROJECT_IDS'))

    async def _test_aws(self, regions: List[str], credentials: List[Dict]) -> List[Dict]:
        """Test AWS infrastructure."""
        findings = []

        for region in regions:
            region = region.strip()
            if not region:
                continue

            logger.info(f"[{self.name}] Testing AWS region: {region}")

            # S3 bucket enumeration
            findings.extend(await self._enum_s3_buckets(region))

            # IAM analysis
            findings.extend(await self._analyze_iam(region))

            # EC2/Security Groups
            findings.extend(await self._analyze_ec2_sg(region))

            # Lambda functions
            findings.extend(await self._analyze_lambda(region))

            # RDS/Databases
            findings.extend(await self._analyze_rds(region))

            # CloudTrail/Config
            findings.extend(await self._check_logging(region))

        return findings

    async def _enum_s3_buckets(self, region: str) -> List[Dict]:
        """Enumerate S3 buckets for public access."""
        findings = []

        # Use awscli to list buckets
        result = await self.execute_tool('aws', ['s3', 'ls', '--region', region], timeout=60)
        if result.returncode != 0:
            return findings

        buckets = []
        for line in result.stdout.strip().split('\n'):
            if line.strip():
                parts = line.split()
                if len(parts) >= 3:
                    buckets.append(parts[2])

        # Check each bucket
        for bucket in buckets[:50]:  # Limit to first 50
            # Check public read
            result = await self.execute_tool('aws', ['s3', 'ls', f's3://{bucket}', '--region', region, '--no-sign-request'], timeout=30)
            if result.returncode == 0:
                findings.append(self._make_finding(
                    f"S3 Bucket Public Read: {bucket}",
                    f"s3://{bucket}",
                    "cloud_s3_public_read",
                    7, 7,
                    f"Bucket {bucket} allows anonymous LIST",
                    ["T1530"], ["D3-CSM", "D3-IAM"]
                ))

            # Check public write
            result = await self.execute_tool('aws', ['s3', 'cp', '/tmp/test.txt', f's3://{bucket}/test.txt', '--region', region, '--no-sign-request'], timeout=30)
            if result.returncode == 0:
                findings.append(self._make_finding(
                    f"S3 Bucket Public Write: {bucket}",
                    f"s3://{bucket}",
                    "cloud_s3_public_write",
                    9, 9,
                    f"Bucket {bucket} allows anonymous WRITE",
                    ["T1530", "T1567"], ["D3-CSM", "D3-IAM", "D3-PMA"]
                ))

        return findings

    async def _analyze_iam(self, region: str) -> List[Dict]:
        """Analyze IAM for overprivileged roles."""
        findings = []

        # Check for admin policies attached to users/roles
        result = await self.execute_tool('aws', ['iam', 'list-policies', '--scope', 'AWSManaged', '--query', 'Policies[?PolicyName==`AdministratorAccess`].Arn', '--output', 'text'], timeout=60)
        if result.returncode == 0 and result.stdout.strip():
            admin_arn = result.stdout.strip()
            # Check who has this policy
            result = await self.execute_tool('aws', ['iam', 'list-entities-for-policy', '--policy-arn', admin_arn], timeout=60)
            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout)
                    for entity in data.get('PolicyUsers', []):
                        findings.append(self._make_finding(
                            f"IAM User with AdministratorAccess: {entity['UserName']}",
                            f"arn:aws:iam::{entity.get('UserId', '')}:user/{entity['UserName']}",
                            "cloud_iam_overprivileged",
                            8, 8,
                            f"User {entity['UserName']} has full AdministratorAccess",
                            ["T1078.004"], ["D3-IAM", "D3-ARA"]
                        ))
                except:
                    pass

        # Check for access keys not rotated
        result = await self.execute_tool('aws', ['iam', 'list-users'], timeout=60)
        if result.returncode == 0:
            try:
                users = json.loads(result.stdout).get('Users', [])
                for user in users:
                    result = await self.execute_tool('aws', ['iam', 'list-access-keys', '--user-name', user['UserName']], timeout=30)
                    if result.returncode == 0:
                        keys = json.loads(result.stdout).get('AccessKeyMetadata', [])
                        for key in keys:
                            # Would check age here
                            pass
            except:
                pass

        return findings

    async def _analyze_ec2_sg(self, region: str) -> List[Dict]:
        """Analyze EC2 Security Groups for overly permissive rules."""
        findings = []

        result = await self.execute_tool('aws', ['ec2', 'describe-security-groups', '--region', region], timeout=60)
        if result.returncode != 0:
            return findings

        try:
            sgs = json.loads(result.stdout).get('SecurityGroups', [])
            for sg in sgs:
                for rule in sg.get('IpPermissions', []):
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            port = rule.get('FromPort', 0)
                            if port in [22, 3389, 445, 1433, 3306, 5432, 27017, 6379]:
                                findings.append(self._make_finding(
                                    f"Security Group Open to World: Port {port}",
                                    sg['GroupId'],
                                    "cloud_sg_open_world",
                                    8, 7,
                                    f"SG {sg['GroupId']} allows 0.0.0.0/0 on port {port}",
                                    ["T1562.007"], ["D3-NA", "D3-SDA"]
                                ))
        except:
            pass

        return findings

    async def _analyze_lambda(self, region: str) -> List[Dict]:
        """Analyze Lambda functions for excessive permissions."""
        findings = []

        result = await self.execute_tool('aws', ['lambda', 'list-functions', '--region', region], timeout=60)
        if result.returncode != 0:
            return findings

        try:
            functions = json.loads(result.stdout).get('Functions', [])
            for fn in functions:
                # Check if function has admin role
                role_arn = fn.get('Role', '')
                if 'admin' in role_arn.lower() or 'full' in role_arn.lower():
                    findings.append(self._make_finding(
                        f"Lambda Function with Overprivileged Role: {fn['FunctionName']}",
                        fn['FunctionArn'],
                        "cloud_lambda_overprivileged",
                        7, 7,
                        f"Lambda {fn['FunctionName']} uses potentially overprivileged role",
                        ["T1580"], ["D3-IAM", "D3-ARA"]
                    ))

                # Check environment variables for secrets
                env_vars = fn.get('Environment', {}).get('Variables', {})
                for k, v in env_vars.items():
                    if any(secret in k.lower() for secret in ['key', 'secret', 'password', 'token', 'cred']):
                        findings.append(self._make_finding(
                            f"Lambda Hardcoded Secret: {fn['FunctionName']}",
                            fn['FunctionArn'],
                            "cloud_lambda_secret",
                            8, 7,
                            f"Lambda {fn['FunctionName']} has potential secret in env var {k}",
                            ["T1552.001"], ["D3-KDU", "D3-PSA"]
                        ))
        except:
            pass

        return findings

    async def _analyze_rds(self, region: str) -> List[Dict]:
        """Analyze RDS instances for public access and encryption."""
        findings = []

        result = await self.execute_tool('aws', ['rds', 'describe-db-instances', '--region', region], timeout=60)
        if result.returncode != 0:
            return findings

        try:
            instances = json.loads(result.stdout).get('DBInstances', [])
            for db in instances:
                if db.get('PubliclyAccessible', False):
                    findings.append(self._make_finding(
                        f"RDS Instance Publicly Accessible: {db['DBInstanceIdentifier']}",
                        db['DBInstanceArn'],
                        "cloud_rds_public",
                        9, 8,
                        f"RDS {db['DBInstanceIdentifier']} is publicly accessible",
                        ["T1190"], ["D3-NA", "D3-CSM"]
                    ))

                if not db.get('StorageEncrypted', False):
                    findings.append(self._make_finding(
                        f"RDS Instance Unencrypted: {db['DBInstanceIdentifier']}",
                        db['DBInstanceArn'],
                        "cloud_rds_unencrypted",
                        6, 5,
                        f"RDS {db['DBInstanceIdentifier']} storage is not encrypted",
                        ["T1557"], ["D3-CTA", "D3-CH"]
                    ))
        except:
            pass

        return findings

    async def _check_logging(self, region: str) -> List[Dict]:
        """Check CloudTrail and Config logging."""
        findings = []

        # CloudTrail
        result = await self.execute_tool('aws', ['cloudtrail', 'describe-trails', '--region', region], timeout=60)
        if result.returncode == 0:
            try:
                trails = json.loads(result.stdout).get('trailList', [])
                if not trails:
                    findings.append(self._make_finding(
                        "CloudTrail Not Enabled",
                        f"arn:aws:cloudtrail:{region}:trail",
                        "cloud_cloudtrail_disabled",
                        6, 6,
                        f"No CloudTrail trails configured in {region}",
                        ["T1562.008"], ["D3-WHIA", "D3-FCA"]
                    ))
                else:
                    for trail in trails:
                        if not trail.get('IsLogging', False):
                            findings.append(self._make_finding(
                                f"CloudTrail Not Logging: {trail['Name']}",
                                trail['TrailARN'],
                                "cloud_cloudtrail_not_logging",
                                6, 5,
                                f"CloudTrail {trail['Name']} exists but is not logging",
                                ["T1562.008"], ["D3-WHIA"]
                            ))
            except:
                pass

        return findings

    async def _test_azure(self, subscriptions: List[str], credentials: List[Dict]) -> List[Dict]:
        """Test Azure infrastructure."""
        findings = []

        for sub in subscriptions:
            sub = sub.strip()
            if not sub:
                continue

            # Set subscription
            await self.execute_tool('az', ['account', 'set', '--subscription', sub], timeout=30)

            # Storage accounts
            result = await self.execute_tool('az', ['storage', 'account', 'list', '--query', '[].{name:name, rg:resourceGroup, kind:kind, access:allowBlobPublicAccess, https:enableHttpsTrafficOnly}', '-o', 'json'], timeout=60)
            if result.returncode == 0:
                try:
                    accounts = json.loads(result.stdout)
                    for acct in accounts:
                        if acct.get('allowBlobPublicAccess', False):
                            findings.append(self._make_finding(
                                f"Azure Storage Public Access: {acct['name']}",
                                f"/subscriptions/{sub}/resourceGroups/{acct['rg']}/providers/Microsoft.Storage/storageAccounts/{acct['name']}",
                                "cloud_azure_storage_public",
                                7, 7,
                                f"Storage account {acct['name']} allows public blob access",
                                ["T1530"], ["D3-CSM", "D3-IAM"]
                            ))
                        if not acct.get('enableHttpsTrafficOnly', True):
                            findings.append(self._make_finding(
                                f"Azure Storage Allows HTTP: {acct['name']}",
                                f"/subscriptions/{sub}/resourceGroups/{acct['rg']}/providers/Microsoft.Storage/storageAccounts/{acct['name']}",
                                "cloud_azure_storage_http",
                                5, 6,
                                f"Storage account {acct['name']} allows unencrypted HTTP traffic",
                                ["T1557"], ["D3-CTA", "D3-CH"]
                            ))
                except:
                    pass

        return findings

    async def _test_gcp(self, projects: List[str], credentials: List[Dict]) -> List[Dict]:
        """Test GCP infrastructure."""
        findings = []

        for project in projects:
            project = project.strip()
            if not project:
                continue

            # Storage buckets
            result = await self.execute_tool('gsutil', ['ls', '-p', project], timeout=60)
            if result.returncode == 0:
                buckets = result.stdout.strip().split('\n')
                for bucket in buckets:
                    if bucket:
                        # Check IAM
                        result = await self.execute_tool('gsutil', ['iam', 'get', bucket], timeout=30)
                        if result.returncode == 0:
                            if 'allUsers' in result.stdout or 'allAuthenticatedUsers' in result.stdout:
                                findings.append(self._make_finding(
                                    f"GCP Bucket Public Access: {bucket}",
                                    bucket,
                                    "cloud_gcp_bucket_public",
                                    7, 7,
                                    f"Bucket {bucket} has public IAM bindings",
                                    ["T1530"], ["D3-CSM", "D3-IAM"]
                                ))

        return findings

    async def _test_metadata_ssrf(self, endpoints: List[str]) -> List[Dict]:
        """Test for SSRF to cloud metadata services."""
        findings = []

        metadata_urls = [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'http://169.254.169.254/latest/user-data/',
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://169.254.169.254/metadata/instance/',
        ]

        for endpoint in endpoints:
            if not self.validate_target(endpoint):
                continue

            for meta_url in metadata_urls:
                # Test via potential SSRF parameters
                ssrf_params = ['url', 'uri', 'link', 'src', 'source', 'target', 'dest', 'destination', 'redirect', 'next', 'return', 'callback', 'webhook', 'import', 'feed', 'fetch']
                for param in ssrf_params:
                    test_url = f"{endpoint}?{param}={meta_url}"
                    result = await self.execute_tool('curl', ['-s', '-m', '10', test_url], timeout=15)
                    if result.returncode == 0 and ('iam' in result.stdout or 'instance-id' in result.stdout or 'project-id' in result.stdout):
                        findings.append(self._make_finding(
                            f"Cloud Metadata SSRF via {param}",
                            endpoint,
                            "cloud_metadata_ssrf",
                            9, 9,
                            f"SSRF on {param} parameter accesses cloud metadata: {meta_url}",
                            ["T1552.005", "T1190"], ["D3-SFI", "D3-CSM"]
                        ))
                        break

        return findings

    async def _run_prowler(self, regions: List[str]) -> List[Dict]:
        """Run Prowler for AWS security assessment."""
        findings = []

        for region in regions[:3]:  # Limit regions
            region = region.strip()
            if not region:
                continue

            result = await self.execute_tool('prowler', ['aws', '-M', 'csv', '-f', region, '-o', '/tmp/prowler'], timeout=600)
            if result.returncode == 0:
                # Parse CSV output
                import csv
                import glob
                csv_files = glob.glob('/tmp/prowler/*.csv')
                for csv_file in csv_files:
                    try:
                        with open(csv_file) as f:
                            reader = csv.DictReader(f)
                            for row in reader:
                                if row.get('STATUS') == 'FAIL':
                                    findings.append(self._make_finding(
                                        f"Prowler: {row.get('CHECK_ID', 'Unknown')}",
                                        row.get('RESOURCE_ID', 'AWS'),
                                        "cloud_prowler_finding",
                                        7, 6,
                                        f"{row.get('CHECK_TITLE', '')}: {row.get('RESOURCE_ID', '')}",
                                        [], []
                                    ))
                    except:
                        pass

        return findings

    async def _run_scoutsuite(self, credentials: List[Dict]) -> List[Dict]:
        """Run ScoutSuite for multi-cloud assessment."""
        findings = []

        # ScoutSuite requires creds - run if available
        if await self._check_aws_creds(credentials):
            result = await self.execute_tool('scout', ['aws', '--no-browser', '--output-dir', '/tmp/scoutsuite'], timeout=600)
            if result.returncode == 0:
                # Parse report
                import glob
                report_files = glob.glob('/tmp/scoutsuite/**/report.html', recursive=True)
                for report in report_files:
                    findings.append(self._make_finding(
                        "ScoutSuite Report Generated",
                        "AWS",
                        "cloud_scoutsuite_report",
                        5, 3,
                        f"ScoutSuite HTML report: {report}",
                        [], []
                    ))

        return findings

    def _make_finding(self, title: str, target: str, ftype: str, conf: int, sev: int, evidence: str, mitre: List[str], d3fend: List[str]) -> Dict:
        """Create a finding dict."""
        finding = Finding(
            id=f"HERMES-CLOUD-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{ftype}",
            title=title,
            target=target,
            type=ftype,
            confidence=conf,
            severity=sev,
            status="confirmed",
            evidence=evidence,
            discovered_by=self.name,
            mitre_attack=mitre,
            d3fend=d3fend
        )
        self.add_finding(finding)
        return finding.__dict__
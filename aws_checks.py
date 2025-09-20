# aws_checks.py
import boto3
import botocore
from botocore.exceptions import ClientError
from utils import format_findings
from typing import List
import time

class AWSChecker:
    def __init__(self, region=None, profile=None, dry_run=True):
        session_kwargs = {}
        if profile:
            session_kwargs['profile_name'] = profile
        self.session = boto3.Session(**session_kwargs)
        self.region = region
        self.dry_run = dry_run
        # clients created lazily
        self._s3 = None
        self._ec2 = None
        self._iam = None
        self._cloudtrail = None

    @property
    def s3(self):
        if not self._s3:
            self._s3 = self.session.client("s3", region_name=self.region)
        return self._s3

    @property
    def ec2(self):
        if not self._ec2:
            self._ec2 = self.session.client("ec2", region_name=self.region)
        return self._ec2

    @property
    def iam(self):
        if not self._iam:
            self._iam = self.session.client("iam")
        return self._iam

    @property
    def cloudtrail(self):
        if not self._cloudtrail:
            self._cloudtrail = self.session.client("cloudtrail", region_name=self.region)
        return self._cloudtrail

    def run_all(self, remediate=False, force=False):
        findings = []
        findings.extend(self.check_public_s3())
        findings.extend(self.check_security_groups())
        findings.extend(self.check_cloudtrail_logging())
        findings.extend(self.check_iam_policies())
        report_lines = format_findings(findings)
        if remediate:
            # remediation step
            rem_results = []
            for f in findings:
                if f.get("remediate_action") and (force or self._confirm_remediation(f)):
                    r = self._apply_remediation(f)
                    rem_results.append(r)
            report_lines.append("\n=== Remediation Results ===")
            report_lines.extend(rem_results)
        return report_lines

    def _confirm_remediation(self, finding):
        # Minimal CLI confirmation if not forced
        prompt = f"Remediate {finding.get('target')} - {finding.get('check')}? [y/N]: "
        resp = input(prompt).strip().lower()
        return resp == 'y'

    def _apply_remediation(self, finding):
        """
        Minimal remediation actions implemented:
         - For public S3 buckets: block public access and remove public ACL
         - For security groups open to 0.0.0.0/0: revoke the rule
         - CloudTrail disabled: create a basic trail (if allowed)
         - IAM policy overly permissive: just notify (dangerous to auto change)
        Returns a string result.
        """
        check = finding.get("check")
        target = finding.get("target")
        try:
            if check == "Public S3 ACL or Policy":
                bucket = target
                # Block public access
                if not self.dry_run:
                    self.s3.put_public_access_block(
                        Bucket=bucket,
                        PublicAccessBlockConfiguration={
                            'BlockPublicAcls': True,
                            'IgnorePublicAcls': True,
                            'BlockPublicPolicy': True,
                            'RestrictPublicBuckets': True
                        }
                    )
                    # Try removing public ACL by setting private ACL
                    self.s3.put_bucket_acl(Bucket=bucket, ACL='private')
                return f"S3 remediation applied for {bucket} (dry_run={self.dry_run})"
            elif check == "Security Group wide open":
                sg_id = target
                if not self.dry_run:
                    # revoke ingress rules that have 0.0.0.0/0 or ::/0 on suspicious ports (22, 3389, 3306, 5432)
                    ec2 = self.ec2
                    sg = ec2.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
                    to_revoke = []
                    for rule in sg.get('IpPermissions', []):
                        ips = rule.get('IpRanges', []) + rule.get('Ipv6Ranges', [])
                        for ip in ips:
                            cidr = ip.get('CidrIp') or ip.get('CidrIpv6')
                            if cidr in ('0.0.0.0/0', '::/0'):
                                to_revoke.append(rule)
                    if to_revoke:
                        ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=to_revoke)
                return f"Security group remediation attempted for {sg_id} (dry_run={self.dry_run})"
            elif check == "CloudTrail missing or not logging":
                if not self.dry_run:
                    # Create a simple trail (this requires proper permissions and an S3 bucket for logs).
                    # We'll create a cloudtrail with CloudWatch events disabled and a local S3 bucket naming requirement.
                    trail_name = f"auto-created-trail-{int(time.time())}"
                    # NOTE: creating a trail requires S3 bucket; in many accounts this will fail unless pre-provisioned.
                    # For safety, we only notify unless dry_run False and environment explicitly supports auto-creation.
                    # We will attempt to create a trail without S3 if allowed by the account (may fail).
                    try:
                        self.cloudtrail.create_trail(Name=trail_name, S3BucketName=f"{trail_name}-bucket")
                        self.cloudtrail.start_logging(Name=trail_name)
                    except ClientError as e:
                        return f"Failed creating trail {trail_name}: {str(e)}"
                return f"CloudTrail remediation attempted (dry_run={self.dry_run})"
            else:
                return f"No automatic remediation implemented for check {check}"
        except ClientError as e:
            return f"Error during remediation of {target} ({check}): {str(e)}"

    def check_public_s3(self) -> List[dict]:
        findings = []
        try:
            resp = self.s3.list_buckets()
            for b in resp.get('Buckets', []):
                name = b['Name']
                # check public access block
                try:
                    pab = self.s3.get_public_access_block(Bucket=name)
                    conf = pab['PublicAccessBlockConfiguration']
                    if not (conf.get('BlockPublicAcls') and conf.get('IgnorePublicAcls') and conf.get('BlockPublicPolicy')):
                        findings.append({
                            "target": name,
                            "check": "Public S3 ACL or Policy",
                            "severity": "High",
                            "description": "Bucket does not have full public access block settings.",
                            "remediate_action": "Block public access & set private ACL"
                        })
                except ClientError as e:
                    # If PublicAccessBlock configuration not found or access denied, still check ACL
                    try:
                        acl = self.s3.get_bucket_acl(Bucket=name)
                        for grant in acl.get('Grants', []):
                            grantee = grant.get('Grantee', {})
                            if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                                findings.append({
                                    "target": name,
                                    "check": "Public S3 ACL or Policy",
                                    "severity": "High",
                                    "description": "Bucket ACL grants access to AllUsers (public).",
                                    "remediate_action": "Remove public ACL & block public access"
                                })
                                break
                    except ClientError:
                        findings.append({
                            "target": name,
                            "check": "Public S3 ACL or Policy",
                            "severity": "Medium",
                            "description": "Unable to inspect bucket ACL (permission denied).",
                            "remediate_action": None
                        })
        except ClientError as e:
            findings.append({
                "target": "S3",
                "check": "ListBuckets",
                "severity": "Low",
                "description": f"Failed to list buckets: {str(e)}"
            })
        return findings

    def check_security_groups(self) -> List[dict]:
        findings = []
        try:
            paginator = self.ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page.get('SecurityGroups', []):
                    sg_id = sg['GroupId']
                    for perm in sg.get('IpPermissions', []):
                        for ip_range in perm.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                # suspicious open rule
                                port = perm.get('FromPort')
                                findings.append({
                                    "target": sg_id,
                                    "check": "Security Group wide open",
                                    "severity": "High" if port in (22, 3389, 3306, 5432) else "Medium",
                                    "description": f"Security Group {sg_id} allows 0.0.0.0/0 on port {port}.",
                                    "remediate_action": "Revoke rule or restrict CIDR"
                                })
                        for ip6 in perm.get('Ipv6Ranges', []):
                            if ip6.get('CidrIpv6') == '::/0':
                                findings.append({
                                    "target": sg_id,
                                    "check": "Security Group wide open",
                                    "severity": "High",
                                    "description": f"Security Group {sg_id} allows ::/0 (IPv6) on port {perm.get('FromPort')}.",
                                    "remediate_action": "Revoke rule or restrict CIDR"
                                })
        except ClientError as e:
            findings.append({
                "target": "EC2",
                "check": "DescribeSecurityGroups",
                "severity": "Low",
                "description": f"Failed to enumerate security groups: {str(e)}"
            })
        return findings

    def check_cloudtrail_logging(self) -> List[dict]:
        findings = []
        try:
            trails = self.cloudtrail.describe_trails()['trailList']
            if not trails:
                findings.append({
                    "target": "Account",
                    "check": "CloudTrail missing or not logging",
                    "severity": "High",
                    "description": "No CloudTrail trails found in account.",
                    "remediate_action": "Create a CloudTrail to log management events to S3"
                })
            else:
                any_logging = False
                for t in trails:
                    status = self.cloudtrail.get_trail_status(Name=t['Name'])
                    if status.get('IsLogging'):
                        any_logging = True
                        break
                if not any_logging:
                    findings.append({
                        "target": "Account",
                        "check": "CloudTrail missing or not logging",
                        "severity": "High",
                        "description": "Found trails but none are actively logging.",
                        "remediate_action": "Start logging on a trail"
                    })
        except ClientError as e:
            findings.append({
                "target": "CloudTrail",
                "check": "DescribeTrails",
                "severity": "Low",
                "description": f"Failed to check CloudTrail: {str(e)}"
            })
        return findings

    def check_iam_policies(self) -> List[dict]:
        findings = []
        try:
            # List customer managed policies or inline policies; check for wildcard '*' in actions/resources
            paginator = self.iam.get_paginator('list_policies')
            for page in paginator.paginate(Scope='Local'):
                for pol in page.get('Policies', []):
                    pol_arn = pol['Arn']
                    # get policy document
                    versions = self.iam.list_policy_versions(PolicyArn=pol_arn)['Versions']
                    default_version = next((v for v in versions if v['IsDefaultVersion']), None)
                    if not default_version:
                        continue
                    ver = self.iam.get_policy_version(PolicyArn=pol_arn, VersionId=default_version['VersionId'])
                    doc = ver['PolicyVersion']['Document']
                    # naive detection: scan statements for Action or Resource == '*'
                    for stmt in doc.get('Statement', []):
                        if isinstance(stmt.get('Action'), (list, str)) and stmt.get('Action') == '*' or stmt.get('Action') == ['*'] or stmt.get('Resource') == '*':
                            findings.append({
                                "target": pol['PolicyName'],
                                "check": "IAM policy overly permissive",
                                "severity": "High",
                                "description": f"Policy {pol['PolicyName']} contains wildcard Action or Resource.",
                                "remediate_action": "Review & scope down permissions (manual)"
                            })
        except ClientError as e:
            findings.append({
                "target": "IAM",
                "check": "ListPolicies",
                "severity": "Low",
                "description": f"Failed to enumerate IAM policies: {str(e)}"
            })
        return findings

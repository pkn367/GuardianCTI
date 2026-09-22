"""
Control catalogue for GuardianCTI.

Every check is one testable statement about a cloud resource, mapped to the
compliance frameworks a healthcare organisation is actually audited against.
This file is the "predefined security policy" baseline described in Section 8.2
of the project document; the AI layer (guardian/ai_model.py) sits on top of it
and re-ranks what these checks produce.

Fields
------
id              stable identifier, used as the join key everywhere else
title           one line, phrased as the *desired* state
service         AWS service, also used to match CTI feed entries
base_severity   1..5 analyst prior, before AI and threat-intel adjustment
impact_axis     which security property fails: C, I or A
hipaa           HIPAA Security Rule citation (45 CFR Part 164)
cis             CIS AWS Foundations Benchmark v3.0.0 control number
nist            NIST SP 800-53 Rev.5 control
attack          MITRE ATT&CK technique(s) this misconfiguration enables
remediation     the exact fix, written for a tired administrator
"""

CHECKS = {
    "S3.1": {
        "title": "S3 buckets holding PHI block all public access",
        "service": "s3",
        "base_severity": 5,
        "impact_axis": "C",
        "hipaa": "164.312(a)(1) Access Control",
        "cis": "2.1.4",
        "nist": "AC-3",
        "attack": ["T1530"],
        "remediation": "Enable all four Block Public Access settings on the bucket, then re-run the assessment.",
    },
    "S3.2": {
        "title": "S3 buckets are encrypted at rest",
        "service": "s3",
        "base_severity": 4,
        "impact_axis": "C",
        "hipaa": "164.312(a)(2)(iv) Encryption and Decryption",
        "cis": "2.1.1",
        "nist": "SC-28",
        "attack": ["T1530"],
        "remediation": "Apply default encryption (SSE-KMS preferred over SSE-S3 for PHI, so key use is auditable).",
    },
    "S3.3": {
        "title": "S3 buckets have versioning enabled",
        "service": "s3",
        "base_severity": 3,
        "impact_axis": "I",
        "hipaa": "164.312(c)(1) Integrity",
        "cis": "2.1.3",
        "nist": "SI-7",
        "attack": ["T1485", "T1486"],
        "remediation": "Enable versioning so ransomware overwrites of patient records can be rolled back.",
    },
    "S3.4": {
        "title": "S3 buckets log server access",
        "service": "s3",
        "base_severity": 2,
        "impact_axis": "I",
        "hipaa": "164.312(b) Audit Controls",
        "cis": "3.6",
        "nist": "AU-2",
        "attack": ["T1530"],
        "remediation": "Send server access logs to a separate logging bucket retained for six years.",
    },
    "EC2.1": {
        "title": "Security groups do not expose admin ports to the internet",
        "service": "ec2",
        "base_severity": 5,
        "impact_axis": "C",
        "hipaa": "164.312(e)(1) Transmission Security",
        "cis": "5.2",
        "nist": "SC-7",
        "attack": ["T1021.001", "T1021.004", "T1190"],
        "remediation": "Replace 0.0.0.0/0 on ports 22, 3389, 3306, 5432 with the hospital VPN CIDR, or use SSM Session Manager and remove the rule entirely.",
    },
    "EC2.2": {
        "title": "Security groups do not allow unrestricted inbound traffic on all ports",
        "service": "ec2",
        "base_severity": 4,
        "impact_axis": "C",
        "hipaa": "164.312(e)(1) Transmission Security",
        "cis": "5.3",
        "nist": "SC-7",
        "attack": ["T1190"],
        "remediation": "Delete the -1 (all protocols) rule and re-add only the ports the application needs.",
    },
    "EC2.3": {
        "title": "EBS volumes are encrypted",
        "service": "ec2",
        "base_severity": 4,
        "impact_axis": "C",
        "hipaa": "164.312(a)(2)(iv) Encryption and Decryption",
        "cis": "2.2.1",
        "nist": "SC-28",
        "attack": ["T1005"],
        "remediation": "Enable EBS encryption by default in the account, then snapshot and restore existing volumes as encrypted.",
    },
    "EC2.4": {
        "title": "EC2 instances require IMDSv2",
        "service": "ec2",
        "base_severity": 4,
        "impact_axis": "C",
        "hipaa": "164.312(a)(1) Access Control",
        "cis": "5.6",
        "nist": "AC-6",
        "attack": ["T1552.005"],
        "remediation": "Set HttpTokens=required on the instance metadata options to stop SSRF from stealing role credentials.",
    },
    "IAM.1": {
        "title": "No IAM policy grants Action:* on Resource:*",
        "service": "iam",
        "base_severity": 5,
        "impact_axis": "C",
        "hipaa": "164.308(a)(4) Information Access Management",
        "cis": "1.16",
        "nist": "AC-6",
        "attack": ["T1078.004", "T1098"],
        "remediation": "Split the wildcard policy into job-function roles; start from the AWS managed ReadOnlyAccess policy and add only what breaks.",
    },
    "IAM.2": {
        "title": "Access keys are rotated within 90 days",
        "service": "iam",
        "base_severity": 3,
        "impact_axis": "C",
        "hipaa": "164.308(a)(5)(ii)(D) Password Management",
        "cis": "1.14",
        "nist": "IA-5",
        "attack": ["T1078.004"],
        "remediation": "Rotate the key, or delete it if the last-used date shows it is dormant.",
    },
    "IAM.3": {
        "title": "All IAM users have MFA enabled",
        "service": "iam",
        "base_severity": 5,
        "impact_axis": "C",
        "hipaa": "164.312(d) Person or Entity Authentication",
        "cis": "1.10",
        "nist": "IA-2(1)",
        "attack": ["T1078.004", "T1621"],
        "remediation": "Enforce MFA with an IAM policy that denies every action unless aws:MultiFactorAuthPresent is true.",
    },
    "IAM.4": {
        "title": "Unused IAM credentials are removed within 45 days",
        "service": "iam",
        "base_severity": 2,
        "impact_axis": "C",
        "hipaa": "164.308(a)(3)(ii)(C) Termination Procedures",
        "cis": "1.12",
        "nist": "AC-2",
        "attack": ["T1078"],
        "remediation": "Disable the credential; dormant accounts are the ones attackers keep.",
    },
    "RDS.1": {
        "title": "RDS instances are not publicly accessible",
        "service": "rds",
        "base_severity": 5,
        "impact_axis": "C",
        "hipaa": "164.312(a)(1) Access Control",
        "cis": "2.3.3",
        "nist": "SC-7",
        "attack": ["T1190", "T1213"],
        "remediation": "Set PubliclyAccessible=false and move the instance into private subnets.",
    },
    "RDS.2": {
        "title": "RDS storage is encrypted",
        "service": "rds",
        "base_severity": 4,
        "impact_axis": "C",
        "hipaa": "164.312(a)(2)(iv) Encryption and Decryption",
        "cis": "2.3.1",
        "nist": "SC-28",
        "attack": ["T1213"],
        "remediation": "Encryption cannot be turned on in place: snapshot, copy the snapshot with a KMS key, restore.",
    },
    "RDS.3": {
        "title": "RDS automated backups are retained",
        "service": "rds",
        "base_severity": 3,
        "impact_axis": "A",
        "hipaa": "164.308(a)(7)(ii)(A) Data Backup Plan",
        "cis": "2.3.2",
        "nist": "CP-9",
        "attack": ["T1486"],
        "remediation": "Set a backup retention period of at least 7 days; 0 means backups are off.",
    },
    "LOG.1": {
        "title": "CloudTrail is enabled in all regions",
        "service": "cloudtrail",
        "base_severity": 5,
        "impact_axis": "I",
        "hipaa": "164.312(b) Audit Controls",
        "cis": "3.1",
        "nist": "AU-2",
        "attack": ["T1562.008"],
        "remediation": "Create a multi-region trail with log file validation enabled. Without it there is no breach investigation.",
    },
    "LOG.2": {
        "title": "CloudTrail log file validation is enabled",
        "service": "cloudtrail",
        "base_severity": 3,
        "impact_axis": "I",
        "hipaa": "164.312(c)(1) Integrity",
        "cis": "3.2",
        "nist": "AU-9",
        "attack": ["T1070"],
        "remediation": "Turn on log file validation so tampering with audit logs is detectable.",
    },
    "KMS.1": {
        "title": "Customer managed KMS keys have annual rotation enabled",
        "service": "kms",
        "base_severity": 2,
        "impact_axis": "C",
        "hipaa": "164.312(a)(2)(iv) Encryption and Decryption",
        "cis": "3.8",
        "nist": "SC-12",
        "attack": ["T1552"],
        "remediation": "Enable automatic key rotation on the CMK.",
    },
    "LAMBDA.1": {
        "title": "Lambda environment variables hold no plaintext secrets",
        "service": "lambda",
        "base_severity": 4,
        "impact_axis": "C",
        "hipaa": "164.312(a)(1) Access Control",
        "cis": "n/a",
        "nist": "IA-5",
        "attack": ["T1552.001"],
        "remediation": "Move the value into Secrets Manager or an SSM SecureString parameter and read it at runtime.",
    },
}

# Severity band used consistently by the scorer, the dashboard and the report.
SEVERITY_BANDS = [
    (20.0, "Critical"),
    (12.0, "High"),
    (6.0, "Medium"),
    (0.0, "Low"),
]


def band(risk_score: float) -> str:
    for threshold, name in SEVERITY_BANDS:
        if risk_score >= threshold:
            return name
    return "Low"

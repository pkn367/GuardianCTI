"""
Cloud configuration collection layer (project document Sections 8.1 and 8.2).

Reads the live AWS account through boto3 and emits one finding record per
(check, resource) pair. Nothing here judges risk -- that is scoring.py's job.
Every collector is wrapped so that a denied API call in the Learner Lab
degrades to a skipped check instead of killing the run.
"""

from __future__ import annotations

import datetime as dt
import json
import logging

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from .checks import CHECKS

log = logging.getLogger("guardian.collector")

ADMIN_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 27017: "MongoDB"}
SECRET_HINTS = ("password", "secret", "token", "apikey", "api_key", "private_key", "passwd", "credential")

_now = lambda: dt.datetime.now(dt.timezone.utc)


def _finding(check_id, resource_id, resource_type, status, evidence, phi=False):
    """One row. `status` is PASS, FAIL or SKIP."""
    return {
        "check_id": check_id,
        "title": CHECKS[check_id]["title"],
        "service": CHECKS[check_id]["service"],
        "resource_id": resource_id,
        "resource_type": resource_type,
        "status": status,
        "evidence": evidence,
        "phi": phi,
        "collected_at": _now().isoformat(),
    }


def _safe(label):
    """Decorator: never let one unavailable service abort the whole assessment."""
    def wrap(fn):
        def inner(*a, **kw):
            try:
                return fn(*a, **kw)
            except (ClientError, BotoCoreError) as exc:
                log.warning("%s collector skipped: %s", label, exc)
                return []
        inner.__name__ = fn.__name__
        return inner
    return wrap


def _is_phi(tags):
    """A resource is PHI-bearing if it is tagged so. Untagged storage is treated
    as PHI-bearing too, because in a hospital that assumption fails safe."""
    values = {(t.get("Key") or "").lower(): (t.get("Value") or "").lower() for t in (tags or [])}
    if "dataclassification" in values:
        return values["dataclassification"] in {"phi", "ephi", "restricted", "sensitive"}
    return not values


# --------------------------------------------------------------------------- S3
@_safe("s3")
def collect_s3(session):
    s3 = session.client("s3")
    out = []
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        try:
            tags = s3.get_bucket_tagging(Bucket=name).get("TagSet", [])
        except ClientError:
            tags = []
        phi = _is_phi(tags)

        try:
            cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            blocked = all(cfg.get(k) for k in
                          ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"))
        except ClientError:
            cfg, blocked = {}, False
        out.append(_finding("S3.1", name, "AWS::S3::Bucket",
                            "PASS" if blocked else "FAIL", {"public_access_block": cfg}, phi))

        try:
            rules = s3.get_bucket_encryption(Bucket=name)["ServerSideEncryptionConfiguration"]["Rules"]
            algo = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
            enc_ok, ev = True, {"algorithm": algo}
        except ClientError:
            enc_ok, ev = False, {"algorithm": None}
        out.append(_finding("S3.2", name, "AWS::S3::Bucket", "PASS" if enc_ok else "FAIL", ev, phi))

        ver = s3.get_bucket_versioning(Bucket=name).get("Status")
        out.append(_finding("S3.3", name, "AWS::S3::Bucket",
                            "PASS" if ver == "Enabled" else "FAIL", {"versioning": ver or "Disabled"}, phi))

        logging_cfg = s3.get_bucket_logging(Bucket=name).get("LoggingEnabled")
        out.append(_finding("S3.4", name, "AWS::S3::Bucket",
                            "PASS" if logging_cfg else "FAIL", {"access_logging": bool(logging_cfg)}, phi))
    return out


# -------------------------------------------------------------------------- EC2
@_safe("ec2")
def collect_ec2(session):
    ec2 = session.client("ec2")
    out = []

    for sg in ec2.describe_security_groups().get("SecurityGroups", []):
        sg_id, exposed, wide_open = sg["GroupId"], [], False
        for perm in sg.get("IpPermissions", []):
            open_to_world = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", []))
            if not open_to_world:
                continue
            if perm.get("IpProtocol") == "-1":
                wide_open = True
                continue
            lo, hi = perm.get("FromPort", 0), perm.get("ToPort", 65535)
            for port, svc in ADMIN_PORTS.items():
                if lo <= port <= hi:
                    exposed.append({"port": port, "service": svc})
        out.append(_finding("EC2.1", sg_id, "AWS::EC2::SecurityGroup",
                            "FAIL" if exposed else "PASS",
                            {"group_name": sg.get("GroupName"), "exposed_admin_ports": exposed}, False))
        out.append(_finding("EC2.2", sg_id, "AWS::EC2::SecurityGroup",
                            "FAIL" if wide_open else "PASS",
                            {"group_name": sg.get("GroupName"), "all_protocols_open": wide_open}, False))

    for vol in ec2.describe_volumes().get("Volumes", []):
        out.append(_finding("EC2.3", vol["VolumeId"], "AWS::EC2::Volume",
                            "PASS" if vol.get("Encrypted") else "FAIL",
                            {"size_gb": vol.get("Size"), "encrypted": bool(vol.get("Encrypted"))},
                            _is_phi(vol.get("Tags"))))

    for res in ec2.describe_instances().get("Reservations", []):
        for inst in res.get("Instances", []):
            tokens = (inst.get("MetadataOptions") or {}).get("HttpTokens")
            out.append(_finding("EC2.4", inst["InstanceId"], "AWS::EC2::Instance",
                                "PASS" if tokens == "required" else "FAIL",
                                {"http_tokens": tokens, "state": inst["State"]["Name"]},
                                _is_phi(inst.get("Tags"))))
    return out


# -------------------------------------------------------------------------- IAM
@_safe("iam")
def collect_iam(session):
    iam = session.client("iam")
    out = []

    for pol in iam.list_policies(Scope="Local", MaxItems=200).get("Policies", []):
        try:
            doc = iam.get_policy_version(PolicyArn=pol["Arn"], VersionId=pol["DefaultVersionId"])
        except ClientError as exc:
            log.warning("IAM.1 skipped for %s: %s", pol["PolicyName"], exc)
            continue
        stmts = doc["PolicyVersion"]["Document"].get("Statement", [])
        stmts = stmts if isinstance(stmts, list) else [stmts]
        admin = any(
            s.get("Effect") == "Allow"
            and "*" in (s.get("Action") if isinstance(s.get("Action"), list) else [s.get("Action", "")])
            and "*" in (s.get("Resource") if isinstance(s.get("Resource"), list) else [s.get("Resource", "")])
            for s in stmts
        )
        out.append(_finding("IAM.1", pol["PolicyName"], "AWS::IAM::Policy",
                            "FAIL" if admin else "PASS",
                            {"arn": pol["Arn"], "grants_full_admin": admin}, False))

    try:
        users = iam.list_users().get("Users", [])
    except ClientError as exc:
        log.warning("IAM.3/2/4 skipped, cannot list users: %s", exc)
        users = []

    for user in users:
        uname = user["UserName"]
        try:
            mfa = iam.list_mfa_devices(UserName=uname).get("MFADevices", [])
            out.append(_finding("IAM.3", uname, "AWS::IAM::User",
                                "PASS" if mfa else "FAIL", {"mfa_devices": len(mfa)}, False))
        except ClientError as exc:
            log.warning("IAM.3 skipped for %s: %s", uname, exc)

        try:
            keys = iam.list_access_keys(UserName=uname).get("AccessKeyMetadata", [])
        except ClientError as exc:
            log.warning("IAM.2/4 skipped for %s: %s", uname, exc)
            continue
        for key in keys:
            age = (_now() - key["CreateDate"]).days
            out.append(_finding("IAM.2", key["AccessKeyId"], "AWS::IAM::AccessKey",
                                "FAIL" if age > 90 else "PASS",
                                {"user": uname, "age_days": age, "status": key["Status"]}, False))
            try:
                used = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"]).get("AccessKeyLastUsed", {})
            except ClientError as exc:
                log.warning("IAM.4 skipped for %s: %s", key["AccessKeyId"], exc)
                continue
            last = used.get("LastUsedDate")
            idle = (_now() - last).days if last else age
            out.append(_finding("IAM.4", key["AccessKeyId"], "AWS::IAM::AccessKey",
                                "FAIL" if idle > 45 else "PASS",
                                {"user": uname, "idle_days": idle, "ever_used": bool(last)}, False))
    return out


# -------------------------------------------------------------------------- RDS
@_safe("rds")
def collect_rds(session):
    rds = session.client("rds")
    out = []
    for db in rds.describe_db_instances().get("DBInstances", []):
        ident = db["DBInstanceIdentifier"]
        tags = db.get("TagList", [])
        phi = _is_phi(tags)
        out.append(_finding("RDS.1", ident, "AWS::RDS::DBInstance",
                            "FAIL" if db.get("PubliclyAccessible") else "PASS",
                            {"publicly_accessible": bool(db.get("PubliclyAccessible")),
                             "engine": db.get("Engine")}, phi))
        out.append(_finding("RDS.2", ident, "AWS::RDS::DBInstance",
                            "PASS" if db.get("StorageEncrypted") else "FAIL",
                            {"storage_encrypted": bool(db.get("StorageEncrypted"))}, phi))
        retention = db.get("BackupRetentionPeriod", 0)
        out.append(_finding("RDS.3", ident, "AWS::RDS::DBInstance",
                            "PASS" if retention >= 7 else "FAIL",
                            {"backup_retention_days": retention}, phi))
    return out


# ------------------------------------------------------------------- CloudTrail
@_safe("cloudtrail")
def collect_cloudtrail(session):
    ct = session.client("cloudtrail")
    trails = ct.describe_trails().get("trailList", [])
    if not trails:
        return [_finding("LOG.1", "account", "AWS::CloudTrail::Trail", "FAIL",
                         {"trails": 0, "note": "no trail configured"}, False)]
    out = []
    multi = any(t.get("IsMultiRegionTrail") for t in trails)
    out.append(_finding("LOG.1", trails[0]["Name"], "AWS::CloudTrail::Trail",
                        "PASS" if multi else "FAIL",
                        {"trails": len(trails), "multi_region": multi}, False))
    for t in trails:
        out.append(_finding("LOG.2", t["Name"], "AWS::CloudTrail::Trail",
                            "PASS" if t.get("LogFileValidationEnabled") else "FAIL",
                            {"log_file_validation": bool(t.get("LogFileValidationEnabled"))}, False))
    return out


# -------------------------------------------------------------------------- KMS
@_safe("kms")
def collect_kms(session):
    kms = session.client("kms")
    out = []
    for key in kms.list_keys().get("Keys", [])[:50]:
        kid = key["KeyId"]
        meta = kms.describe_key(KeyId=kid)["KeyMetadata"]
        if meta.get("KeyManager") != "CUSTOMER" or meta.get("KeyState") != "Enabled":
            continue
        try:
            rotating = kms.get_key_rotation_status(KeyId=kid).get("KeyRotationEnabled", False)
        except ClientError:
            rotating = False
        out.append(_finding("KMS.1", kid, "AWS::KMS::Key",
                            "PASS" if rotating else "FAIL",
                            {"rotation_enabled": rotating, "description": meta.get("Description", "")}, False))
    return out


# ----------------------------------------------------------------------- Lambda
@_safe("lambda")
def collect_lambda(session):
    lam = session.client("lambda")
    out = []
    for fn in lam.list_functions().get("Functions", []):
        env = (fn.get("Environment") or {}).get("Variables", {}) or {}
        leaked = [k for k in env if any(h in k.lower() for h in SECRET_HINTS)]
        out.append(_finding("LAMBDA.1", fn["FunctionName"], "AWS::Lambda::Function",
                            "FAIL" if leaked else "PASS",
                            {"suspicious_env_keys": leaked, "runtime": fn.get("Runtime")}, False))
    return out


COLLECTORS = [collect_s3, collect_ec2, collect_iam, collect_rds,
              collect_cloudtrail, collect_kms, collect_lambda]


def collect_all(region="us-east-1", profile=None):
    session = boto3.Session(profile_name=profile, region_name=region) if profile \
        else boto3.Session(region_name=region)
    findings = []
    for fn in COLLECTORS:
        rows = fn(session)
        log.info("%s -> %d findings", fn.__name__, len(rows))
        findings.extend(rows)
    for f in findings:
        f["region"] = region
    return findings


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    print(json.dumps(collect_all(), indent=2, default=str))

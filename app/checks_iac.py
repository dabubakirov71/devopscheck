"""
Infrastructure-as-Code checks: Terraform, and light Ansible/Helm signals.

These are the findings platform teams act on — an ingress rule open to the
whole internet, an unencrypted bucket, state stored on someone's laptop. All
checks return an empty list when the repository has no IaC, so a plain
application repo is never penalised for infrastructure it does not own.
"""
import logging
import re

from django.utils.translation import gettext as _

logger = logging.getLogger(__name__)

MAX_TF_FILES = 40

SENSITIVE_PORTS = {
    22: 'SSH', 3389: 'RDP', 3306: 'MySQL', 5432: 'PostgreSQL', 6379: 'Redis',
    27017: 'MongoDB', 9200: 'Elasticsearch', 5984: 'CouchDB', 11211: 'Memcached',
    2375: 'Docker daemon', 2379: 'etcd',
}


def _collect_terraform(client):
    paths = [p for p in client.walk(suffixes=('.tf', '.tfvars')) if 'examples/' not in p][:MAX_TF_FILES]
    parts = []
    for p in paths:
        c = client.get_content(p)
        if c:
            parts.append((p, c))
    return parts


def _open_ingress(blob: str) -> list[str]:
    """Ports reachable from 0.0.0.0/0 in an ingress block."""
    exposed = []
    for block in re.finditer(
        r'ingress\s*\{(.*?)\}', blob, re.DOTALL | re.IGNORECASE
    ):
        body = block.group(1)
        if '0.0.0.0/0' not in body and '::/0' not in body:
            continue
        from_port = re.search(r'from_port\s*=\s*(\d+)', body)
        to_port = re.search(r'to_port\s*=\s*(\d+)', body)
        if not from_port:
            continue
        lo, hi = int(from_port.group(1)), int(to_port.group(1)) if to_port else int(from_port.group(1))
        for port, label in SENSITIVE_PORTS.items():
            if lo <= port <= hi:
                exposed.append(f'{port} ({label})')
        if lo == 0 and hi >= 65535:
            exposed.append(_('all ports'))
    return sorted(set(exposed))


def check_iac(client) -> list[dict]:
    from app.checks import _c

    tf_files = _collect_terraform(client)
    if not tf_files:
        logger.info('IaC: no Terraform found for %s, skipping', client.full_name)
        return []

    blob = '\n'.join(c for _p, c in tf_files)
    logger.info('IaC: scanning %d Terraform file(s) for %s', len(tf_files), client.full_name)
    checks = []

    # 1. Remote state with locking.
    has_backend = bool(re.search(r'backend\s+"(s3|gcs|azurerm|remote|http|consul|kubernetes)"', blob))
    has_locking = bool(
        re.search(r'dynamodb_table\s*=', blob) or
        re.search(r'use_lockfile\s*=\s*true', blob) or
        re.search(r'backend\s+"(gcs|azurerm|remote|kubernetes)"', blob)
    )
    checks.append(_c(
        'iac.remote_state',
        _('Terraform state is remote and locked'),
        _('Local state means no team can apply safely — two people applying at once corrupt it, '
          'and the file usually holds secrets in plain text.')
        if not (has_backend and has_locking) else _('Remote backend with state locking is configured.'),
        'crit' if not has_backend else 'warn',
        has_backend and has_locking, 'iac',
        _('Configure a remote backend with locking:\n'
          'terraform {\n  backend "s3" {\n    bucket         = "my-tf-state"\n'
          '    key            = "prod/terraform.tfstate"\n    region         = "eu-central-1"\n'
          '    dynamodb_table = "tf-state-lock"\n    encrypt        = true\n  }\n}'),
    ))

    # 2. Security groups open to the internet.
    exposed = _open_ingress(blob)
    checks.append(_c(
        'iac.open_ingress',
        _('No sensitive ports open to the internet'),
        _('Ingress from 0.0.0.0/0 reaches: %(ports)s. These are scanned continuously by bots.')
        % {'ports': ', '.join(exposed)} if exposed else
        _('No sensitive port is reachable from 0.0.0.0/0.'),
        'crit', not exposed, 'iac',
        _('Restrict cidr_blocks to your VPC or office ranges, and reach admin ports through a bastion '
          'host or SSM Session Manager instead of exposing them.'),
    ))

    # 3. Storage encryption.
    has_s3 = 'aws_s3_bucket' in blob
    has_rds = 'aws_db_instance' in blob or 'aws_rds_cluster' in blob
    has_ebs = 'aws_ebs_volume' in blob
    if has_s3 or has_rds or has_ebs:
        s3_ok = (not has_s3) or bool(
            re.search(r'server_side_encryption_configuration|aws_s3_bucket_server_side_encryption_configuration', blob)
        )
        rds_ok = (not has_rds) or bool(re.search(r'storage_encrypted\s*=\s*true', blob))
        ebs_ok = (not has_ebs) or bool(re.search(r'encrypted\s*=\s*true', blob))
        encrypted = s3_ok and rds_ok and ebs_ok
        missing = []
        if not s3_ok: missing.append('S3')
        if not rds_ok: missing.append('RDS')
        if not ebs_ok: missing.append('EBS')
        checks.append(_c(
            'iac.encryption_at_rest',
            _('Storage is encrypted at rest'),
            _('Encryption at rest is not configured for: %(what)s.') % {'what': ', '.join(missing)}
            if missing else _('Encryption at rest is configured for the storage resources found.'),
            'warn', encrypted, 'iac',
            _('Set storage_encrypted = true on RDS, encrypted = true on EBS volumes, and add an '
              'aws_s3_bucket_server_side_encryption_configuration resource for each bucket.'),
        ))

    # 4. Publicly accessible databases.
    public_db = bool(re.search(r'publicly_accessible\s*=\s*true', blob))
    if has_rds:
        checks.append(_c(
            'iac.private_database',
            _('Databases are not publicly accessible'),
            _('A managed database has publicly_accessible = true — it is reachable from the open internet.')
            if public_db else _('Databases are confined to private subnets.'),
            'crit', not public_db, 'iac',
            _('Set publicly_accessible = false and place the instance in private subnets. '
              'Reach it through a bastion host or VPN.'),
        ))

    # 5. Public bucket ACLs.
    public_bucket = bool(re.search(r'acl\s*=\s*"public-read(?:-write)?"', blob))
    if has_s3:
        checks.append(_c(
            'iac.no_public_buckets',
            _('No publicly readable object storage'),
            _('A bucket is declared with a public-read ACL. Public buckets are the single most common '
              'source of accidental data exposure.')
            if public_bucket else _('No bucket grants public access.'),
            'crit', not public_bucket, 'iac',
            _('Remove the public ACL and add an aws_s3_bucket_public_access_block with all four '
              'settings set to true. Serve public objects through CloudFront instead.'),
        ))

    # 6. Provider credentials in code.
    hardcoded = bool(re.search(
        r'(?i)\b(access_key|secret_key|client_secret|password)\s*=\s*"[^"$\s]{8,}"', blob
    ))
    checks.append(_c(
        'iac.no_hardcoded_credentials',
        _('No provider credentials hardcoded in Terraform'),
        _('Credentials are assigned as literals in .tf files, which puts them in git history.')
        if hardcoded else _('Credentials come from variables or the environment.'),
        'crit', not hardcoded, 'iac',
        _('Move them to variables sourced from the environment (TF_VAR_*), or to a secret manager '
          'data source. Never commit a .tfvars file holding real values.'),
    ))

    # 7. Provider version constraints.
    pinned = bool(re.search(r'required_providers\s*\{', blob) and re.search(r'version\s*=\s*"', blob))
    checks.append(_c(
        'iac.pinned_providers',
        _('Provider versions are constrained'),
        _('Without required_providers version constraints, a plan can silently change behaviour '
          'when a new provider release lands.')
        if not pinned else _('Provider versions are constrained.'),
        'warn', pinned, 'iac',
        _('Add:\nterraform {\n  required_version = ">= 1.6"\n  required_providers {\n'
          '    aws = {\n      source  = "hashicorp/aws"\n      version = "~> 5.0"\n    }\n  }\n}'),
    ))

    # 8. IaC scanning in CI.
    ci_blob = ' '.join(filter(None, [
        client.get_content('.gitlab-ci.yml') or '',
        *[client.get_content(f'.github/workflows/{f}') or ''
          for f in client.list_dir('.github/workflows')[:10]],
    ])).lower()
    has_iac_scan = any(w in ci_blob for w in ['checkov', 'tfsec', 'terrascan', 'trivy config', 'kics', 'tflint'])
    checks.append(_c(
        'iac.scanning',
        _('Terraform is scanned in CI'),
        _('An IaC scanner catches a misconfigured resource in review, not after it is live.'),
        'warn', has_iac_scan, 'iac',
        _('Add Checkov or tfsec to the pipeline:\n'
          '- run: pip install checkov && checkov -d . --quiet --compact'),
    ))

    return checks

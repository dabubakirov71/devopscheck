"""
Software Bill of Materials export.

The EU Cyber Resilience Act obliges manufacturers of products with digital
elements to maintain an SBOM for the top-level dependencies of their software.
That obligation is a reason to buy, not a nice-to-have — so the export is a
first-class feature of the Compliance plan rather than a hidden button.

Two formats are produced from the same parsed dependency list:
  • CycloneDX 1.5 (JSON) — the OWASP format most scanners consume
  • SPDX 2.3 (JSON)      — the format procurement and legal teams ask for
"""
import hashlib
import logging
import uuid

from app.checks_extra import (
    _parse_cargo_toml,
    _parse_go_mod,
    _parse_package_json,
    _parse_requirements_txt,
)

logger = logging.getLogger(__name__)

# (filename, parser, CycloneDX purl type, SPDX-friendly ecosystem label)
SOURCES = [
    ('requirements.txt', _parse_requirements_txt, 'pypi',   'PyPI'),
    ('package.json',     _parse_package_json,     'npm',    'npm'),
    ('go.mod',           _parse_go_mod,           'golang', 'Go'),
    ('Cargo.toml',       _parse_cargo_toml,       'cargo',  'crates.io'),
]


def collect_components(get_content_fn) -> list[dict]:
    """Parse every recognised manifest into a deduplicated component list."""
    components = []
    seen = set()
    for filename, parser, purl_type, ecosystem in SOURCES:
        content = get_content_fn(filename)
        if not content:
            continue
        for name, version in parser(content):
            key = (purl_type, name.lower(), version)
            if key in seen:
                continue
            seen.add(key)
            components.append({
                'name': name,
                'version': version,
                'purl': f'pkg:{purl_type}/{name}@{version}',
                'ecosystem': ecosystem,
                'source_file': filename,
            })
    logger.info('SBOM: collected %d component(s)', len(components))
    return components


def _deterministic_serial(repo_name: str) -> str:
    """A stable URN for a repository, so re-exports are diffable."""
    digest = hashlib.sha256(repo_name.encode()).digest()[:16]
    return f'urn:uuid:{uuid.UUID(bytes=digest, version=4)}'


def build_cyclonedx(repo_name: str, components: list[dict], timestamp) -> dict:
    return {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.5',
        'serialNumber': _deterministic_serial(repo_name),
        'version': 1,
        'metadata': {
            'timestamp': timestamp.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'tools': [{'vendor': 'DevOpsCheck', 'name': 'devops-audit', 'version': '1.0'}],
            'component': {
                'type': 'application',
                'name': repo_name,
                'bom-ref': f'app:{repo_name}',
            },
        },
        'components': [
            {
                'type': 'library',
                'bom-ref': c['purl'],
                'name': c['name'],
                'version': c['version'],
                'purl': c['purl'],
            }
            for c in components
        ],
    }


def build_spdx(repo_name: str, components: list[dict], timestamp) -> dict:
    def spdx_id(index):
        return f'SPDXRef-Package-{index}'

    packages = [
        {
            'SPDXID': spdx_id(i),
            'name': c['name'],
            'versionInfo': c['version'],
            'downloadLocation': 'NOASSERTION',
            'filesAnalyzed': False,
            'licenseConcluded': 'NOASSERTION',
            'licenseDeclared': 'NOASSERTION',
            'copyrightText': 'NOASSERTION',
            'externalRefs': [{
                'referenceCategory': 'PACKAGE-MANAGER',
                'referenceType': 'purl',
                'referenceLocator': c['purl'],
            }],
        }
        for i, c in enumerate(components, start=1)
    ]
    return {
        'spdxVersion': 'SPDX-2.3',
        'dataLicense': 'CC0-1.0',
        'SPDXID': 'SPDXRef-DOCUMENT',
        'name': f'{repo_name}-sbom',
        'documentNamespace': f'https://devopscheck.com/sbom/{repo_name}/{timestamp:%Y%m%d%H%M%S}',
        'creationInfo': {
            'created': timestamp.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'creators': ['Tool: devops-audit-1.0'],
        },
        'packages': packages,
        'relationships': [
            {
                'spdxElementId': 'SPDXRef-DOCUMENT',
                'relationshipType': 'DESCRIBES',
                'relatedSpdxElement': p['SPDXID'],
            }
            for p in packages
        ],
    }


def generate(repo_name: str, get_content_fn, fmt: str, timestamp,
             components: list[dict] | None = None) -> tuple[dict, str]:
    """
    Return (document, suggested filename) for 'cyclonedx' or 'spdx'.

    Pass `components` to build from an inventory captured at audit time; only
    when none is given is the repository read again.
    """
    if components is None:
        components = collect_components(get_content_fn)
    safe = repo_name.replace('/', '_')
    if fmt == 'spdx':
        return build_spdx(repo_name, components, timestamp), f'{safe}.spdx.json'
    return build_cyclonedx(repo_name, components, timestamp), f'{safe}.cdx.json'

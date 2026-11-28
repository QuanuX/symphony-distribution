#!/usr/bin/env python3
"""Print public Anaconda overview fields for Symphony package names as JSON."""
from __future__ import annotations

import copy
import json
from functools import cache
from pathlib import Path

HOME = 'https://quanux.org'
DOCS = 'https://quanux.org/downloads/anaconda'
RELEASES = 'https://github.com/QuanuX/symphony-distribution/releases'
ROOT = Path(__file__).resolve().parents[1]
D09_PLAN = json.loads((ROOT / 'evidence/d09-anaconda-stage-plan.json').read_text(encoding='utf-8'))
REVIEW_SOURCE = D09_PLAN['corresponding_source_url']
D09_NAMES = {item['name'] for item in D09_PLAN['packages']}
REVIEW_NAMES = {'symphony-client-bridge-review-payload', 'symphony-corresponding-source-review-payload'}
KEYRING = 'symphony-node-keyring-deb-payload'
BETA1_SOURCE_NAMES = {'symphony-client-payload', 'symphony-corresponding-source-payload'}
SUMMARIES = json.loads(Path(__file__).with_name('package_summaries.json').read_text(encoding='utf-8'))

BETA_GUIDANCE = (
    'Install Symphony from the explicit package list for your operating system and architecture. '
    'Conda places the files under share/symphony/carriers in the chosen environment. '
    'Native setup, activation, removal and application selection are separate steps.\n\n'
    'For corresponding source, open the file description for the exact build. '
    'A component version can be reused across platforms and Symphony releases. '
    'Install the matching optional source package in a separate environment, extract its payload.tar, '
    'and read the source index, scope records and included license notices. '
    f'Signed release indexes and verification instructions are available at <{RELEASES}>.'
)
KEYRING_GUIDANCE = (
    'Select the Ubuntu 26.04 AMD64 or ARM64 build for your node. The Conda archive delivers a .deb. '
    'Install the .deb with the Debian package manager to configure the native keyring. '
    'This supplement is optional and is separate from the default Symphony installation.\n\n'
    'Use the file description for the corresponding source of your exact build. '
    f'The signed supplement index, source archive and license notices accompany the Symphony release at <{RELEASES}>.'
)


@cache
def beta1_source_guidance():
    """Reuse the per-platform source links published on the original beta.1 version cards."""
    references = []
    for profile in ('macos15-arm64', 'ubuntu24.04-amd64', 'ubuntu24.04-arm64', 'ubuntu26.04-amd64'):
        receipt = ROOT / 'evidence/beta-publication' / f'{profile}-anaconda.json'
        publication = json.loads(receipt.read_text(encoding='utf-8'))
        source, = (row for row in publication['packages'] if row['selection'] == 'optional-source')
        url = source['immutable_source_retrieval']['url']
        references.append(f'- {profile}: <{url}>')
    return 'Historical corresponding source for Symphony 0.2.0-beta.1:\n\n' + '\n'.join(references)


def overview(name, *, review_source=REVIEW_SOURCE):
    """The same component version can have both beta and historical review builds."""
    summary = SUMMARIES.get(name)
    if summary is None:
        unit = name.removeprefix('symphony-').removesuffix('-payload').replace('-', ' ')
        summary = f'Provides the {unit} component of Symphony.'
    if name in REVIEW_NAMES:
        guidance = (
            'This package was staged for D09 review on Intel macOS using the d09-review label. '
            'For the supported public beta, use the platform lists in the Anaconda installation guide.\n\n'
            f'Exact reviewed corresponding source: <{review_source}>. Install that optional source package '
            'in a separate environment, extract payload.tar under share/symphony/carriers, and read '
            'source-index.json and SOURCE-SCOPE.json inside the source archive for original and derived '
            'source bindings. The archive includes the corresponding notices. Native activation is separate.'
        )
    elif name == KEYRING:
        guidance = KEYRING_GUIDANCE
    else:
        guidance = BETA_GUIDANCE
        if name in D09_NAMES:
            guidance += (
                '\n\nFor the historical Intel macOS D09 review builds, the exact corresponding source is '
                f'<{review_source}>. The optional review archive contains source-index.json and SOURCE-SCOPE.json '
                'with the original and derived source bindings.'
            )
    paragraphs = [summary, guidance]
    if name in BETA1_SOURCE_NAMES:
        paragraphs.append(beta1_source_guidance())
    paragraphs.append(f'Installation and verification: <{DOCS}>.')
    return {'summary': summary, 'description': '\n\n'.join(paragraphs), 'home': HOME, 'doc_url': DOCS}


SERVER_FIELDS = {'access', 'builds', 'conda_platforms', 'created_at', 'files', 'full_name', 'html_url', 'id',
    'latest_version', 'modified_at', 'name', 'ndownloads', 'owner', 'platforms', 'public', 'releases', 'revision',
    'upvoted', 'url', 'versions', 'watchers'}


def public_attrs(package):
    if 'public_attrs' in package:
        if not isinstance(package['public_attrs'], dict):
            raise ValueError('Package attributes unavailable')
        return copy.deepcopy(package['public_attrs'])
    return copy.deepcopy({k: v for k, v in package.items() if k not in SERVER_FIELDS})


def ensure_catalog(api, owner, row, fields, mutate, *, require_existing=False):
    from binstar_client.errors import NotFound
    from binstar_client.utils.config import PackageType

    name, version = row['name'], row['version']
    try:
        package = api.package(owner, name)
    except NotFound:
        if require_existing:
            raise ValueError('Serial catalog preparation required before parallel publication')
        mutate('create_package', row, lambda: api.add_package(
            owner, name, summary=fields['summary'], license='LicenseRef-Complete-Embedded-Notices',
            public=True, attrs=fields.copy(), package_type=PackageType.CONDA))
        package = api.package(owner, name)
    if package.get('public') is not True:
        raise ValueError('Existing package is not public')
    desired = {**public_attrs(package), **fields}
    try:
        api.release(owner, name, version)
    except NotFound:
        if require_existing:
            raise ValueError('Serial release preparation required before parallel publication')
        # Anaconda displays the version description on its public overview page.
        mutate('create_release', row, lambda: api.add_release(owner, name, version, {}, '', fields.copy()))
        api.release(owner, name, version)
    # Creating a version can reset package metadata. Restore the attributes
    # observed before creation, including unrelated license and custom fields.
    current = api.package(owner, name)
    if current.get('public') is not True:
        raise ValueError('Existing package is not public')
    if public_attrs(current) == desired:
        return
    if require_existing:
        raise ValueError('Serial package metadata preparation required')
    mutate('update_catalog_metadata_preserving_attributes', row, lambda: api.update_package(owner, name, desired))
    after = api.package(owner, name)
    if after.get('public') is not True or public_attrs(after) != desired:
        raise ValueError('Package attributes were not preserved')


if __name__ == '__main__':
    print(json.dumps({name: overview(name) for name in sorted(SUMMARIES)}, indent=2))

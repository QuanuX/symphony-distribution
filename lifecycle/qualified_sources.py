"""Closed retained-source compatibility, never caller-supplied trust policy."""
from pathlib import Path

import go_delivery

owners = go_delivery.owners
require = owners.require
PRIOR_COMMIT = 'ad7ed0e0857a1d8cc9d0fa3617579bbf5fc46b70'
PRIOR_TREE = 'f0bb667817514515d33b86679c72431947260f39'
# Historical controller for this one qualified pairing; never advance these
# constants merely because source-binding.json selects a newer candidate.
CURRENT_COMMIT = '5fd6cee1bae477048bf0045b691ee8bdf334e216'
CURRENT_TREE = '327edd0f22860e84d30fe745f5a2b0e602f4af88'
PRIOR_FILE_SHA256 = '0698b5818b10e11667ac3c7f1be8da55a8b8b89a3fc3b19cc30fb44de1de3329'


def retained_binding(current):
    require((current['source_commit'], current['source_tree']) == (CURRENT_COMMIT, CURRENT_TREE),
            'Retained source has not been qualified against this controller source')
    path = Path(__file__).parent / 'qualified-sources' / (PRIOR_COMMIT + '.json')
    data = path.read_bytes()
    require(owners.sha(data) == PRIOR_FILE_SHA256, 'Code-owned retained source evidence changed')
    prior = owners.strict_json(data)
    require((prior['source_commit'], prior['source_tree']) == (PRIOR_COMMIT, PRIOR_TREE), 'Retained source identity differs')
    owners.validate_seal(prior, 'binding_digest', prior['binding_digest'])
    # This bounded pairing reuses exactly the same three native owner runtime
    # implementations and scoped dispatcher. Test/qualification fixes differ;
    # historical local results do not become fresh-host acceptance.
    roots = [owners.OWNERS[c]['source_root'] + '/' for c in owners.SERVICE_IDS]
    roots.append('tools/qxctl/internal/knowledgelifecycle/')
    exact = {'tools/qxctl/cmd/qxctl/lifecycle_apply.go', 'tools/qxctl/cmd/qxctl/commands.go',
             'cmake/mvp-go-owner-closure.json'}
    def runtime_rows(binding):
        return {r['path']: r['sha256'] for r in binding['source_evidence']
                if not r['path'].endswith('_test.go') and (r['path'] in exact or any(r['path'].startswith(p) for p in roots))}
    require(runtime_rows(prior) == runtime_rows(current) and runtime_rows(prior),
            'Retained native owner or dispatcher implementation differs; fresh qualification required')
    return prior


def resolve(catalog, expected_digest, controller_source=None):
    current = owners.reviewed_binding()
    if controller_source is not None:
        require((controller_source['commit'], controller_source['tree']) ==
                (current['source_commit'], current['source_tree']), 'Scoped controller differs from reviewed current source')
    if (catalog.get('source_commit'), catalog.get('source_tree')) == (current['source_commit'], current['source_tree']):
        binding = current
    else:
        require(catalog.get('source_commit') == PRIOR_COMMIT and catalog.get('source_tree') == PRIOR_TREE,
                'Unqualified retained owner source; no arbitrary historical catalog fallback')
        binding = retained_binding(current)
    owners.validate_catalog(catalog, expected_digest, binding=binding)
    return binding

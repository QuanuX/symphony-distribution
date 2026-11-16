"""Bounded package-stage proposals; runtime owners retain every mutation.

These checks classify caller-selected intent. They neither establish a historical
upgrade/rollback nor assert that an idle observation proves process retirement.
"""
from pathlib import Path

import contracts as contract
import go_delivery

require = contract.require
PROTOCOL = 'symphony.distribution.scoped-package-request.v2'
OPERATIONS = frozenset(('install', 'upgrade', 'swap', 'remove', 'rollback'))
TRANSITIONS = frozenset(('upgrade', 'swap', 'rollback'))
FIELDS = ('operation', 'prior_receipt_digest', 'prior_install_root')


def operation(request):
    return request.get('operation', 'install')


def overlap(first, second):
    a, b = Path(first), Path(second)
    return a == b or a in b.parents or b in a.parents


def validate_request(request, base_fields):
    require(isinstance(request, dict), 'Package request must be an object')
    if request.get('protocol') != PROTOCOL:
        contract.exact(request, base_fields, 'install request')
        require(request['protocol'] == 'symphony.distribution.scoped-install-request.v1' and
                type(request['format_version']) is int and request['format_version'] == 1,
                'Unknown install request version')
        return 'install'
    contract.exact(request, [*base_fields, *FIELDS], 'package journey request')
    require(type(request['format_version']) is int and request['format_version'] == 2 and
            request['operation'] in OPERATIONS, 'Unknown package journey version or operation')
    require(request['component_id'] in go_delivery.owners.SERVICE_IDS and request['state_scope'] == 'user',
            'Package journeys require a qualified user-scope native service owner; raw or unknown owners refuse')
    if request['operation'] in TRANSITIONS:
        require(contract.tagged(request['prior_receipt_digest']) and contract.safe_path(request['prior_install_root']),
                'An exact prior receipt and installation root are required')
    else:
        require(request['prior_receipt_digest'] is None and request['prior_install_root'] is None,
                'Unrelated prior candidate evidence is not allowed')
    return request['operation']


def receipt_identity(receipt):
    return {'package_id': receipt['package_id'], 'version': receipt['version'],
            'receipt_protocol': receipt['protocol'], 'receipt_digest': receipt['receipt_digest']}


def validate_state(request, component, current, receipt, prior_receipt, registry):
    op = operation(request)
    if request.get('protocol') == PROTOCOL:
        require(component['activation'] == 'inactive' and component['docking']['disposition'] == 'undocked',
                'Package journey cannot request activation or docking')
    if op == 'install':
        require(prior_receipt is None, 'Initial install does not accept a prior candidate')
        require(component['presence'] == 'present' and component['selected_package'] == receipt_identity(receipt),
                'Exact desired receipt identity is required')
        if current is not None:
            require(current['packages'] == [] and current['selected_package_digest'] is None and
                    current['activation'] == 'inactive' and current['docking'] == 'undocked',
                    'First handoff is installation into an absent component, not upgrade or live replacement')
        return 'install'
    require(current is not None and current['selected_package_digest'] is None and
            current['activation'] == 'inactive' and current['docking'] == 'undocked' and
            current['receptor_id'] is None and current['platform_compatibility'] == 'compatible',
            'Explicit deselected, inactive, undocked, compatible native observation required; no live transition')
    require(all(current[k] == component[k] for k in ('component_id', 'component_kind', 'module_id', 'vector_id', 'engine_id')),
            'Observed native component identity differs from the full desired profile')
    require(component['activation'] == 'inactive' and component['docking']['disposition'] == 'undocked',
            'Package journey cannot request activation or docking')
    require(len(current['packages']) == 1, 'Ambiguous or multiple installed candidates require separate native review')
    installed = current['packages'][0]
    require(installed['integrity'] == 'valid' and installed['entry_points_validated'] is True,
            'Installed receipt and entry points must be valid')
    if op == 'remove':
        require(prior_receipt is None and component['presence'] == 'absent' and component['selected_package'] is None,
                'Removal requires exact full-profile desired absence')
        expected, root = receipt, component['install_root']
        kind = 'uninstall'
    else:
        require(prior_receipt is not None, 'Retained prior receipt and candidate evidence required')
        registry.validate(prior_receipt, 'urn:symphony:knowledge:install-receipt:v2')
        contract.validate_receipt(prior_receipt, component)
        require(prior_receipt['receipt_digest'] == request['prior_receipt_digest'], 'Prior receipt identity differs')
        require(component['presence'] == 'present' and component['selected_package'] == receipt_identity(receipt),
                'Target candidate must match the unchanged full desired profile')
        require(receipt['receipt_digest'] != prior_receipt['receipt_digest'],
                'Transition must name a distinct exact candidate; byte-identical receipts need only a carrier transaction, no native replacement scope')
        require(not overlap(component['install_root'], request['prior_install_root']),
                'Target candidate requires a distinct nonoverlapping immutable root; no in-place replacement')
        expected, root, kind = prior_receipt, request['prior_install_root'], 'install'
    require({k: installed[k] for k in receipt_identity(expected)} == receipt_identity(expected) and
            installed['install_root'] == root, 'Observed installed candidate differs from exact retained prior identity/root')
    return kind


def describe(request, scope, receipt, native_binding, prior_binding):
    """Describe only verified preparation, without inventing runtime results."""
    op = operation(request)
    if request.get('protocol') != PROTOCOL:
        return None
    require(native_binding is not None, 'Package journey requires an explicit retained native owner')
    require((prior_binding is not None) == (op in TRANSITIONS), 'Prior retained controller coverage differs')
    return {
        'operation': op, 'stage': 'native_removal_proposal' if op == 'remove' else 'target_install_proposal',
        'effect_kind': scope['effects'][0]['kind'], 'target_receipt_digest': receipt['receipt_digest'],
        'prior_receipt_digest': request['prior_receipt_digest'], 'prior_install_root': request['prior_install_root'],
        'retained_target_candidate': native_binding, 'retained_prior_candidate': prior_binding,
        'full_profile_digest': scope['profile_digest'], 'execution_scope_digest': scope['scope_digest'],
        'runtime_owner_reference_and_process_checks': 'required_at_execution',
        'history_proven': False, 'journey_completed': False, 'old_candidate_reclaimed': False,
        'remaining_owner_steps': (['native_exact_scope_execution_and_verification'] if op in ('install', 'remove') else
                                 ['native_target_install_and_verification', 'separate_existing_selection_owner_review',
                                  'separate_old_candidate_retirement_review']),
    }

#!/usr/bin/env python3
"""Source-bound owner classification only. This module never executes an owner."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

SOURCE_COMMIT = "82abaa1421b99aefb836ba4030dfd80895d70ebb"
SOURCE_TREE = "f874d76f5102aba9251ec8a988501ff7e7547553"
IDENTITIES_SHA256 = "49e358f8b9e6b3085eef79b3e57235f8bad740e6068db15ad55ef8190d2a5335"
SOURCE_EVIDENCE_SHA256 = "4cf962e64cd1023e210be1fd0e8111e95b286105002cc8f583cd3b778f19ac0a"
PROTOCOL = "symphony.distribution.runtime-owner-catalog.v1"
CATALOG_VERSION = 1
OPERATIONS = {"verify_carrier", "stage_carrier", "install_runtime", "select_runtime",
              "swap_runtime", "remove_runtime", "remove_carrier"}


class InvalidCatalog(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def strict_json(data):
    if len(data) > 2 * 1024 * 1024:
        raise InvalidCatalog("document exceeds size limit")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise InvalidCatalog("duplicate JSON field")
            result[key] = value
        return result
    def constant(_):
        raise InvalidCatalog("nonfinite JSON number")
    return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)


def identities():
    data = (Path(__file__).parent / "inputs/delivery-identities.json").read_bytes()
    if sha(data) != IDENTITIES_SHA256:
        raise InvalidCatalog("reviewed delivery identity snapshot changed")
    return strict_json(data)


# These source-reviewed policy records are code-owned, not package-provided argv.
GO_OWNERS = {
    "secure-identity-access-governance": {
        "contract": "ssiag.package-owner.v1", "kind": "module_receipt_owner",
        "runtime_receipt": "symphony.knowledge.install-receipt.v2",
        "source_operations": ["package_install", "package_uninstall", "foundation_lifecycle"],
        "scopes": ["user", "system"], "selection_owner": "ssiag_foundation_lifecycle",
        "blockers": ["owner_dispatch_not_qualified", "admission_retirement_race", "authority_and_audit_required"],
        "evidence": ["modules/secure-identity-access-governance/SPEC.md", "modules/secure-identity-access-governance/INSTALL.md", "modules/secure-identity-access-governance/internal/packageinstall/package.go"],
    },
    "stav-append-authority": {
        "contract": "stav.package-owner.v1", "kind": "module_receipt_owner",
        "runtime_receipt": "symphony.knowledge.install-receipt.v2",
        "source_operations": ["install", "uninstall", "foundation_lifecycle"],
        "scopes": ["user", "system"], "selection_owner": "stav_foundation_lifecycle",
        "blockers": ["owner_dispatch_not_qualified", "admission_retirement_race", "pending_work_and_audit_required"],
        "evidence": ["modules/stav-append-authority/SPEC.md", "modules/stav-append-authority/INSTALL.md", "modules/stav-append-authority/internal/lifecycle/lifecycle.go"],
    },
    "accordare-stav-producer": {
        "contract": "accordare.package-owner.v1", "kind": "module_receipt_owner",
        "runtime_receipt": "symphony.knowledge.install-receipt.v2",
        "source_operations": ["install", "uninstall", "enrollment", "supervision", "grant_lifecycle"],
        "scopes": ["user", "system"], "selection_owner": "accordare_enrollment_supervision",
        "blockers": ["owner_dispatch_not_qualified", "admission_retirement_race", "pending_intents_outbox_and_grants"],
        "evidence": ["modules/accordare-stav-producer/INSTALL.md", "modules/accordare-stav-producer/internal/packageinstall/package.go"],
    },
    "qxctl": {
        "contract": "qxctl.executable-and-host-owner.v1", "kind": "raw_executable_host_binding",
        "runtime_receipt": None, "source_operations": ["exact_executable_selection", "linux_host_provision"],
        "scopes": ["user", "system"], "selection_owner": "explicit_client_or_linux_host_binding",
        "blockers": ["raw_delivery_custody_not_implemented", "self_and_recovery_copy_retention", "external_use_unknown"],
        "evidence": ["tools/qxctl/README.md", "tools/qxctl/internal/knowledgelifecycle/host_admin_unix.go"],
    },
    "sov-ssh-adapter": {
        "contract": "sov-ssh.exact-invocation-owner.v1", "kind": "raw_executable_invocation",
        "runtime_receipt": None, "source_operations": ["direct_v1_exact_invocation", "qualified_v2_transport_binding"],
        "scopes": ["selected_invocation"], "selection_owner": "sov_endpoint_or_qualified_transport_profile",
        "blockers": ["raw_delivery_custody_not_implemented", "v2_closure_not_supplied_by_raw_carrier", "admitted_session_release_required"],
        "evidence": ["tools/sov-ssh-adapter/README.md", "tools/sov-transport-profile-admin/INSTALL.md"],
    },
    "sov-stdio-adapter": {
        "contract": "sov-stdio.exact-invocation-owner.v1", "kind": "raw_executable_invocation",
        "runtime_receipt": None, "source_operations": ["target_configuration", "exact_invocation", "explicit_job_cancel"],
        "scopes": ["selected_invocation"], "selection_owner": "sov_target_and_invocation",
        "blockers": ["raw_delivery_custody_not_implemented", "configuration_removal_does_not_cancel_jobs", "admitted_outcome_reconciliation_required"],
        "evidence": ["tools/sov-stdio-adapter/README.md"],
    },
    "sov-transport-profile-admin": {
        "contract": "sov-admin.protected-host-provisioning.v1", "kind": "protected_host_provisioning",
        "runtime_receipt": None, "source_operations": ["administrator_provisioning", "reviewed_sudo_policy"],
        "scopes": ["administrator"], "selection_owner": "protected_host_policy",
        "blockers": ["protected_host_deployment_not_qualified", "pending_attempt_exact_binary_retention", "no_user_carrier_elevation"],
        "evidence": ["tools/sov-transport-profile-admin/INSTALL.md", "tools/sov-transport-profile-admin/SPEC.md"],
    },
}

NATIVE_OWNER = {
    "contract": "native.receipt-v2.classification.v1", "kind": "native_receipt_classification",
    "runtime_receipt": "symphony.knowledge.install-receipt.v2",
    "source_operations": ["candidate_verification", "exact_receipt_owned_files"],
    "scopes": ["explicit_prefix"], "selection_owner": "existing_profile_binding_and_receptor",
    "blockers": ["exact_owner_dispatch_requires_review", "live_use_release_unqualified"],
    "evidence": ["tools/qxctl/internal/knowledgelifecycle/executor.go", "tools/qxctl/internal/knowledgelifecycle/install_unix.go", "modules/maestro/SPEC.md"],
}


def owner_for(unit):
    if unit["kind"] == "go_command":
        try:
            policy = GO_OWNERS[unit["component_id"]]
        except KeyError:
            raise InvalidCatalog("unrecognized Go owner") from None
    elif unit["kind"] == "native_receipt_unit":
        policy = NATIVE_OWNER
    else:
        raise InvalidCatalog("unrecognized delivery kind")
    return {**policy, "contract_version": 1, "critical": True,
            "generic_receipt_delete_authorized": False, "owner_invocation_implemented": False,
            "live_removal_qualified": False}


def expected_units():
    return [{**unit, "runtime_owner": owner_for(unit)} for unit in identities()["units"]]


def build(repository):
    repository = Path(repository).resolve(strict=True)
    tree = subprocess.check_output(["git", "-C", str(repository), "rev-parse", SOURCE_COMMIT + "^{tree}"], text=True).strip()
    if tree != SOURCE_TREE:
        raise InvalidCatalog("source object identity mismatch")
    units = expected_units()
    paths = sorted({p for u in units for p in u["runtime_owner"]["evidence"]})
    evidence = [{"path": p, "sha256": sha(subprocess.check_output(
        ["git", "-C", str(repository), "show", SOURCE_COMMIT + ":" + p]))} for p in paths]
    if sha(canonical(evidence)) != SOURCE_EVIDENCE_SHA256:
        raise InvalidCatalog("source evidence does not match reviewed owner contracts")
    value = {"schema": PROTOCOL, "format_version": CATALOG_VERSION,
             "contract_source": {"commit": SOURCE_COMMIT, "tree": SOURCE_TREE},
             "delivery_snapshot_sha256": IDENTITIES_SHA256,
             "delivery_source": {k: identities()[k] for k in ("source_commit", "source_tree", "prior_catalog_sha256")},
             "units": units, "source_evidence": evidence,
             "classification_only": True, "runtime_execution_authorized": False,
             "publication_authorized": False, "release_acceptance_complete": False}
    value["catalog_digest"] = "sha256:" + sha(canonical(value))
    return value


def validate(value, expected_digest):
    keys = {"schema", "format_version", "contract_source", "delivery_snapshot_sha256", "delivery_source",
            "units", "source_evidence", "classification_only", "runtime_execution_authorized",
            "publication_authorized", "release_acceptance_complete", "catalog_digest"}
    if not isinstance(value, dict) or set(value) != keys:
        raise InvalidCatalog("closed catalog field set mismatch")
    if not isinstance(expected_digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_digest):
        raise InvalidCatalog("independently selected catalog digest required")
    basis = {k: v for k, v in value.items() if k != "catalog_digest"}
    if value["catalog_digest"] != expected_digest or expected_digest != "sha256:" + sha(canonical(basis)):
        raise InvalidCatalog("catalog digest mismatch")
    if value["schema"] != PROTOCOL or type(value["format_version"]) is not int or value["format_version"] != 1:
        raise InvalidCatalog("unsupported critical catalog version")
    if value["contract_source"] != {"commit": SOURCE_COMMIT, "tree": SOURCE_TREE}:
        raise InvalidCatalog("contract source substituted")
    snapshot = identities()
    if value["delivery_snapshot_sha256"] != IDENTITIES_SHA256 or value["delivery_source"] != {k: snapshot[k] for k in ("source_commit", "source_tree", "prior_catalog_sha256")}:
        raise InvalidCatalog("delivery source substituted")
    if canonical(value["units"]) != canonical(expected_units()):
        raise InvalidCatalog("unit identity or reviewed owner policy substituted")
    if value["classification_only"] is not True or any(value[k] is not False for k in ("runtime_execution_authorized", "publication_authorized", "release_acceptance_complete")):
        raise InvalidCatalog("classification cannot authorize runtime or publication")
    paths = sorted({p for u in value["units"] for p in u["runtime_owner"]["evidence"]})
    if not isinstance(value["source_evidence"], list) or len(value["source_evidence"]) != len(paths):
        raise InvalidCatalog("source evidence incomplete")
    for item, path in zip(value["source_evidence"], paths):
        if not isinstance(item, dict) or set(item) != {"path", "sha256"} or item["path"] != path or not re.fullmatch(r"[0-9a-f]{64}", str(item["sha256"])):
            raise InvalidCatalog("source evidence identity invalid")
    if sha(canonical(value["source_evidence"])) != SOURCE_EVIDENCE_SHA256:
        raise InvalidCatalog("source evidence hash substituted")


def classify(catalog, expected_digest, request):
    """Return reviewed metadata; never execute, emit argv, or grant file access."""
    validate(catalog, expected_digest)
    fields = {"unit_id", "native_version", "definition_sha256", "owner_contract", "profile", "operation"}
    if not isinstance(request, dict) or set(request) != fields or not all(type(v) is str for v in request.values()):
        raise InvalidCatalog("closed request field set mismatch")
    if request["operation"] not in OPERATIONS:
        raise InvalidCatalog("unknown operation")
    unit = next((u for u in catalog["units"] if u["unit_id"] == request["unit_id"]), None)
    if unit is None:
        raise InvalidCatalog("unknown unit: no owner authority inferred")
    if request["native_version"] != unit["native_version"] or request["definition_sha256"] != unit["definition_sha256"] or request["owner_contract"] != unit["runtime_owner"]["contract"]:
        raise InvalidCatalog("exact unit, version, definition and owner must match")
    profiles = {p["profile"] for p in unit["platform_candidates"]}
    if request["profile"] not in profiles:
        raise InvalidCatalog("unlisted platform; no platform acceptance inferred")
    metadata_only = request["operation"] in {"verify_carrier", "stage_carrier"}
    return {"schema": "symphony.distribution.owner-classification.v1", "unit_id": unit["unit_id"],
            "catalog_digest": expected_digest, "owner_contract": unit["runtime_owner"]["contract"],
            "profile": request["profile"], "requested_operation": request["operation"],
            "disposition": "carrier_verification_staging_contract_only" if metadata_only else "blocked_pending_owner_qualification",
            "execution_authorized": False, "owner_invoked": False, "platform_accepted": False,
            "blockers": ["artifact_trust_and_exact_bytes_required"] if metadata_only else unit["runtime_owner"]["blockers"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    generate = sub.add_parser("generate"); generate.add_argument("--repository", required=True); generate.add_argument("--output", required=True)
    inspect = sub.add_parser("classify"); inspect.add_argument("--catalog", required=True); inspect.add_argument("--catalog-digest", required=True); inspect.add_argument("--request", required=True)
    args = parser.parse_args()
    if args.command == "generate":
        value = build(args.repository)
        out = Path(args.output)
        if out.exists() or out.is_symlink():
            raise InvalidCatalog("output must be a new file")
        if out.resolve().is_relative_to(Path(args.repository).resolve()):
            raise InvalidCatalog("output cannot be inside source repository")
        with out.open("x", encoding="utf-8") as handle:
            handle.write(json.dumps(value, indent=2, sort_keys=True) + "\n")
        print(value["catalog_digest"])
    else:
        value = strict_json(Path(args.catalog).read_bytes())
        request = strict_json(Path(args.request).read_bytes())
        print(json.dumps(classify(value, args.catalog_digest, request), sort_keys=True))


if __name__ == "__main__":
    main()

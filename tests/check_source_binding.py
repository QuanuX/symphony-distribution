#!/usr/bin/env python3
"""Check the exact reviewed core source; never update the binding implicitly."""
import importlib.util
import json
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('owners', root / 'owner-catalog/native_owners.py')
owners = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owners)
expected = owners.reviewed_binding()
actual = owners.bind_source(Path(sys.argv[1]), expected['source_commit'])
owners.require(actual == expected, 'core source differs from reviewed binding')
catalog = json.loads((root / 'go-owner-catalog.json').read_text())
owners.validate_catalog(catalog, catalog['catalog_digest'], expected)
print('Verified exact core source and all seven Go owner routes')

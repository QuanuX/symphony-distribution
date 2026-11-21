"""Offline integration check with synthetic primary records and two real Ubuntu packages."""
import argparse
import json
from pathlib import Path
import tempfile
import types
from unittest.mock import patch

import prepare_release as prep
import publish_optional as optional


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--distribution', required=True, type=Path)
    parser.add_argument('--supplement', required=True, type=Path)
    a = parser.parse_args()
    pub = prep.load_publisher(a.distribution)
    import beta_downloads as downloads
    import test_beta_publish as fixtures
    with tempfile.TemporaryDirectory() as temp:
        testroot = Path(temp).resolve()
        primary = testroot / 'fixture-primary'
        primary.mkdir()
        output = testroot / 'fixture-with-real-supplement'
        packages, artifacts = [], []
        for profile in pub.PROFILES:
            folder = primary / 'packages' / profile
            folder.mkdir(parents=True)
            for i in range(60):
                path = folder / f'fixture-{i}.conda'
                path.write_bytes(b'local test fixture')
                pathstr = path.relative_to(primary).as_posix()
                artifacts.append({'path': pathstr, 'sha256': pub.fs.digest(path), 'size': path.stat().st_size})
                packages.append({'path': pathstr, 'selection': 'default' if i else 'optional-source', 'profile': profile})
        profiles = {p: {'source_binding': {'source_commit': prep.RELEASE_SOURCE, 'source_tree': prep.SOURCE_TREE}} for p in pub.PROFILES}
        index = {'release': prep.RELEASE, 'profiles': profiles, 'state': 'qualified_public_beta_bundle_prepared', 'conda_packages': packages,
                 'publication_performed': False, 'signature_performed': False, 'public_downloads': ['release-index.json'], 'artifacts': sorted(artifacts, key=lambda r: r['path'])}
        primary_index = primary / 'release-index.json'
        primary_index.write_bytes(pub.fs.canonical(index))
        args = types.SimpleNamespace(primary=primary, supplement=a.supplement, output=output, primary_sha256=pub.fs.digest(primary_index),
                                     supplement_sha256='a' * 64, distribution=a.distribution)
        try:
            prep.attach(args)
        except ValueError:
            assert not output.exists()
        else:
            raise AssertionError('Incorrect supplement pin accepted')
        args.supplement_sha256 = pub.fs.digest(a.supplement / prep.INDEX)
        prep.attach(args)
        attached = pub.document(output / 'release-index.json')
        assert pub.document(primary_index)['conda_packages'] == attached['conda_packages'] and len(attached['artifacts']) == 252
        assert pub.fs.digest(primary_index) == args.primary_sha256
        args = types.SimpleNamespace(artifacts_root=output, signature_root=testroot / 'signature', openssl=Path('/usr/bin/openssl'),
                       output=testroot / 'local-attempt', plan=testroot / 'plan.json', allow_public_beta_publication=True)
        objects = [{**r, 'key': 'symphony/' + prep.RELEASE + '/' + r['path'], 'url': downloads.ORIGIN + 'symphony/' + prep.RELEASE + '/' + r['path']}
                   for r in attached['artifacts'] if r['path'] in attached['public_downloads']]
        signed_fixture = {'release': prep.RELEASE, 'release_index_sha256': pub.fs.digest(output / 'release-index.json'), 'objects': objects}
        with patch.object(downloads, 'prepare', return_value=signed_fixture):
            plan = optional.prepare(args, pub)
        assert len(plan['packages']) == 2
        args.plan.write_bytes(pub.fs.canonical(plan))
        api = fixtures.API()
        modules = {'binstar_client.errors': types.SimpleNamespace(NotFound=fixtures.Missing),
                   'binstar_client.utils.config': types.SimpleNamespace(PackageType=types.SimpleNamespace(CONDA='conda'))}
        verified_urls = []
        def readback(row, path):
            assert api.files[pub.remote_key(row)]['sha256'] == row['sha256']
            verified_urls.append(row['url'])
            return {'url': row['url'], 'sha256': row['sha256']}
        with patch.dict('sys.modules', modules), patch.object(pub.s, 'publisher_api', return_value=api), patch.object(pub.s, 'download', side_effect=readback), patch.object(downloads, 'public_readback') as read_source:
            optional.publish(args, pub, plan)
        assert read_source.call_count == 2 and len(verified_urls) == 4 and len([call for call in api.calls if call[0] == 'upload']) == 2
        (output / plan['packages'][0]['archive_mirror']).write_bytes(b'invalid mirror')
        with patch.object(downloads, 'prepare', return_value=signed_fixture):
            try:
                optional.prepare(args, pub)
            except (ValueError, optional.tarfile.TarError):
                pass
            else:
                raise AssertionError('Tampered package mirror accepted')
    print('PASS unsigned primary-copy attachment and pin refusal; 240 synthetic primary rows preserved; two real package audits; mocked source-first publication, four label readbacks and tampered-mirror refusal')


if __name__ == '__main__':
    main()

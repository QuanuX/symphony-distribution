"""Exact public curl test-fixture exceptions for corresponding-source scanning.

Only a temporary scan view changes. Original upstream source archives, legal
attribution and fixture bytes remain intact; no exception applies to installed
payloads, publisher files, another archive or a changed member.
"""
import hashlib
import re

CURL_ARCHIVE_SHA256 = '6fea2aac6a4610fbd0400afb0bcddbe7258a64c63f1f68e5855ebc0c659710cd'
CURL_ARCHIVE_URL = 'https://curl.se/download/curl-8.7.1.tar.xz'
TLS_FIXTURES = {
    'curl-8.7.1/tests/stunnel.pem': 'd36819944c4a523fdb3a74bcd4003a08755c3f5ce358870dce06c76c25259d48',
    'curl-8.7.1/tests/certs/Server-localhost.nn-sv.key': 'ee02aec7b361967bbba53db0d3d90748203d9bdbdeab0e36cacde141294222d4',
    'curl-8.7.1/tests/certs/Server-localhost.nn-sv.pem': '043c717a3d0066aec27794bb0cce61017a1387589288e8ceec8a8721e0550b80',
    'curl-8.7.1/tests/certs/EdelCurlRoot-ca.key': '6b4cdb1b436ae85e2d3515880e6362724db9b3981b2371ff1f63abfadd7986fe',
    'curl-8.7.1/tests/certs/Server-localhost-lastSAN-sv.key': 'ba72d0fbb04cfcef9dbc271e848ef2ebd675cad75a7ed4c7deeab07fc5c47d38',
    'curl-8.7.1/tests/certs/Server-localhost-firstSAN-sv.pem': 'bfa45fc08fbe9d58d041abdb22a2894b41a99d44346a23d3cd5af2d91fab3f7e',
    'curl-8.7.1/tests/certs/Server-localhost0h-sv.key': 'b78c45e686b00306119b4da36a69e298e35c2d8a1b38344919a039ad06bb491f',
    'curl-8.7.1/tests/certs/Server-localhost-firstSAN-sv.key': '264134f386befacc09fa05dfad406bbc056ac8571c33935b29212f8b55039ffb',
    'curl-8.7.1/tests/certs/Server-localhost-sv.key': 'ed6355f43b845ce753c2445eb509c3c9c02915e02085d23467b4ad373c7448e5',
    'curl-8.7.1/tests/certs/stunnel-sv.pem': 'd36819944c4a523fdb3a74bcd4003a08755c3f5ce358870dce06c76c25259d48',
    'curl-8.7.1/tests/certs/Server-localhost-sv.pem': 'f2bc25a1009e2294e94f366bb41cf799169ebbad72faaa58a59303a64fd26816',
    'curl-8.7.1/tests/certs/Server-localhost0h-sv.pem': '85f6841f883c14fcb3543283284bce74ddf2d2c9d9cdedb8a3c6c51d0e4bf25a',
    'curl-8.7.1/tests/certs/stunnel-sv.key': '7575fa3e93af311bcca2c4638ffa3d4b90ddf994d38b035258e02199dca1e18f',
    'curl-8.7.1/tests/certs/Server-localhost-lastSAN-sv.pem': '70469341ddad4ab5aa3a3e7a2da47f58273625a9b228f1535b291eecbb7ca1a3',
}
THANKS_PATH = 'curl-8.7.1/docs/THANKS'
THANKS_SHA256 = '67671db9f0b52fe28a7a0fa57a9f00e4c1d4bd1050d15d67db29cba65b691b4d'
# Exact two substring positions in unchanged upstream contributor attributions.
# No private policy value or credited name is embedded in this exception.
THANKS_OVERLAPS = {(12216, 6), (12239, 6)}
PRIVATE_KEY = re.compile(rb'-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\r\n]+[A-Za-z0-9+/=\r\n]{32,}-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----')
AWS_ACCESS_KEY = re.compile(rb'AKIA[A-Z0-9]{16}')
PROVENANCE = {
    'archive_url': CURL_ARCHIVE_URL, 'archive_sha256': CURL_ARCHIVE_SHA256,
    'official_archive_verification': 'HTTPS retrieval on 2026-11-16 matched the exact frozen source SHA256; no signature verification inferred',
    'upstream_archive_listing': 'https://curl.se/download/',
    'fixture_reference_sources': [
        {'path': 'curl-8.7.1/tests/certs/Makefile.am', 'sha256': 'cac0e92e09447cedb2132a21df1646b711eca42f99d03e4fed7d2ec687e5097b',
         'scope': 'names all thirteen admitted tests/certs key/PEM files'},
        {'path': 'curl-8.7.1/tests/secureserver.pl', 'sha256': '76932f5faf1f82cdc15bc15937607f824a1677ade04e1a70423e9b59e84691fb',
         'scope': 'references the admitted tests/stunnel.pem test server fixture'},
    ],
    'attribution_classification': 'two unchanged public upstream contributor-credit substrings overlap a private scan marker; not publisher-added metadata',
    'source_bytes_modified': False,
}


def require(value, message):
    if not value:
        raise ValueError(message)


def scan_member(scanner, archive_sha256, name, raw):
    expected = TLS_FIXTURES.get(name)
    attribution = name == THANKS_PATH
    if expected is None and not attribution:
        scanner.scan(name, raw)
        return None
    require(archive_sha256 == CURL_ARCHIVE_SHA256, 'Reviewed upstream archive identity differs')
    expected = THANKS_SHA256 if attribution else expected
    require(hashlib.sha256(raw).hexdigest() == expected, 'Reviewed upstream member bytes changed')
    # Filename and publisher-data checks always inspect the original bytes.
    scanner.scan(name, b'')
    allowed = THANKS_OVERLAPS if attribution else set()
    for marker in scanner.PRIVATE_MARKERS:
        start = 0
        while (offset := raw.lower().find(marker.lower(), start)) >= 0:
            require((offset, len(marker)) in allowed, 'Unreviewed publisher private marker in upstream source')
            start = offset + 1
    require(not AWS_ACCESS_KEY.search(raw), 'Unreviewed credential-shaped value in upstream source')
    if attribution:
        require(not PRIVATE_KEY.search(raw), 'Unreviewed complete private key in upstream attribution')
        view = bytearray(raw)
        for offset, length in allowed:
            require(offset >= 0 and length > 0 and offset + length <= len(view), 'Invalid attribution overlap range')
            view[offset:offset + length] = b'~' * length
        scanner.scan(name, bytes(view))
        role, rule, count = 'unchanged_public_upstream_attribution_overlap', 'exact_attribution_substring', len(allowed)
    else:
        matches = list(PRIVATE_KEY.finditer(raw))
        require(len(matches) == 1, 'Reviewed upstream TLS fixture key count differs')
        scanner.scan(name, PRIVATE_KEY.sub(b'PUBLIC_UPSTREAM_TLS_TEST_FIXTURE', raw))
        role, rule, count = 'public_upstream_TLS_regression_fixture', 'complete_private_key', 1
    return {'archive_sha256': archive_sha256, 'member_path': name, 'member_sha256': expected,
            'role': role, 'admitted_rule': rule, 'reviewed_occurrence_count': count,
            'scope': 'exact archive, member path, bytes and reviewed role only; remaining publisher/key/credential checks unchanged',
            'archived_source_bytes_changed': False}


def manifest(exceptions):
    if not exceptions:
        return None
    require(len(exceptions) == 15 and {row['member_path'] for row in exceptions} == set(TLS_FIXTURES) | {THANKS_PATH},
            'Reviewed upstream exception coverage differs')
    return {'protocol': 'symphony.distribution.upstream-source-exceptions.v1', 'provenance': PROVENANCE,
            'exceptions': sorted(exceptions, key=lambda row: row['member_path']),
            'publisher_approval_granted': False, 'publication_authorized': False}

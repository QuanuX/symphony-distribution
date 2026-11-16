#!/usr/bin/env python3
"""Retain bounded, sanitized D06 diagnostics without copying raw build logs.

This read-only observer does not change builders, source, payloads or results.
Its optional before/after helper manifest supplements the builder's own hashes.
"""
from __future__ import annotations
import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat

ROOT = Path(__file__).resolve().parents[1]
HELPERS = ('qualification/native_campaign.py', 'owner-catalog/native_owners.py',
           'source-export/export_source.py', 'qualification/d06_sdk_closure.py', 'qualification/d06_delivery_record.py',
           'qualification/d06_failure_summary.py')
MAX_JSON = 2 * 1024 * 1024
MAX_LOG = 64 * 1024 * 1024
TAIL_BYTES, TAIL_LINES = 8192, 40
LABEL = r'[A-Za-z0-9_.-]{1,160}'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def no_links(path):
    path = Path(os.path.abspath(path))
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'symlink evidence path refused')
    return path


def regular(path, maximum):
    path = no_links(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= maximum,
                'nonregular, shared or oversized evidence refused')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(maximum + 1)
        after = os.fstat(fd)
        require(len(raw) <= maximum and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'evidence changed while reading')
        return raw
    finally:
        os.close(fd)


def document(path):
    return json.loads(regular(path, MAX_JSON))


def manifest():
    files = [{'path': name, 'sha256': digest(regular(ROOT / name, MAX_JSON))} for name in HELPERS]
    canonical = json.dumps(files, sort_keys=True, separators=(',', ':')).encode()
    return {'protocol': 'symphony.distribution.d06-extra-helper-manifest.v1',
            'files': files, 'manifest_sha256': digest(canonical)}


def validate_manifest(value):
    require(isinstance(value, dict) and set(value) == {'protocol', 'files', 'manifest_sha256'} and
            value['protocol'] == 'symphony.distribution.d06-extra-helper-manifest.v1', 'helper baseline schema differs')
    rows = value['files']
    require(isinstance(rows, list) and len(rows) == len(HELPERS), 'helper baseline inventory differs')
    require(all(isinstance(row, dict) and set(row) == {'path', 'sha256'} and row['path'] == path and
                isinstance(row['sha256'], str) and re.fullmatch('[0-9a-f]{64}', row['sha256']) for row, path in zip(rows, HELPERS)),
            'helper baseline identity differs')
    require(value['manifest_sha256'] == digest(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()),
            'helper baseline digest differs')
    return value


def write_new(path, value):
    path = no_links(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def sanitize(text, aliases=(), identities=()):
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', text)
    text = re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|\Z)',
                  '[private material omitted]', text, flags=re.S)
    for path, role in sorted(aliases, key=lambda x: len(str(x[0])), reverse=True):
        text = text.replace(str(path), '<' + role + '>')
    output = []
    for line in text.splitlines():
        # Environment dumps and authentication diagnostics never become public tails.
        if re.match(r'^\s*(?:export\s+)?(?:[A-Za-z_][A-Za-z0-9_]{1,80}\s*=|[A-Z_][A-Z0-9_]{1,80}\s*:)', line) or re.search(
                r'(?i)(?:authorization|password|passwd|secret|access[_ -]?token|api[_ -]?key|private[_ -]?key)\s*[:=]|'
                r'--(?:token|password|secret|api-key)\b|\b(?:gh[pousr]_|github_pat_|AKIA[0-9A-Z]|sk-proj-)', line):
            output.append('[environment or credential line omitted]')
            continue
        line = re.sub(r'https?://[^\s]+', lambda m: '[private URL omitted]' if '@' in m[0] or '?' in m[0] else m[0], line)
        line = re.sub(r'\b[A-Za-z0-9_.+%-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', '[email omitted]', line)
        line = re.sub(r'/(?:Users|home)/[^\s"\x27:]+', '<user-path>', line)
        line = re.sub(r'/(?:private/)?var/folders/[^\s"\x27:]+', '<private-temporary>', line)
        line = re.sub(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', '[network address omitted]', line)
        line = re.sub(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b', '[identifier omitted]', line)
        line = re.sub(r'\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b', '[hardware address omitted]', line)
        if re.fullmatch(r'\s*[A-Za-z0-9+/=]{40,}\s*', line):
            line = '[encoded value omitted]'
        line = re.sub(r'\b[A-Za-z0-9+/=]{80,}\b', '[encoded value omitted]', line)
        for identity in identities:
            if len(identity) >= 3:
                line = re.sub(r'(?<![A-Za-z0-9])' + re.escape(identity) + r'(?![A-Za-z0-9])', '[host identity omitted]', line, flags=re.I)
        line = ''.join(c for c in line if c == '\t' or ord(c) >= 32)
        output.append(line[:1024])
    return '\n'.join(output[-TAIL_LINES:]).encode()[-TAIL_BYTES:].decode(errors='ignore')


def selected_log(cohort, external, sdk_closure=None, delivery=None):
    """Select only a known failed step; never recursively collect arbitrary logs."""
    incomplete = cohort / 'INCOMPLETE.json'
    rounds = sorted((p for p in cohort.glob('round-*') if re.fullmatch(r'round-[12]', p.name)), reverse=True)
    if incomplete.is_file():
        reason = str(document(incomplete).get('reason', ''))
        match = re.search(r'step failed: (' + LABEL + r');', reason)
        if match:
            for root in rounds:
                log = root / 'logs' / (match[1] + '.log')
                if log.is_file():
                    return reason, match[1], log, False
        match = re.search(r'Detached SDK (' + LABEL + r') failed', reason)
        if match:
            for root in rounds:
                log = root / 'sdk-audit/logs' / (match[1] + '.log')
                if log.is_file():
                    return reason, 'sdk-' + match[1], log, False
        if 'installed owner tests failed' in reason:
            for root in rounds:
                for index in (1, 0):
                    log = root / 'owner-audit' / (str(index) + '-events.jsonl')
                    if log.is_file():
                        return reason, 'installed-owner-' + str(index), log, True
        return reason, None, None, False
    report = external / 'external-build.json'
    if report.is_file():
        value = document(report)
        if value.get('status') == 'failed':
            reason = str(value.get('failure', 'external build failed'))
            failed = [r for r in value.get('commands', []) if r.get('exit_code') != 0]
            if failed and re.fullmatch(LABEL, str(failed[-1].get('name', ''))):
                label = failed[-1]['name']
                return reason, label, external / 'logs' / (label + '.log'), False
            return reason, None, None, False
    if delivery is not None and (delivery / 'delivery-record.json').is_file():
        value = document(delivery / 'delivery-record.json')
        if value.get('state') in ('failed', 'incomplete'):
            logs = [p for p in (delivery / 'logs').glob('*.log') if re.fullmatch(LABEL + r'\.log', p.name)]
            require(len(logs) <= 1000, 'delivery diagnostic log set exceeds bound')
            latest = max(logs, key=lambda p: p.lstat().st_mtime_ns) if logs else None
            return 'Delivery record incomplete before SDK closure; latest command context retained.', 'delivery-record', latest, False
    if sdk_closure is not None and (sdk_closure / 'result.json').is_file():
        value = document(sdk_closure / 'result.json')
        if value.get('status') == 'incomplete':
            rows = value.get('logs', [])
            failed = [r for r in rows if (r.get('exit_code') != 0 if r.get('expected') == 'success'
                                        else not isinstance(r.get('exit_code'), int) or r['exit_code'] <= 0)]
            context = (failed or rows)[-1] if failed or rows else None
            if context and re.fullmatch(LABEL + r'\.log', str(context.get('name', ''))):
                label = 'sdk-closure-' + (context['name'][:-4] if failed else 'postcondition')
                return 'SDK closure incomplete; selected command context retained.', label, sdk_closure / 'logs' / context['name'], False
            return 'SDK closure incomplete without command diagnostics.', 'sdk-closure', None, False
    return None, None, None, False


def summarize(cohort, external, workspace, runner_temp, helper_baseline=None, sdk_closure=None, delivery=None):
    cohort, external, workspace, runner_temp = map(no_links, (cohort, external, workspace, runner_temp))
    sdk_closure = no_links(sdk_closure or runner_temp / 'd06-sdk-closure')
    delivery = no_links(delivery or runner_temp / 'd06-delivery')
    aliases = [(cohort, 'cohort'), (external, 'external'), (workspace, 'workspace'), (runner_temp, 'temporary'),
               (sdk_closure, 'sdk-closure'), (delivery, 'delivery')]
    identities = {getpass.getuser(), socket.gethostname()}
    for path, _ in aliases:
        match = re.search(r'/(?:Users|home)/([^/]+)', str(path))
        if match:
            identities.add(match[1])
    scrub = lambda text: sanitize(text, aliases, identities)
    current = manifest()
    closure = {'observed': current, 'scope': 'post-job imported-helper snapshot', 'unchanged_from_baseline': None}
    if helper_baseline is not None and Path(helper_baseline).is_file():
        baseline = validate_manifest(document(helper_baseline))
        closure.update(baseline_manifest_sha256=baseline.get('manifest_sha256'),
                       unchanged_from_baseline=baseline == current, scope='before/after imported-helper comparison')
    report = {'protocol': 'symphony.distribution.d06-failure-summary.v1',
              'scope': 'bounded sanitized diagnostic excerpt; no raw log or environment publication',
              'candidate_privacy_approved': False, 'release_acceptance_complete': False,
              'publication_authorized': False, 'extra_helper_closure': closure, 'status': 'no_failure_recorded'}
    try:
        reason, label, log, json_lines = selected_log(cohort, external, sdk_closure, delivery)
        if reason:
            report.update(status='failure_observed', failure=scrub(reason), failed_step=scrub(label) if label else None)
        if log is not None:
            raw = regular(log, MAX_LOG)
            text = raw[-32768:].decode('utf-8', errors='replace')
            if json_lines:
                messages = []
                for line in text.splitlines():
                    try:
                        event = json.loads(line)
                        messages.append(str(event.get('Output', '')))
                    except json.JSONDecodeError:
                        continue
                text = ''.join(messages)
            report['log'] = {'sha256': digest(raw), 'size': len(raw), 'tail': scrub(text),
                             'tail_limit_bytes': TAIL_BYTES, 'tail_limit_lines': TAIL_LINES,
                             'full_log_published': False}
        latest = sorted((p for p in cohort.glob('round-*') if re.fullmatch(r'round-[12]', p.name)), reverse=True)
        for root in latest:
            progress = root / 'progress.json'
            if progress.is_file():
                value = document(progress)
                done, expected = value.get('completed_native'), value.get('expected_native')
                if isinstance(done, list) and type(expected) is int and 0 <= len(done) <= expected <= 1000:
                    report['native_progress'] = {'completed': len(done), 'expected': expected}
                break
    except (OSError, ValueError, KeyError, TypeError):
        # Refused evidence must not reveal its path/content through exception text.
        report.update(status='diagnostic_evidence_refused', diagnostic='Evidence was unavailable, changed, unsafe or exceeded its size limit.')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('cohort', 'external', 'workspace', 'runner-temp', 'output', 'helper-baseline', 'record-baseline', 'sdk-closure', 'delivery'):
        parser.add_argument('--' + name, type=Path)
    args = parser.parse_args()
    if args.record_baseline:
        require(not args.output, 'baseline and summary are separate operations')
        write_new(args.record_baseline, manifest())
        print('Imported helper baseline recorded.')
        return
    require(all(getattr(args, name) is not None for name in ('cohort', 'external', 'workspace', 'runner_temp', 'output')),
            'summary requires explicit cohort, external, workspace, runner-temp and output paths')
    report = summarize(args.cohort, args.external, args.workspace, args.runner_temp, args.helper_baseline, args.sdk_closure, args.delivery)
    write_new(args.output, report)
    print(json.dumps({'diagnostic_status': report['status'], 'candidate_privacy_approved': False}))
    require(report['extra_helper_closure']['unchanged_from_baseline'] is not False, 'imported helper bytes changed during the job')


if __name__ == '__main__':
    main()

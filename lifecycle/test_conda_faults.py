"""S07 real-manager fault boundaries in disposable private carrier attempts.

These are local custody/Conda tests, not fresh-host or native-owner acceptance.
Child barriers are reached only after the named real boundary has run; the
controller then kills that child. No scheduler timing is treated as evidence.
"""
import fcntl
import json
import multiprocessing
import os
from pathlib import Path
import shutil
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import conda_transaction as c
from test_conda_transaction import SUBDIR, index_channel, package, spec


def _temporary(prefix):
    """Ordinary tests clean up; the private campaign may retain inspectable state."""
    retained = os.environ.get('SYMPHONY_CONDA_FAULT_EVIDENCE_ROOT')
    if not retained:
        return tempfile.TemporaryDirectory(prefix=prefix)
    root = c._absolute(retained)
    info = root.lstat()
    c.require(root.is_dir() and info.st_uid == os.geteuid() and not info.st_mode & 0o077,
              'Fault evidence parent must be an owned private directory')
    return SimpleNamespace(name=tempfile.mkdtemp(prefix=prefix, dir=root), cleanup=lambda: None)


def _inherited_worker(attempt, row, connection):
    """Fork is intentional here: an inherited flock must not grant authority."""
    try:
        attempt.transact('install', add_specs=[spec(row)], expected_link=[row])
    except c.Refused as exc:
        connection.send({'status': 'refused', 'error': str(exc)})
    except BaseException as exc:
        connection.send({'status': 'unexpected', 'error': repr(exc)})
    else:
        connection.send({'status': 'unsafe-complete'})
    finally:
        connection.close()


def _crash_worker(root, channel, row, phase, connection):
    """Run a real transaction and stop precisely at an acknowledged boundary."""
    try:
        from conda.core.link import UnlinkLinkTransaction
        from conda.core.path_actions import UnlinkPathAction
        attempt = c.Attempt.create(root, channel, SUBDIR)
        sentinel = attempt.prefix / 'foreign-sentinel'
        sentinel.write_bytes(b'preserve independently owned user state\n')
        def reached():
            connection.send({'status': 'boundary-reached', 'phase': phase})
            connection.recv()  # controller kills this process, never auto-resumes
            raise AssertionError('Crash fixture was unexpectedly resumed')
        write_new = c._write_new
        execute = UnlinkLinkTransaction.execute
        unlink = UnlinkPathAction.execute
        if phase == 'partial-unlink':
            attempt.transact('install', add_specs=[spec(row)], expected_link=[row])
            def partial(action):
                result = unlink(action)
                if action.target_short_path in row['files']:
                    if os.path.lexists(attempt.prefix / action.target_short_path):
                        raise AssertionError('Real unlink did not remove its selected payload')
                    reached()
                return result
            with patch.object(UnlinkPathAction, 'execute', partial):
                attempt.transact('remove', remove_names=[row['name']], expected_unlink=[row])
        else:
            def boundary_write(path, data, mode=0o600):
                write_new(path, data, mode)
                if ((phase == 'validated-before-execution' and Path(path).name == 'validated.json') or
                    (phase == 'execution-started-before-effect' and Path(path).name == 'execution-started.json')):
                    reached()
            def lost_ack(transaction):
                result = execute(transaction)
                if phase == 'effect-before-acknowledgement':
                    # Prove real complete manager effect before losing the reply.
                    if set(attempt._inventory()) != {row['name']}:
                        raise AssertionError('Real manager effect has not completed')
                    reached()
                return result
            with patch.object(c, '_write_new', boundary_write), patch.object(UnlinkLinkTransaction, 'execute', lost_ack):
                attempt.transact('install', add_specs=[spec(row)], expected_link=[row])
        connection.send({'status': 'unexpected-complete'})
    except BaseException as exc:
        connection.send({'status': 'unexpected-error', 'error': repr(exc)})
    finally:
        connection.close()


def _create_race_worker(root, channel, row, connection):
    """Both independent creators reach the actual exclusive mkdir boundary."""
    root = Path(root)
    original = Path.mkdir
    try:
        def barrier(path, *args, **kwargs):
            if path == root:
                connection.send({'status': 'create-boundary-reached'})
                if connection.recv() != 'proceed':
                    raise AssertionError('Unexpected create-race release')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'mkdir', barrier):
            with c.Attempt.create(root, channel, SUBDIR) as attempt:
                result = attempt.transact('install', add_specs=[spec(row)], expected_link=[row])
                connection.send({'status': result['status']})
    except FileExistsError:
        connection.send({'status': 'exclusive-create-refused'})
    except BaseException as exc:
        connection.send({'status': 'unexpected-error', 'error': repr(exc)})
    finally:
        connection.close()


class CondaFaults(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = _temporary('s07-conda-fixtures-')
        cls.fixture_root = Path(cls.fixture.name).resolve()
        cls.channel, cls.work = cls.fixture_root / 'channel', cls.fixture_root / 'work'
        cls.work.mkdir()
        for subdir in (SUBDIR, 'noarch'):
            (cls.channel / subdir).mkdir(parents=True)
        records, identities = {}, []
        for name, build in (('test-alpha', 'b0'), ('test-alpha', 'b1'), ('test-beta', 'b0')):
            archive, record = package(cls.channel, cls.work, name, build=build)
            records[archive.name] = record
            identities.append(c.artifact_identity(archive))
        index_channel(cls.channel, records)
        cls.a, cls.a1, cls.b = identities

    @classmethod
    def tearDownClass(cls):
        cls.fixture.cleanup()

    def setUp(self):
        self.temp = _temporary('s07-conda-fault-')
        self.root = Path(self.temp.name).resolve()

    def tearDown(self):
        self.temp.cleanup()

    def attempt(self, name='attempt'):
        return c.Attempt.create(self.root / name, self.channel, SUBDIR)

    def install(self, attempt, row=None):
        row = row or self.a
        return attempt.transact('install', add_specs=[spec(row)], expected_link=[row])

    def assert_no_execution(self, attempt, sequence=1):
        evidence = attempt.root / 'evidence' / f'{sequence:04d}'
        self.assertFalse((evidence / 'execution-started.json').exists())
        self.assertTrue(attempt.poisoned)
        with self.assertRaisesRegex(c.Refused, 'replayed'):
            self.install(attempt)

    def test_fork_inheritance_does_not_transfer_live_attempt_authority(self):
        with self.attempt() as attempt:
            # An independent file description cannot acquire the held flock.
            fd = os.open(attempt.root / 'owner.lock', os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)
            parent, child = multiprocessing.get_context('fork').Pipe()
            worker = multiprocessing.get_context('fork').Process(target=_inherited_worker, args=(attempt, self.a, child))
            worker.start()
            child.close()
            try:
                self.assertTrue(parent.poll(20), 'Forked caller did not reach the guard')
                reply = parent.recv()
                self.assertEqual(reply['status'], 'refused', reply)
                self.assertIn('creating process', reply['error'])
                worker.join(20)
                self.assertEqual(worker.exitcode, 0)
            finally:
                if worker.is_alive():
                    worker.kill()
                    worker.join(20)
                parent.close()
            self.assertEqual(attempt.sequence, 0)
            self.assertFalse(list((attempt.root / 'evidence').iterdir()))
            self.assertEqual(self.install(attempt)['status'], 'observed-complete')

    def test_competing_threads_reach_guard_without_poisoning_active_operation(self):
        with self.attempt() as attempt:
            reached, release = threading.Event(), threading.Event()
            results = []
            original = attempt._validate_plan
            def barrier(*args):
                original(*args)
                reached.set()
                if not release.wait(45):
                    raise AssertionError('Controller never released validated solver boundary')
            def first():
                try:
                    results.append(self.install(attempt))
                except BaseException as exc:
                    results.append(exc)
            with patch.object(attempt, '_validate_plan', barrier):
                worker = threading.Thread(target=first)
                worker.start()
                try:
                    self.assertTrue(reached.wait(45), 'First operation never reached real solver validation')
                    for action in (lambda: self.install(attempt, self.b), attempt.clean_cache, attempt.inventory, attempt.close):
                        with self.assertRaisesRegex(c.Refused, 'active operation'):
                            action()
                    self.assertFalse(attempt.poisoned)
                    self.assertEqual(attempt.sequence, 1)
                    self.assertEqual(len(list((attempt.root / 'evidence').iterdir())), 1)
                finally:
                    release.set()
                    worker.join(60)
            self.assertFalse(worker.is_alive())
            self.assertEqual(len(results), 1)
            self.assertIsInstance(results[0], dict, results)
            self.assertEqual(results[0]['status'], 'observed-complete')
            self.assertEqual(set(attempt.inventory()), {self.a['name']})

    def test_independent_processes_racing_same_new_root_have_one_effect(self):
        context = multiprocessing.get_context('spawn')
        peers = []
        attempt_root = self.root / 'create-race'
        try:
            for _ in range(2):
                parent, child = context.Pipe()
                worker = context.Process(target=_create_race_worker,
                    args=(attempt_root, self.channel, self.a, child))
                worker.start()
                child.close()
                peers.append((parent, worker))
            for parent, _ in peers:
                self.assertTrue(parent.poll(45), 'Independent creator never reached exclusive mkdir')
                self.assertEqual(parent.recv(), {'status': 'create-boundary-reached'})
            for parent, _ in peers:
                parent.send('proceed')
            outcomes = []
            for parent, worker in peers:
                self.assertTrue(parent.poll(60), 'Independent creator did not report its result')
                outcomes.append(parent.recv())
                worker.join(20)
                self.assertEqual(worker.exitcode, 0)
            self.assertCountEqual(outcomes, [{'status': 'exclusive-create-refused'}, {'status': 'observed-complete'}])
            self.assertEqual(len(list((attempt_root / 'evidence').glob('*/result.json'))), 1)
            self.assertTrue(all(c._hash_file(attempt_root / 'prefix' / p) == row for p, row in self.a['files'].items()))
        finally:
            for parent, worker in peers:
                if worker.is_alive():
                    worker.kill()
                    worker.join(20)
                parent.close()

    def test_intent_write_failure_poisoned_before_any_manager_effect(self):
        with self.attempt() as attempt:
            original = c._write_new
            reached = []
            def denied(path, data, mode=0o600):
                if Path(path).name == 'intent.json':
                    reached.append(True)
                    raise OSError('Injected durable intent write failure')
                return original(path, data, mode)
            with patch.object(c, '_write_new', denied):
                with self.assertRaisesRegex(OSError, 'intent write'):
                    self.install(attempt)
            self.assertEqual(reached, [True])
            self.assert_no_execution(attempt)
            self.assertFalse(any((attempt.prefix / p).exists() for p in self.a['files']))

    def test_damaged_retained_rollback_archive_never_changes_installed_replacement(self):
        for damage in ('truncated', 'missing'):
            with self.subTest(damage=damage), self.attempt(damage) as attempt:
                self.install(attempt, self.a1)
                before = c._snapshot(attempt.prefix)
                retained = attempt.channel / SUBDIR / self.a['filename']
                if damage == 'truncated':
                    retained.write_bytes(retained.read_bytes()[:16])
                else:
                    retained.unlink()
                with self.assertRaisesRegex(c.Refused, 'Private channel changed'):
                    attempt.transact('rollback', add_specs=[spec(self.a)], expected_link=[self.a], expected_unlink=[self.a1])
                self.assertTrue(attempt.poisoned)
                self.assertEqual(attempt.sequence, 1)
                self.assertEqual(c._snapshot(attempt.prefix), before)
                with self.assertRaisesRegex(c.Refused, 'replayed'):
                    self.install(attempt)

    def _crash_at(self, phase):
        attempt_root = self.root / phase
        context = multiprocessing.get_context('spawn')
        parent, child = context.Pipe()
        worker = context.Process(target=_crash_worker, args=(attempt_root, self.channel, self.a, phase, child))
        worker.start()
        child.close()
        try:
            self.assertTrue(parent.poll(75), 'Child did not reach the required real-manager boundary')
            reply = parent.recv()
            self.assertEqual(reply, {'status': 'boundary-reached', 'phase': phase})
            worker.kill()
            worker.join(20)
            self.assertEqual(worker.exitcode, -9)
        finally:
            if worker.is_alive():
                worker.kill()
                worker.join(20)
            parent.close()
        prefix = attempt_root / 'prefix'
        evidence = attempt_root / 'evidence' / ('0002' if phase == 'partial-unlink' else '0001')
        self.assertTrue((evidence / 'validated.json').is_file())
        self.assertEqual((evidence / 'execution-started.json').exists(), phase != 'validated-before-execution')
        self.assertFalse((evidence / 'result.json').exists())
        self.assertFalse((evidence / 'failure.json').exists(), 'SIGKILL cannot manufacture an observed outcome')
        before = c._snapshot(prefix)
        with self.assertRaisesRegex(c.Refused, 'Existing'):
            c.Attempt.create(attempt_root, self.channel, SUBDIR)
        self.assertEqual(c._snapshot(prefix), before)
        self.assertEqual((prefix / 'foreign-sentinel').read_bytes(), b'preserve independently owned user state\n')
        return prefix

    def test_kill_after_validation_before_execution_retains_unreopenable_attempt(self):
        prefix = self._crash_at('validated-before-execution')
        self.assertFalse(any((prefix / p).exists() for p in self.a['files']))

    def test_kill_after_execution_marker_before_effect_retains_uncertainty(self):
        prefix = self._crash_at('execution-started-before-effect')
        self.assertFalse(any((prefix / p).exists() for p in self.a['files']))

    def test_kill_after_real_execution_before_ack_retains_uncertainty(self):
        prefix = self._crash_at('effect-before-acknowledgement')
        self.assertTrue(all(c._hash_file(prefix / p) == row for p, row in self.a['files'].items()))
        self.assertTrue((prefix / f"conda-meta/{self.a['name']}-{self.a['version']}-{self.a['build']}.json").is_file())

    def test_kill_during_real_unlink_preserves_partial_state_without_replay(self):
        prefix = self._crash_at('partial-unlink')
        self.assertEqual(sum((prefix / p).exists() for p in self.a['files']), len(self.a['files']) - 1)

    def test_custody_replacement_after_real_prepare_refuses_before_execution(self):
        from conda.core.link import UnlinkLinkTransaction
        original = UnlinkLinkTransaction.prepare
        for target in ('prefix', 'owner.lock', 'channel', 'cache', 'evidence'):
            with self.subTest(target=target), self.attempt(target.replace('.', '-')) as attempt:
                held = attempt.root / target
                displaced = attempt.root / (target + '-original')
                reached = []
                def replace(transaction):
                    original(transaction)
                    reached.append(True)
                    held.rename(displaced)
                    if displaced.is_dir():
                        shutil.copytree(displaced, held)
                    else:
                        shutil.copyfile(displaced, held)
                        held.chmod(0o600)
                with patch.object(UnlinkLinkTransaction, 'prepare', replace):
                    with self.assertRaisesRegex(c.Refused, 'custody'):
                        self.install(attempt)
                self.assertEqual(reached, [True], 'Replacement must occur after actual preparation')
                self.assert_no_execution(attempt)
                self.assertFalse(any((attempt.prefix / p).exists() for p in self.a['files']))

    def test_changed_or_missing_installed_payload_refuses_rollback(self):
        for damage in ('tamper', 'missing', 'hardlink', 'symlink'):
            with self.subTest(damage=damage), self.attempt(damage) as attempt:
                self.install(attempt, self.a1)
                payload = attempt.prefix / next(iter(self.a1['files']))
                external = self.root / (damage + '-independent-user-file')
                external.write_bytes(b'preserve independent user data\n')
                if damage == 'tamper':
                    payload.write_bytes(b'changed installed payload\n')
                elif damage == 'missing':
                    payload.unlink()
                else:
                    payload.unlink()
                    if damage == 'hardlink':
                        os.link(external, payload)
                    else:
                        payload.symlink_to(external)
                with self.assertRaises((c.Refused, FileNotFoundError)):
                    attempt.transact('rollback', add_specs=[spec(self.a)], expected_link=[self.a], expected_unlink=[self.a1])
                self.assert_no_execution(attempt, 2)
                self.assertEqual(external.read_bytes(), b'preserve independent user data\n')

    def test_foreign_metadata_claim_blocks_removal_without_touching_foreign_state(self):
        with self.attempt() as attempt:
            self.install(attempt)
            record = attempt.prefix / f"conda-meta/{self.a['name']}-{self.a['version']}-{self.a['build']}.json"
            foreign = json.loads(record.read_text())
            foreign['name'] = 'foreign-owner'
            foreign_path = attempt.prefix / 'conda-meta/foreign-owner-1.0-b0.json'
            foreign_path.write_bytes(c.canonical(foreign))
            before = c._snapshot(attempt.prefix)
            with self.assertRaisesRegex(c.Refused, 'outside reviewed'):
                attempt.transact('remove', remove_names=[self.a['name']], expected_unlink=[self.a])
            self.assert_no_execution(attempt, 2)
            self.assertEqual(c._snapshot(attempt.prefix), before)

    def test_lock_hardlink_and_reused_descriptor_refuse_before_execution(self):
        for fault in ('hardlink', 'descriptor'):
            with self.subTest(fault=fault):
                attempt = self.attempt(fault)
                foreign_fd = None
                try:
                    if fault == 'hardlink':
                        os.link(attempt.root / 'owner.lock', self.root / 'foreign-lock-alias')
                    else:
                        os.close(attempt._lock)
                        foreign_fd = os.open(self.root / 'independent-foreign-file', os.O_RDWR | os.O_CREAT, 0o600)
                        # dup2 makes descriptor reuse deterministic, not allocator luck.
                        if foreign_fd != attempt._lock:
                            os.dup2(foreign_fd, attempt._lock)
                            os.close(foreign_fd)
                            foreign_fd = attempt._lock
                    with self.assertRaisesRegex(c.Refused, 'lock descriptor'):
                        self.install(attempt)
                    self.assertEqual(attempt.sequence, 0)
                    self.assertTrue(attempt.poisoned)
                    if foreign_fd is not None:
                        before = os.fstat(foreign_fd)
                        with self.assertRaisesRegex(c.Refused, 'foreign handle retained'):
                            attempt.close()
                        self.assertTrue(attempt.closed)
                        self.assertTrue(attempt.poisoned)
                        self.assertEqual(os.fstat(foreign_fd), before)
                        os.write(foreign_fd, b'foreign handle remains usable\n')
                        attempt.close()  # idempotent; still must not close the foreign fd
                        self.assertEqual(os.fstat(foreign_fd).st_ino, before.st_ino)
                finally:
                    attempt.close()
                    if foreign_fd is not None:
                        os.close(foreign_fd)

    def test_early_create_failure_retains_root_and_releases_only_its_lock(self):
        for fault in ('lock', 'directory', 'manifest'):
            with self.subTest(fault=fault):
                root = self.root / fault
                opened = []
                original_open, original_mkdir, original_write = os.open, Path.mkdir, c._write_new
                def capture(path, *args, **kwargs):
                    fd = original_open(path, *args, **kwargs)
                    if Path(path) == root / 'owner.lock':
                        opened.append(fd)
                    return fd
                def directory(path, *args, **kwargs):
                    if path == root / 'cache':
                        raise OSError('Injected private directory setup failure')
                    return original_mkdir(path, *args, **kwargs)
                def manifest(path, data, mode=0o600):
                    if Path(path).name == 'ATTEMPT.json':
                        raise OSError('Injected attempt manifest setup failure')
                    return original_write(path, data, mode)
                with patch.object(os, 'open', capture):
                    if fault == 'lock':
                        with patch.object(fcntl, 'flock', side_effect=OSError('Injected flock setup failure')):
                            with self.assertRaisesRegex(OSError, 'setup failure'):
                                self.attempt(fault)
                    elif fault == 'directory':
                        with patch.object(Path, 'mkdir', directory):
                            with self.assertRaisesRegex(OSError, 'setup failure'):
                                self.attempt(fault)
                    else:
                        with patch.object(c, '_write_new', manifest):
                            with self.assertRaisesRegex(OSError, 'setup failure'):
                                self.attempt(fault)
                self.assertEqual(len(opened), 1)
                with self.assertRaises(OSError):
                    os.fstat(opened[0])
                failure = root / ('evidence/create-failed.json' if fault == 'manifest' else 'create-failed.json')
                self.assertEqual(json.loads(failure.read_text())['status'], 'refused-retained')
                fd = os.open(root / 'owner.lock', os.O_RDWR)
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(fd)
                with self.assertRaisesRegex(c.Refused, 'Existing'):
                    self.attempt(fault)


if __name__ == '__main__':
    unittest.main()

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("installer", Path(__file__).with_name("install-symphony.py"))
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class QuickInstallTests(unittest.TestCase):
    def test_exact_supported_hosts(self):
        cases = [
            ("Darwin", "arm64", "15.7.2", "", "macos15-arm64"),
            ("Linux", "x86_64", "24.04", "ubuntu", "ubuntu24.04-amd64"),
            ("Linux", "aarch64", "24.04", "ubuntu", "ubuntu24.04-arm64"),
            ("Linux", "x86_64", "26.04", "ubuntu", "ubuntu26.04-amd64"),
            ("Darwin", "x86_64", "15.7.2", "", None),
            ("Darwin", "arm64", "26.0", "", None),
            ("Linux", "aarch64", "26.04", "ubuntu", None),
            ("Linux", "x86_64", "24.04", "debian", None),
            ("Windows", "AMD64", "", "", None),
        ]
        for system, machine, version, distribution, expected in cases:
            with self.subTest(system=system, machine=machine, version=version, os=distribution), \
                 patch.object(installer.platform, "system", return_value=system), \
                 patch.object(installer.platform, "machine", return_value=machine), \
                 patch.object(installer.platform, "mac_ver", return_value=(version, (), machine)), \
                 patch.object(installer.platform, "freedesktop_os_release",
                              return_value={"ID": distribution, "VERSION_ID": version}):
                if expected:
                    self.assertEqual(installer.host_profile(), expected)
                else:
                    with self.assertRaises(ValueError):
                        installer.host_profile()

    def test_existing_installation_and_links_are_preserved_before_network(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(installer.Path, "home", return_value=Path(tmp)), \
             patch.object(installer.os, "geteuid", return_value=1000), \
             patch.object(installer, "host_profile", return_value="ubuntu26.04-amd64"), \
             patch.object(installer.sys, "argv", ["install-symphony.py"]), \
             patch.object(installer, "fetch") as fetch:
            root = Path(tmp) / ("symphony-" + installer.RELEASE)
            root.mkdir()
            marker = root / "my-file"
            marker.write_text("keep")
            with self.assertRaisesRegex(ValueError, "already exists"):
                installer.main()
            self.assertEqual(marker.read_text(), "keep")
            marker.unlink()
            root.rmdir()
            root.symlink_to("missing")
            with self.assertRaisesRegex(ValueError, "already exists"):
                installer.main()
            self.assertTrue(root.is_symlink())
            fetch.assert_not_called()

    def test_verifies_trust_inputs_and_selected_archive_before_install(self):
        for profile, signed_suffix in [
            ("macos15-arm64", "MacOSX-arm64"),
            ("ubuntu24.04-amd64", "Linux-x86_64"),
            ("ubuntu24.04-arm64", "Linux-aarch64"),
            ("ubuntu26.04-amd64", "Linux-x86_64"),
        ]:
            with self.subTest(profile=profile):
                self.check_verified_download(profile, signed_suffix)

    def check_verified_download(self, profile, signed_suffix):
        name = f"installers/{profile}/Symphony-{installer.RELEASE}-{signed_suffix}.sh"
        archive = b"installer bytes"
        index = json.dumps({"artifacts":[{"path": name, "size": len(archive)}],
                            "profiles":{profile: {"receipt":"arm64"}}}).encode()
        verified = []

        def fetch(url, target, limit):
            if target.suffix == ".sh":
                self.assertEqual(verified, ["release-index.json"])
                self.assertEqual(url, f"{installer.GITHUB}/Symphony-{installer.RELEASE}-{profile}.sh")
                self.assertEqual(target.relative_to(work).as_posix(), name)
                self.assertEqual(limit, len(archive))
                target.write_bytes(archive)
            else:
                self.assertEqual(url, installer.GITHUB + "/" + target.name)
                target.write_bytes(index if target.name == "release-index.json" else b"fixture")

        with tempfile.TemporaryDirectory() as tmp, patch.object(installer, "fetch", side_effect=fetch), \
             patch.object(installer, "verify", side_effect=lambda work, path: verified.append(path)), \
             patch.object(installer, "VERIFIER_SHA256", hashlib.sha256(b"fixture").hexdigest()), \
             patch.object(installer, "INDEX_SHA256", hashlib.sha256(index).hexdigest()), \
             contextlib.redirect_stdout(io.StringIO()):
            work = Path(tmp)
            with patch.object(installer, "VERIFIER_SHA256", "0" * 64):
                with self.assertRaisesRegex(ValueError, "verify_beta.py"):
                    installer.prepare(work, profile)
                self.assertEqual(verified, [])
            path, record = installer.prepare(work, profile)
            self.assertEqual(verified, ["release-index.json", name])
            self.assertEqual(path.read_bytes(), archive)
            self.assertEqual(record, {"receipt":"arm64"})

    def test_failed_constructor_is_preserved_and_retry_can_reserve_path(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            root = Path(tmp) / "symphony-test"
            with patch.object(installer.subprocess, "run", side_effect=subprocess.CalledProcessError(1,"bash")):
                for _ in range(2):
                    with self.assertRaises(subprocess.CalledProcessError):
                        installer.install(root, Path("test.sh"), {})
                    self.assertFalse(root.exists())
            self.assertEqual(len(list(root.parent.glob(".symphony-test-incomplete-*"))), 2)
            # Simulate another installer winning the destination between verification and installation.
            root.mkdir()
            with patch.object(installer.subprocess, "run") as run, self.assertRaises(FileExistsError):
                installer.install(root, Path("test.sh"), {})
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()

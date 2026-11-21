import hashlib
import json
import unittest

import beta_download_redirects as redirects


class DownloadRedirectsTest(unittest.TestCase):
    def test_archives_match_verified_release_downloads(self):
        packages = {k: v for k, v in redirects.redirects().items() if k.endswith(".conda")}
        self.assertEqual(len(packages), 720)
        # The independent signed-index audit retrieved and SHA-256 checked every destination.
        canonical = json.dumps(packages, sort_keys=True, separators=(",", ":")).encode()
        self.assertEqual(hashlib.sha256(canonical).hexdigest(),
                         "3d66f2a10ae91c677bdfe16339d6da545def7d2f1e5aa2dd0652c7b49ff94a7a")

    def test_entry_points_keep_the_requested_version(self):
        routes = redirects.redirects()
        for path in ("/", "/symphony", "/symphony/"):
            self.assertEqual(routes[path], "https://quanux.org/downloads")
        for version in ("0.2.0-beta.1", "0.2.0-beta.2", "0.2.0-beta.2.1"):
            for suffix in ("", "/"):
                self.assertEqual(routes[f"/symphony/{version}{suffix}"],
                                 f"https://github.com/QuanuX/symphony-distribution/releases/tag/v{version}")
            self.assertNotIn(f"/symphony/{version}/release-index.json", routes)
        self.assertEqual(routes["/robots.txt"], "https://quanux.org/robots.txt")
        self.assertEqual(routes["/favicon.ico"], "https://quanux.org/favicon.svg")

    def test_edge_matches_only_configured_get_and_head_urls(self):
        plan = redirects.configuration()
        self.assertEqual(len(plan["items"]), 731)
        self.assertEqual(plan["rule"]["expression"],
                         'http.host eq "downloads.quanux.org" and http.request.method in {"GET" "HEAD"} '
                         'and http.request.full_uri in $symphony_public_downloads')
        self.assertEqual(plan["rule"]["action_parameters"]["from_list"],
                         {"name": plan["list"]["name"], "key": "http.request.full_uri"})
        for item in plan["items"]:
            rule = item["redirect"]
            self.assertTrue(rule["source_url"].startswith("downloads.quanux.org/"))
            self.assertEqual(rule["status_code"], 301)
            for flag in ("include_subdomains", "subpath_matching", "preserve_path_suffix", "preserve_query_string"):
                self.assertIs(rule[flag], False)


if __name__ == "__main__":
    unittest.main()

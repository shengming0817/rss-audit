"""Regression tests for consumer credential lifetime."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "check_consumer.py"
SPEC = importlib.util.spec_from_file_location("check_consumer", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load consumer checker")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class ConsumerEnvironmentTests(unittest.TestCase):
    """Only dependency acquisition may receive repository credentials."""

    def test_execution_environment_is_offline_and_credential_free(self) -> None:
        execution = CHECKER.execution_environment(
            {
                "PATH": "/usr/bin",
                "SYSTEM_ACCESSTOKEN": "secret",
                "AZURE_DEVOPS_EXT_PAT": "secret",
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "http.example.extraheader",
                "GIT_CONFIG_VALUE_0": "AUTHORIZATION: bearer secret",
            }
        )

        self.assertEqual(execution["CARGO_NET_OFFLINE"], "true")
        self.assertEqual(execution["PATH"], "/usr/bin")
        self.assertNotIn("SYSTEM_ACCESSTOKEN", execution)
        self.assertNotIn("AZURE_DEVOPS_EXT_PAT", execution)
        self.assertFalse(any(key.startswith("GIT_CONFIG_") for key in execution))

        visible = json.loads(
            subprocess.check_output(
                [
                    sys.executable,
                    "-c",
                    "import json, os; print(json.dumps(sorted(os.environ)))",
                ],
                env=execution,
                text=True,
            )
        )
        self.assertNotIn("SYSTEM_ACCESSTOKEN", visible)
        self.assertFalse(any(key.startswith("GIT_CONFIG_") for key in visible))

    def test_adapter_features_are_explicit_and_independent(self) -> None:
        import tomllib
        for scenario, expected in (("pg", []), ("ledger", ["ledger"]), ("messaging", ["messaging"]), ("ledger-messaging", ["ledger", "messaging"])):
            manifest = tomllib.loads(CHECKER.manifest('path = "/tmp/core"', scenario, 'path = "/tmp/adapter", default-features = false'))
            self.assertEqual(manifest["dependencies"]["rss-audit-postgres"]["features"], expected)
            self.assertFalse(manifest["dependencies"]["rss-audit-postgres"]["default-features"])
            self.assertEqual("rss-ledger-postgres" in manifest["dependencies"], "ledger" in expected)
            self.assertEqual("rss-transactional-messaging-postgres" in manifest["dependencies"], "messaging" in expected)

    def test_http_consumer_declares_only_plain_adapter_features(self) -> None:
        import tomllib
        manifest = tomllib.loads(CHECKER.manifest('path = "/tmp/core"', "http", 'path = "/tmp/pg", default-features = false', 'path = "/tmp/http", default-features = false'))
        self.assertEqual(manifest["dependencies"]["rss-audit-postgres"]["features"], [])
        self.assertFalse(manifest["dependencies"]["rss-audit-http-axum"]["default-features"])
        self.assertIn("http1", manifest["dependencies"]["axum"]["features"])
        self.assertNotIn("rss-ledger-postgres", manifest["dependencies"])
        self.assertNotIn("rss-transactional-messaging-postgres", manifest["dependencies"])


if __name__ == "__main__":
    unittest.main()

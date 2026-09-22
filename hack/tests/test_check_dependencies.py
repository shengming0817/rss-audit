"""Regression tests for complete RSS Git source pinning."""

import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "check_dependencies.py"
SPEC = importlib.util.spec_from_file_location("check_dependencies", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load dependency checker")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class RssGitSourceTests(unittest.TestCase):
    """The guard covers future package names, not only today's direct roots."""

    def test_accepts_unknown_package_at_the_exact_revision(self) -> None:
        source = (
            f"git+{CHECKER.RSS_URL}?rev={CHECKER.RSS_REVISION}"
            f"#{CHECKER.RSS_REVISION}"
        )
        CHECKER.validate_rss_git_sources(
            [{"name": "future-rss-package", "source": source}]
        )

    def test_rejects_unknown_package_on_a_branch(self) -> None:
        source = f"git+{CHECKER.RSS_URL}?branch=develop#deadbeef"
        with self.assertRaisesRegex(ValueError, "wrong RSS source"):
            CHECKER.validate_rss_git_sources(
                [{"name": "future-rss-package", "source": source}]
            )

    def test_rejects_internal_package_from_registry(self) -> None:
        with self.assertRaisesRegex(ValueError, "wrong RSS source"):
            CHECKER.validate_rss_git_sources(
                [
                    {
                        "name": "rss-future",
                        "source": "registry+https://github.com/rust-lang/crates.io-index",
                    }
                ]
            )

    def test_rejects_internal_package_from_alternate_git(self) -> None:
        with self.assertRaisesRegex(ValueError, "wrong RSS source"):
            CHECKER.validate_rss_git_sources(
                [
                    {
                        "name": "rss-future",
                        "source": "git+https://example.invalid/rss?rev=deadbeef#deadbeef",
                    }
                ]
            )


if __name__ == "__main__":
    unittest.main()

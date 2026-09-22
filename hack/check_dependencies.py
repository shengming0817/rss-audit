#!/usr/bin/env python3
"""Validate the exact RSS Git source and effective feature closure."""

import json
from pathlib import Path
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parent.parent
RSS_URL = "https://dev.azure.com/shengming0923/rss/_git/rss"
RSS_REVISION = "c3fbd187b8d97ff25cc5968243062d1521714fb7"
RSS_ROOTS = {
    "rss-contract",
    "rss-diag-context",
    "rss-ledger",
    "rss-redact",
    "rss-request-context",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_rss_git_sources(packages: list[dict]) -> None:
    """Require every non-workspace RSS package to use the one accepted Git source."""
    expected_source = f"git+{RSS_URL}?rev={RSS_REVISION}#{RSS_REVISION}"
    rss_git_prefix = f"git+{RSS_URL}"
    for package in packages:
        source = package["source"]
        protected = package["name"].startswith("rss-") or (
            source is not None and source.startswith(rss_git_prefix)
        )
        if protected and source is not None:
            require(source == expected_source, f"wrong RSS source for {package['name']}")


def main() -> None:
    manifest = tomllib.loads((ROOT / "Cargo.toml").read_text())
    declarations = manifest["workspace"]["dependencies"]
    roots = {name: declarations[name] for name in RSS_ROOTS}
    require(set(roots) == RSS_ROOTS, "RSS dependency roots are incomplete")
    for name, declaration in roots.items():
        require(declaration.get("git") == RSS_URL, f"{name} has an unknown RSS URL")
        require(
            declaration.get("rev") == RSS_REVISION,
            f"{name} is not pinned to the accepted RSS revision",
        )
        require(
            declaration.get("default-features") is False,
            f"{name} must disable default features explicitly",
        )
        require(
            not any(key in declaration for key in ("path", "branch", "tag", "registry")),
            f"{name} has an ambiguous source",
        )
    require(not manifest.get("patch") and not manifest.get("replace"), "source override forbidden")

    metadata = json.loads(
        subprocess.check_output(
            ["cargo", "metadata", "--locked", "--format-version", "1"], cwd=ROOT
        )
    )
    workspace = set(metadata["workspace_members"])
    found = set()
    packages = {package["id"]: package for package in metadata["packages"]}
    validate_rss_git_sources(list(packages.values()))
    for package in metadata["packages"]:
        if package["name"] in RSS_ROOTS:
            found.add(package["name"])
        if package["source"] is None:
            require(package["id"] in workspace, "external path dependency forbidden")
            Path(package["manifest_path"]).resolve().relative_to(ROOT)
    require(found == RSS_ROOTS, f"RSS source closure drift: {sorted(found)}")

    feature_sets = {
        packages[node["id"]]["name"]: set(node["features"])
        for node in metadata["resolve"]["nodes"]
        if packages[node["id"]]["name"] in RSS_ROOTS
    }
    expected_features = {name: set() for name in RSS_ROOTS}
    expected_features["rss-contract"] = {"default"}
    expected_features["rss-request-context"] = {"default"}
    require(
        feature_sets == expected_features,
        f"RSS feature closure drift: {feature_sets}",
    )
    print(json.dumps({"revision": RSS_REVISION, "packages": sorted(found)}))


if __name__ == "__main__":
    main()

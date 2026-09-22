#!/usr/bin/env python3
"""Run an isolated source or fixed-revision consumer of rss-audit-core."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parent.parent
AUDIT_URL = "https://dev.azure.com/shengming0923/rss/_git/rss-audit"
RSS_URL = "https://dev.azure.com/shengming0923/rss/_git/rss"
RSS_REVISION = "c3fbd187b8d97ff25cc5968243062d1521714fb7"
FORBIDDEN = {
    "axum",
    "sqlx",
    "rss-ledger-postgres",
    "rss-transactional-messaging",
    "rss-transactional-messaging-postgres",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def exact_revision(value: str) -> bool:
    return len(value) == 40 and all(character in "0123456789abcdef" for character in value)


def ensure_external(path: Path) -> None:
    resolved = path.resolve()
    for ancestor in (ROOT, *ROOT.parents):
        require(resolved != ancestor, "consumer output must not be a repository ancestor")
    require(ROOT not in resolved.parents, "consumer output must be outside the repository")


def manifest(dependency: str) -> str:
    return f'''[workspace]
resolver = "3"

[package]
name = "rss-audit-core-consumer"
version = "0.0.0"
edition = "2024"
publish = false

[dependencies]
rss-audit-core = {{ {dependency} }}
rss-contract = {{ git = "{RSS_URL}", rev = "{RSS_REVISION}", default-features = false }}
rss-request-context = {{ git = "{RSS_URL}", rev = "{RSS_REVISION}", default-features = false }}
'''


def check_metadata(metadata: dict, revision: str | None) -> None:
    require(len(metadata["workspace_members"]) == 1, "consumer workspace must have one member")
    packages = metadata["packages"]
    audit = [package for package in packages if package["name"] == "rss-audit-core"]
    require(len(audit) == 1, "expected exactly one rss-audit-core package")
    if revision:
        require(
            audit[0]["source"] == f"git+{AUDIT_URL}?rev={revision}#{revision}",
            "audit package is not the requested fixed revision",
        )
    else:
        require(audit[0]["source"] is None, "source consumer must use the local checkout")
        require(
            Path(audit[0]["manifest_path"]).resolve() == ROOT / "crates/audit-core/Cargo.toml",
            "source consumer resolved the wrong checkout",
        )

    expected_rss_revision = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"][
        "dependencies"
    ]["rss-ledger"]["rev"]
    require(expected_rss_revision == RSS_REVISION, "consumer RSS revision drift")
    expected_rss = f"git+{RSS_URL}?rev={expected_rss_revision}#{expected_rss_revision}"
    workspace_members = set(metadata["workspace_members"])
    rss_packages = [package for package in packages if package["name"].startswith("rss-")]
    for package in rss_packages:
        if package["name"] == "rss-audit-core" or package["id"] in workspace_members:
            continue
        require(package["source"] == expected_rss, f"wrong RSS source: {package['name']}")
    names = {package["name"] for package in packages}
    require(not names.intersection(FORBIDDEN), f"forbidden consumer closure: {names & FORBIDDEN}")


def run(output: Path, revision: str | None) -> None:
    ensure_external(output)
    output.mkdir(mode=0o700)
    (output / "src").mkdir()
    (output / ".cargo").mkdir()
    dependency = (
        f'git = "{AUDIT_URL}", rev = "{revision}", default-features = false'
        if revision
        else f'path = "{ROOT / "crates/audit-core"}", default-features = false'
    )
    (output / "Cargo.toml").write_text(manifest(dependency))
    (output / ".cargo/config.toml").write_text("[net]\ngit-fetch-with-cli = true\n")
    shutil.copyfile(ROOT / "tests/consumers/core.rs", output / "src/main.rs")

    env = dict(os.environ)
    env["CARGO_TARGET_DIR"] = str(output / "target")
    for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER"):
        env.pop(key, None)
    subprocess.run(["cargo", "generate-lockfile"], cwd=output, env=env, check=True)
    metadata = json.loads(
        subprocess.check_output(
            ["cargo", "metadata", "--locked", "--format-version", "1"],
            cwd=output,
            env=env,
        )
    )
    check_metadata(metadata, revision)
    subprocess.run(["cargo", "run", "--locked"], cwd=output, env=env, check=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--revision")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.revision:
        require(exact_revision(args.revision), "revision must be a full lowercase SHA")
    if args.output:
        require(args.output.is_absolute(), "output must be absolute")
        require(not args.output.exists(), "output must not already exist")
        run(args.output, args.revision)
    else:
        with tempfile.TemporaryDirectory(prefix="rss-audit-consumer-") as temporary:
            run(Path(temporary) / "workspace", args.revision)


if __name__ == "__main__":
    main()

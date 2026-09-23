#!/usr/bin/env python3
"""Run isolated core and PostgreSQL feature consumers from source or a fixed revision."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib
import uuid

ROOT = Path(__file__).resolve().parent.parent
AUDIT_URL = "https://dev.azure.com/shengming0923/rss/_git/rss-audit"
RSS_URL = "https://dev.azure.com/shengming0923/rss/_git/rss"
RSS_REVISION = "c752578e1b5e30724b8e81726a62553211b66dd5"
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


def manifest(dependency: str, scenario: str = "core", adapter: str = "", http: str = "") -> str:
    result = f'''[workspace]
resolver = "3"

[package]
name = "rss-audit-core-consumer"
version = "0.0.0"
edition = "2024"
publish = false

[dependencies]
rss-audit-core = {{ {dependency} }}
rss-contract = {{ git = "{RSS_URL}", rev = "{RSS_REVISION}", default-features = false }}
rss-ledger = {{ git = "{RSS_URL}", rev = "{RSS_REVISION}", default-features = false }}
rss-request-context = {{ git = "{RSS_URL}", rev = "{RSS_REVISION}", default-features = false }}
'''
    if scenario == "core":
        return result
    features = [name for name in ("ledger", "messaging") if name in scenario]
    result += f'''rss-audit-postgres = {{ {adapter}, features = {json.dumps(features)} }}
rss-transactional-messaging = {{ git = "{RSS_URL}", rev = "{RSS_REVISION}", default-features = false }}
testkit = {{ git = "{RSS_URL}", rev = "{RSS_REVISION}", default-features = false, features = ["containers"] }}
sqlx = {{ version = "=0.9.0", default-features = false, features = ["runtime-tokio", "tls-rustls", "postgres"] }}
tokio = {{ version = "1", features = ["rt-multi-thread", "macros", "time"] }}
tokio-util = "0.7"
anyhow = "1"
'''
    for feature in features:
        package = "rss-ledger-postgres" if feature == "ledger" else "rss-transactional-messaging-postgres"
        result += f'{package} = {{ git = "{RSS_URL}", rev = "{RSS_REVISION}", default-features = false }}\n'
    if scenario == "http":
        result += f'''rss-audit-http-axum = {{ {http} }}
axum = {{ version = "=0.8.9", default-features = false, features = ["json", "query", "tokio", "http1"] }}
serde_json = "1"
reqwest = {{ version = "0.13", default-features = false, features = ["json"] }}
'''
        result = result.replace('"macros", "time"]', '"macros", "time", "net"]')
    result += '\n[features]\nledger = []\nmessaging = []\nhttp = []\n'
    return result


def check_metadata(metadata: dict, revision: str | None, scenario: str = "core") -> None:
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
    rss_packages = [package for package in packages if package["name"].startswith("rss-") or package["name"] == "testkit"]
    for package in rss_packages:
        if package["name"] in ("rss-audit-core", "rss-audit-postgres", "rss-audit-http-axum"):
            if revision:
                require(package["source"] == f"git+{AUDIT_URL}?rev={revision}#{revision}", "mixed Audit source")
            else:
                expected = ROOT / "crates" / package["name"].removeprefix("rss-") / "Cargo.toml"
                require(package["source"] is None and Path(package["manifest_path"]).resolve() == expected, "wrong Audit checkout")
            continue
        if package["id"] in workspace_members:
            continue
        require(package["source"] == expected_rss, f"wrong RSS source: {package['name']}")
    names = {package["name"] for package in packages}
    if scenario == "core":
        require(not names.intersection(FORBIDDEN), f"forbidden consumer closure: {names & FORBIDDEN}")
    else:
        require("rss-audit-postgres" in names, "missing Audit adapter")
        nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
        adapter = next(package for package in packages if package["name"] == "rss-audit-postgres")
        expected = {name for name in ("ledger", "messaging") if name in scenario}
        require(set(nodes[adapter["id"]]["features"]) == expected, "Audit adapter feature drift")
    if scenario == "http":
        require("rss-audit-http-axum" in names, "missing HTTP adapter")
        http_adapter = next(package for package in packages if package["name"] == "rss-axum")
        require(not nodes[http_adapter["id"]]["features"], "HTTP consumer enabled managed serving")
    for package in packages:
        if package["source"] is None and package["id"] not in workspace_members:
            require(package["name"] in ("rss-audit-core", "rss-audit-postgres", "rss-audit-http-axum") and not revision, "unexpected external path")


def execution_environment(fetch_environment: dict[str, str]) -> dict[str, str]:
    """Remove repository credentials and force all build/run subprocesses offline."""
    environment = {
        key: value
        for key, value in fetch_environment.items()
        if key not in ("SYSTEM_ACCESSTOKEN", "AZURE_DEVOPS_EXT_PAT", "ADO_PAT", "GH_TOKEN", "GITHUB_TOKEN")
        and not key.startswith("GIT_CONFIG_")
    }
    environment["CARGO_NET_OFFLINE"] = "true"
    return environment


def run_case(output: Path, revision: str | None, scenario: str, target: Path) -> None:
    ensure_external(output)
    output.mkdir(mode=0o700)
    (output / "src").mkdir()
    (output / ".cargo").mkdir()
    dependency = (
        f'git = "{AUDIT_URL}", rev = "{revision}", default-features = false'
        if revision
        else f'path = "{ROOT / "crates/audit-core"}", default-features = false'
    )
    adapter = (
        f'git = "{AUDIT_URL}", rev = "{revision}", default-features = false'
        if revision else f'path = "{ROOT / "crates/audit-postgres"}", default-features = false'
    )
    http = (
        f'git = "{AUDIT_URL}", rev = "{revision}", default-features = false'
        if revision else f'path = "{ROOT / "crates/audit-http-axum"}", default-features = false'
    )
    (output / "Cargo.toml").write_text(manifest(dependency, scenario, adapter, http))
    (output / ".cargo/config.toml").write_text("[net]\ngit-fetch-with-cli = true\n")
    shutil.copyfile(ROOT / "tests/consumers" / ("core.rs" if scenario == "core" else "postgres.rs"), output / "src/main.rs")

    if scenario == "http":
        shutil.copytree(ROOT / "tests/consumers/http-host", output / "src/http-host")
    fetch_env = dict(os.environ)
    fetch_env["CARGO_TARGET_DIR"] = str(target)
    fetch_env["RSS_TEST_RUN_ID"] = f"audit-consumer-{uuid.uuid4().hex}"
    for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER"):
        fetch_env.pop(key, None)
    subprocess.run(["cargo", "generate-lockfile"], cwd=output, env=fetch_env, check=True)
    subprocess.run(["cargo", "fetch", "--locked"], cwd=output, env=fetch_env, check=True)
    run_env = execution_environment(fetch_env)
    features = [name for name in ("ledger", "messaging") if name in scenario]
    if scenario == "http":
        features.append("http")
    arguments = ["--features", ",".join(features)] if features else []
    metadata = json.loads(
        subprocess.check_output(
            ["cargo", "metadata", "--locked", "--format-version", "1", *arguments],
            cwd=output,
            env=run_env,
        )
    )
    check_metadata(metadata, revision, scenario)
    subprocess.run(["cargo", "run", "--locked", *arguments], cwd=output, env=run_env, check=True)
    print(json.dumps({"scenario": scenario, "revision": revision, "result": "passed"}), flush=True)


def run(output: Path, revision: str | None) -> None:
    ensure_external(output)
    output.mkdir(mode=0o700)
    for scenario in ("core", "pg", "ledger", "messaging", "ledger-messaging", "http"):
        run_case(output / scenario, revision, scenario, output / "target")


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

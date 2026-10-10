"""Regression tests: production must always use the compose.prod.yaml overlay.

Covers the Makefile blessed targets, scripts/deploy_prod.sh wrapper,
scripts/enforce_prod_compose.sh guard, and the enforce-prod-compose CI job.
Render checks requiring `docker compose` are exercised only when docker is
available; static file-content checks always run (Windows-safe).
"""

import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]


def _read(name: str) -> str:
    return (REPO_ROOT / name).read_text(encoding="utf-8")


def _load_yaml(name: str):
    """Load a compose file, tolerating compose-spec tags like `!reset`."""

    class _ComposeLoader(yaml.SafeLoader):
        pass

    def _unknown_tag(loader, tag_suffix, node):
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node, deep=True)
        if isinstance(node, yaml.MappingNode):
            return loader.construct_mapping(node, deep=True)
        return loader.construct_scalar(node)

    _ComposeLoader.add_multi_constructor("!", _unknown_tag)
    return yaml.load((REPO_ROOT / name).read_text(encoding="utf-8"), Loader=_ComposeLoader)


def test_blessed_entrypoints_exist():
    assert (REPO_ROOT / "Makefile").is_file()
    assert (REPO_ROOT / "scripts" / "deploy_prod.sh").is_file()
    assert (REPO_ROOT / "scripts" / "enforce_prod_compose.sh").is_file()
    assert (REPO_ROOT / "compose.yaml").is_file()
    assert (REPO_ROOT / "compose.prod.yaml").is_file()


def test_makefile_prod_targets_pin_overlay():
    text = _read("Makefile")
    for target in ("up-prod:", "build-prod:", "deploy-prod:", "config-prod:", "migrate-prod:"):
        assert target in text, f"Makefile missing prod target {target}"
    assert "-f compose.yaml -f compose.prod.yaml" in text
    # Dev targets must stay on the base file only (explicit local-dev path).
    assert "up-dev:" in text


def test_deploy_wrapper_enforces_overlay_and_fails_fast():
    text = _read("scripts/deploy_prod.sh")
    assert "compose.prod.yaml" in text
    assert '-f "${BASE_FILE}" -f "${PROD_FILE}"' in text
    assert "ENV=production" in text
    # Refuses caller-supplied -f/--file so the overlay cannot be sidestepped.
    assert "--file" in text
    # Required production secrets fail fast.
    for var in ("SECRET_KEY", "POSTGRES_PASSWORD", "ALLOWED_RECEIVER_DOMAINS", "PUBLIC_BASE_URL"):
        assert var in text
    # Demo/seed profiles refused against production.
    assert "demo" in text and "seed" in text
    # TLS guard for public stack commands.
    assert "deploy/tls/fullchain.pem" in text


def test_enforce_script_guards_overlay():
    text = _read("scripts/enforce_prod_compose.sh")
    assert "compose.prod.yaml" in text
    assert "enforce-prod-compose" in text
    assert "ports: !reset []" in text or "ports: \\[\\]" in text
    assert "COMPOSE_FILE" in text
    assert "main" in text and "master" in text


def test_ci_contains_enforce_prod_compose_job():
    text = _read(".github/workflows/ci.yml")
    assert "enforce-prod-compose:" in text
    assert "scripts/enforce_prod_compose.sh" in text
    assert "compose.prod.yaml" in text


def test_prod_overlay_static_fail_closed_guards():
    prod = _load_yaml("compose.prod.yaml")
    services = prod.get("services", {})
    # DB/Redis/web must not publish host ports in prod.
    for svc in ("postgres", "redis", "web"):
        assert svc in services, f"prod overlay missing service {svc}"
        assert not services[svc].get("ports"), f"prod service {svc} must have empty ports"
    # Web forces production env.
    web_env = services["web"].get("environment", [])
    env_text = "\n".join(str(e) for e in web_env)
    assert "ENV=production" in env_text
    assert "ALLOW_LOCAL_RECEIVERS=False" in env_text
    assert "USE_DEMO_RETRY_POLICY=False" in env_text
    # Prod nginx conf mounted, dev conf absent.
    proxy_volumes = " ".join(str(v) for v in services.get("reverse_proxy", {}).get("volumes", []))
    assert "deploy/nginx.conf" in proxy_volumes
    assert "nginx.dev.conf" not in proxy_volumes
    # Required secrets are fail-closed (:?... markers).
    raw = _read("compose.prod.yaml")
    for var in ("SECRET_KEY", "POSTGRES_PASSWORD", "ALLOWED_RECEIVER_DOMAINS", "PUBLIC_BASE_URL"):
        assert re.search(r"\$\{" + var + r":\?", raw), f"prod overlay must require ${{{var}:?...}}"


def test_bare_base_compose_is_not_prod_safe():
    """Proves the overlay is load-bearing: base alone exposes DB/Redis ports."""
    base = _load_yaml("compose.yaml")
    pg_ports = base["services"]["postgres"].get("ports", [])
    redis_ports = base["services"]["redis"].get("ports", [])
    assert pg_ports, "expected base compose to publish postgres ports (overlay removes them)"
    assert redis_ports, "expected base compose to publish redis ports (overlay removes them)"


def _working_bash() -> str | None:
    """Return a usable bash executable, or None (Windows WSL stubs don't count)."""
    candidates = [shutil.which("bash"), r"C:\Program Files\Git\bin\bash.exe"]
    for exe in candidates:
        if not exe:
            continue
        try:
            proc = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            continue
        if proc.returncode == 0 and "GNU bash" in (proc.stdout or ""):
            return exe
    return None


def test_enforce_script_static_only_passes():
    bash_exe = _working_bash()
    if bash_exe is None:
        pytest.skip("no working bash available")
    proc = subprocess.run(
        [bash_exe, "scripts/enforce_prod_compose.sh", "--static-only"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert proc.returncode == 0, f"enforce script failed:\n{proc.stdout}\n{proc.stderr}"
    assert "all static enforcement checks passed" in proc.stdout

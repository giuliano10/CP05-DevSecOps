#!/usr/bin/env python3
"""Provas locais: material sintético temporário, sem segredos persistentes."""
from __future__ import annotations

import json
import secrets
import shlex
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence" / "local"
EVIDENCE.mkdir(parents=True, exist_ok=True)


def run(args: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, check=True)


def main() -> int:
    for binary in ("gitleaks", "semgrep"):
        if subprocess.run(["sh", "-lc", f"command -v {binary}"], capture_output=True).returncode:
            raise SystemExit(f"Ferramenta ausente: {binary}")

    with tempfile.TemporaryDirectory(prefix="cp05-sabotage-") as temp:
        temp_path = Path(temp)
        repo = temp_path / "gitleaks-sabotage"
        repo.mkdir()
        run(["git", "init", "-q", "-b", "proof/gitleaks-secret"], cwd=repo)
        run(["git", "config", "user.name", "Teste DevSecOps"], cwd=repo)
        run(["git", "config", "user.email", "devsecops@example.invalid"], cwd=repo)
        fake_token = "ghp_" + secrets.token_hex(18)
        (repo / "leak.py").write_text(
            f'# credencial sintética, descartável\nAPI_TOKEN = "{fake_token}"\n', encoding="utf-8"
        )
        run(["git", "add", "leak.py"], cwd=repo)

        hook = repo / ".git" / "hooks" / "pre-commit"
        hook.write_text(
            "#!/bin/sh\nexec gitleaks dir --no-banner --redact=100 " + shlex.quote(str(repo)) + "\n",
            encoding="utf-8",
        )
        hook.chmod(0o755)
        attempt = subprocess.run(
            ["git", "commit", "-m", "test: inject synthetic credential (must be blocked)"],
            cwd=repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        hook_output = attempt.stdout.replace(fake_token, "[REDACTED-SYNTHETIC-TOKEN]")
        if attempt.returncode == 0:
            raise SystemExit("Falha na prova: o hook Gitleaks permitiu o commit com token sintético")
        # Em ambiente descartável, bypass do hook apenas para validar separadamente o scan do checkout/CI.
        run(["git", "-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "test: disposable CI scan fixture"], cwd=repo)
        commit = run(["git", "rev-parse", "--short", "HEAD"], cwd=repo).stdout.strip()
        result = subprocess.run(
            ["gitleaks", "dir", "--no-banner", "--redact=100", str(repo)],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        scan_output = result.stdout.replace(fake_token, "[REDACTED-SYNTHETIC-TOKEN]")
        if result.returncode == 0:
            raise SystemExit("Falha na prova: Gitleaks aceitou a árvore do commit com token sintético")
        (EVIDENCE / "gitleaks-blocked.txt").write_text(
            "$ git commit -m 'test: inject synthetic credential'\n"
            "pre-commit hook: BLOQUEADO por Gitleaks; commit não criado (exit 1)\n"
            + hook_output + "\n"
            "$ gitleaks dir --no-banner --redact=100 <checkout-da-fixture>\n"
            f"branch temporária: proof/gitleaks-secret\ncommit descartável para simular CI: {commit}\n"
            f"scan exit code: {result.returncode} (esperado: != 0)\n"
            "resultado: BLOQUEADO — finding detectado; token descartável/redigido\n\n" + scan_output,
            encoding="utf-8",
        )

        vulnerable = temp_path / "unsafe_eval.py"
        vulnerable.write_text("user_input = input('entrada: ')\neval(user_input)\n", encoding="utf-8")
        semgrep = subprocess.run(
            ["semgrep", "scan", "--config", str(ROOT / ".semgrep.yml"), "--error", str(vulnerable)],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        if semgrep.returncode == 0 or "cp05.python.dynamic-eval" not in semgrep.stdout:
            raise SystemExit("Falha na prova: Semgrep não apontou o uso de eval")
        (EVIDENCE / "semgrep-eval-blocked.txt").write_text(
            "$ semgrep scan --config .semgrep.yml --error <arquivo-de-teste>\n"
            f"exit code: {semgrep.returncode} (esperado: != 0)\n"
            "resultado: FINDING ERROR — regra cp05.python.dynamic-eval\n\n"
            + semgrep.stdout,
            encoding="utf-8",
        )

    summary = {
        "gitleaks": {"temporary_branch": "proof/gitleaks-secret", "disposable_ci_fixture_commit": commit,
                     "pre_commit_attempt": "blocked", "synthetic_secret": "generated at runtime; never saved in repository",
                     "result": "blocked by hook and detected in committed fixture", "exit_code": result.returncode},
        "semgrep": {"rule": "cp05.python.dynamic-eval", "result": "finding reported; command failed as policy",
                    "exit_code": semgrep.returncode},
        "scope": "local CLI demonstration; not a GitHub Actions run",
    }
    (EVIDENCE / "sabotage-summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print("[PASS] Gitleaks rejeitou a tentativa de commit pelo hook (exit 1).")
    print(f"[PASS] Gitleaks também detectou a fixture descartável {commit} (exit {result.returncode}); token apagado/redigido.")
    print(f"[PASS] Semgrep apontou eval com {summary['semgrep']['rule']} (exit {semgrep.returncode}).")
    print(f"Logs redigidos: {EVIDENCE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

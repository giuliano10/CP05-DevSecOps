# Evidências

- `local/gitleaks-blocked.txt`: commit de teste temporário bloqueado (segredo sintético gerado em runtime e redigido).
- `local/semgrep-eval-blocked.txt`: finding ERROR da regra `cp05.python.dynamic-eval`.
- `local/trivy-image-scan.txt`: scan do OCI do site (Alpine 3.24.2) com zero vulnerabilidades conhecidas; gate CRITICAL com exit code 0.
- `local/trivy-vulnerable-image-blocked.txt`: sabotagem adicional em `alpine:3.12`; CVE-2022-37434 (zlib) CRITICAL; gate com exit code 1.
- `../CP05-Relatorio-DevSecOps.pdf`: relatório com capturas das saídas de CLI e análise.

**Limite de proveniência:** enquanto o conector GitHub estiver desativado, essas são provas locais reproduzíveis, não capturas da aba Actions. O job GitHub Actions é fornecido em `.github/workflows/security.yml` para execução após publicação autorizada.

# CP05 — Pipeline DevSecOps de referência

Site estático servido por Nginx não privilegiado e pipeline GitHub Actions com três jobs independentes: **Gitleaks**, **Semgrep** e **Trivy**.

## Barreiras

| Job | Alvo | Política de bloqueio |
|---|---|---|
| `gitleaks` | Histórico completo do Git (`fetch-depth: 0`) | Falha ao encontrar segredo; não armazene exceções com credenciais reais. |
| `semgrep` | Código fonte + regra local `.semgrep.yml` | `--error` transforma findings em status não zero; a regra `cp05.python.dynamic-eval` detecta `eval(...)` em Python. |
| `trivy` | Imagem que o job constrói do próprio commit | Examina vulnerabilidades OS e bibliotecas; falha quando encontra qualquer issue reportada com severidade `CRITICAL`, mesmo sem correção disponível. |

O workflow dispara em `push`, `pull_request` e execução manual. Cada job é um check separado. Para tornar a barreira obrigatória para merge, configure as regras de proteção da branch principal no GitHub e marque **os três checks** como obrigatórios. O arquivo YAML não ativa sozinho a proteção de branch.

As GitHub Actions estão fixadas por SHA e o container Semgrep por digest para reduzir risco de alteração silenciosa de dependências externas. Revise e atualize esses pins periodicamente após validar novas versões.

## Site e imagem

```bash
podman build --pull -t cp05-site:local .
podman run --rm -p 8080:8080 cp05-site:local
# abra http://localhost:8080
```

Também é possível usar `docker build` / `docker run`. A base `nginxinc/nginx-unprivileged:stable-alpine` serve a página na porta 8080 sem executar como root. Para produção, prefira fixar a imagem base por digest e automatizar atualizações controladas.

## Reproduzir as sabotagens locais

Requisitos: Python 3, Git, Gitleaks CLI e Semgrep CLI.

```bash
python3 scripts/prove_sabotage.py
```

O script cria um repositório temporário e um **token sintético aleatório em tempo de execução**. O hook pré-commit rejeita a tentativa de commit; depois, apenas numa fixture descartável, o script ignora o hook para criar um commit de teste e confirmar que Gitleaks reprova a árvore versionada. Em seguida, cria um arquivo transitório com `eval(input())` e exige que Semgrep acione a regra local. Ao fim, apaga os diretórios temporários. Os logs em `evidence/local/` registram o hash da fixture, a regra e os exit codes; nenhum token é armazenado nos arquivos entregues.

A demonstração reproduz as políticas usando as CLIs no Sandbox. Não representa execução nem captura real do GitHub Actions; para isso, o repositório deve ser enviado a uma conta GitHub autorizada.

## Teste da política Trivy

```bash
trivy image --severity CRITICAL --exit-code 1 cp05-site:local
```

Com Podman, exporte a imagem como Docker archive e informe o tar ao Trivy (isso evita depender de um daemon Docker):

```bash
podman save -o /tmp/cp05-site.tar cp05-site:local
trivy image --input /tmp/cp05-site.tar --severity CRITICAL --exit-code 1
```

Para verificar que a política realmente falha diante de um alvo vulnerável, rode o mesmo comando contra uma imagem deliberadamente obsoleta em ambiente isolado (por exemplo `alpine:3.12`) e confirme o exit code diferente de zero. Não use essa imagem vulnerável como base do produto.

## Resposta a segredo exposto

Um alerta no commit não revoga uma credencial: **rotacione/revogue imediatamente a chave real**, investigue usos, remova o segredo do histórico quando apropriado e migre para GitHub Secrets/gerenciador de segredos. Não reutilize a chave comprometida.

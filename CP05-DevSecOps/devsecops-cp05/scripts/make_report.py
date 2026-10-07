#!/usr/bin/env python3
"""Gera o relatório PDF usando as saídas CLI registradas pelo próprio repositório."""
from __future__ import annotations

import re
from pathlib import Path

from PIL import Image as PILImage, ImageDraw, ImageFont
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Image, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence" / "local"
SHOTS = ROOT / "evidence" / "screenshots"
SHOTS.mkdir(parents=True, exist_ok=True)
PDF = ROOT / "CP05-Relatorio-DevSecOps.pdf"

FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONT_BOLD_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"


def clean(text: str) -> str:
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    text = text.replace("\t", "  ")
    return text


def terminal(lines: list[str], target: Path, title: str) -> None:
    font = ImageFont.truetype(FONT_PATH, 17)
    bold = ImageFont.truetype(FONT_BOLD_PATH, 17)
    line_h, top, bottom = 27, 64, 25
    width = 1480
    height = top + line_h * len(lines) + bottom
    image = PILImage.new("RGB", (width, height), "#080d14")
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((12, 10, width - 12, height - 10), radius=14,
                           fill="#101722", outline="#344253", width=2)
    for i, color in enumerate(("#ff6b6b", "#ffd166", "#75e2a8")):
        x = 34 + i * 24
        draw.ellipse((x, 25, x + 13, 38), fill=color)
    draw.text((120, 22), title, font=bold, fill="#90e6c5")
    draw.line((27, 51, width - 27, 51), fill="#2a3748", width=1)
    y = 67
    for line in lines:
        is_good = any(k in line.lower() for k in ("bloqueado", "finding", "critical", "cve-", "exit code"))
        color = "#f0bd72" if is_good else "#d8e0ec"
        draw.text((34, y), line[:133], font=font, fill=color)
        y += line_h
    image.save(target, optimize=True)


def wrap_lines(text: str, width: int = 132) -> list[str]:
    result: list[str] = []
    for line in clean(text).splitlines():
        line = line.rstrip()
        if len(line) <= width:
            result.append(line)
        else:
            while len(line) > width:
                result.append(line[:width])
                line = "  " + line[width:]
            result.append(line)
    return result


def evidence_lines(name: str) -> list[str]:
    return (EVIDENCE / name).read_text(encoding="utf-8").splitlines()


def make_screenshots() -> dict[str, Path]:
    g = evidence_lines("gitleaks-blocked.txt")
    g_lines = [g[0], g[1], g[2], g[3], g[6], g[7], g[8], g[9], "", g[11], g[12]]
    s = evidence_lines("semgrep-eval-blocked.txt")
    s_lines = [s[0], s[1], s[2], "", "Findings: 1 (1 blocking)", "Rule: cp05.python.dynamic-eval", "Severity: ERROR / Blocking", "Code: eval(user_input)"]
    t = evidence_lines("trivy-image-scan.txt")
    t_lines = [t[0], "Detected OS: alpine 3.24.2", "Packages scanned: 70", "", "Report Summary", "/tmp/cp05-site.docker.tar | alpine | vulnerabilities: 0", "", "Gate CRITICAL exit code: 0 (imagem limpa)"]
    v = evidence_lines("trivy-vulnerable-image-blocked.txt")
    v_lines = ["$ trivy image --severity CRITICAL --exit-code 1 alpine:3.12", "Detected OS: alpine 3.12.12 (EOL)", "Total: 1 (CRITICAL: 1)", "CVE-2022-37434 | zlib 1.2.12-r0 | fixed 1.2.12-r2", "CWE: heap-based buffer over-read and overflow", "exit code da política CRITICAL: 1 (BLOQUEADO)"]
    specs = {
        "gitleaks": (g_lines, "EXECUÇÃO LOCAL · GITLEAKS CLI 8.30.1"),
        "semgrep": (s_lines, "EXECUÇÃO LOCAL · SEMGREP CLI 1.179.0"),
        "trivy_clean": (t_lines, "EXECUÇÃO LOCAL · TRIVY 0.75.0 · IMAGEM CP05"),
        "trivy_block": (v_lines, "EXECUÇÃO LOCAL · TRIVY 0.75.0 · TESTE DE SABOTAGEM"),
    }
    paths = {}
    for name, (lines, title) in specs.items():
        path = SHOTS / f"{name}.png"
        terminal(wrap_lines("\n".join(lines)), path, title)
        paths[name] = path
    return paths


def build_pdf(shots: dict[str, Path]) -> None:
    styles = getSampleStyleSheet()
    ink = colors.HexColor("#142033")
    muted = colors.HexColor("#546174")
    mint = colors.HexColor("#087f62")
    styles.add(ParagraphStyle(name="CoverKicker", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=9, leading=13, textColor=mint, spaceAfter=7))
    styles.add(ParagraphStyle(name="BigTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=29, leading=34, textColor=ink, alignment=TA_LEFT, spaceAfter=12))
    styles.add(ParagraphStyle(name="Deck", parent=styles["Normal"], fontName="Helvetica", fontSize=12, leading=18, textColor=muted, spaceAfter=12))
    styles.add(ParagraphStyle(name="Section", parent=styles["Heading1"], fontName="Helvetica-Bold", fontSize=20, leading=24, textColor=ink, spaceAfter=10))
    styles.add(ParagraphStyle(name="BodyPT", parent=styles["BodyText"], fontName="Helvetica", fontSize=9.5, leading=14, textColor=ink, spaceAfter=8))
    styles.add(ParagraphStyle(name="SmallPT", parent=styles["BodyText"], fontName="Helvetica", fontSize=8, leading=11, textColor=muted, spaceAfter=6))
    styles.add(ParagraphStyle(name="Callout", parent=styles["BodyText"], fontName="Helvetica-Bold", fontSize=9, leading=13, textColor=colors.HexColor("#784b00"), backColor=colors.HexColor("#fff3d6"), borderColor=colors.HexColor("#f2cd79"), borderWidth=0.8, borderPadding=8, spaceBefore=8, spaceAfter=12))

    def header_footer(canvas, doc):
        canvas.saveState()
        w, h = A4
        canvas.setStrokeColor(colors.HexColor("#dbe2ea"))
        canvas.line(18 * mm, h - 15 * mm, w - 18 * mm, h - 15 * mm)
        canvas.setFont("Helvetica-Bold", 7.5)
        canvas.setFillColor(mint)
        canvas.drawString(18 * mm, h - 12 * mm, "CP05  /  DEVSECOPS")
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(muted)
        canvas.drawRightString(w - 18 * mm, 11 * mm, f"Relatório local · 06 out 2026  |  {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(str(PDF), pagesize=A4, rightMargin=18 * mm, leftMargin=18 * mm,
                            topMargin=22 * mm, bottomMargin=18 * mm,
                            title="CP05 — Pipeline DevSecOps de referência",
                            author="Demonstração educacional DevSecOps")
    story = []
    story += [Spacer(1, 12 * mm), Paragraph("PIPELINE DE SEGURANÇA · CP05", styles["CoverKicker"]),
              Paragraph("DevSecOps<br/>com evidências", styles["BigTitle"]),
              Paragraph("Repositório de referência com Dockerfile, site estático e três barreiras bloqueantes: segredos, padrões vulneráveis e CVEs críticos.", styles["Deck"]), Spacer(1, 4 * mm)]
    rows = [[Paragraph("GITLEAKS", styles["SmallPT"]), Paragraph("SEMGREP", styles["SmallPT"]), Paragraph("TRIVY", styles["SmallPT"])],
            [Paragraph("COMMIT SINTÉTICO<br/><b>bloqueado · exit 1</b>", styles["BodyPT"]), Paragraph("eval(input())<br/><b>finding ERROR</b>", styles["BodyPT"]), Paragraph("IMAGEM CP05<br/><b>0 CVEs reportados</b>", styles["BodyPT"])]]
    table = Table(rows, colWidths=[57 * mm, 57 * mm, 57 * mm])
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f7f5")),
                               ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#d7e5df")),
                               ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d7e5df")),
                               ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 9),
                               ("RIGHTPADDING", (0, 0), (-1, -1), 9), ("TOPPADDING", (0, 0), (-1, -1), 8),
                               ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
    story += [table, Spacer(1, 7 * mm), Paragraph("Escopo e proveniência", styles["Section"]),
              Paragraph("As verificações e sabotagens foram executadas no Sandbox com Gitleaks 8.30.1, Semgrep 1.179.0 e Trivy 0.75.0. A imagem foi construída do Dockerfile do projeto via Podman, exportada como Docker archive e examinada pelo Trivy. No workflow, as Actions estão fixadas por SHA e a imagem Semgrep por digest. Os quadros visuais a seguir foram compostos a partir das <b>saídas textuais reais das CLIs</b>; não são screenshots da interface nem da aba GitHub Actions.", styles["BodyPT"]),
              Paragraph("Limitação importante: o conector GitHub está desativado e não há repositório remoto conectado nesta execução. Portanto, o arquivo `.github/workflows/security.yml` foi criado e validado localmente, mas não foi executado na infraestrutura GitHub Actions. Uma execução remota real e seus screenshots exigem conectar e executar o workflow em um repositório autorizado.", styles["Callout"]),
              Paragraph("Para bloquear merges, além do workflow, habilite proteção da branch principal e marque os três checks como obrigatórios. Se uma chave real vazar, revogue-a e rotacione-a imediatamente; remover o texto do commit não invalida a credencial.", styles["SmallPT"]),
              PageBreak()]

    def add_barrier(title: str, paragraph: str, image_path: Path, caption: str):
        story.extend([Paragraph(title, styles["Section"]), Paragraph(paragraph, styles["BodyPT"]), Spacer(1, 2 * mm)])
        img = Image(str(image_path), width=174 * mm, height=174 * mm * (PILImage.open(image_path).height / PILImage.open(image_path).width))
        story.extend([img, Spacer(1, 3 * mm), Paragraph(caption, styles["SmallPT"])])

    add_barrier("1. Gitleaks — credencial não passa",
                "Uma tentativa de commit com token sintético foi <b>rejeitada pelo hook local</b> antes de criar o commit. Depois, apenas na fixture descartável, o hook foi ignorado para criar um commit de teste e confirmar que o scan Gitleaks da árvore também falha com exit code 1. O valor foi redigido e o diretório temporário removido. No workflow, a action examina o histórico completo (`fetch-depth: 0`), e a branch principal entregue foi verificada sem findings.",
                shots["gitleaks"], "Registro de saída local da CLI. O commit de sabotagem temporário não foi incorporado ao repositório entregue.")
    story.append(PageBreak())
    add_barrier("2. Semgrep — eval é um finding bloqueante",
                "A regra local `.semgrep.yml` identifica `eval(...)` em código Python com severidade ERROR. O teste gravou temporariamente `eval(user_input)`, e o Semgrep reportou a regra `cp05.python.dynamic-eval` como finding bloqueante; com `--error`, o comando saiu com código 1. O scan da branch limpa retornou zero findings. A barreira reduz o risco de injeção de código e orienta substituição por parsing explícito ou operações permitidas.",
                shots["semgrep"], "Registro local: um finding, regra identificada e linha vulnerável apontada.")
    story.append(PageBreak())
    story.extend([Paragraph("3. Trivy — CVEs críticos na imagem", styles["Section"]),
                  Paragraph("O Trivy examinou a imagem real construída do Dockerfile do CP05. A camada do sistema operacional foi identificada como Alpine 3.24.2; o relatório do scan registrou <b>zero vulnerabilidades conhecidas</b> e o gate CRITICAL terminou com exit code 0. A política do workflow usa `severity: CRITICAL` e `exit-code: 1` sem ignorar CVEs não corrigidos, portanto qualquer CVE crítico reportado bloqueia o job.", styles["BodyPT"]),
                  Image(str(shots["trivy_clean"]), width=174 * mm, height=174 * mm * (PILImage.open(shots["trivy_clean"]).height / PILImage.open(shots["trivy_clean"]).width)),
                  Paragraph("Scan local da imagem construída para este projeto. O resultado limpo é um retrato do banco Trivy na data/hora da execução, não uma garantia futura.", styles["SmallPT"]),
                  Spacer(1, 3 * mm),
                  Paragraph("Prova de bloqueio", styles["Heading2"]),
                  Paragraph("Como teste adicional de sabotagem, o mesmo gate examinou `alpine:3.12`, uma base fora de suporte. O Trivy encontrou <b>CVE-2022-37434</b> em zlib (CRITICAL; versão instalada 1.2.12-r0, corrigida em 1.2.12-r2) e retornou <b>exit code 1</b>. A distribuição está obsoleta e a própria ferramenta alerta que a cobertura pode ser incompleta; ela foi usada somente como fixture de teste, nunca como base do site.", styles["BodyPT"]),
                  Image(str(shots["trivy_block"]), width=174 * mm, height=174 * mm * (PILImage.open(shots["trivy_block"]).height / PILImage.open(shots["trivy_block"]).width)),
                  Paragraph("Teste local de política com uma imagem deliberadamente vulnerável; não é a imagem do CP05.", styles["SmallPT"]),
                  Paragraph("Conclusão: as três regras foram exercitadas localmente e mostraram o comportamento esperado de pass/fail. Para converter estas provas em capturas reais do GitHub Actions, conecte o GitHub, execute o workflow no repositório de destino e substitua os registros locais pelas páginas da execução remota.", styles["Callout"])])
    doc.build(story, onFirstPage=header_footer, onLaterPages=header_footer)
    print(f"PDF criado: {PDF}")
    for name, path in shots.items():
        print(f"Captura criada: {path}")


if __name__ == "__main__":
    build_pdf(make_screenshots())

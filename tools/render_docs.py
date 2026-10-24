"""Render assessment report and working-concept handbook; optional reportlab dependency."""

from pathlib import Path
from html import escape
import re
import json
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    PageBreak,
    Table,
    TableStyle,
    Preformatted,
    Image,
    KeepTogether,
)
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.graphics.shapes import Drawing, Rect, String, Line, Polygon

ROOT = Path(__file__).resolve().parents[1]
NAVY = colors.HexColor("#153047")
TEAL = colors.HexColor("#007f86")
INK = colors.HexColor("#263748")
styles = getSampleStyleSheet()
styles.add(
    ParagraphStyle(
        name="BodyTextDoc",
        fontName="Helvetica",
        fontSize=9.8,
        leading=13.5,
        spaceAfter=7,
        textColor=INK,
        allowWidows=0,
        allowOrphans=0,
    )
)
styles.add(
    ParagraphStyle(
        name="Section",
        fontName="Helvetica-Bold",
        fontSize=13.2,
        leading=17,
        spaceBefore=12,
        spaceAfter=7,
        textColor=NAVY,
        keepWithNext=True,
    )
)
styles.add(
    ParagraphStyle(
        name="SubSection", parent=styles["Section"], fontSize=11.2, leading=15
    )
)
styles.add(
    ParagraphStyle(
        name="SmallDoc",
        fontName="Helvetica",
        fontSize=8,
        leading=10.5,
        spaceAfter=5,
        textColor=INK,
    )
)
styles.add(
    ParagraphStyle(
        name="Cover",
        fontName="Helvetica-Bold",
        fontSize=29,
        leading=35,
        textColor=NAVY,
        spaceAfter=20,
    )
)
styles.add(
    ParagraphStyle(
        name="CodeDoc",
        fontName="Courier",
        fontSize=7.2,
        leading=10,
        leftIndent=8,
        spaceBefore=4,
        spaceAfter=8,
    )
)


def inline(text):
    text = escape(text)
    text = re.sub(
        r"\[([^\]]+)\]\((https?://[^)]+)\)",
        r'<link href="\2" color="#007f86">\1</link>',
        text,
    )
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"`([^`]+)`", r'<font name="Courier">\1</font>', text)
    return text


def workflow():
    draw = Drawing(500, 90)
    labels = [
        ("OBSERVE", "CSV / PCAP"),
        ("VALIDATE", "Evidence quality"),
        ("CONTEXT", "60s / 300s"),
        ("LEARN", "Calibrated trees"),
        ("CHECK", "Rules / uncertainty"),
        ("TRIAGE", "Alert / review / clear"),
    ]
    for index, (title, note) in enumerate(labels):
        x = index * 84
        draw.add(
            Rect(
                x,
                31,
                76,
                43,
                rx=4,
                ry=4,
                fillColor=colors.HexColor("#edf7f7"),
                strokeColor=TEAL,
                strokeWidth=0.8,
            )
        )
        draw.add(
            String(
                x + 38,
                57,
                title,
                textAnchor="middle",
                fontName="Helvetica-Bold",
                fontSize=8,
                fillColor=NAVY,
            )
        )
        draw.add(
            String(
                x + 38,
                43,
                note,
                textAnchor="middle",
                fontName="Helvetica",
                fontSize=6.5,
                fillColor=INK,
            )
        )
        if index < 5:
            draw.add(Line(x + 76, 52, x + 82, 52, strokeColor=TEAL))
            draw.add(
                Polygon(
                    [x + 82, 52, x + 79, 54, x + 79, 50],
                    fillColor=TEAL,
                    strokeColor=TEAL,
                )
            )
    return draw


def make_table(lines):
    raw = [
        [cell.strip() for cell in line.strip().strip("|").split("|")] for line in lines
    ]
    raw = [
        row
        for row in raw
        if not all(re.fullmatch(r"[:\- ]+", cell or "-") for cell in row)
    ]
    count = len(raw[0])
    width = 503
    widths = [140, 125, 238] if count == 3 else [width / count] * count
    cells = [
        [Paragraph(inline(cell), styles["SmallDoc"]) for cell in row] for row in raw
    ]
    table = Table(cells, colWidths=widths, repeatRows=1, hAlign="LEFT", splitInRow=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#d6ecec")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cad9df")),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [colors.white, colors.HexColor("#f4f7fa")],
                ),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    return table


def footer(canvas, document):
    width, height = A4
    canvas.saveState()
    canvas.setStrokeColor(colors.HexColor("#cbd8df"))
    canvas.line(46, 36, width - 46, 36)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#657683"))
    canvas.drawString(46, 24, "SENTINEL / CONTEXT IDS / RESEARCH EDITION")
    canvas.drawRightString(width - 46, 24, str(document.page))
    canvas.restoreState()


def comparison_page():
    story = []
    story += [
        PageBreak(),
        Paragraph("Measured comparison and combined error matrix", styles["Section"]),
        Paragraph(
            "Locked synthetic test: every row contributes, including reviewed observations.",
            styles["BodyTextDoc"],
        ),
    ]
    matrix = Image(str(ROOT / "results/confusion_matrix.png"), width=470, height=353)
    story.append(matrix)
    metrics = json.loads((ROOT / "results/metrics.json").read_text())
    table = ["| System | Accuracy | Macro F1 |", "| --- | --- | --- |"]
    for name, block in metrics["locked_test"].items():
        table.append(f"| {name} | {block['accuracy']:.2%} | {block['macro_f1']:.2%} |")
    story.append(make_table(table))
    story.append(
        Paragraph(
            "Headline results are synthetic. Broader training is a major comparison confounder; context adds one flow and rules do not improve class accuracy on this test.",
            styles["SmallDoc"],
        )
    )
    return story


def render(source, output, title, subtitle, handbook=False):
    story = [
        Spacer(1, 90),
        Paragraph("SENTINEL", styles["Cover"]),
        Paragraph(title, styles["Title"]),
        Spacer(1, 18),
        Paragraph(subtitle, styles["BodyTextDoc"]),
        Spacer(1, 25),
        Paragraph(
            "MegaMinds IT Services | Individual technical assessment",
            styles["BodyTextDoc"],
        ),
        Paragraph("25 October 2026 | Research edition 3.0", styles["BodyTextDoc"]),
        Spacer(1, 30),
        workflow(),
        Paragraph(
            "Synthetic efficacy, explicit uncertainty, reproducible evidence. No world-first or universal detection claim.",
            styles["SmallDoc"],
        ),
        PageBreak(),
    ]
    if handbook:
        story.append(Paragraph("Contents", styles["Section"]))
        toc = TableOfContents()
        toc.levelStyles = [
            ParagraphStyle(
                name="TOC",
                fontName="Helvetica",
                fontSize=9,
                leading=11.5,
                spaceBefore=0,
                leftIndent=0,
            )
        ]
        story += [toc, PageBreak()]
    lines = source.read_text(encoding="utf-8").splitlines()
    index = 1
    section_number = 0
    while index < len(lines):
        line = lines[index].strip()
        if not line:
            index += 1
            continue
        if line.startswith("#"):
            level = len(line) - len(line.lstrip("#"))
            title_text = line.lstrip("# ").strip()
            if not handbook and title_text == "References":
                story.extend(comparison_page())
            section_number += 1
            para = Paragraph(
                inline(title_text), styles["Section" if level <= 2 else "SubSection"]
            )
            if level <= 2:
                para._bookmarkName = f"section-{section_number}"
            story.append(para)
            index += 1
            continue
        if line.startswith("|"):
            table_lines = []
            while index < len(lines) and lines[index].strip().startswith("|"):
                table_lines.append(lines[index])
                index += 1
            story += [make_table(table_lines), Spacer(1, 9)]
            continue
        if line.startswith("```"):
            code = []
            index += 1
            while index < len(lines) and not lines[index].strip().startswith("```"):
                code.append(lines[index])
                index += 1
            story.append(
                Preformatted("\n".join(code), styles["CodeDoc"], maxLineLength=100)
            )
            index += 1
            continue
        paragraph = []
        while (
            index < len(lines)
            and lines[index].strip()
            and not lines[index].strip().startswith(("#", "|", "```"))
        ):
            paragraph.append(lines[index].strip())
            index += 1
        story.append(Paragraph(inline(" ".join(paragraph)), styles["BodyTextDoc"]))
    document = SimpleDocTemplate(
        str(output),
        pagesize=A4,
        leftMargin=46,
        rightMargin=46,
        topMargin=44,
        bottomMargin=50,
        title=title,
        author="Individual assessment submission",
        pageCompression=1,
    )

    def after(flowable):
        if isinstance(flowable, Paragraph) and hasattr(flowable, "_bookmarkName"):
            key = flowable._bookmarkName
            document.canv.bookmarkPage(key)
            document.canv.addOutlineEntry(flowable.getPlainText(), key, 0, False)
            if handbook:
                document.notify(
                    "TOCEntry", (0, flowable.getPlainText(), document.page, key)
                )

    document.afterFlowable = after
    document.multiBuild(story, onFirstPage=footer, onLaterPages=footer)
    print(output)


def main():
    render(
        ROOT / "docs/TECHNICAL_REPORT.md",
        ROOT / "docs/Sentinel_Technical_Report.pdf",
        "Context-Aware Intrusion Detection",
        "Technical report: design, evaluation, security considerations and limits.",
    )
    render(
        ROOT / "docs/WORKING_CONCEPT.md",
        ROOT / "docs/Sentinel_Working_Concept_Handbook.pdf",
        "Complete Working-Concept Handbook",
        "Networking, feature equations, machine learning, uncertainty, evidence policy, usefulness and operational boundaries.",
        True,
    )


if __name__ == "__main__":
    main()

"""
Vector PDF Security Audit Report Generator
Uses ReportLab to produce executive audit reports with severity tables,
risk scores, redacted evidence, and remediation guidelines.
"""

import io
from pathlib import Path
from typing import Any, Dict, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
)


class PDFReportGenerator:
    """Generates professional DevSecOps PDF audit reports."""

    SEVERITY_COLORS = {
        "CRITICAL": colors.HexColor("#dc3545"),
        "HIGH": colors.HexColor("#fd7e14"),
        "MEDIUM": colors.HexColor("#ffc107"),
        "LOW": colors.HexColor("#0dcaf0"),
        "INFO": colors.HexColor("#6c757d"),
    }

    @classmethod
    def generate(cls, scan_data: Dict[str, Any], findings: List[Dict[str, Any]]) -> bytes:
        """Renders scan data into PDF bytes."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#0f172a"),
            fontName="Helvetica-Bold",
        )
        subtitle_style = ParagraphStyle(
            "DocSubtitle",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#475569"),
        )
        h2_style = ParagraphStyle(
            "SectionH2",
            parent=styles["Heading2"],
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#1e293b"),
            fontName="Helvetica-Bold",
            spaceBefore=14,
            spaceAfter=6,
        )
        body_style = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#334155"),
        )
        code_style = ParagraphStyle(
            "CodeSnippet",
            parent=styles["Normal"],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#0f172a"),
            fontName="Courier",
            backColor=colors.HexColor("#f1f5f9"),
        )

        elements = []

        elements.append(Paragraph("Secret Leak Guard — Security Audit Report", title_style))
        elements.append(Paragraph(
            f"Project: <b>{scan_data.get('project_name', 'N/A')}</b> | "
            f"Scan ID: {scan_data.get('scan_id', 'N/A')} | "
            f"Date: {scan_data.get('completed_at', scan_data.get('created_at', 'N/A'))}",
            subtitle_style,
        ))
        elements.append(Spacer(1, 10))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#cbd5e1"), spaceAfter=14))

        elements.append(Paragraph("Executive Summary & Risk Posture", h2_style))
        summary = scan_data.get("summary", {})
        risk_score = scan_data.get("risk_score", 0.0)
        grade = scan_data.get("security_grade", "A")

        summary_data = [
            [
                Paragraph("<b>Overall Security Grade:</b>", body_style),
                Paragraph(f"<b><font size='+4' color='{'#dc3545' if grade in ['D', 'F'] else '#198754'}'>{grade}</font></b>", body_style),
                Paragraph("<b>Calculated Risk Score:</b>", body_style),
                Paragraph(f"<b>{risk_score} / 100</b>", body_style),
            ],
            [
                Paragraph("<b>Total Findings:</b>", body_style),
                Paragraph(str(summary.get("total_findings", 0)), body_style),
                Paragraph("<b>Duration:</b>", body_style),
                Paragraph(f"{scan_data.get('duration_seconds', 0)}s", body_style),
            ],
            [
                Paragraph("<b>Critical Findings:</b>", body_style),
                Paragraph(f"<font color='#dc3545'><b>{summary.get('critical', 0)}</b></font>", body_style),
                Paragraph("<b>High Findings:</b>", body_style),
                Paragraph(f"<font color='#fd7e14'><b>{summary.get('high', 0)}</b></font>", body_style),
            ],
            [
                Paragraph("<b>Medium Findings:</b>", body_style),
                Paragraph(f"<font color='#ffc107'><b>{summary.get('medium', 0)}</b></font>", body_style),
                Paragraph("<b>Low / Info Findings:</b>", body_style),
                Paragraph(f"<font color='#0dcaf0'><b>{summary.get('low', 0)}</b></font>", body_style),
            ],
            [
                Paragraph("<b>Engines Executed:</b>", body_style),
                Paragraph(", ".join(scan_data.get("engines_executed", ["Gitleaks", "Semgrep", "Bandit", "Trivy", "OSV"])), body_style),
                Paragraph("<b>Source Target:</b>", body_style),
                Paragraph(scan_data.get("source_target", "Workspace"), body_style),
            ],
        ]

        summary_table = Table(summary_data, colWidths=[130, 130, 130, 150])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("PADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 16))

        elements.append(Paragraph(f"Detailed Security Findings ({len(findings)})", h2_style))

        if not findings:
            elements.append(Paragraph(
                "<i>No security vulnerabilities, leaked credentials, or vulnerable dependencies detected. Clean codebase!</i>",
                body_style,
            ))
        else:
            for idx, f in enumerate(findings, start=1):
                sev = f.get("severity", "MEDIUM")
                sev_color = cls.SEVERITY_COLORS.get(sev, colors.HexColor("#6c757d"))

                finding_table_data = [
                    [
                        Paragraph(f"<b>#{idx}. {f.get('title', 'Security Finding')}</b>", body_style),
                        Paragraph(f"<b><font color='{sev_color.hexval()}'>[{sev}]</font></b>", body_style),
                    ],
                    [
                        Paragraph(
                            f"<b>Location:</b> {f.get('file_path', 'unknown')}:{f.get('line_number', 'N/A')} | "
                            f"<b>Engine:</b> {f.get('engine', 'N/A')} | "
                            f"<b>Category:</b> {f.get('category', 'N/A')}",
                            body_style,
                        ),
                        Paragraph(f"<b>CWE:</b> {f.get('cwe', 'N/A')}", body_style),
                    ],
                    [
                        Paragraph(f"<b>Description:</b> {f.get('description', '')}", body_style),
                        "",
                    ],
                ]

                if f.get("evidence_redacted"):
                    finding_table_data.append([
                        Paragraph(f"<b>Redacted Evidence:</b><br/>{f.get('evidence_redacted')}", code_style),
                        "",
                    ])

                if f.get("recommended_remediation"):
                    finding_table_data.append([
                        Paragraph(f"<b>Remediation:</b> {f.get('recommended_remediation')}", body_style),
                        "",
                    ])

                ft = Table(finding_table_data, colWidths=[420, 120])
                ft.setStyle(TableStyle([
                    ("SPAN", (0, 2), (1, 2)),
                    ("SPAN", (0, 3), (1, 3)) if len(finding_table_data) > 3 else ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("SPAN", (0, 4), (1, 4)) if len(finding_table_data) > 4 else ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#ffffff")),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("LINEBEFORE", (0, 0), (0, -1), 3, sev_color),
                    ("PADDING", (0, 0), (-1, -1), 4),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]))
                elements.append(ft)
                elements.append(Spacer(1, 8))

        doc.build(elements)
        return buffer.getvalue()

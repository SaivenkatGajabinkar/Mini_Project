"""
CyberShield — Enterprise PDF Security Audit Report Generator
=============================================================

Generates high-fidelity, SOC-grade PDF reports for network capture analyses
using ReportLab. Includes executive risk summaries, threat breakdowns,
protocol statistics, suspicious telemetry, and incident recommendations.
"""

import io
from datetime import datetime
from typing import Any, Dict, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas that computes total page count dynamically
    and renders a professional header/footer on every page.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states: List[Dict[str, Any]] = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_page_decorations(self, page_count: int):
        self.saveState()

        # Running header (Pages 2+)
        if self._pageNumber > 1:
            self.setFont("Helvetica-Bold", 8)
            self.setFillColor(colors.HexColor("#0F172A"))
            self.drawString(36, 756, "CYBERSHIELD")
            self.setFont("Helvetica", 8)
            self.setFillColor(colors.HexColor("#64748B"))
            self.drawString(105, 756, "— Network Security Threat Analysis Report")
            self.drawRightString(576, 756, "CONFIDENTIAL / SOC AUDIT")

            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.75)
            self.line(36, 748, 576, 748)

        # Running footer (All pages)
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.75)
        self.line(36, 38, 576, 38)

        self.setFont("Helvetica", 7.5)
        self.setFillColor(colors.HexColor("#64748B"))
        self.drawString(
            36,
            24,
            "CyberShield Detection Engine • Automated Incident Audit Report • For Authorized Use Only",
        )
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(576, 24, page_str)

        self.restoreState()


def _format_date(val: Any) -> str:
    """Safely format ISO date string to human-readable format."""
    if not val:
        return "N/A"
    try:
        dt = datetime.fromisoformat(str(val))
        return dt.strftime("%b %d, %Y %H:%M:%S UTC")
    except Exception:
        return str(val)


def generate_pdf_report(capture: Dict[str, Any]) -> bytes:
    """
    Generate an executive PDF security report for a network capture.

    Args:
        capture: Dictionary containing capture analysis data
                 (id, original_name, risk_score, risk_level, status,
                  total_flows, attack_flows, normal_flows, attack_ratio,
                  mean_attack_probability, suspicious_ips,
                  top_suspicious_flows, protocol_breakdown, etc.)

    Returns:
        Raw PDF document bytes ready for HTTP response or file storage.
    """
    buf = io.BytesIO()

    # Printable width = 612 - 72 = 540 pt
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=46,
    )

    base_styles = getSampleStyleSheet()

    # Custom typography palette
    style_h1 = ParagraphStyle(
        "ReportTitle",
        parent=base_styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0F172A"),
        spaceAfter=2,
    )
    style_subtitle = ParagraphStyle(
        "ReportSubtitle",
        parent=base_styles["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor("#64748B"),
        spaceAfter=10,
    )
    style_section_h2 = ParagraphStyle(
        "SectionHeader",
        parent=base_styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#0F172A"),
        spaceBefore=12,
        spaceAfter=6,
    )
    style_meta_label = ParagraphStyle(
        "MetaLabel",
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#475569"),
    )
    style_meta_val = ParagraphStyle(
        "MetaVal",
        fontName="Helvetica",
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#0F172A"),
    )
    style_cell = ParagraphStyle(
        "TableCell",
        fontName="Helvetica",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#1E293B"),
    )
    style_cell_bold = ParagraphStyle(
        "TableCellBold",
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#0F172A"),
    )
    style_cell_header = ParagraphStyle(
        "TableHeader",
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=11,
        textColor=colors.white,
    )
    style_cell_danger = ParagraphStyle(
        "TableCellDanger",
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#DC2626"),
    )
    style_cell_success = ParagraphStyle(
        "TableCellSuccess",
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#16A34A"),
    )
    style_kpi_value = ParagraphStyle(
        "KPIVal",
        fontName="Helvetica-Bold",
        fontSize=15,
        leading=18,
        alignment=1,  # Center
    )
    style_kpi_label = ParagraphStyle(
        "KPILabel",
        fontName="Helvetica-Bold",
        fontSize=7.5,
        leading=9,
        textColor=colors.HexColor("#64748B"),
        alignment=1,  # Center
    )
    style_body = ParagraphStyle(
        "BodyTextCustom",
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#334155"),
    )

    story = []

    # ─────────────────────────────────────────────────────────────
    # 1. HEADER & BRANDING BANNER
    # ─────────────────────────────────────────────────────────────
    header_content = [
        [
            Paragraph("CYBERSHIELD DEFENSE SUITE", style_meta_label),
            Paragraph(
                f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
                ParagraphStyle("GenDate", parent=style_meta_label, alignment=2),
            ),
        ]
    ]
    header_tbl = Table(header_content, colWidths=[270, 270])
    header_tbl.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    story.append(header_tbl)
    story.append(Spacer(1, 4))

    story.append(Paragraph("Network Threat & Intrusion Analysis Report", style_h1))
    story.append(
        Paragraph(
            "Automated packet flow extraction, random forest classification, and risk evaluation.",
            style_subtitle,
        )
    )

    # ─────────────────────────────────────────────────────────────
    # 2. CAPTURE METADATA CARD
    # ─────────────────────────────────────────────────────────────
    cid = str(capture.get("capture_id") or capture.get("id") or "UNKNOWN")
    filename = str(capture.get("filename") or capture.get("original_name") or "Network_Capture.pcap")
    uploaded_at = _format_date(capture.get("analysed_at") or capture.get("uploaded_at"))
    model_ver = str(capture.get("model_version") or "v1.0 (Random Forest)")

    meta_rows = [
        [
            Paragraph("Target File:", style_meta_label),
            Paragraph(filename, style_meta_val),
            Paragraph("Capture ID:", style_meta_label),
            Paragraph(cid[:18] + ("..." if len(cid) > 18 else ""), style_meta_val),
        ],
        [
            Paragraph("Analysis Date:", style_meta_label),
            Paragraph(uploaded_at, style_meta_val),
            Paragraph("ML Engine:", style_meta_label),
            Paragraph(f"Random Forest ({model_ver})", style_meta_val),
        ],
    ]
    meta_table = Table(meta_rows, colWidths=[80, 190, 80, 190])
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#E2E8F0")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#F1F5F9")),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    story.append(meta_table)
    story.append(Spacer(1, 10))

    # ─────────────────────────────────────────────────────────────
    # 3. EXECUTIVE VERDICT & RISK LEVEL BANNER
    # ─────────────────────────────────────────────────────────────
    status = str(capture.get("status", "NORMAL")).upper()
    risk_level = str(capture.get("risk_level", "LOW")).upper()
    risk_score = float(capture.get("risk_score", 0.0))

    is_attack = status == "ATTACK" or risk_level == "HIGH"

    verdict_bg = colors.HexColor("#FEF2F2" if is_attack else "#F0FDF4")
    verdict_border = colors.HexColor("#EF4444" if is_attack else "#22C55E")
    verdict_text_color = colors.HexColor("#DC2626" if is_attack else "#16A34A")

    verdict_title = "[THREAT DETECTED] MALICIOUS NETWORK TRAFFIC" if is_attack else "[VERDICT: NORMAL] BENIGN NETWORK TRAFFIC"
    verdict_desc = (
        f"The machine learning classification engine identified active threat traffic. "
        f"Overall risk score evaluated at {risk_score:.1f}/100 with {risk_level} threat severity. "
        f"Recommended defensive containment actions are outlined below."
        if is_attack
        else f"Packet flows conform to baseline benign traffic parameters. "
        f"Overall risk score evaluated at {risk_score:.1f}/100 with {risk_level} risk level. "
        f"No volume flooding or exploit signatures were flagged."
    )

    verdict_content = [
        [
            Paragraph(
                f"<b>{verdict_title}</b>",
                ParagraphStyle("VTitle", parent=style_h1, fontSize=12, leading=15, textColor=verdict_text_color),
            ),
            Paragraph(
                f"<b>Risk Score: {risk_score:.1f} / 100</b><br/><font size='8'>Level: {risk_level}</font>",
                ParagraphStyle("VScore", parent=style_meta_label, fontSize=10, leading=13, alignment=2, textColor=verdict_text_color),
            ),
        ],
        [
            Paragraph(verdict_desc, style_body),
            Paragraph("", style_body),
        ],
    ]
    verdict_table = Table(verdict_content, colWidths=[400, 140])
    verdict_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), verdict_bg),
                ("BOX", (0, 0), (-1, -1), 1.5, verdict_border),
                ("SPAN", (0, 1), (1, 1)),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    story.append(verdict_table)
    story.append(Spacer(1, 10))

    # ─────────────────────────────────────────────────────────────
    # 4. SUMMARY METRIC CARDS (KPIs)
    # ─────────────────────────────────────────────────────────────
    total_flows = int(capture.get("total_flows", 0))
    attack_flows = int(capture.get("attack_flows", 0))
    normal_flows = int(capture.get("normal_flows", 0))
    attack_ratio = float(capture.get("attack_ratio", 0.0)) * 100.0
    mean_prob = float(capture.get("mean_attack_probability", 0.0)) * 100.0

    kpi_cols = [
        [
            Paragraph(f"{total_flows:,}", ParagraphStyle("K1", parent=style_kpi_value, textColor=colors.HexColor("#0284C7"))),
            Paragraph("TOTAL FLOWS", style_kpi_label),
        ],
        [
            Paragraph(f"{attack_flows:,}", ParagraphStyle("K2", parent=style_kpi_value, textColor=colors.HexColor("#DC2626"))),
            Paragraph(f"ATTACK FLOWS ({attack_ratio:.1f}%)", style_kpi_label),
        ],
        [
            Paragraph(f"{normal_flows:,}", ParagraphStyle("K3", parent=style_kpi_value, textColor=colors.HexColor("#16A34A"))),
            Paragraph("NORMAL FLOWS", style_kpi_label),
        ],
        [
            Paragraph(f"{mean_prob:.1f}%", ParagraphStyle("K4", parent=style_kpi_value, textColor=colors.HexColor("#D97706"))),
            Paragraph("MEAN ATTACK CONFIDENCE", style_kpi_label),
        ],
    ]

    # Transpose into 1 row of 4 columns
    kpi_cells = [
        [kpi_cols[0][0], kpi_cols[1][0], kpi_cols[2][0], kpi_cols[3][0]],
        [kpi_cols[0][1], kpi_cols[1][1], kpi_cols[2][1], kpi_cols[3][1]],
    ]
    kpi_table = Table(kpi_cells, colWidths=[135, 135, 135, 135])
    kpi_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#E2E8F0")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, 0), 7),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 2),
                ("TOPPADDING", (0, 1), (-1, 1), 0),
                ("BOTTOMPADDING", (0, 1), (-1, 1), 7),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ]
        )
    )
    story.append(kpi_table)
    story.append(Spacer(1, 10))

    # ─────────────────────────────────────────────────────────────
    # 5. PROTOCOL DISTRIBUTION
    # ─────────────────────────────────────────────────────────────
    story.append(Paragraph("Protocol Distribution", style_section_h2))

    protocol_data = capture.get("protocol_breakdown") or {}
    proto_rows = [
        [
            Paragraph("Protocol", style_cell_header),
            Paragraph("Flow Count", style_cell_header),
            Paragraph("Share of Traffic", style_cell_header),
        ]
    ]

    if protocol_data:
        for proto, count in protocol_data.items():
            pct = (count / total_flows * 100) if total_flows > 0 else 0
            proto_rows.append(
                [
                    Paragraph(f"<b>{proto}</b>", style_cell_bold),
                    Paragraph(f"{count:,}", style_cell),
                    Paragraph(f"{pct:.1f}%", style_cell),
                ]
            )
    else:
        proto_rows.append([Paragraph("No protocol records found", style_cell), Paragraph("0", style_cell), Paragraph("0.0%", style_cell)])

    proto_table = Table(proto_rows, colWidths=[180, 180, 180])
    proto_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(proto_table)
    story.append(Spacer(1, 10))

    # ─────────────────────────────────────────────────────────────
    # 6. SUSPICIOUS IP ADDRESSES
    # ─────────────────────────────────────────────────────────────
    suspicious_ips = capture.get("suspicious_ips") or []
    story.append(Paragraph("Flagged Threat Actors & Suspicious IP Addresses", style_section_h2))

    ip_rows = [
        [
            Paragraph("IP Address", style_cell_header),
            Paragraph("Attack Flows", style_cell_header),
            Paragraph("Threat Severity", style_cell_header),
            Paragraph("Mitigation Action", style_cell_header),
        ]
    ]

    if suspicious_ips:
        for item in suspicious_ips:
            ip_str = item.get("ip", "N/A")
            af = item.get("attack_flows", 0)
            sev = "HIGH" if af >= 5 else ("MEDIUM" if af >= 2 else "LOW")
            action = "Firewall Null-Route / Simulated Block"
            ip_rows.append(
                [
                    Paragraph(f"<font name='Helvetica-Bold'>{ip_str}</font>", style_cell_danger),
                    Paragraph(str(af), style_cell),
                    Paragraph(f"<b>{sev}</b>", style_cell_danger if sev == "HIGH" else style_cell),
                    Paragraph(action, style_cell),
                ]
            )
    else:
        ip_rows.append(
            [
                Paragraph("None detected (Clean traffic)", style_cell_success),
                Paragraph("0", style_cell),
                Paragraph("N/A", style_cell),
                Paragraph("Routine monitoring", style_cell),
            ]
        )

    ip_table = Table(ip_rows, colWidths=[150, 90, 110, 190])
    ip_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(ip_table)
    story.append(Spacer(1, 10))

    # ─────────────────────────────────────────────────────────────
    # 7. TOP SUSPICIOUS FLOW TELEMETRY
    # ─────────────────────────────────────────────────────────────
    flows = capture.get("top_suspicious_flows") or []
    story.append(Paragraph(f"Network Flow Telemetry ({min(len(flows), 25)} Suspicious Flows)", style_section_h2))

    flow_rows = [
        [
            Paragraph("Source (IP:Port)", style_cell_header),
            Paragraph("Destination (IP:Port)", style_cell_header),
            Paragraph("Proto", style_cell_header),
            Paragraph("Attack Prob.", style_cell_header),
            Paragraph("ML Verdict", style_cell_header),
        ]
    ]

    if flows:
        for flow in flows[:25]:  # Include top 25 flows
            src = f"{flow.get('src_ip', '0.0.0.0')}:{flow.get('src_port', 0)}"
            dst = f"{flow.get('dst_ip', '0.0.0.0')}:{flow.get('dst_port', 0)}"
            proto = str(flow.get("protocol", "TCP"))
            prob = float(flow.get("attack_probability", 0.0)) * 100.0
            label = str(flow.get("label", "Attack"))

            lbl_style = style_cell_danger if label.lower() == "attack" else style_cell_success

            flow_rows.append(
                [
                    Paragraph(src, style_cell),
                    Paragraph(dst, style_cell),
                    Paragraph(proto, style_cell),
                    Paragraph(f"{prob:.1f}%", style_cell_danger if prob >= 50 else style_cell),
                    Paragraph(f"<b>{label.upper()}</b>", lbl_style),
                ]
            )
    else:
        flow_rows.append(
            [
                Paragraph("No suspicious flows detected", style_cell_success),
                Paragraph("-", style_cell),
                Paragraph("-", style_cell),
                Paragraph("0.0%", style_cell),
                Paragraph("NORMAL", style_cell_success),
            ]
        )

    # Col widths sum to 540 pt: 145 + 145 + 50 + 100 + 100 = 540
    flow_table = Table(flow_rows, colWidths=[145, 145, 50, 100, 100])
    flow_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(flow_table)
    story.append(Spacer(1, 10))

    # ─────────────────────────────────────────────────────────────
    # 8. INCIDENT RESPONSE & SECURITY RECOMMENDATIONS
    # ─────────────────────────────────────────────────────────────
    recs_elements = [
        Paragraph("Recommended Incident Response Actions", style_section_h2),
    ]

    if is_attack:
        actions = [
            "<b>1. Perimeter Isolation:</b> Immediately block or rate-limit identified source IPs at border firewalls or edge routers.",
            "<b>2. Internal Endpoint Review:</b> Inspect targeted destination host ports for signs of service compromise or backdoor activity.",
            "<b>3. Threat Simulation & Testing:</b> Utilize the CyberShield IP blocking tool to verify automated defense policy simulation.",
            "<b>4. Forensic PCAP Archival:</b> Retain this PCAP file and SHA-256 hash for forensic chain of custody and incident response logs.",
        ]
    else:
        actions = [
            "<b>1. Continuous Baseline Monitoring:</b> Maintain standard network traffic sampling to detect sudden flow volume anomalies.",
            "<b>2. Sensor Health:</b> Verify packet capture tap points and ensure feature extraction pipelines remain operational.",
            "<b>3. Periodic Audit:</b> Schedule automated PCAP analysis for recurring security evaluations.",
        ]

    for act in actions:
        recs_elements.append(Paragraph(f"&bull; {act}", style_body))
        recs_elements.append(Spacer(1, 3))

    recs_elements.append(Spacer(1, 6))
    recs_elements.append(
        Paragraph(
            "<font color='#64748B'><b>Methodology Note:</b> Risk Score = 100 * (0.5 * Attack_Ratio + 0.3 * Mean_Probability + 0.2 * Volume_Factor). "
            "Classifier uses 22 statistical flow features analyzed by Random Forest. Generated for demonstration and educational purposes.</font>",
            ParagraphStyle("Methodology", parent=style_body, fontSize=7.5, leading=10, textColor=colors.HexColor("#64748B")),
        )
    )

    story.append(KeepTogether(recs_elements))

    # Build PDF with custom NumberedCanvas
    doc.build(story, canvasmaker=NumberedCanvas)

    pdf_bytes = buf.getvalue()
    buf.close()
    return pdf_bytes

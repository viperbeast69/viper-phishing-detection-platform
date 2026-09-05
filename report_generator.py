import json
from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)


# ============================================================
# REPORT DIRECTORY
# ============================================================

REPORT_DIRECTORY = Path("reports")

REPORT_DIRECTORY.mkdir(
    exist_ok=True
)


# ============================================================
# SAFE FILENAME
# ============================================================

def create_filename(url, extension):
    """
    Create a safe report filename from a URL.
    """

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    safe_url = (
        url.replace("https://", "")
        .replace("http://", "")
        .replace("/", "_")
        .replace(":", "_")
        .replace("?", "_")
        .replace("&", "_")
        .replace("=", "_")
    )

    safe_url = safe_url[:80]

    return (
        REPORT_DIRECTORY
        / f"scan_{safe_url}_{timestamp}.{extension}"
    )


# ============================================================
# DATABASE SCAN → REPORT FORMAT
# ============================================================

def database_scan_to_result(scan):
    """
    Convert a SQLite scan record into the result structure
    expected by the report generator.
    """

    indicators = scan.get(
        "indicators",
        []
    )

    if isinstance(indicators, str):

        try:
            indicators = json.loads(
                indicators
            )

        except json.JSONDecodeError:
            indicators = []

    return {

        "url": scan.get(
            "url",
            "Unknown"
        ),

        "score": scan.get(
            "score",
            0
        ),

        "risk": scan.get(
            "classification",
            "Unknown"
        ),

        "severity": scan.get(
            "severity",
            "UNKNOWN"
        ),

        "confidence": scan.get(
            "confidence",
            0
        ),

        "warnings": indicators,

        "features": {},

        "dns": {
            "resolved": bool(
                scan.get(
                    "dns_resolved",
                    0
                )
            )
        },

        "domain": {
            "registered_domain": scan.get(
                "domain"
            )
        },

        "reputation": {

            "malicious": scan.get(
                "reputation_malicious",
                0
            ),

            "suspicious": scan.get(
                "reputation_suspicious",
                0
            ),

            "harmless": scan.get(
                "reputation_harmless",
                0
            )

        },

        "ml": {

            "phishing_probability": scan.get(
                "ml_phishing_probability"
            ),

            "legitimate_probability": scan.get(
                "ml_legitimate_probability"
            )

        },

        "components": {

            "rule_score": scan.get(
                "rule_score"
            ),

            "ml_score": scan.get(
                "ml_score"
            ),

            "reputation_score": scan.get(
                "reputation_score"
            )

        }

    }


# ============================================================
# JSON REPORT
# ============================================================

def generate_json_report(result):
    """
    Generate a complete JSON report.
    """

    filename = create_filename(
        result.get(
            "url",
            "unknown"
        ),
        "json"
    )

    report = {

        "report_generated": (
            datetime.now().isoformat(
                timespec="seconds"
            )
        ),

        "report_type": (
            "Phishing Detection Analysis"
        ),

        "scan": result

    }

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4,
            default=str
        )

    return str(filename)


# ============================================================
# TEXT REPORT
# ============================================================

def generate_text_report(result):
    """
    Generate a human-readable security report.
    """

    filename = create_filename(
        result.get(
            "url",
            "unknown"
        ),
        "txt"
    )

    url = result.get(
        "url",
        "Unknown"
    )

    score = result.get(
        "score",
        0
    )

    risk = result.get(
        "risk",
        "Unknown"
    )

    severity = result.get(
        "severity",
        "Unknown"
    )

    confidence = result.get(
        "confidence",
        0
    )

    features = result.get(
        "features",
        {}
    )

    dns = result.get(
        "dns",
        {}
    )

    domain = result.get(
        "domain",
        {}
    )

    reputation = result.get(
        "reputation",
        {}
    )

    ml = result.get(
        "ml",
        {}
    )

    components = result.get(
        "components",
        {}
    )

    warnings = result.get(
        "warnings",
        []
    )

    lines = []

    lines.append("=" * 70)
    lines.append("PHISHING DETECTION & ANALYSIS REPORT")
    lines.append("=" * 70)
    lines.append("")

    lines.append(
        f"Report Generated : "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    lines.append(
        f"Analyzed URL     : {url}"
    )

    lines.append("")

    lines.append("-" * 70)
    lines.append("RISK ASSESSMENT")
    lines.append("-" * 70)

    lines.append(
        f"Risk Score       : {score}/100"
    )

    lines.append(
        f"Classification   : {risk}"
    )

    lines.append(
        f"Severity         : {severity}"
    )

    lines.append(
        f"Confidence       : {confidence}%"
    )

    lines.append("")

    lines.append("-" * 70)
    lines.append("SCORE COMPONENTS")
    lines.append("-" * 70)

    lines.append(
        f"Rule-Based Score : "
        f"{components.get('rule_score', 'N/A')}"
    )

    lines.append(
        f"ML Score         : "
        f"{components.get('ml_score', 'N/A')}"
    )

    lines.append(
        f"Reputation Score : "
        f"{components.get('reputation_score', 'N/A')}"
    )

    lines.append("")

    lines.append("-" * 70)
    lines.append("MACHINE LEARNING ANALYSIS")
    lines.append("-" * 70)

    lines.append(
        f"Phishing Probability   : "
        f"{ml.get('phishing_probability', 'N/A')}%"
    )

    lines.append(
        f"Legitimate Probability : "
        f"{ml.get('legitimate_probability', 'N/A')}%"
    )

    lines.append("")

    lines.append("-" * 70)
    lines.append("DOMAIN ANALYSIS")
    lines.append("-" * 70)

    lines.append(
        f"Registered Domain: "
        f"{domain.get('registered_domain', 'N/A')}"
    )

    lines.append("")

    lines.append("-" * 70)
    lines.append("DNS ANALYSIS")
    lines.append("-" * 70)

    lines.append(
        f"DNS Resolved     : "
        f"{dns.get('resolved', False)}"
    )

    lines.append("")

    lines.append("-" * 70)
    lines.append("REPUTATION INTELLIGENCE")
    lines.append("-" * 70)

    lines.append(
        f"Malicious        : "
        f"{reputation.get('malicious', 0)}"
    )

    lines.append(
        f"Suspicious       : "
        f"{reputation.get('suspicious', 0)}"
    )

    lines.append(
        f"Harmless         : "
        f"{reputation.get('harmless', 0)}"
    )

    lines.append("")

    lines.append("-" * 70)
    lines.append("DETECTION INDICATORS")
    lines.append("-" * 70)

    if warnings:

        for index, warning in enumerate(
            warnings,
            start=1
        ):

            if isinstance(
                warning,
                dict
            ):

                severity_text = warning.get(
                    "severity",
                    "unknown"
                ).upper()

                title = warning.get(
                    "title",
                    "Unknown"
                )

                description = warning.get(
                    "description",
                    ""
                )

                lines.append(
                    f"{index}. "
                    f"[{severity_text}] "
                    f"{title}"
                )

                lines.append(
                    f"   {description}"
                )

            else:

                lines.append(
                    f"{index}. {warning}"
                )

            lines.append("")

    else:

        lines.append(
            "No detection indicators were generated."
        )

        lines.append("")

    if features:

        lines.append("-" * 70)
        lines.append("EXTRACTED URL FEATURES")
        lines.append("-" * 70)

        for feature, value in features.items():

            lines.append(
                f"{feature:<35} : {value}"
            )

        lines.append("")

    lines.append("=" * 70)
    lines.append("DISCLAIMER")
    lines.append("=" * 70)

    lines.append(
        "This report is generated by an automated "
        "phishing detection system."
    )

    lines.append(
        "Results should be treated as security intelligence "
        "rather than absolute proof."
    )

    lines.append("=" * 70)

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "\n".join(lines)
        )

    return str(filename)


# ============================================================
# PDF REPORT
# ============================================================

def generate_pdf_report(result):
    """
    Generate a professional PDF security report.
    """

    filename = create_filename(
        result.get(
            "url",
            "unknown"
        ),
        "pdf"
    )

    document = SimpleDocTemplate(
        str(filename),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=20,
        spaceAfter=12
    )

    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=13,
        spaceBefore=10,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["BodyText"],
        fontSize=9,
        leading=13
    )

    small_style = ParagraphStyle(
        "SmallText",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11
    )

    story = []

    # --------------------------------------------------------
    # TITLE
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "PHISHING DETECTION & ANALYSIS REPORT",
            title_style
        )
    )

    story.append(
        Paragraph(
            "Automated Security Analysis",
            body_style
        )
    )

    story.append(
        Spacer(
            1,
            10
        )
    )

    # --------------------------------------------------------
    # BASIC INFORMATION
    # --------------------------------------------------------

    url = result.get(
        "url",
        "Unknown"
    )

    score = result.get(
        "score",
        0
    )

    risk = result.get(
        "risk",
        "Unknown"
    )

    severity = result.get(
        "severity",
        "Unknown"
    )

    confidence = result.get(
        "confidence",
        0
    )

    metadata = [
        [
            Paragraph(
                "<b>Analyzed URL</b>",
                body_style
            ),
            Paragraph(
                str(url),
                body_style
            )
        ],
        [
            Paragraph(
                "<b>Risk Score</b>",
                body_style
            ),
            Paragraph(
                f"{score}/100",
                body_style
            )
        ],
        [
            Paragraph(
                "<b>Classification</b>",
                body_style
            ),
            Paragraph(
                str(risk),
                body_style
            )
        ],
        [
            Paragraph(
                "<b>Severity</b>",
                body_style
            ),
            Paragraph(
                str(severity),
                body_style
            )
        ],
        [
            Paragraph(
                "<b>Confidence</b>",
                body_style
            ),
            Paragraph(
                f"{confidence}%",
                body_style
            )
        ],
        [
            Paragraph(
                "<b>Report Generated</b>",
                body_style
            ),
            Paragraph(
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                body_style
            )
        ]
    ]

    table = Table(
        metadata,
        colWidths=[
            45 * mm,
            125 * mm
        ]
    )

    table.setStyle(
        TableStyle([
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),
            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                6
            ),
            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                6
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                6
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                6
            )
        ])
    )

    story.append(
        table
    )

    # --------------------------------------------------------
    # SCORE COMPONENTS
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "Score Components",
            heading_style
        )
    )

    components = result.get(
        "components",
        {}
    )

    component_data = [
        [
            Paragraph(
                "<b>Component</b>",
                body_style
            ),
            Paragraph(
                "<b>Score</b>",
                body_style
            )
        ],
        [
            Paragraph(
                "Rule-Based Analysis",
                body_style
            ),
            Paragraph(
                str(
                    components.get(
                        "rule_score",
                        "N/A"
                    )
                ),
                body_style
            )
        ],
        [
            Paragraph(
                "Machine Learning",
                body_style
            ),
            Paragraph(
                str(
                    components.get(
                        "ml_score",
                        "N/A"
                    )
                ),
                body_style
            )
        ],
        [
            Paragraph(
                "Reputation Intelligence",
                body_style
            ),
            Paragraph(
                str(
                    components.get(
                        "reputation_score",
                        "N/A"
                    )
                ),
                body_style
            )
        ]
    ]

    component_table = Table(
        component_data,
        colWidths=[
            110 * mm,
            60 * mm
        ]
    )

    component_table.setStyle(
        TableStyle([
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.lightgrey
            ),
            (
                "ALIGN",
                (1, 1),
                (1, -1),
                "CENTER"
            )
        ])
    )

    story.append(
        component_table
    )

    # --------------------------------------------------------
    # MACHINE LEARNING
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "Machine Learning Analysis",
            heading_style
        )
    )

    ml = result.get(
        "ml",
        {}
    )

    ml_data = [
        [
            Paragraph(
                "<b>Metric</b>",
                body_style
            ),
            Paragraph(
                "<b>Value</b>",
                body_style
            )
        ],
        [
            Paragraph(
                "Model Available",
                body_style
            ),
            Paragraph(
                str(
                    ml.get(
                        "model_available",
                        "N/A"
                    )
                ),
                body_style
            )
        ],
        [
            Paragraph(
                "Prediction",
                body_style
            ),
            Paragraph(
                str(
                    ml.get(
                        "prediction_label",
                        "N/A"
                    )
                ),
                body_style
            )
        ],
        [
            Paragraph(
                "Phishing Probability",
                body_style
            ),
            Paragraph(
                f"{ml.get('phishing_probability', 'N/A')}%",
                body_style
            )
        ],
        [
            Paragraph(
                "Legitimate Probability",
                body_style
            ),
            Paragraph(
                f"{ml.get('legitimate_probability', 'N/A')}%",
                body_style
            )
        ]
    ]

    ml_table = Table(
        ml_data,
        colWidths=[
            110 * mm,
            60 * mm
        ]
    )

    ml_table.setStyle(
        TableStyle([
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.lightgrey
            )
        ])
    )

    story.append(
        ml_table
    )

    # --------------------------------------------------------
    # DOMAIN + DNS
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "Domain & DNS Analysis",
            heading_style
        )
    )

    domain = result.get(
        "domain",
        {}
    )

    dns = result.get(
        "dns",
        {}
    )

    domain_dns_data = [
        [
            Paragraph(
                "<b>Field</b>",
                body_style
            ),
            Paragraph(
                "<b>Value</b>",
                body_style
            )
        ],
        [
            Paragraph(
                "Registered Domain",
                body_style
            ),
            Paragraph(
                str(
                    domain.get(
                        "registered_domain",
                        "N/A"
                    )
                ),
                body_style
            )
        ],
        [
            Paragraph(
                "DNS Resolved",
                body_style
            ),
            Paragraph(
                str(
                    dns.get(
                        "resolved",
                        False
                    )
                ),
                body_style
            )
        ],
        [
            Paragraph(
                "Hostname",
                body_style
            ),
            Paragraph(
                str(
                    dns.get(
                        "hostname",
                        "N/A"
                    )
                ),
                body_style
            )
        ]
    ]

    domain_dns_table = Table(
        domain_dns_data,
        colWidths=[
            110 * mm,
            60 * mm
        ]
    )

    domain_dns_table.setStyle(
        TableStyle([
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.lightgrey
            )
        ])
    )

    story.append(
        domain_dns_table
    )

    # --------------------------------------------------------
    # REPUTATION
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "Reputation Intelligence",
            heading_style
        )
    )

    reputation = result.get(
        "reputation",
        {}
    )

    reputation_data = [
        [
            Paragraph(
                "<b>Metric</b>",
                body_style
            ),
            Paragraph(
                "<b>Value</b>",
                body_style
            )
        ],
        [
            Paragraph(
                "Malicious",
                body_style
            ),
            Paragraph(
                str(
                    reputation.get(
                        "malicious",
                        0
                    )
                ),
                body_style
            )
        ],
        [
            Paragraph(
                "Suspicious",
                body_style
            ),
            Paragraph(
                str(
                    reputation.get(
                        "suspicious",
                        0
                    )
                ),
                body_style
            )
        ],
        [
            Paragraph(
                "Harmless",
                body_style
            ),
            Paragraph(
                str(
                    reputation.get(
                        "harmless",
                        0
                    )
                ),
                body_style
            )
        ]
    ]

    reputation_table = Table(
        reputation_data,
        colWidths=[
            110 * mm,
            60 * mm
        ]
    )

    reputation_table.setStyle(
        TableStyle([
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.lightgrey
            )
        ])
    )

    story.append(
        reputation_table
    )

    # --------------------------------------------------------
    # DETECTION INDICATORS
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "Detection Indicators",
            heading_style
        )
    )

    warnings = result.get(
        "warnings",
        []
    )

    if warnings:

        for index, warning in enumerate(
            warnings,
            start=1
        ):

            if isinstance(
                warning,
                dict
            ):

                severity_text = warning.get(
                    "severity",
                    "unknown"
                ).upper()

                title = warning.get(
                    "title",
                    "Unknown"
                )

                description = warning.get(
                    "description",
                    ""
                )

                story.append(
                    Paragraph(
                        f"<b>{index}. "
                        f"[{severity_text}] "
                        f"{title}</b>",
                        body_style
                    )
                )

                story.append(
                    Paragraph(
                        description,
                        small_style
                    )
                )

            else:

                story.append(
                    Paragraph(
                        f"{index}. {warning}",
                        body_style
                    )
                )

            story.append(
                Spacer(
                    1,
                    4
                )
            )

    else:

        story.append(
            Paragraph(
                "No detection indicators were generated.",
                body_style
            )
        )

    # --------------------------------------------------------
    # DISCLAIMER
    # --------------------------------------------------------

    story.append(
        Spacer(
            1,
            12
        )
    )

    story.append(
        Paragraph(
            "Disclaimer",
            heading_style
        )
    )

    story.append(
        Paragraph(
            "This report is generated by an automated "
            "phishing detection system. Results should be "
            "treated as security intelligence rather than "
            "absolute proof. Multiple signals should be "
            "considered when making a final security decision.",
            small_style
        )
    )

    # --------------------------------------------------------
    # BUILD PDF
    # --------------------------------------------------------

    document.build(
        story
    )

    return str(filename)


# ============================================================
# GENERATE ALL REPORTS
# ============================================================

def generate_reports(result):
    """
    Generate JSON, TXT and PDF reports.
    """

    json_report = generate_json_report(
        result
    )

    text_report = generate_text_report(
        result
    )

    pdf_report = generate_pdf_report(
        result
    )

    return {
        "json": json_report,
        "text": text_report,
        "pdf": pdf_report
    }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print(
        "Report generator module loaded successfully."
    )

    print(
        f"Report directory: {REPORT_DIRECTORY}"
    )
from flask import Flask, render_template, request, jsonify
from datetime import datetime

from detector.url_validator import validate_url

from detector.feature_extractor import extract_features
from detector.dns_analyzer import analyze_dns
from detector.domain_analyzer import analyze_domain
from detector.reputation_analyzer import analyze_reputation
from detector.ml_analyzer import analyze_ml
from detector.risk_engine import calculate_risk

from database import (
    initialize_database,
    save_scan,
    get_scan_history,
    get_scan_by_id,
    get_scan_statistics
)

from report_generator import (
    generate_json_report,
    generate_text_report,
    generate_pdf_report,
    database_scan_to_result
)


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(__name__)

initialize_database()


# ============================================================
# HELPER FUNCTION
# ============================================================

def analyze_url(url):
    """
    Run the complete phishing detection pipeline.

    URL validation happens before feature extraction,
    DNS analysis, reputation analysis, or ML analysis.
    """

    # --------------------------------------------------------
    # 1. URL VALIDATION
    # --------------------------------------------------------

    validation = validate_url(url)

    if not validation["valid"]:

        return {
            "success": False,
            "error": validation["error"],
            "validation": validation
        }

    normalized_url = validation["normalized_url"]

    # --------------------------------------------------------
    # 2. FEATURE EXTRACTION
    # --------------------------------------------------------

    features = extract_features(normalized_url)

    # --------------------------------------------------------
    # 3. DNS ANALYSIS
    # --------------------------------------------------------

    dns_result = analyze_dns(normalized_url)

    # --------------------------------------------------------
    # 4. DOMAIN ANALYSIS
    # --------------------------------------------------------

    domain_result = analyze_domain(normalized_url)

    # --------------------------------------------------------
    # 5. REPUTATION ANALYSIS
    # --------------------------------------------------------

    reputation_result = analyze_reputation(normalized_url)

    # --------------------------------------------------------
    # 6. MACHINE LEARNING ANALYSIS
    # --------------------------------------------------------

    ml_result = analyze_ml(normalized_url)

    # --------------------------------------------------------
    # 7. ENSEMBLE RISK ENGINE
    # --------------------------------------------------------

    risk_result = calculate_risk(
        features=features,
        dns_result=dns_result,
        domain_result=domain_result,
        reputation_result=reputation_result,
        ml_result=ml_result
    )

    # --------------------------------------------------------
    # 8. BUILD FINAL RESULT
    # --------------------------------------------------------

    result = {
        "url": normalized_url,

        "score": risk_result.get(
            "score",
            0
        ),

        "risk": risk_result.get(
            "classification",
            "Unknown"
        ),

        "classification": risk_result.get(
            "classification",
            "Unknown"
        ),

        "severity": risk_result.get(
            "severity",
            "Unknown"
        ),

        "confidence": risk_result.get(
            "confidence",
            0
        ),

        "warnings": risk_result.get(
            "indicators",
            []
        ),

        "indicators": risk_result.get(
            "indicators",
            []
        ),

        "features": features,

        "dns": dns_result,

        "domain": domain_result,

        "reputation": reputation_result,

        "ml": ml_result,

        "components": risk_result.get(
            "components",
            {}
        ),

        "timestamp": datetime.now().isoformat()
    }

    return {
        "success": True,
        "result": result
    }


# ============================================================
# HOME PAGE
# ============================================================

@app.route("/", methods=["GET", "POST"])
def index():

    result = None
    error = None

    if request.method == "POST":

        url = request.form.get(
            "url",
            ""
        ).strip()

        try:

            analysis = analyze_url(url)

            if not analysis["success"]:

                error = analysis["error"]

            else:

                result = analysis["result"]

                # Save only valid completed scans.
                save_scan(result)

        except Exception as exc:

            error = f"An error occurred while analyzing the URL: {exc}"

    return render_template(
        "index.html",
        result=result,
        error=error
    )


# ============================================================
# API - SCAN URL
# ============================================================

@app.route(
    "/api/scan",
    methods=["POST"]
)
def api_scan():

    try:

        data = request.get_json(
            silent=True
        ) or {}

        url = data.get(
            "url",
            ""
        ).strip()

        if not url:

            return jsonify({
                "success": False,
                "error": "URL is required."
            }), 400

        analysis = analyze_url(url)

        # ----------------------------------------------------
        # Invalid URL
        # ----------------------------------------------------

        if not analysis["success"]:

            return jsonify({
                "success": False,
                "error": analysis["error"],
                "validation": analysis.get(
                    "validation",
                    {}
                )
            }), 400

        # ----------------------------------------------------
        # Valid URL
        # ----------------------------------------------------

        result = analysis["result"]

        scan_id = save_scan(result)

        result["scan_id"] = scan_id

        return jsonify({
            "success": True,
            "result": result
        })

    except Exception as exc:

        return jsonify({
            "success": False,
            "error": str(exc)
        }), 500


# ============================================================
# API - SCAN HISTORY
# ============================================================

@app.route(
    "/api/history",
    methods=["GET"]
)
def api_history():

    try:

        limit = request.args.get(
            "limit",
            default=50,
            type=int
        )

        limit = max(
            1,
            min(limit, 200)
        )

        history = get_scan_history(
            limit
        )

        return jsonify({
            "success": True,
            "count": len(history),
            "history": history
        })

    except Exception as exc:

        return jsonify({
            "success": False,
            "error": str(exc)
        }), 500


# ============================================================
# API - SINGLE SCAN
# ============================================================

@app.route(
    "/api/history/<int:scan_id>",
    methods=["GET"]
)
def api_scan_details(scan_id):

    try:

        scan = get_scan_by_id(
            scan_id
        )

        if scan is None:

            return jsonify({
                "success": False,
                "error": "Scan not found."
            }), 404

        return jsonify({
            "success": True,
            "scan": scan
        })

    except Exception as exc:

        return jsonify({
            "success": False,
            "error": str(exc)
        }), 500


# ============================================================
# API - STATISTICS
# ============================================================

@app.route(
    "/api/statistics",
    methods=["GET"]
)
def api_statistics():

    try:

        statistics = get_scan_statistics()

        return jsonify({
            "success": True,
            "statistics": statistics
        })

    except Exception as exc:

        return jsonify({
            "success": False,
            "error": str(exc)
        }), 500


# ============================================================
# REPORT - JSON
# ============================================================

@app.route(
    "/api/report/<int:scan_id>/json",
    methods=["GET"]
)
def json_report(scan_id):

    try:

        scan = get_scan_by_id(
            scan_id
        )

        if scan is None:

            return jsonify({
                "success": False,
                "error": "Scan not found."
            }), 404

        result = database_scan_to_result(
            scan
        )

        report_path = generate_json_report(
            result
        )

        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "report_type": "JSON",
            "report_path": report_path
        })

    except Exception as exc:

        return jsonify({
            "success": False,
            "error": str(exc)
        }), 500


# ============================================================
# REPORT - TEXT
# ============================================================

@app.route(
    "/api/report/<int:scan_id>/text",
    methods=["GET"]
)
def text_report(scan_id):

    try:

        scan = get_scan_by_id(
            scan_id
        )

        if scan is None:

            return jsonify({
                "success": False,
                "error": "Scan not found."
            }), 404

        result = database_scan_to_result(
            scan
        )

        report_path = generate_text_report(
            result
        )

        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "report_type": "TXT",
            "report_path": report_path
        })

    except Exception as exc:

        return jsonify({
            "success": False,
            "error": str(exc)
        }), 500


# ============================================================
# REPORT - PDF
# ============================================================

@app.route(
    "/api/report/<int:scan_id>/pdf",
    methods=["GET"]
)
def pdf_report(scan_id):

    try:

        scan = get_scan_by_id(
            scan_id
        )

        if scan is None:

            return jsonify({
                "success": False,
                "error": "Scan not found."
            }), 404

        result = database_scan_to_result(
            scan
        )

        report_path = generate_pdf_report(
            result
        )

        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "report_type": "PDF",
            "report_path": report_path
        })

    except Exception as exc:

        return jsonify({
            "success": False,
            "error": str(exc)
        }), 500


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route(
    "/api/health",
    methods=["GET"]
)
def health_check():

    return jsonify({
        "success": True,
        "application": (
            "Web-Based Phishing Detection "
            "& Analysis Platform"
        ),
        "status": "running"
    })


# ============================================================
# APPLICATION ENTRY POINT
# ============================================================

if __name__ == "__main__":

    print("=" * 70)
    print(
        "Web-Based Phishing Detection "
        "& Analysis Platform"
    )
    print("=" * 70)

    print(
        "Server: http://127.0.0.1:5000"
    )

    print(
        "API Health: "
        "http://127.0.0.1:5000/api/health"
    )

    print(
        "API History: "
        "http://127.0.0.1:5000/api/history"
    )

    print(
        "API Statistics: "
        "http://127.0.0.1:5000/api/statistics"
    )

    print("=" * 70)

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
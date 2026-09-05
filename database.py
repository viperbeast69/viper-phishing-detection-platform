import sqlite3
import json
from datetime import datetime


DATABASE_NAME = "scan_history.db"


def get_connection():
    """
    Create and return a connection to the SQLite database.
    """

    connection = sqlite3.connect(
        DATABASE_NAME
    )

    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():
    """
    Create the scan history table if it does not already exist.
    """

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            url TEXT NOT NULL,

            timestamp TEXT NOT NULL,

            score REAL NOT NULL,

            classification TEXT NOT NULL,

            severity TEXT NOT NULL,

            confidence REAL,

            rule_score REAL,

            ml_score REAL,

            ml_phishing_probability REAL,

            ml_legitimate_probability REAL,

            reputation_score REAL,

            reputation_malicious INTEGER,

            reputation_suspicious INTEGER,

            reputation_harmless INTEGER,

            dns_resolved INTEGER,

            domain TEXT,

            indicators TEXT

        )
        """
    )

    connection.commit()

    connection.close()


def save_scan(result):
    """
    Save a completed URL analysis result.
    """

    connection = get_connection()

    cursor = connection.cursor()

    ml_result = result.get(
        "ml",
        {}
    )

    reputation_result = result.get(
        "reputation",
        {}
    )

    dns_result = result.get(
        "dns",
        {}
    )

    domain_result = result.get(
        "domain",
        {}
    )

    components = result.get(
        "components",
        {}
    )

    indicators = result.get(
        "warnings",
        []
    )

    cursor.execute(
        """
        INSERT INTO scans (

            url,
            timestamp,
            score,
            classification,
            severity,
            confidence,

            rule_score,
            ml_score,

            ml_phishing_probability,
            ml_legitimate_probability,

            reputation_score,

            reputation_malicious,
            reputation_suspicious,
            reputation_harmless,

            dns_resolved,

            domain,

            indicators

        )

        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,

        (

            result.get(
                "url",
                ""
            ),

            datetime.now().isoformat(
                timespec="seconds"
            ),

            result.get(
                "score",
                0
            ),

            result.get(
                "risk",
                "Unknown"
            ),

            result.get(
                "severity",
                "UNKNOWN"
            ),

            result.get(
                "confidence"
            ),

            components.get(
                "rule_score"
            ),

            components.get(
                "ml_score"
            ),

            ml_result.get(
                "phishing_probability"
            ),

            ml_result.get(
                "legitimate_probability"
            ),

            components.get(
                "reputation_score"
            ),

            reputation_result.get(
                "malicious",
                0
            ),

            reputation_result.get(
                "suspicious",
                0
            ),

            reputation_result.get(
                "harmless",
                0
            ),

            int(
                dns_result.get(
                    "resolved",
                    False
                )
            ),

            domain_result.get(
                "registered_domain"
            ),

            json.dumps(
                indicators
            )

        )
    )

    connection.commit()

    scan_id = cursor.lastrowid

    connection.close()

    return scan_id


def get_scan_history(limit=50):
    """
    Retrieve the most recent scans.
    """

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM scans
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,)
    )

    rows = cursor.fetchall()

    connection.close()

    return [
        dict(row)
        for row in rows
    ]


def get_scan_by_id(scan_id):
    """
    Retrieve one scan by its database ID.
    """

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM scans
        WHERE id = ?
        """,
        (scan_id,)
    )

    row = cursor.fetchone()

    connection.close()

    if row is None:
        return None

    result = dict(row)

    try:

        result["indicators"] = json.loads(
            result["indicators"]
        )

    except (
        json.JSONDecodeError,
        TypeError
    ):

        result["indicators"] = []

    return result


def get_scan_statistics():
    """
    Return basic statistics about stored scans.
    """

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT COUNT(*) AS total_scans
        FROM scans
        """
    )

    total_scans = cursor.fetchone()[
        "total_scans"
    ]

    cursor.execute(
        """
        SELECT COUNT(*) AS phishing_scans
        FROM scans
        WHERE classification = 'Likely Phishing'
        """
    )

    phishing_scans = cursor.fetchone()[
        "phishing_scans"
    ]

    cursor.execute(
        """
        SELECT COUNT(*) AS suspicious_scans
        FROM scans
        WHERE classification = 'Suspicious'
        """
    )

    suspicious_scans = cursor.fetchone()[
        "suspicious_scans"
    ]

    cursor.execute(
        """
        SELECT COUNT(*) AS safe_scans
        FROM scans
        WHERE classification = 'Likely Safe'
        """
    )

    safe_scans = cursor.fetchone()[
        "safe_scans"
    ]

    connection.close()

    return {
        "total_scans": total_scans,
        "phishing_scans": phishing_scans,
        "suspicious_scans": suspicious_scans,
        "safe_scans": safe_scans
    }


if __name__ == "__main__":

    initialize_database()

    print(
        "SQLite database initialized successfully."
    )

    print(
        f"Database file: {DATABASE_NAME}"
    )
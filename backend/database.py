import sqlite3
import psycopg2
import psycopg2.extras
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta

# Load environment variables
load_dotenv()

# ============================================================
# SCANNER DATABASE (SQLite - READ ONLY)
# ============================================================
SCANNER_DB_FILE = r"C:\Users\gatsi\github\Automated_Vulnerability_Scanner\databases\vulnerability_management.db"
 
def get_scanner_connection():
    """Connection to the scanner SQLite database (READ ONLY)."""
    conn = sqlite3.connect(SCANNER_DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

# ============================================================
# YOUR PLATFORM DATABASE (PostgreSQL - READ/WRITE)
# ============================================================
PLATFORM_DB_CONFIG = {
    "host": os.getenv("POSTGRES_HOST", "localhost"),
    "port": os.getenv("POSTGRES_PORT", "5432"),
    "dbname": os.getenv("POSTGRES_DB", "cyber_range"),
    "user": os.getenv("POSTGRES_USER", "cyber_range_user"),
    "password": os.getenv("POSTGRES_PASSWORD")
}

def get_platform_connection():
    """Connection to YOUR PostgreSQL platform database (READ/WRITE)."""
    return psycopg2.connect(**PLATFORM_DB_CONFIG)

# ============================================================
# INITIALIZE YOUR PLATFORM DATABASE (PostgreSQL)
# ============================================================
def init_platform_db():
    """Create your platform tables in PostgreSQL."""
    conn = get_platform_connection()
    cursor = conn.cursor()
    
    # Your platform's vulnerability table (COPY of interesting CVEs)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS platform_vulnerabilities (
            id SERIAL PRIMARY KEY,
            cve_id TEXT UNIQUE NOT NULL,
            description TEXT,
            cvss_score REAL,
            asset TEXT,
            severity TEXT,
            is_kev BOOLEAN DEFAULT FALSE,
            interestingness_score INTEGER,
            first_detected TIMESTAMP,
            last_seen TIMESTAMP,
            platform_status TEXT DEFAULT 'pending'  -- pending, active, archived
        )
    ''')
    
    # Your platform's missions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS missions (
            id SERIAL PRIMARY KEY,
            vulnerability_id INTEGER REFERENCES platform_vulnerabilities(id),
            cve_id TEXT,
            red_team_brief TEXT,
            blue_team_brief TEXT,
            status TEXT DEFAULT 'draft',  -- draft, active, completed
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Your platform's AI scoring history
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ai_scores (
            id SERIAL PRIMARY KEY,
            cve_id TEXT,
            score INTEGER,
            scored_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()
    print("[OK] Platform database initialized in PostgreSQL")

# ============================================================
# READ FROM SCANNER DATABASE (SQLite - READ ONLY)
# ============================================================
def fetch_vulnerabilities_from_scanner():
    """Read ONLY NEW vulnerabilities from scanner database (last 24 hours)."""
    conn = get_scanner_connection()
    cursor = conn.cursor()
    
    # Check if 'findings' table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='findings'")
    table_exists = cursor.fetchone()
    
    if not table_exists:
        print("[ERROR] 'findings' table not found in scanner database.")
        print("   Please check your scanner database path or table name.")
        conn.close()
        return []
    
    try:
        # Calculate yesterday's date for filtering
        yesterday = (datetime.now() - timedelta(days=1)).isoformat()
        
        print(f"[INFO] Filtering vulnerabilities from: {yesterday}")
        
        # Query ONLY vulnerabilities seen in the last 24 hours
        cursor.execute('''
            SELECT 
                cve_id, 
                description_of_cve, 
                cvss_score, 
                asset, 
                is_kev,
                severity,
                last_seen,
                first_detected
            FROM findings 
            WHERE cve_id IS NOT NULL
            AND cve_id != ''
            AND last_seen >= ?
            ORDER BY cvss_score DESC
        ''', (yesterday,))
        
        rows = cursor.fetchall()
        conn.close()
        
        if not rows:
            print("[INFO] No NEW vulnerabilities found in the last 24 hours.")
            print("   The scanner may not have run recently, or all findings are old.")
            return []
        
        vulnerabilities = []
        for row in rows:
            vulnerabilities.append({
                "cve_id": row["cve_id"],
                "description": row["description_of_cve"],
                "cvss_score": float(row["cvss_score"]) if row["cvss_score"] else 0,
                "asset": row["asset"],
                "is_kev": bool(row["is_kev"]) if row["is_kev"] is not None else False,
                "severity": row["severity"],
                "last_seen": row["last_seen"],
                "first_detected": row["first_detected"]
            })
        
        print(f"[OK] Found {len(vulnerabilities)} NEW vulnerabilities in the last 24 hours.")
        return vulnerabilities
        
    except sqlite3.OperationalError as e:
        print(f"[ERROR] Error reading from scanner: {e}")
        print("   Please check your scanner database schema.")
        conn.close()
        return []

# ============================================================
# YOUR PLATFORM DATABASE FUNCTIONS (PostgreSQL)
# ============================================================
def save_to_platform(cve_id: str, description: str, cvss_score: float, asset: str, is_kev: bool, interestingness_score: int):
    """Save/refresh a vulnerability in YOUR PostgreSQL platform database.

    IMPORTANT: this is called for every CVE the scanner reports this run,
    not just the ones scoring >=5. That's what keeps archive_old_vulnerabilities()
    from wrongly archiving a CVE that's still live but happened to score
    lower on this particular AI pass.
    """
    conn = get_platform_connection()
    cursor = conn.cursor()
    today = datetime.now()

    cursor.execute("SELECT id, platform_status FROM platform_vulnerabilities WHERE cve_id = %s", (cve_id,))
    existing = cursor.fetchone()

    if existing:
        existing_id, existing_status = existing
        # It was seen again by the scanner -> it's no longer "not seen today".
        # If it had been archived, bring it back to pending. Never touch an
        # 'active' mission that's currently in progress.
        new_status = 'pending' if existing_status == 'archived' else existing_status

        cursor.execute('''
            UPDATE platform_vulnerabilities
            SET last_seen = %s, cvss_score = %s, is_kev = %s, interestingness_score = %s,
                description = %s, asset = %s, platform_status = %s
            WHERE cve_id = %s
        ''', (today, cvss_score, is_kev, interestingness_score, description, asset, new_status, cve_id))
        print(f"[OK] Updated in platform: {cve_id} (last_seen refreshed, status={new_status})")
    else:
        # Only brand-new CVEs are gated by the interestingness score —
        # no point ever surfacing a boring one as a mission candidate.
        if interestingness_score < 5:
            print(f"[SKIP] {cve_id} is new but not interesting (score {interestingness_score}). Not added.")
            conn.close()
            return
        severity = get_severity_label(cvss_score)
        cursor.execute('''
            INSERT INTO platform_vulnerabilities 
            (cve_id, description, cvss_score, asset, severity, is_kev, interestingness_score, first_detected, last_seen, platform_status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ''', (cve_id, description, cvss_score, asset, severity, is_kev, interestingness_score, today, today, 'pending'))
        print(f"[OK] Added to platform: {cve_id}")

    conn.commit()
    conn.close()

def get_severity_label(cvss_score: float) -> str:
    """Convert CVSS score to severity label."""
    if cvss_score >= 9.0:
        return "CRITICAL"
    elif cvss_score >= 7.0:
        return "HIGH"
    elif cvss_score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"

def get_pending_vulnerabilities():
    """Get vulnerabilities pending mission creation from YOUR platform."""
    conn = get_platform_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute("""
        SELECT * FROM platform_vulnerabilities 
        WHERE platform_status = 'pending' 
        ORDER BY interestingness_score DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return rows

def create_mission(vulnerability_id: int, cve_id: str, red_team_brief: str, blue_team_brief: str):
    """Create a mission in YOUR platform database."""
    conn = get_platform_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO missions (vulnerability_id, cve_id, red_team_brief, blue_team_brief, status, created_at)
        VALUES (%s, %s, %s, %s, %s, %s)
    ''', (vulnerability_id, cve_id, red_team_brief, blue_team_brief, 'active', datetime.now()))
    
    # Update vulnerability platform_status to 'active'
    cursor.execute("UPDATE platform_vulnerabilities SET platform_status = 'active' WHERE id = %s", (vulnerability_id,))
    
    conn.commit()
    conn.close()
    print(f"[OK] Mission created for {cve_id}")

def get_all_missions():
    """Get all missions from YOUR platform."""
    conn = get_platform_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute('SELECT * FROM missions ORDER BY created_at DESC')
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_active_missions():
    """Get only active missions from YOUR platform."""
    conn = get_platform_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute('''
        SELECT * FROM missions 
        WHERE status = 'active'
        ORDER BY created_at DESC
    ''')
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_vulnerability_count():
    """Get count of vulnerabilities by status."""
    conn = get_platform_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT 
            platform_status,
            COUNT(*) as count
        FROM platform_vulnerabilities
        GROUP BY platform_status
    """)
    rows = cursor.fetchall()
    conn.close()
    
    result = {}
    for row in rows:
        result[row[0]] = row[1]
    return result

def get_top_interesting_vulnerabilities(limit: int = 10):
    """Get the top N most interesting pending vulnerabilities."""
    conn = get_platform_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute("""
        SELECT * FROM platform_vulnerabilities 
        WHERE platform_status = 'pending' 
        ORDER BY interestingness_score DESC
        LIMIT %s
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows

def archive_old_vulnerabilities():
    """
    Archive ALL vulnerabilities that haven't been seen TODAY.
    Only vulnerabilities with last_seen = TODAY remain active/pending.
    """
    conn = get_platform_connection()
    cursor = conn.cursor()
    
    # Get today's date (without time) for comparison
    today = datetime.now().date()
    
    # Archive everything where last_seen is NOT today
    # This handles both 'pending' and 'active' statuses
    cursor.execute("""
        UPDATE platform_vulnerabilities 
        SET platform_status = 'archived' 
        WHERE platform_status IN ('pending', 'active')
        AND DATE(last_seen) != %s
    """, (today,))
    
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    
    print(f"[OK] Archived {affected} vulnerabilities (last_seen != today)")
    return affected

def get_active_vulnerabilities():
    """Get vulnerabilities that are currently active."""
    conn = get_platform_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute("""
        SELECT * FROM platform_vulnerabilities 
        WHERE platform_status = 'active'
        ORDER BY cvss_score DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_archived_vulnerabilities(min_interestingness: int = 5):
    """Archived vulnerabilities that are still worth showing (score > threshold)."""
    conn = get_platform_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute("""
        SELECT * FROM platform_vulnerabilities
        WHERE platform_status = 'archived'
        AND interestingness_score > %s
        ORDER BY last_seen DESC
    """, (min_interestingness,))
    rows = cursor.fetchall()
    conn.close()
    return rows
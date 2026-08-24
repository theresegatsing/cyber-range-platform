from database import (
    fetch_vulnerabilities_from_scanner,
    save_to_platform,
    init_platform_db,
    get_vulnerability_count,
    archive_old_vulnerabilities,
    get_active_vulnerabilities
)
from ai_helper import score_cve_interestingness
from datetime import datetime, timedelta

# ============================================================
# IMPORT AND PROCESS VULNERABILITIES
# ============================================================

from database import get_platform_vulnerability  # add to existing import line

def import_vulnerabilities():
    print("[INFO] Reading vulnerabilities from scanner database (READ ONLY)...")
    vulnerabilities = fetch_vulnerabilities_from_scanner()

    if not vulnerabilities:
        print("[INFO] No new vulnerabilities found.")
        print("PROGRESS done=0 total=0", flush=True)
        return

    total = len(vulnerabilities)
    print(f"[INFO] Found {total} vulnerabilities in the scan window.")
    print(f"PROGRESS done=0 total={total}", flush=True)

    for i, vuln in enumerate(vulnerabilities, 1):
        cve_id = vuln["cve_id"]
        description = vuln["description"]
        cvss_score = vuln["cvss_score"]
        asset = vuln["asset"]
        is_kev = vuln["is_kev"]

        # emit BEFORE the work, so the UI shows what's currently being processed
        print(f"PROGRESS done={i - 1} total={total} cve={cve_id}", flush=True)

        print(f"\n{'='*50}")
        print(f"Processing: {cve_id}")

        existing = get_platform_vulnerability(cve_id)

        if existing:
            print(f"[SKIP-SCORE] {cve_id} already in platform (score={existing['interestingness_score']}). Just refreshing last_seen.")
            save_to_platform(cve_id, description, cvss_score, asset, is_kev, interestingness_score=None)
        else:
            # cheap heuristic first — only ask the model when it's genuinely ambiguous
            if is_kev and cvss_score >= 9.0:
                interestingness = 10
                print("   Interestingness Score: 10/10 (KEV + critical, no AI needed)")
            elif cvss_score < 4.0 and not is_kev:
                interestingness = 2
                print("   Interestingness Score: 2/10 (low severity, no AI needed)")
            else:
                print("[AI] Scoring (new CVE)...")
                interestingness = score_cve_interestingness(cve_id, description, cvss_score, is_kev)
                print(f"   Interestingness Score: {interestingness}/10")
            save_to_platform(cve_id, description, cvss_score, asset, is_kev, interestingness)

    print(f"PROGRESS done={total} total={total}", flush=True)
    print("\n[OK] Import complete.")
# ============================================================
# RUN FULL PIPELINE
# ============================================================
def run_full_pipeline():
    """Run the entire pipeline."""
    print("=" * 60)
    print("  Cyber Range Pipeline (PostgreSQL + SQLite)")
    print("=" * 60)
    
    # Step 1: Initialize database
    init_platform_db()
    
    # Step 2: Import and score vulnerabilities
    import_vulnerabilities()
    
    # Step 3: Archive OLD vulnerabilities (last_seen != today)
    # THIS MUST RUN AFTER IMPORT so that newly imported ones have today's date
    archived_count = archive_old_vulnerabilities()
    print(f"[OK] Archived {archived_count} vulnerabilities (not seen today)")
    
    print("\n" + "=" * 60)
    print("  [OK] PIPELINE COMPLETE!")
    print("=" * 60)
    
    counts = get_vulnerability_count()
    print(f"\nPlatform Database Summary:")
    print(f"   Pending: {counts.get('pending', 0)}")
    print(f"   Active: {counts.get('active', 0)}")
    print(f"   Archived: {counts.get('archived', 0)}")

if __name__ == "__main__":
    run_full_pipeline()
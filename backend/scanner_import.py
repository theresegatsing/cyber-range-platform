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
def import_vulnerabilities():
    """Import vulnerabilities from scanner, score with AI, save to platform."""
    
    print("[INFO] Reading vulnerabilities from scanner database (READ ONLY)...")
    
    vulnerabilities = fetch_vulnerabilities_from_scanner()
    
    if not vulnerabilities:
        print("[INFO] No new vulnerabilities found.")
        return
    
    print(f"[INFO] Found {len(vulnerabilities)} new vulnerabilities.")
    
    for vuln in vulnerabilities:
        cve_id = vuln["cve_id"]
        description = vuln["description"]
        cvss_score = vuln["cvss_score"]
        asset = vuln["asset"]
        is_kev = vuln["is_kev"]
        
        print(f"\n{'='*50}")
        print(f"Processing: {cve_id}")
        print(f"CVSS Score: {cvss_score}")
        print(f"Asset: {asset}")
        print(f"KEV: {'Yes' if is_kev else 'No'}")
        
        print("[AI] Scoring...")
        interestingness = score_cve_interestingness(cve_id, description, cvss_score, is_kev)
        print(f"   Interestingness Score: {interestingness}/10")
        
        if interestingness >= 5:
            print(f"[OK] {cve_id} is interesting (score {interestingness}). Saving...")
            save_to_platform(cve_id, description, cvss_score, asset, is_kev, interestingness)
        else:
            print(f"[SKIP] {cve_id} is not interesting (score {interestingness}). Skipping.")
    
    print("\n[OK] Import complete.")

# ============================================================
# RUN ARCHIVE (RENAMED TO AVOID RECURSION)
# ============================================================
def run_archive():
    """
    Archive vulnerabilities that haven't been seen today.
    This runs automatically during the import process.
    """
    print("\n[INFO] Checking for vulnerabilities to archive...")
    
    # Archive vulnerabilities not seen today (1 day threshold)
    archived_count = archive_old_vulnerabilities(days_threshold=1)
    
    if archived_count > 0:
        print(f"[OK] Archived {archived_count} vulnerabilities (not seen today)")
    else:
        print("[INFO] No vulnerabilities to archive")
    
    return archived_count

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
    
    # Step 3: Archive old vulnerabilities (RENAMED FUNCTION)
    run_archive()
    
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
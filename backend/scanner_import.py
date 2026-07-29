from database import (
    fetch_vulnerabilities_from_scanner,
    save_to_platform,
    init_platform_db,
    get_vulnerability_count
)
from ai_helper import score_cve_interestingness

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
        
        # AI scores the vulnerability
        print("[AI] Scoring...")
        interestingness = score_cve_interestingness(cve_id, description, cvss_score, is_kev)
        print(f"   Interestingness Score: {interestingness}/10")
        
        # Only keep interesting vulnerabilities (score >= 5)
        if interestingness >= 5:
            print(f"[OK] {cve_id} is interesting (score {interestingness}). Saving...")
            save_to_platform(cve_id, description, cvss_score, asset, is_kev, interestingness)
        else:
            print(f"[SKIP] {cve_id} is not interesting (score {interestingness}). Skipping.")
    
    print("\n[OK] Import complete.")

# ============================================================
# RUN FULL PIPELINE
# ============================================================
def run_full_pipeline():
    """Run the entire pipeline."""
    print("=" * 60)
    print("  Cyber Range Pipeline (PostgreSQL + SQLite)")
    print("=" * 60)
    
    init_platform_db()
    import_vulnerabilities()
    
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
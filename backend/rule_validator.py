import requests
import docker
import time
import subprocess
import json

# Configuration
VULN_APP_URL = "http://localhost:8080/vuln"
CONTAINER_NAME = "custom-vuln-app"

# ----------------------------------------------------------
# The Attack Payload (Same as the learner used)
# ----------------------------------------------------------
def get_attack_payload() -> dict:
    """Return the SQL injection payload that the learner used."""
    return {
        "id": "1 OR 1=1"
    }

# ----------------------------------------------------------
# Run the Attack (Returns True if attack succeeded)
# ----------------------------------------------------------
def run_attack() -> bool:
    """Execute the SQL injection attack and return if it succeeded."""
    try:
        payload = get_attack_payload()
        response = requests.get(VULN_APP_URL, params=payload, timeout=5)
        
        # Attack succeeds if we see both admin and john (all users returned)
        if "admin" in response.text and "john" in response.text:
            return True
        else:
            return False
    except Exception as e:
        print(f"❌ Attack failed: {e}")
        return False

# ----------------------------------------------------------
# Apply a Detection Rule (Simulated – this is where you'd add WAF config)
# ----------------------------------------------------------
def apply_rule(rule: str) -> bool:
    """Apply a detection rule to block the attack."""
    # This is a SIMULATION. In production, you would:
    # - Add the rule to a WAF (e.g., ModSecurity)
    # - Add the rule to a firewall (e.g., iptables)
    # - Add the rule to Splunk as an alert
    
    print(f"🔧 Applying rule: {rule}")
    
    # For now, we simulate by checking if the rule contains keywords
    if "OR 1=1" in rule or "sql" in rule.lower():
        print("✅ Rule looks valid (contains attack pattern)")
        return True
    else:
        print("❌ Rule does not contain attack pattern")
        return False

# ----------------------------------------------------------
# Validate the Rule (The Main Function)
# ----------------------------------------------------------
def validate_rule(rule: str) -> dict:
    """Run the full validation loop: attack, apply rule, attack again."""
    
    # Step 1: Run attack WITHOUT rule (should succeed)
    print("🔴 Test 1: Running attack WITHOUT rule...")
    attack_success = run_attack()
    
    if not attack_success:
        return {
            "status": "error",
            "message": "Attack failed even without a rule. Make sure the vulnerable app is running."
        }
    
    print("✅ Attack succeeded without rule (as expected)")
    
    # Step 2: Apply the rule
    print("🔧 Step 2: Applying detection rule...")
    rule_applied = apply_rule(rule)
    
    if not rule_applied:
        return {
            "status": "failed",
            "message": "Your rule could not be applied. Make sure it contains the correct attack pattern."
        }
    
    # Step 3: Run attack WITH rule (should fail if rule works)
    print("🔴 Test 2: Running attack WITH rule active...")
    attack_blocked = run_attack()
    
    if attack_blocked:
        # Attack succeeded even with rule – rule didn't work
        return {
            "status": "failed",
            "message": "❌ Your rule did NOT block the attack. The attack still succeeded. Review your rule and try again."
        }
    else:
        # Attack was blocked – rule works!
        return {
            "status": "passed",
            "message": "✅ Your rule successfully blocked the attack! Great job!"
        }

# ----------------------------------------------------------
# Validate Without Applying Rule (Just test the attack)
# ----------------------------------------------------------
def test_attack() -> dict:
    """Just test if the attack works."""
    attack_success = run_attack()
    
    if attack_success:
        return {
            "status": "attack_works",
            "message": "The attack works. You can now write a rule to block it."
        }
    else:
        return {
            "status": "attack_failed",
            "message": "The attack failed. Make sure the vulnerable app is running on port 8080."
        }
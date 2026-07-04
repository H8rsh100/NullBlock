# Seed Ledger Script for NullBlock CLI
# Ensure we are in the correct directory
cd "$PSScriptRoot"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "NullBlock Threat Ledger Seeding Script" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# 1. Install dependencies
Write-Host "[*] Checking/Installing dependencies..." -ForegroundColor Yellow
pip install colorama cryptography

# 2. Register Analysts (Generates RSA keys in analysts/ directory)
Write-Host "`n[*] Registering threat analysts..." -ForegroundColor Yellow
python .py register-analyst --name "Alice"
python .py register-analyst --name "Bob"
python .py register-analyst --name "Carol"

# 3. Log threats & malware signatures
Write-Host "`n[*] Logging threat intelligence blocks..." -ForegroundColor Yellow

# Block 1: Threat
python .py add-threat --ip "198.51.100.42" --type "Brute Force SSH" --severity "MEDIUM" --port 22 --protocol "TCP" --reporter "Alice" --notes "Multiple failed SSH login attempts from known malicious IP range"

# Block 2: Malware
python .py add-malware --hash "5f4dcc3b5aa765d61d8327deb882cf9937654321098765432109876543210987" --name "WannaCry" --family "Ransomware" --reporter "Bob" --notes "Ransomware threat targeting MS17-010 vulnerability"

# Block 3: Threat
python .py add-threat --ip "203.0.113.88" --type "SQL Injection" --severity "HIGH" --port 443 --protocol "TCP" --reporter "Carol" --notes "SQLi attempt on billing database endpoints"

# Block 4: Threat
python .py add-threat --ip "185.220.101.5" --type "Log4j Exploit" --severity "CRITICAL" --port 8080 --protocol "TCP" --reporter "Alice" --notes "JNDI injection attempts detected on public facing APIs"

# Block 5: Malware
python .py add-malware --hash "ab56cd78ef1234567890abcdef1234567890abcdef1234567890abcdef123456" --name "Cobalt Strike Beacon" --family "Trojan / Backdoor" --reporter "Carol" --notes "Pre-configured beacon communicating with external C2 servers"

# 4. Verify chain integrity
Write-Host "`n[*] Validating chain integrity..." -ForegroundColor Yellow
python .py validate

Write-Host "`n==========================================" -ForegroundColor Green
Write-Host "Seeding Complete!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green

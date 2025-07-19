#!/bin/bash

# RanDT Installation Script
# Author: Joaquin Villegas
# Description: Automated setup for RanDT Threat Detection System

set -e

echo "RanDT Installation Script"
echo "============================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' 

##### Function Definitions #####
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

##### CHECK SYSTEM REQUIREMENTS #####
if [[ "$OSTYPE" != "darwin"* ]]; then
    log_warning "This script is optimized for macOS. Some features may not work on other systems."
fi

#### CHECK FOR PREREQUISITES #####
log_info "Checking Node.js installation..."
if ! command -v node &> /dev/null; then
    log_error "Node.js is not installed. Please install Node.js first:"
    log_info "Visit: https://nodejs.org/"
    exit 1
else
    NODE_VERSION=$(node --version)
    log_success "Node.js found: $NODE_VERSION"
fi

##### CHECK NPM INSTALLATION #####
log_info "Checking npm installation..."
if ! command -v npm &> /dev/null; then
    log_error "npm is not installed. Please install npm first."
    exit 1
else
    NPM_VERSION=$(npm --version)
    log_success "npm found: $NPM_VERSION"
fi

##### INSTALLING YARA #####
log_info "Checking YARA installation..."
if ! command -v yara &> /dev/null; then
    log_warning "YARA not found. Installing YARA..."
    
    if command -v brew &> /dev/null; then
        brew install yara
        log_success "YARA installed via Homebrew"
    else
        log_error "Homebrew not found. Please install YARA manually:"
        log_info "macOS: Install Homebrew first: /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        log_info "Then run: brew install yara"
        exit 1
    fi
else
    YARA_VERSION=$(yara --version 2>&1 | head -n1)
    log_success "YARA found: $YARA_VERSION"
fi

#### NODE MODULES INSTALLATION #####
log_info "Installing Node.js dependencies..."
npm install
log_success "Node.js dependencies installed"

#### VALIDATE YARA RULES #####
log_info "Validating YARA rules..."
RULES_VALID=true

for rule_file in rules/*.yar; do
    if [ -f "$rule_file" ]; then
        log_info "Validating $rule_file..."
        if yara "$rule_file" /dev/null &> /dev/null; then
            log_success "✓ $rule_file is valid"
        else
            log_error "✗ $rule_file has syntax errors"
            RULES_VALID=false
        fi
    fi
done

if [ "$RULES_VALID" = false ]; then
    log_error "Some YARA rules have syntax errors. Please fix them before running RanDT."
    exit 1
fi

#### DIRECTIRORY SETUP #####
log_info "Creating necessary directories..."
mkdir -p quarantine
mkdir -p logs
mkdir -p test/samples
log_success "Directories created"

##### CONFIGURATION FILE #####
if [[ "$OSTYPE" == "darwin"* ]]; then
    log_info "Would you like to set up RanDT as a system service? (y/n)"
    read -r setup_service
    
    if [[ $setup_service == "y" || $setup_service == "Y" ]]; then
        PLIST_FILE="$HOME/Library/LaunchAgents/com.randt.detector.plist"
        CURRENT_DIR=$(pwd)
        
        cat > "$PLIST_FILE" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.randt.detector</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/node</string>
        <string>$CURRENT_DIR/detector.js</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$CURRENT_DIR</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$CURRENT_DIR/logs/randt.log</string>
    <key>StandardErrorPath</key>
    <string>$CURRENT_DIR/logs/randt.error.log</string>
</dict>
</plist>
EOF
        log_success "LaunchAgent plist created at $PLIST_FILE"
        log_info "To start the service: launchctl load $PLIST_FILE"
        log_info "To stop the service: launchctl unload $PLIST_FILE"
    fi
fi

### INITIAL TEST RUN #####
log_info "Running initial test..."
if npm test &> /dev/null; then
    log_success "Initial test passed"
else
    log_warning "Initial test failed. This might be normal if no test files exist."
fi

### INSTALLATION COMPLETED ###
echo ""
log_success "RanDT installation completed successfully!"
echo ""
log_info "Next steps:"
log_info "1. Review configuration in config.json"
log_info "2. Start RanDT: npm start"
log_info "3. View logs: npm run logs"
log_info "4. Stop RanDT: npm run stop"
echo ""
log_info "For help, run: node detector.js --help"
echo ""

###PROMPT TO START RANDBT NOW###
log_info "Would you like to start RanDT now? (y/n)"
read -r start_now

if [[ $start_now == "y" || $start_now == "Y" ]]; then
    log_info "Starting RanDT..."
    npm start
    log_success "RanDT started successfully!"
fi
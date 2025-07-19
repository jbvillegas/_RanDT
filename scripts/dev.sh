#!/bin/bash

#### COMPREHENSIVE DEVELOPMENT UTILITY SCRIPT FOR RANDBT ####
## THIS SCRIPT PROVIDES A SET OF TOOLS FOR DEVELOPERS TO SET UP, TEST, LINT, PACKAGE, AND PROFILE THE RANDBT THREAT DETECTION SYSTEM ##
# Usage: ./dev.sh [command]

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

### COLORS FOR OUTPUT ###
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

### HELPER FUNCTIONS ###
print_header() {
    echo -e "${BLUE}$1${NC}"
    echo "================================================"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

### COMMAND FUNCTIONS ###
cmd_setup() {
    print_header "Setting up development environment"
    
    ## NODE
    if ! command -v node &> /dev/null; then
        print_error "Node.js not found. Please install Node.js 14+"
        exit 1
    fi
    
    print_success "Node.js found: $(node --version)"
    
    ## YARA
    if ! command -v yara &> /dev/null; then
        print_warning "YARA not found. Installing via Homebrew..."
        if command -v brew &> /dev/null; then
            brew install yara
            print_success "YARA installed"
        else
            print_error "Homebrew not found. Please install YARA manually"
            exit 1
        fi
    else
        print_success "YARA found: $(yara --version)"
    fi
    
    ## DEPENDENCIES
    print_header "Installing Node.js dependencies"
    npm install
    print_success "Dependencies installed"
    
    ## RULES
    print_header "Validating YARA rules"
    npm run validate-rules
    print_success "All rules validated"
    
    print_success "Development environment ready!"
}

cmd_test() {
    print_header "Running comprehensive tests"
    
    echo "1. Validating YARA rules..."
    npm run validate-rules
    
    echo "2. Running Node.js tests..."
    npm test
    
    echo "3. Testing rule detection..."
    npm run test-rules
    
    print_success "All tests passed!"
}

cmd_lint() {
    print_header "Linting codebase"
    
    echo "Checking JavaScript files..."
    npx eslint . --ext .js || print_warning "ESLint issues found"
    
    echo "Checking YARA rules syntax..."
    for rule_file in rules/*.yar; do
        echo "Checking $rule_file..."
        yara -w "$rule_file" /dev/null 2>/dev/null || print_warning "Issues in $rule_file"
    done
    
    print_success "Linting complete"
}

cmd_package() {
    print_header "Creating distribution package"
    
    ## DIST DIRECTORY
    rm -rf dist
    mkdir -p dist/RanDT
    
    ## COPY FILES
    cp -r rules dist/RanDT/
    cp -r src dist/RanDT/
    cp config.json package.json dist/RanDT/
    cp README.md LICENSE scripts/install.sh scripts/test-rules.sh dist/RanDT/
    
    ## CREATE TARBALL 
    cd dist
    tar -czf RanDT-$(date +%Y%m%d).tar.gz RanDT/
    cd ..
    
    print_success "Package created: dist/RanDT-$(date +%Y%m%d).tar.gz"
}

cmd_profile() {
    print_header "Profiling RanDT performance"
    
    echo "Starting performance monitoring..."
    node --prof detector.js &
    DETECTOR_PID=$!
    
    ## TIMER
    sleep 30
    
    ## STOP MONITORING
    kill $DETECTOR_PID
    
    ## PROFILING
    node --prof-process isolate-*.log > profile.txt
    rm isolate-*.log
    
    print_success "Profile saved to profile.txt"
}

cmd_coverage() {
    print_header "Running test coverage analysis"
    
    npx nyc npm test
    npx nyc report --reporter=html
    
    print_success "Coverage report generated in coverage/"
}

cmd_benchmark() {
    print_header "Running performance benchmarks"
    
    ## TEST FILES
    mkdir -p temp_test
    
    ## TEST FILES FOR DIFFERENT SIZES
    echo "Creating test files..."
    echo "This is a small test file" > temp_test/small.txt
    dd if=/dev/zero of=temp_test/medium.bin bs=1024 count=1024 2>/dev/null
    dd if=/dev/zero of=temp_test/large.bin bs=1024 count=10240 2>/dev/null
    
    ## TIME SCANNING
    echo "Benchmarking scan performance..."
    time yara rules/master.yar temp_test/*
    
    ## CLEAN UP
    rm -rf temp_test
    
    print_success "Benchmark complete"
}

cmd_docs() {
    print_header "Generating documentation"
    
    ## JSDOC
    if command -v jsdoc &> /dev/null; then
        jsdoc -c jsdoc.json -d docs/ *.js
        print_success "API documentation generated in docs/"
    else
        print_warning "JSDoc not found, skipping API docs"
    fi
    
    ## RULE DOCUMENTATION
    echo "# YARA Rules Documentation" > RULES.md
    echo "" >> RULES.md
    
    for rule_file in rules/*.yar; do
        echo "## $(basename "$rule_file")" >> RULES.md
        echo "" >> RULES.md
        echo "\`\`\`yara" >> RULES.md
        head -20 "$rule_file" >> RULES.md
        echo "\`\`\`" >> RULES.md
        echo "" >> RULES.md
    done
    
    print_success "Rule documentation generated: RULES.md"
}

cmd_clean() {
    print_header "Cleaning development environment"
    
    echo "Removing temporary files..."
    rm -rf node_modules
    rm -rf dist
    rm -rf coverage
    rm -rf docs
    rm -f profile.txt
    rm -f *.log
    
    print_success "Environment cleaned"
}

## MAIN COMMANDS
case "$1" in
    setup)
        cmd_setup
        ;;
    test)
        cmd_test
        ;;
    lint)
        cmd_lint
        ;;
    package)
        cmd_package
        ;;
    profile)
        cmd_profile
        ;;
    coverage)
        cmd_coverage
        ;;
    benchmark)
        cmd_benchmark
        ;;
    docs)
        cmd_docs
        ;;
    clean)
        cmd_clean
        ;;
    *)
        echo "Usage: $0 {setup|test|lint|package|profile|coverage|benchmark|docs|clean}"
        echo ""
        echo "Commands:"
        echo "  setup     - Set up development environment"
        echo "  test      - Run all tests"
        echo "  lint      - Lint code and rules"
        echo "  package   - Create distribution package"
        echo "  profile   - Profile performance"
        echo "  coverage  - Run test coverage"
        echo "  benchmark - Performance benchmarks"
        echo "  docs      - Generate documentation"
        echo "  clean     - Clean environment"
        exit 1
        ;;
esac

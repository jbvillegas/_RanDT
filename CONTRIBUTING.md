# Contributing to RanDT

Thank you for your interest in contributing to RanDT (Real-time Threat Detection)! This document provides guidelines for contributing to this cybersecurity project.

## Quick Start

1. **Fork** the repository
2. **Clone** your fork: `git clone https://github.com/jbvillegas/_RanDT.git`
3. **Install** dependencies: `npm install && ./install.sh`
4. **Create** a feature branch: `git checkout -b feature/your-feature-name`
5. **Make** your changes
6. **Test** thoroughly: `npm test`
7. **Submit** a pull request

## How to Contribute

### Bug Reports

Before submitting a bug report:
- **Search existing issues** to avoid duplicates
- **Test with the latest version**
- **Include system information** (OS, Node.js version, YARA version)

**Bug Report Template:**
```markdown
**Bug Description:** Brief description of the issue

**Steps to Reproduce:**
1. Step one
2. Step two
3. Step three

**Expected Behavior:** What should happen

**Actual Behavior:** What actually happens

**Environment:**
- OS: macOS/Linux/Windows
- Node.js version: 
- YARA version: 
- RanDT version: 

**Logs:** Include relevant log snippets (sanitize sensitive data)

**Additional Context:** Screenshots, error messages, etc.
```

### Feature Requests

We welcome feature suggestions! Please:
- **Check existing issues** for similar requests
- **Explain the use case** and problem it solves
- **Consider security implications**
- **Propose implementation approach** if possible

### Code Contributions

#### **Types of Contributions Welcome:**

1. **YARA Rules** 
   - New threat detection rules
   - Improvements to existing rules
   - Rule performance optimizations
   - False positive reductions

2. **Core Engine** 
   - Performance improvements
   - New monitoring features
   - Cross-platform compatibility
   - Error handling enhancements

3. **User Interface** 
   - CLI improvements
   - Web dashboard features
   - Mobile app components
   - Desktop application features

4. **Documentation** 
   - README improvements
   - Code comments
   - API documentation
   - User guides and tutorials

5. **Testing** 
   - Unit tests
   - Integration tests
   - Performance benchmarks
   - Security test cases

## Security-Specific Guidelines

### **YARA Rule Contributions**

**Rule Quality Standards:**
- **Clear metadata** with author, description, and date
- **Specific conditions** to minimize false positives
- **Performance optimization** (avoid slow regex patterns)
- **Comprehensive testing** with sample files
- **No real malware** in submissions (use test signatures only)

**Example Rule Structure:**
```yara
rule example_threat_detection {
    meta:
        author = "Your Name"
        description = "Detects Example Threat"
        date = "2025-07-15"
        version = "1.0"
        severity = "medium"
        category = "malware"
        
    strings:
        $string1 = "malicious_pattern" nocase
        $string2 = { 48 65 6c 6c 6f }  // "Hello" in hex
        
    condition:
        $string1 and $string2
}
```

**Rule Testing Requirements:**
- Test against known clean files
- Test against target malicious patterns
- Benchmark performance impact
- Document expected behavior

### **Security Research Ethics**

- **Defensive Purpose Only** - Contributions should enhance defensive capabilities
- **Responsible Disclosure** - Report vulnerabilities privately first
- **Legal Compliance** - Ensure all contributions comply with applicable laws
- **No Harmful Content** - Do not include actual malware, exploits, or illegal content
- **Privacy Respect** - Consider privacy implications of monitoring features

### **Sensitive Data Handling**

When contributing:
- **Sanitize logs** and examples of personal information
- **Use test data** instead of real system information
- **Respect user privacy** in feature implementations
- **Follow data protection** best practices (GDPR, CCPA, etc.)

## Development Setup

### **Prerequisites**
```bash
# System requirements
- macOS 10.15+ (primary), Linux, or Windows
- Node.js 14.0.0+
- YARA 4.0.0+
- Git

# Install dependencies
brew install yara node
npm install -g npm@latest
```

### **Development Environment**
```bash
# Clone and setup
git clone https://github.com/jbvillegas/_RanDT.git
cd _RanDT
npm install
./install.sh

# Development commands
./dev.sh setup    # Complete development setup
./dev.sh test     # Run all tests
./dev.sh lint     # Code quality checks
./dev.sh docs     # Generate documentation
```

### **Project Structure**
```
RanDT/
├── cli.js              # Command-line interface
├── detector.js         # Core detection engine
├── server.js           # Web server (future)
├── config.json         # Configuration
├── package.json        # Dependencies
├── rules/              # YARA detection rules
│   ├── master.yar      # Main rules file
│   ├── phishing.yar    # Email/web threats
│   ├── malware.yar     # Malware detection
│   ├── documents.yar   # Document analysis
│   ├── privacy.yar     # Data theft detection
│   └── network.yar     # Network threats
├── tests/              # Test files
├── docs/               # Documentation
└── public/             # Web interface (future)
```

## Testing Requirements

### **Before Submitting**
```bash
# Run full test suite
npm test

# Validate YARA rules
npm run validate-rules

# Test rule detection
npm run test-rules

# Check code quality
./dev.sh lint

# Performance benchmarks
./dev.sh benchmark
```

### **Test Coverage Requirements**
- **Unit tests** for new functions
- **Integration tests** for new features
- **YARA rule tests** for detection rules
- **Performance tests** for monitoring code
- **Security tests** for sensitive operations

### **Test Categories**

1. **Functional Tests**
   - Core detection logic
   - File monitoring
   - CLI commands
   - Configuration loading

2. **YARA Rule Tests**
   - True positive detection
   - False positive prevention
   - Performance benchmarks
   - Edge case handling

3. **Security Tests**
   - Input validation
   - Path traversal prevention
   - Access control
   - Data sanitization

4. **Performance Tests**
   - Memory usage
   - CPU utilization
   - File scanning speed
   - Concurrent operations

## Code Standards

### **JavaScript Style Guide**
- **ES6+** syntax preferred
- **2 spaces** for indentation
- **Semicolons** required
- **camelCase** for variables and functions
- **PascalCase** for classes
- **UPPER_CASE** for constants

### **Code Quality**
```javascript
// Good: Clear, documented, error-handled
async function scanFile(filePath) {
    try {
        // Validate input
        if (!filePath || typeof filePath !== 'string') {
            throw new Error('Invalid file path');
        }
        
        // Implementation with error handling
        const result = await yaraEngine.scan(filePath);
        return result;
        
    } catch (error) {
        logger.error(`Scan failed for ${filePath}: ${error.message}`);
        throw error;
    }
}
```

### **Documentation Standards**
- **JSDoc** comments for functions
- **Inline comments** for complex logic
- **README updates** for new features
- **API documentation** for public methods

### **Commit Message Format**
```
type(scope): description

Types: feat, fix, docs, style, refactor, test, chore
Scope: cli, detector, rules, docs, tests

Examples:
feat(rules): add ransomware detection rule
fix(detector): resolve memory leak in file monitoring
docs(readme): update installation instructions
test(rules): add phishing detection test cases
```

## Pull Request Process

### **Before Submitting**
- [ ] **Branch naming**: `feature/description`, `fix/description`, `docs/description`
- [ ] **Code quality**: Passes linting and formatting
- [ ] **Tests**: All tests pass, new tests added for new features
- [ ] **Documentation**: Updated for new features/changes
- [ ] **Security**: No security vulnerabilities introduced
- [ ] **Performance**: No significant performance degradation

### **Pull Request Template**
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Security enhancement

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] YARA rules validated
- [ ] Manual testing completed

## Security Considerations
- [ ] No sensitive data exposed
- [ ] Input validation implemented
- [ ] Security implications considered
- [ ] No new attack vectors introduced

## Performance Impact
- [ ] Performance tested
- [ ] Memory usage checked
- [ ] No significant performance degradation

## Documentation
- [ ] Code comments added/updated
- [ ] README updated (if needed)
- [ ] API documentation updated (if needed)

## Breaking Changes
List any breaking changes and migration steps
```

### **Review Process**
1. **Automated checks** must pass (tests, linting, security scans)
2. **Code review** by maintainers
3. **Security review** for security-related changes
4. **Performance review** for core engine changes
5. **Documentation review** for user-facing changes

## Getting Help

### **Communication Channels**
- **GitHub Issues** - Bug reports and feature requests
- **GitHub Discussions** - General questions and ideas
- **Security Issues** - Email security@randt.project (private)

### **Development Questions**
- **Code questions** - Open a GitHub discussion
- **YARA rule help** - Check YARA documentation or ask in issues
- **Performance questions** - Include benchmarks in your question

### **Response Times**
- **Bug reports** - Within 48 hours
- **Feature requests** - Within 1 week
- **Pull requests** - Within 1 week
- **Security issues** - Within 24 hours

## Recognition

Contributors are recognized in:
- **README.md** contributors section
- **Release notes** for significant contributions
- **Hall of Fame** for exceptional contributions

### **Contribution Types**
- **Bug fixes**
- **New features**
- **Documentation**
- **Security improvements**
- **Performance optimizations**
- **Testing enhancements**
- **UI/UX improvements**

## Legal

### **License Agreement**
By contributing, you agree that your contributions will be licensed under the RanDT License.

### **Copyright**
- **Retain attribution** for significant contributions
- **Respect existing copyrights**
- **Use only open-source dependencies**

### **Security Disclaimer**
- **Educational/Defensive Use** - Contributions should support defensive cybersecurity
- **No Liability** - Contributors not liable for misuse of the software
- **Compliance** - Ensure contributions comply with applicable laws

---

## Thank You!

Your contributions help make the internet a safer place. Whether it's a bug fix, new feature, documentation improvement, or security enhancement, every contribution matters.

**Happy coding, and stay secure!**

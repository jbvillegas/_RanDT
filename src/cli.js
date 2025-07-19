#!/usr/bin/env node

const { Command } = require('commander');
const chalk = require('chalk');
const figlet = require('figlet');
const fs = require('fs');
const path = require('path');
const { exec, spawn } = require('child_process');

const program = new Command();

// Display banner
function displayBanner() {
    console.log(chalk.cyan(figlet.textSync('RanDT', { horizontalLayout: 'full' })));
    console.log(chalk.yellow('Real-time Threat Detection System'));
    console.log(chalk.gray('Author: Joaquin Villegas\n'));
}

// Check system requirements
function checkRequirements() {
    return new Promise((resolve, reject) => {
        exec('yara --version', (error, stdout) => {
            if (error) {
                console.log(chalk.red('✗ YARA not found'));
                console.log(chalk.yellow('Install with: brew install yara'));
                reject(new Error('YARA not installed'));
            } else {
                console.log(chalk.green(`✓ YARA found: ${stdout.trim()}`));
                resolve();
            }
        });
    });
}

// Start detector
async function startDetector(options) {
    try {
        await checkRequirements();
        
        console.log(chalk.blue('Starting RanDT detector...'));
        
        const args = [];
        if (options.config) args.push('--config', options.config);
        if (options.daemon) args.push('--daemon');
        if (options.verbose) args.push('--verbose');
        
        const detector = spawn('node', ['src/detector.js', ...args], {
            stdio: options.daemon ? 'ignore' : 'inherit',
            detached: options.daemon
        });
        
        if (options.daemon) {
            detector.unref();
            console.log(chalk.green(`✓ RanDT started as daemon (PID: ${detector.pid})`));
        }
        
    } catch (error) {
        console.log(chalk.red(`Error: ${error.message}`));
        process.exit(1);
    }
}

// Stop detector
function stopDetector() {
    exec('pkill -f "node src/detector.js"', (error, stdout, stderr) => {
        if (error) {
            console.log(chalk.yellow('RanDT is not running or could not be stopped'));
        } else {
            console.log(chalk.green('✓ RanDT stopped'));
        }
    });
}

// Check status
function checkStatus() {
    exec('pgrep -f "node src/detector.js"', (error, stdout) => {
        if (error) {
            console.log(chalk.yellow('RanDT is not running'));
        } else {
            const pids = stdout.trim().split('\n');
            console.log(chalk.green(`✓ RanDT is running (PID: ${pids.join(', ')})`));
        }
    });
}

// Validate rules
function validateRules() {
    console.log(chalk.blue('Validating YARA rules...'));
    
    const rulesDir = './rules';
    const ruleFiles = fs.readdirSync(rulesDir).filter(file => file.endsWith('.yar'));
    
    let valid = 0;
    let invalid = 0;
    
    ruleFiles.forEach(file => {
        const rulePath = path.join(rulesDir, file);
        exec(`yara ${rulePath} /dev/null`, (error) => {
            if (error) {
                console.log(chalk.red(`✗ ${file}: ${error.message}`));
                invalid++;
            } else {
                console.log(chalk.green(`✓ ${file}`));
                valid++;
            }
            
            if (valid + invalid === ruleFiles.length) {
                console.log(chalk.blue(`\nValidation complete: ${valid} valid, ${invalid} invalid`));
            }
        });
    });
}

// Test rules
function testRules() {
    console.log(chalk.blue('Running rule tests...'));
    
    const testScript = './test-rules.sh';
    if (!fs.existsSync(testScript)) {
        console.log(chalk.red('Test script not found'));
        return;
    }
    
    const test = spawn('bash', [testScript], { stdio: 'inherit' });
    
    test.on('close', (code) => {
        if (code === 0) {
            console.log(chalk.green('✓ All tests completed'));
        } else {
            console.log(chalk.red('✗ Some tests failed'));
        }
    });
}

// Show logs
function showLogs(options) {
    const logFile = options.file || './detection.log';
    
    if (!fs.existsSync(logFile)) {
        console.log(chalk.yellow(`Log file not found: ${logFile}`));
        return;
    }
    
    const args = ['-f'];
    if (options.lines) args.push('-n', options.lines);
    args.push(logFile);
    
    const tail = spawn('tail', args, { stdio: 'inherit' });
    
    console.log(chalk.blue(`📄 Showing logs from: ${logFile}`));
    console.log(chalk.gray('Press Ctrl+C to exit\n'));
}

// Generate report
function generateReport() {
    console.log(chalk.blue('Generating threat report...'));
    
    const logFile = './detection.log';
    if (!fs.existsSync(logFile)) {
        console.log(chalk.yellow('No log file found'));
        return;
    }
    
    const logs = fs.readFileSync(logFile, 'utf8');
    const lines = logs.split('\n');
    
    let stats = {
        total: 0,
        threats: 0,
        clean: 0,
        errors: 0
    };
    
    let threatTypes = {};
    
    lines.forEach(line => {
        if (line.includes('[INFO]') && line.includes('Scanning file:')) {
            stats.total++;
        } else if (line.includes('[ALERT]') && line.includes('THREAT DETECTED')) {
            stats.threats++;
            // Extract threat type from rule name
            const match = line.match(/matches.*?"([^"]+)"/);
            if (match) {
                const threatType = match[1];
                threatTypes[threatType] = (threatTypes[threatType] || 0) + 1;
            }
        } else if (line.includes('[INFO]') && line.includes('File clean:')) {
            stats.clean++;
        } else if (line.includes('[ERROR]')) {
            stats.errors++;
        }
    });
    
    console.log(chalk.green('\nThreat Detection Report'));
    console.log(chalk.gray('========================\n'));
    console.log(`Total files scanned: ${chalk.cyan(stats.total)}`);
    console.log(`Threats detected: ${chalk.red(stats.threats)}`);
    console.log(`Clean files: ${chalk.green(stats.clean)}`);
    console.log(`Errors: ${chalk.yellow(stats.errors)}\n`);
    
    if (Object.keys(threatTypes).length > 0) {
        console.log(chalk.yellow('Threat Types:'));
        Object.entries(threatTypes).forEach(([type, count]) => {
            console.log(`  ${type}: ${count}`);
        });
    }
}

// Setup CLI commands
program
    .name('randt')
    .description('RanDT - Real-time Threat Detection System')
    .version('1.0.0')
    .hook('preAction', () => {
        if (program.args[0] !== 'help') {
            displayBanner();
        }
    });

program
    .command('start')
    .description('Start the threat detector')
    .option('-c, --config <file>', 'configuration file')
    .option('-d, --daemon', 'run as daemon')
    .option('-v, --verbose', 'verbose output')
    .action(startDetector);

program
    .command('stop')
    .description('Stop the threat detector')
    .action(stopDetector);

program
    .command('status')
    .description('Check detector status')
    .action(checkStatus);

program
    .command('validate')
    .description('Validate YARA rules')
    .action(validateRules);

program
    .command('test')
    .description('Run rule tests')
    .action(testRules);

program
    .command('logs')
    .description('Show live logs')
    .option('-f, --file <file>', 'log file path')
    .option('-n, --lines <number>', 'number of lines to show')
    .action(showLogs);

program
    .command('report')
    .description('Generate threat detection report')
    .action(generateReport);

program
    .command('install')
    .description('Run installation script')
    .action(() => {
        const install = spawn('bash', ['./install.sh'], { stdio: 'inherit' });
    });

// Parse command line arguments
program.parse();

// Show help if no command provided
if (!process.argv.slice(2).length) {
    displayBanner();
    program.outputHelp();
}

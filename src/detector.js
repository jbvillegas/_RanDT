const chokidar = require('chokidar');
const fs = require('fs');
const path = require('path');
const { exec, spawn } = require('child_process');
const os = require('os');

// Configuration
const CONFIG = {
    RULES_DIR: path.join(__dirname, 'rules'),
    MASTER_RULES: path.join(__dirname, '..', 'rules', 'master.yar'),
    MAX_FILE_SIZE: 100 * 1024 * 1024, // 100MB
    QUARANTINE_DIR: path.join(__dirname, '..', 'quarantine'),
    LOG_FILE: path.join(__dirname, '..', 'logs', 'detection.log'),
    SCAN_TIMEOUT: 30000, // 30 seconds
};

// macOS-specific paths
const homeDir = os.homedir();
const WATCH_PATHS = [
    path.join(homeDir, 'Documents'),
    path.join(homeDir, 'Desktop'),
    path.join(homeDir, 'Downloads')
];

// Supported file extensions for scanning
const SCAN_EXTENSIONS = new Set([
    '.exe', '.dll', '.bat', '.cmd', '.scr', '.com', '.pif',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.rtf', '.zip', '.rar', '.7z', '.tar', '.gz',
    '.js', '.vbs', '.ps1', '.jar', '.app', '.dmg',
    '.eml', '.msg', '.txt', '.html', '.htm', '.py', '.sh'
]);

// Statistics tracking
const stats = {
    filesScanned: 0,
    threatsDetected: 0,
    filesQuarantined: 0,
    errors: 0,
    startTime: new Date()
};

// Logging function with timestamps and levels
function log(level, message, data = null) {
    const timestamp = new Date().toISOString();
    const logEntry = `[${timestamp}] [${level.toUpperCase()}] ${message}`;
    
    console.log(logEntry);
    
    // Also log to file
    try {
        // Create logs directory if it doesn't exist
        const logDir = path.dirname(CONFIG.LOG_FILE);
        if (!fs.existsSync(logDir)) {
            fs.mkdirSync(logDir, { recursive: true });
        }
        
        const fullLogEntry = data ? 
            `${logEntry}\nData: ${JSON.stringify(data, null, 2)}\n` : 
            `${logEntry}\n`;
        fs.appendFileSync(CONFIG.LOG_FILE, fullLogEntry);
    } catch (err) {
        console.error('Failed to write to log file:', err.message);
    }
}

// Function to check if file should be scanned
function shouldScanFile(filePath) {
    try {
        const ext = path.extname(filePath).toLowerCase();
        const fileName = path.basename(filePath).toLowerCase();
        
        // Check extension
        if (ext && !SCAN_EXTENSIONS.has(ext)) {
            return false;
        }
        
        // Skip certain system files
        const skipPatterns = [
            /^\./, // Hidden files
            /^~/, // Temporary files
            /\.tmp$/i,
            /\.temp$/i,
            /^Thumbs\.db$/i,
            /^\.DS_Store$/i
        ];
        
        return !skipPatterns.some(pattern => pattern.test(fileName));
    } catch (err) {
        log('error', `Error checking file ${filePath}: ${err.message}`);
        return false;
    }
}

// Function to scan file using command-line YARA
function scanWithYaraCommand(filePath, rulesPath) {
    return new Promise((resolve, reject) => {
        const yaraCmd = spawn('yara', [
            '-r',           // Recursive
            '-s',           // Print matching strings
            '-m',           // Print metadata
            '-g',           // Print tags
            rulesPath, 
            filePath
        ], {
            stdio: 'pipe',
            timeout: CONFIG.SCAN_TIMEOUT
        });
        
        let output = '';
        let errorOutput = '';
        
        yaraCmd.stdout.on('data', (data) => {
            output += data.toString();
        });
        
        yaraCmd.stderr.on('data', (data) => {
            errorOutput += data.toString();
        });
        
        yaraCmd.on('close', (code) => {
            if (code === 0) {
                const matches = output.trim().split('\n').filter(line => line.length > 0);
                resolve(matches);
            } else if (code === 1) {
                // No matches found (normal)
                resolve([]);
            } else {
                reject(new Error(`YARA command failed with code ${code}: ${errorOutput}`));
            }
        });
        
        yaraCmd.on('error', (err) => {
            reject(new Error(`YARA command error: ${err.message}`));
        });
        
        // Handle timeout
        setTimeout(() => {
            yaraCmd.kill('SIGTERM');
            reject(new Error('YARA scan timeout'));
        }, CONFIG.SCAN_TIMEOUT);
    });
}

// Function to quarantine suspicious files
function quarantineFile(filePath) {
    try {
        // Create quarantine directory if it doesn't exist
        if (!fs.existsSync(CONFIG.QUARANTINE_DIR)) {
            fs.mkdirSync(CONFIG.QUARANTINE_DIR, { recursive: true });
        }
        
        const fileName = path.basename(filePath);
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const quarantinePath = path.join(CONFIG.QUARANTINE_DIR, `${timestamp}_${fileName}`);
        
        // Move file to quarantine
        fs.renameSync(filePath, quarantinePath);
        
        log('info', `File quarantined: ${quarantinePath}`);
        stats.filesQuarantined++;
        
        return quarantinePath;
    } catch (error) {
        log('error', `Failed to quarantine file ${filePath}: ${error.message}`);
        return null;
    }
}

// Enhanced file scanning function
async function scanFile(filePath) {
    try {
        stats.filesScanned++;
        
        if (!shouldScanFile(filePath)) {
            log('debug', `Skipping file: ${filePath} (not in scan list)`);
            return;
        }
        
        // Check if file exists and is readable
        if (!fs.existsSync(filePath)) {
            log('warn', `File does not exist: ${filePath}`);
            return;
        }
        
        const stats_file = fs.statSync(filePath);
        
        // Skip large files
        if (stats_file.size > CONFIG.MAX_FILE_SIZE) {
            log('warn', `File too large, skipping: ${filePath} (${stats_file.size} bytes)`);
            return;
        }
        
        // Skip empty files
        if (stats_file.size === 0) {
            log('debug', `Empty file, skipping: ${filePath}`);
            return;
        }
        
        log('info', `Scanning file: ${filePath} (${stats_file.size} bytes)`);
        
        // Scan with YARA
        const matches = await scanWithYaraCommand(filePath, CONFIG.MASTER_RULES);
        
        if (matches.length > 0) {
            stats.threatsDetected++;
            
            const threatInfo = {
                file: filePath,
                size: stats_file.size,
                modified: stats_file.mtime,
                matches: matches,
                scanTime: new Date().toISOString()
            };
            
            log('alert', `🚨 THREAT DETECTED in ${filePath}`, threatInfo);
            
            // Optional: Quarantine the file (uncomment to enable)
            // const quarantinePath = quarantineFile(filePath);
            // if (quarantinePath) {
            //     threatInfo.quarantined = quarantinePath;
            // }
            
            // You could also send notifications, update databases, etc.
            
        } else {
            log('info', `✅ File clean: ${path.basename(filePath)}`);
        }
        
    } catch (error) {
        stats.errors++;
        log('error', `Error scanning ${filePath}: ${error.message}`);
    }
}

// Function to display statistics
function displayStats() {
    const uptime = new Date() - stats.startTime;
    const uptimeStr = Math.floor(uptime / 1000 / 60); // minutes
    
    console.log('\n📊 RanDT Statistics:');
    console.log(`Uptime: ${uptimeStr} minutes`);
    console.log(`Files Scanned: ${stats.filesScanned}`);
    console.log(`Threats Detected: ${stats.threatsDetected}`);
    console.log(`Files Quarantined: ${stats.filesQuarantined}`);
    console.log(`Errors: ${stats.errors}`);
    console.log('');
}

// Initialize file watcher
function initializeWatcher() {
    log('info', '🔍 Starting RanDT - Real-time Threat Detector');
    log('info', `Version: 1.0 | Author: Joaquin Villegas`);
    log('info', `Watching directories: ${WATCH_PATHS.join(', ')}`);
    log('info', `Using rules: ${CONFIG.MASTER_RULES}`);
    log('info', `Max file size: ${CONFIG.MAX_FILE_SIZE / 1024 / 1024}MB`);
    
    // Verify rules file exists
    if (!fs.existsSync(CONFIG.MASTER_RULES)) {
        log('error', `Rules file not found: ${CONFIG.MASTER_RULES}`);
        process.exit(1);
    }
    
    // Verify watch paths exist
    WATCH_PATHS.forEach(watchPath => {
        if (!fs.existsSync(watchPath)) {
            log('warn', `Watch path does not exist: ${watchPath}`);
        }
    });
    
    const watcher = chokidar.watch(WATCH_PATHS, {
        ignored: [
            /(^|[\/\\])\../, // ignore dotfiles
            /node_modules/,   // ignore node_modules
            /\.git/,         // ignore git files
            /_RanDT/,        // ignore project directory
            /\.log$/,        // ignore log files
            CONFIG.QUARANTINE_DIR, // ignore quarantine directory
            path.dirname(CONFIG.LOG_FILE) // ignore logs directory
        ],
        persistent: true,
        ignoreInitial: false, // Scan existing files on startup
        awaitWriteFinish: {
            stabilityThreshold: 2000, // Wait 2 seconds after file write
            pollInterval: 100
        },
        depth: 3 // Limit directory depth for performance
    });
    
    watcher
        .on('add', (filePath) => {
            log('debug', `File added: ${filePath}`);
            scanFile(filePath);
        })
        .on('change', (filePath) => {
            log('debug', `File modified: ${filePath}`);
            scanFile(filePath);
        })
        .on('error', (error) => {
            log('error', `Watcher error: ${error.message}`);
            stats.errors++;
        })
        .on('ready', () => {
            log('info', '✅ Initial scan completed. Monitoring for new files...');
            displayStats();
        });
    
    // Display stats every 10 minutes
    setInterval(displayStats, 10 * 60 * 1000);
    
    // Handle graceful shutdown
    process.on('SIGINT', () => {
        log('info', ' Shutting down RanDT...');
        displayStats();
        watcher.close();
        process.exit(0);
    });
    
    process.on('SIGTERM', () => {
        log('info', ' Received SIGTERM, shutting down...');
        displayStats();
        watcher.close();
        process.exit(0);
    });
}

// Check if YARA is installed and start monitoring
exec('yara --version', (error, stdout, stderr) => {
    if (error) {
        log('error', 'YARA not found. Please install YARA:');
        log('info', 'macOS: brew install yara');
        log('info', 'Ubuntu: apt-get install yara');
        log('info', 'Documentation: https://yara.readthedocs.io/');
        process.exit(1);
    } else {
        log('info', `✅ YARA version: ${stdout.trim()}`);
        initializeWatcher();
    }
}); 
  
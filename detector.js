const chokidar = require('chokidar');
const yara = require('yara');
const { exec } = require('child_process');

yara.initialize((err)=> {
    if (err) {
        console.error('Failed to initialize YARA:', err);
        usePythonYara();
        return;
    }

    const rules = yara.compile('rules.yar'); 

    const watcher = chokidar.watch(['/home/user/Downloads', '/home/user/Desktop']);

    watcher.on('add', (path) => {
        console.log('File added:', path);
        yara.scanFile(path, rules, (err, matches) => {
            if (err) {
                console.error('Error scanning file:', err);
                return;
            }
            if (matches.length > 0) {
                console.log('YARA matches found:', matches);
            }
        });
    });
}); 
  
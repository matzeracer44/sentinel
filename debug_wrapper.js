process.on('uncaughtException', (err) => {
  const fs = require('fs');
  fs.writeFileSync('D:/ALLSENT/Sentinel/crash.log', err.stack || err.message || String(err));
  console.error('CRASH:', err);
  process.exit(1);
});
process.on('unhandledRejection', (err) => {
  const fs = require('fs');
  fs.writeFileSync('D:/ALLSENT/Sentinel/crash.log', 'UNHANDLED REJECTION: ' + String(err && err.stack ? err.stack : err));
  console.error('REJECTION:', err);
  process.exit(1);
});
require('./dist/main/main.js');

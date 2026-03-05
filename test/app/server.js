const express = require('express');
const fs = require('fs');
const { exec } = require('child_process');

const app = express();
const PORT = 3000;

// Middleware
app.use(express.json());

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'Hello from Container IDS monitored container!',
    timestamp: new Date().toISOString(),
    container_id: getContainerID(),
    endpoints: [
      'GET /',
      'GET /health',
      'GET /info',
      'POST /create-file',
      'POST /network-test',
      'POST /process-test'
    ]
  });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Container info
app.get('/info', (req, res) => {
  res.json({
    hostname: require('os').hostname(),
    platform: process.platform,
    arch: process.arch,
    node_version: process.version,
    uptime: process.uptime(),
    memory: process.memoryUsage()
  });
});

// Trigger filesystem events (for testing)
app.post('/create-file', (req, res) => {
  const filename = `/tmp/test-${Date.now()}.txt`;
  const content = req.body.content || 'Test file created by API';
  
  fs.writeFileSync(filename, content);
  console.log(`Created file: ${filename}`);
  
  res.json({
    message: 'File created (this triggers filesystem events)',
    filename: filename,
    size: content.length
  });
});

// Trigger network events (for testing)
app.post('/network-test', (req, res) => {
  const https = require('https');
  const url = req.body.url || 'https://api.github.com';
  
  https.get(url, (response) => {
    console.log(`Network request to ${url} - Status: ${response.statusCode}`);
    res.json({
      message: 'Network request made (this triggers network events)',
      url: url,
      status: response.statusCode
    });
  }).on('error', (err) => {
    res.status(500).json({ error: err.message });
  });
});

// Trigger process events (for testing)
app.post('/process-test', (req, res) => {
  const command = req.body.command || 'echo "Hello from child process"';
  
  exec(command, (error, stdout, stderr) => {
    console.log(`Executed: ${command}`);
    res.json({
      message: 'Process spawned (this triggers process events)',
      command: command,
      stdout: stdout.trim(),
      stderr: stderr.trim()
    });
  });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log('='.repeat(60));
  console.log(`Test API Server running on port ${PORT}`);
  console.log(`Container ID: ${getContainerID()}`);
  console.log('='.repeat(60));
  console.log('Available endpoints:');
  console.log(`  GET  http://localhost:${PORT}/`);
  console.log(`  GET  http://localhost:${PORT}/health`);
  console.log(`  GET  http://localhost:${PORT}/info`);
  console.log(`  POST http://localhost:${PORT}/create-file`);
  console.log(`  POST http://localhost:${PORT}/network-test`);
  console.log(`  POST http://localhost:${PORT}/process-test`);
  console.log('='.repeat(60));
});

// Helper to get container ID
function getContainerID() {
  try {
    const cgroup = fs.readFileSync('/proc/self/cgroup', 'utf8');
    const match = cgroup.match(/docker[/-]([a-f0-9]{64})/);
    return match ? match[1].substring(0, 12) : 'unknown';
  } catch {
    return 'unknown';
  }
}
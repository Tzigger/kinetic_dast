const http = require('http');

const PORT = 3333;
const RATE_LIMIT_RPS = 1;
const BURST_SIZE = 1;

let tokens = BURST_SIZE;
let lastRefill = Date.now();

// Refill tokens
function refillTokens() {
  const now = Date.now();
  const timePassed = (now - lastRefill) / 1000; // seconds
  const newTokens = timePassed * RATE_LIMIT_RPS;
  
  if (newTokens > 0) {
    tokens = Math.min(BURST_SIZE, tokens + newTokens);
    lastRefill = now;
  }
}

const server = http.createServer((req, res) => {
  // Handle CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  refillTokens();

  if (tokens >= 1) {
    tokens -= 1;
    console.log(`[${new Date().toISOString()}] 200 OK - Tokens: ${tokens.toFixed(2)}`);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ message: 'Success', tokens: tokens }));
  } else {
    console.log(`[${new Date().toISOString()}] 429 Too Many Requests - Tokens: ${tokens.toFixed(2)}`);
    res.writeHead(429, { 
      'Content-Type': 'application/json'
      // 'Retry-After': '1' // Commented out to test if browser returns 429
    });
    res.end(JSON.stringify({ error: 'Too Many Requests', retryAfter: 1 }));
  }
});

server.listen(PORT, () => {
  console.log(`Rate Limit Test Server running at http://localhost:${PORT}`);
  console.log(`Limit: ${RATE_LIMIT_RPS} RPS, Burst: ${BURST_SIZE}`);
});

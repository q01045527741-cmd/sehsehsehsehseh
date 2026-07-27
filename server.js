const express = require('express');
const path = require('path');
const { checkDomain, warmup } = require('./checker');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// API endpoint
app.post('/api/check', async (req, res) => {
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ error: 'domain required' });

  const clean = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '').toLowerCase().trim();
  if (!clean) return res.status(400).json({ error: 'invalid domain' });

  try {
    const result = await checkDomain(clean);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Health
app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

// Start
(async () => {
  console.log('[Server] Warming up checker...');
  await warmup();
  app.listen(PORT, () => {
    console.log(`[Server] Running on http://localhost:${PORT}`);
    console.log(`[Server] Open http://localhost:${PORT} in browser`);
  });
})();

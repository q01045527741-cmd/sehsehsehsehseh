const axios = require('axios');
const crypto = require('crypto');
const { execSync } = require('child_process');

// ============================================================
// Domain checker engine — 7 providers
// MetaMask (eth-phishing-detect simulation) + Blockaid (SDK)
// + ChainPatrol + PhishFort + ScamSniffer + CryptoScamDB + WalletGuard
// ============================================================

// ── Optional deps (graceful fallback) ──────────────────────
let PhishingDetector = null;
try { PhishingDetector = require('./lib/detector'); } catch { }
if (!PhishingDetector) try { PhishingDetector = require('eth-phishing-detect/src/detector'); } catch { }

let BlockaidSDK = null;
try {
  const mod = require('@blockaid/client');
  BlockaidSDK = mod.default || mod;
} catch { }

// ── Cache ──────────────────────────────────────────────────
let cache = {
  metamask:         { data: null, lastFetch: 0, lastDiffTs: 0, _lastDiffCheck: 0, detector: null },
  requestBlocklist: { data: null, lastFetch: 0 },
  phishfort:        { data: null, lastFetch: 0 },
  scamsniffer:      { data: null, lastFetch: 0 },
  cryptoscamdb:     { data: null, lastFetch: 0 },
  seal:             { data: null, lastFetch: 0 },
  phantom:          { data: null, lastFetch: 0 },
  rainbow:          { data: null, lastFetch: 0 },  // eth-phishing-detect config.json
};

const CACHE_TTL     = 10 * 60 * 1000;   // 10 min full reload
const DIFF_INTERVAL = 60 * 1000;        // 1 min hot diffs
const MAX_RETRIES   = 3;
const RETRY_BASE_MS = 500;

// ── Blockaid client singleton ──────────────────────────────
let blockaidClient = null;
const BLOCKAID_KEY = process.env.BLOCKAID_API_KEY || '';
if (BLOCKAID_KEY && BlockaidSDK) {
  try {
    blockaidClient = new BlockaidSDK({ apiKey: BLOCKAID_KEY });
    console.log('[Blockaid] SDK initialized with API key');
  } catch (e) {
    console.warn('[Blockaid] SDK init failed:', e.message);
  }
}

// ── Shared constants ────────────────────────────────────────
const CHROME_UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';
const MM_EXT_ORIGIN = 'chrome-extension://nkbihfbeogaeaoehlefnkodbefgpgknn';

// ── Robust JSON fetch (axios first, curl fallback) ──────────
async function robustGetJson(url, timeoutSec = 30) {
  // Try axios first (works on most prod servers)
  try {
    const res = await axios.get(url, {
      timeout: timeoutSec * 1000,
      maxContentLength: 50 * 1024 * 1024,
      maxBodyLength: 50 * 1024 * 1024,
      headers: { 'User-Agent': CHROME_UA || 'DomainBanChecker/2.0' },
    });
    return res.data;
  } catch { /* axios failed, try curl */ }
  // curl fallback (for Cloudflare-blocked envs)
  try {
    const out = execSync(
      `curl -s --connect-timeout 10 --max-time ${timeoutSec} "${url}"`,
      { maxBuffer: 50 * 1024 * 1024, timeout: (timeoutSec + 5) * 1000 }
    );
    return JSON.parse(out.toString());
  } catch {
    return null;
  }
}
// Sync version for non-async contexts
function curlGetJson(url, timeoutSec = 30) {
  try {
    const out = execSync(
      `curl -s --connect-timeout 10 --max-time ${timeoutSec} "${url}"`,
      { maxBuffer: 50 * 1024 * 1024, timeout: (timeoutSec + 5) * 1000 }
    );
    return JSON.parse(out.toString());
  } catch {
    return null;
  }
}

// ── HTTP with retry ────────────────────────────────────────
async function httpGet(url, opts = {}) {
  const timeout = opts.timeout || 10000;
  const retries = opts.retries ?? MAX_RETRIES;
  let lastErr;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await axios.get(url, {
        timeout,
        maxContentLength: 50 * 1024 * 1024,  // 50MB
        maxBodyLength: 50 * 1024 * 1024,
        headers: { 'User-Agent': 'DomainBanChecker/2.0', ...opts.headers },
        ...opts,
      });
      return res;
    } catch (err) {
      lastErr = err;
      const status = err.response?.status;
      if (status && status >= 400 && status < 500 && status !== 429) throw err;
      if (attempt < retries) {
        const delay = RETRY_BASE_MS * Math.pow(2, attempt) + Math.random() * 200;
        await sleep(delay);
      }
    }
  }
  throw lastErr;
}

async function httpPost(url, body, opts = {}) {
  const timeout = opts.timeout || 8000;
  const retries = opts.retries ?? MAX_RETRIES;
  let lastErr;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await axios.post(url, body, {
        timeout,
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'DomainBanChecker/2.0',
          ...opts.headers,
        },
      });
      return res;
    } catch (err) {
      lastErr = err;
      const status = err.response?.status;
      if (status && status >= 400 && status < 500 && status !== 429) throw err;
      if (attempt < retries) {
        const delay = RETRY_BASE_MS * Math.pow(2, attempt) + Math.random() * 200;
        await sleep(delay);
      }
    }
  }
  throw lastErr;
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ── Helpers ────────────────────────────────────────────────
function cleanDomain(input) {
  if (!input) return '';
  let s = input.trim().toLowerCase();
  s = s.replace(/^https?:\/\//, '');
  s = s.replace(/\/.*$/, '');
  s = s.replace(/^www\./, '');
  s = s.replace(/:.*$/, '');            // strip port
  s = s.replace(/[^a-z0-9.\-]/g, '');   // strip junk
  return s;
}

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      dp[i][j] = a[i-1] === b[j-1]
        ? dp[i-1][j-1]
        : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
  return dp[m][n];
}

function matchInSet(domain, set, rawList) {
  const parts = domain.split('.');
  for (let i = 0; i < parts.length - 1; i++) {
    const sub = parts.slice(i).join('.');
    if (set.has(sub)) return sub;
  }
  if (rawList) {
    const root = parts.length > 2 ? parts.slice(-2).join('.') : domain;
    const match = rawList.find(b => b === root || b.endsWith('.' + root));
    if (match) return match;
  }
  return null;
}

function sha256(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

function mmWarningUrl(domain) {
  const href = encodeURIComponent(`https://${domain}/`);
  return `https://metamask.github.io/phishing-warning/v5.1.0/#hostname=${domain}&href=${href}`;
}

// ════════════════════════════════════════════════════════════
// 1. MetaMask — Full Simulation Engine
//    Layer A: eth-phishing-detect (same lib MetaMask uses internally)
//    Layer B: client-side-detection request-blocklist (SHA256 hash match)
//    Layer C: stalelist + hot diffs (107k+ domains)
//    Layer D: fuzzylist Levenshtein
// ════════════════════════════════════════════════════════════

async function getMetaMaskData() {
  const now = Date.now();
  const c = cache.metamask;

  // Full reload
  if (!c.data || now - c.lastFetch >= CACHE_TTL) {
    try {
      // axios first, curl fallback (handles both prod and CF-blocked envs)
      const [staleData, configData] = await Promise.all([
        robustGetJson('https://phishing-detection.api.cx.metamask.io/v1/stalelist', 45),
        robustGetJson('https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/master/src/config.json', 30),
      ]);

      const blocklist = new Set();
      const allowlist = new Set();
      let fuzzylist = [];
      let lastUpdated = null;

      if (staleData) {
        const raw = staleData.data || staleData;
        (raw.blocklist || []).forEach(d => blocklist.add(d.toLowerCase()));
        (raw.allowlist || []).forEach(d => allowlist.add(d.toLowerCase()));
        if (raw.fuzzylist) fuzzylist.push(...raw.fuzzylist);
        if (raw.lastUpdated) lastUpdated = new Date(raw.lastUpdated * 1000).toISOString();
      }

      if (configData) {
        (configData.blacklist || []).forEach(d => blocklist.add(d.toLowerCase()));
        (configData.whitelist || []).forEach(d => allowlist.add(d.toLowerCase()));
        if (configData.fuzzylist) fuzzylist.push(...configData.fuzzylist);
      }

      c.data = {
        blocklist,
        allowlist,
        fuzzylist: [...new Set(fuzzylist.map(f => f.toLowerCase()))],
        lastUpdated: lastUpdated || new Date().toISOString(),
        size: blocklist.size,
      };

      // Build PhishingDetector (same engine MetaMask uses internally)
      if (PhishingDetector) {
        try {
          c.detector = new PhishingDetector([{
            blocklist: [...blocklist],
            allowlist: [...allowlist],
            fuzzylist: c.data.fuzzylist,
            name: 'MetaMask',
            version: 2,
            tolerance: 2,
          }]);
          console.log(`[MetaMask] PhishingDetector initialized (eth-phishing-detect)`);
        } catch (e) {
          console.warn('[MetaMask] PhishingDetector init failed:', e.message);
          c.detector = null;
        }
      }

      console.log(`[MetaMask] Combined blocklist loaded: ${c.data.size} domains`);
      c.lastFetch  = now;
      c.lastDiffTs = Math.floor(now / 1000);
      return c.data;
    } catch {
      return c.data || { blocklist: new Set(), allowlist: new Set(), fuzzylist: [], lastUpdated: null, size: 0 };
    }
  }

  // Hot diffs every DIFF_INTERVAL
  if (c.lastDiffTs && now - c._lastDiffCheck >= DIFF_INTERVAL) {
    c._lastDiffCheck = now;
    try {
      const diffJson = await robustGetJson(`https://phishing-detection.api.cx.metamask.io/v1/diffsSince/${c.lastDiffTs}`, 10);
      const diffs = diffJson?.data || [];
      let added = 0, removed = 0;
      for (const d of diffs) {
        const url = d.url?.toLowerCase();
        if (!url) continue;
        if (d.isRemoval) { c.data.blocklist.delete(url); removed++; }
        else             { c.data.blocklist.add(url);    added++;   }
        if (d.timestamp > c.lastDiffTs) c.lastDiffTs = d.timestamp;
      }
      if (added || removed) {
        c.data.lastUpdated = new Date().toISOString();
        c.data.size = c.data.blocklist.size;
        // Rebuild detector with updated data
        if (PhishingDetector) {
          try {
            c.detector = new PhishingDetector([{
              blocklist: [...c.data.blocklist],
              allowlist: [...c.data.allowlist],
              fuzzylist: c.data.fuzzylist,
              name: 'MetaMask',
              version: 2,
              tolerance: 2,
            }]);
          } catch { }
        }
        console.log(`[MetaMask] Hot diff: +${added} -${removed} (total: ${c.data.size})`);
      }
    } catch { /* silent */ }
  }

  return c.data;
}

// ── Request Blocklist (client-side-detection) ──────────────
async function getRequestBlocklist() {
  const now = Date.now();
  if (cache.requestBlocklist.data && now - cache.requestBlocklist.lastFetch < CACHE_TTL)
    return cache.requestBlocklist.data;

  try {
    const raw = await robustGetJson('https://client-side-detection.api.cx.metamask.io/v1/request-blocklist', 15);
    const hashes = new Set(raw?.recentlyAdded || []);
    const removed = new Set(raw?.recentlyRemoved || []);
    cache.requestBlocklist.data = { hashes, removed };
    cache.requestBlocklist.lastFetch = now;
    console.log(`[MetaMask] Request-blocklist loaded: ${hashes.size} hashes`);
    return cache.requestBlocklist.data;
  } catch (e) {
    console.warn('[MetaMask] Request-blocklist fetch failed:', e.message);
    return cache.requestBlocklist.data || { hashes: new Set(), removed: new Set() };
  }
}

async function checkMetaMask(domain) {
  const results = [];

  try {
    // ── Layer A: eth-phishing-detect (MetaMask internal engine) ──
    await getMetaMaskData();
    const detector = cache.metamask.detector;
    if (detector) {
      try {
        const res = detector.check(domain);
        if (res.result === true) {
          const type = res.type === 'fuzzy' ? 'Fuzzy' : 'Blocklist';
          return {
            flagged: true,
            details: `🔬 PhishingDetector: ${type} match${res.match ? ` (${res.match})` : ''}`,
            engine: 'eth-phishing-detect',
          };
        }
        if (res.type === 'allowlist') {
          return { flagged: false, details: '✅ Allowed (MetaMask whitelist)', engine: 'eth-phishing-detect' };
        }
      } catch { /* fallthrough to manual checks */ }
    }

    // ── Layer B: Request-blocklist SHA256 hash match ──
    try {
      const rbData = await getRequestBlocklist();
      const domainHash = sha256(domain);
      // Also hash parent domains
      const parts = domain.split('.');
      for (let i = 0; i < parts.length - 1; i++) {
        const sub = parts.slice(i).join('.');
        const h = sha256(sub);
        if (rbData.hashes.has(h)) {
          return {
            flagged: true,
            details: `🔐 Client-Side Detection: hash match (${sub})`,
            engine: 'request-blocklist',
          };
        }
      }
    } catch { /* silent */ }

    // ── Layer C: Raw stalelist check (fallback) ──
    const { blocklist, allowlist, fuzzylist } = cache.metamask.data || await getMetaMaskData();
    const parts = domain.split('.');

    for (let i = 0; i < parts.length - 1; i++) {
      const sub = parts.slice(i).join('.');
      if (blocklist.has(sub))
        return {
          flagged: true,
          details: `Blocked: ${sub}`,
          engine: 'stalelist',
        };
    }

    if (allowlist.has(domain))
      return { flagged: false, details: 'Allowed (whitelisted)', engine: 'stalelist' };

    // ── Layer D: Fuzzylist Levenshtein ──
    for (const fz of fuzzylist) {
      const root = parts.length > 2 ? parts.slice(-2).join('.') : domain;
      const rootNoTld = root.split('.')[0];
      if (levenshtein(rootNoTld, fz) <= 1 && rootNoTld !== fz)
        return {
          flagged: true,
          details: `Suspicious (fuzzy: ${fz})`,
          engine: 'fuzzylist',
        };
    }

    // ── Layer E: Online verification via MetaMask Security Alerts API ──
    // Local lists say Clean — double-check with MetaMask's live PPOM backend
    try {
      const txPayload = {
        method: 'eth_sendTransaction',
        params: [{
          from: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
          to: '0x0000000000000000000000000000000000000001',
          data: '0x', value: '0x0', gas: '0x5208',
        }],
        origin: `https://${domain}`,
      };
      const alertHeaders = {
        'Content-Type': 'application/json',
        'User-Agent': CHROME_UA,
        'Origin': MM_EXT_ORIGIN,
        'Accept': 'application/json',
      };
      let ppomResult = null;
      try {
        const res = await axios.post(`${MM_SECURITY_ALERTS}/validate/0x1`, txPayload, {
          headers: alertHeaders, timeout: 10000,
        });
        ppomResult = res.data;
      } catch {
        try {
          const out = execSync(
            `curl -s --connect-timeout 8 --max-time 12 -X POST "${MM_SECURITY_ALERTS}/validate/0x1" ` +
            `-H "Content-Type: application/json" ` +
            `-H "User-Agent: ${CHROME_UA}" ` +
            `-H "Origin: ${MM_EXT_ORIGIN}" ` +
            `-H "Accept: application/json" ` +
            `-d ${JSON.stringify(JSON.stringify(txPayload))}`,
            { timeout: 15000, maxBuffer: 1024 * 1024 }
          );
          ppomResult = JSON.parse(out.toString());
        } catch { /* silent */ }
      }
      if (ppomResult?.result_type === 'Malicious' || ppomResult?.result_type === 'Warning') {
        return {
          flagged: true,
          details: 'Malicious (PPOM)',
          engine: 'security-alerts-api',
        };
      }
    } catch { /* silent */ }

    return { flagged: false, details: 'Clean', engine: detector ? 'eth-phishing-detect' : 'stalelist' };
  } catch (err) {
    return { flagged: false, error: true, details: `Error: ${shortErr(err)}` };
  }
}

// ════════════════════════════════════════════════════════════
// 2. Blockaid (separate provider)
//    Priority: SDK → raw API → MetaMask Security Alerts (free!)
//    MetaMask Security Alerts = Blockaid PPOM backend (no key needed)
// ════════════════════════════════════════════════════════════

const MM_SECURITY_ALERTS = 'https://security-alerts.api.cx.metamask.io';

async function checkBlockaid(domain) {
  // ── Path 1: SDK (if API key provided) ──
  if (blockaidClient) {
    try {
      const res = await blockaidClient.site.scan({ url: `https://${domain}`, metadata: {} });
      if (res.status === 'hit') {
        const isMalicious = res.is_malicious === true;
        const score = res.malicious_score != null ? ` (score: ${res.malicious_score})` : '';
        const attacks = res.attack_types ? Object.keys(res.attack_types).join(', ') : '';
        if (isMalicious) return { flagged: true, details: `Malicious${score}${attacks ? ` [${attacks}]` : ''}`, source: 'sdk' };
        return { flagged: false, details: `Clean${score}`, source: 'sdk' };
      }
      return { flagged: false, details: 'Not in database', source: 'sdk' };
    } catch (err) {
      if (err.status !== 401 && err.status !== 403)
        return { flagged: false, error: true, details: `SDK: ${shortErr(err)}` };
    }
  }

  // ── Path 2: Raw Blockaid API (if key provided, no SDK) ──
  if (BLOCKAID_KEY && !blockaidClient) {
    try {
      const res = await httpPost('https://api.blockaid.io/v0/site/scan',
        { url: `https://${domain}`, metadata: {} },
        { headers: { 'X-API-KEY': BLOCKAID_KEY }, timeout: 6000 });
      const d = res.data;
      if (d?.is_malicious === true) return { flagged: true, details: `Malicious (score: ${d.malicious_score || '?'})`, source: 'api' };
      return { flagged: false, details: d?.status === 'miss' ? 'Not in database' : 'Clean', source: 'api' };
    } catch { /* fall through to free path */ }
  }

  // ── Path 3: MetaMask Security Alerts API (FREE Blockaid!) ──
  const txPayload = {
    method: 'eth_sendTransaction',
    params: [{
      from: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
      to: '0x0000000000000000000000000000000000000001',
      data: '0x', value: '0x0', gas: '0x5208',
    }],
    origin: `https://${domain}`,
  };
  const alertHeaders = {
    'Content-Type': 'application/json',
    'User-Agent': CHROME_UA,
    'Origin': MM_EXT_ORIGIN,
    'Accept': 'application/json',
  };

  // Try axios first (works on most prod servers)
  try {
    const res = await axios.post(`${MM_SECURITY_ALERTS}/validate/0x1`, txPayload, {
      headers: alertHeaders, timeout: 12000,
    });
    const result = res.data;
    if (result.result_type === 'Malicious') {
      return {
        flagged: true,
        details: 'Malicious',
        features: result.features || [],
        source: 'metamask-security-alerts',
      };
    }
    if (result.result_type === 'Warning') {
      return { flagged: true, details: 'Warning', source: 'metamask-security-alerts' };
    }
    return { flagged: false, details: 'Clean', source: 'metamask-security-alerts' };
  } catch {
    // Axios blocked (Cloudflare) — try curl fallback
    try {
      const out = execSync(
        `curl -s --connect-timeout 8 --max-time 12 -X POST "${MM_SECURITY_ALERTS}/validate/0x1" ` +
        `-H "Content-Type: application/json" ` +
        `-H "User-Agent: ${CHROME_UA}" ` +
        `-H "Origin: ${MM_EXT_ORIGIN}" ` +
        `-H "Accept: application/json" ` +
        `-d ${JSON.stringify(JSON.stringify(txPayload))}`,
        { timeout: 15000, maxBuffer: 1024 * 1024 }
      );
      const result = JSON.parse(out.toString());
      if (result.result_type === 'Malicious') {
        return {
          flagged: true,
          details: 'Malicious',
          features: result.features || [],
          source: 'metamask-security-alerts',
        };
      }
      if (result.result_type === 'Warning') {
        return { flagged: true, details: 'Warning', source: 'metamask-security-alerts' };
      }
      return { flagged: false, details: 'Clean', source: 'metamask-security-alerts' };
    } catch (err2) {
      return { flagged: false, error: true, details: `Error: ${shortErr(err2)}` };
    }
  }
}


// ════════════════════════════════════════════════════════════
// 3. ChainPatrol (live REST API)
// ════════════════════════════════════════════════════════════

async function checkChainPatrol(domain) {
  const url = 'https://app.chainpatrol.io/api/v2/asset/check';
  const body = { content: domain };
  const hdrs = {
    'Content-Type': 'application/json',
    'User-Agent': 'Mozilla/5.0 Chrome/126.0.0.0',
    'Origin': 'https://app.chainpatrol.io',
    'Referer': 'https://app.chainpatrol.io/',
  };

  function parseResult(data) {
    if (data.status === 'BLOCKED') {
      const sources = (data.sources || []).map(s => s.source).join(', ');
      return { flagged: true, details: `BLOCKED${sources ? ` (${sources})` : ''}` };
    }
    return { flagged: false, details: `Clean (${data.status || 'OK'})` };
  }

  // Try axios first
  try {
    const res = await axios.post(url, body, { headers: hdrs, timeout: 8000 });
    return parseResult(res.data);
  } catch {
    // Axios failed — try curl fallback
    try {
      const out = execSync(
        `curl -s --connect-timeout 6 --max-time 10 -X POST "${url}" ` +
        `-H "Content-Type: application/json" ` +
        `-H "User-Agent: Mozilla/5.0 Chrome/126.0.0.0" ` +
        `-H "Origin: https://app.chainpatrol.io" ` +
        `-H "Referer: https://app.chainpatrol.io/" ` +
        `-d ${JSON.stringify(JSON.stringify(body))}`,
        { timeout: 12000, maxBuffer: 1024 * 1024 }
      );
      return parseResult(JSON.parse(out.toString()));
    } catch (err2) {
      return { flagged: false, error: true, details: `Error: ${shortErr(err2)}` };
    }
  }
}

// ════════════════════════════════════════════════════════════
// 4. PhishFort (GitHub blacklist)
// ════════════════════════════════════════════════════════════

async function getPhishFortList() {
  const now = Date.now();
  if (cache.phishfort.data && now - cache.phishfort.lastFetch < CACHE_TTL)
    return cache.phishfort.data;
  const url = 'https://raw.githubusercontent.com/phishfort/phishfort-lists/master/blacklists/domains.json';
  let data = await robustGetJson(url, 15);
  if (!data) {
    try {
      const res = await httpGet(url, { timeout: 15000 });
      data = res.data;
    } catch { }
  }
  const rawList = (Array.isArray(data) ? data : []).map(d => d.toLowerCase());
  cache.phishfort.data = { set: new Set(rawList), rawList };
  cache.phishfort.lastFetch = now;
  return cache.phishfort.data;
}

async function checkPhishFort(domain) {
  try {
    const { set, rawList } = await getPhishFortList();
    const hit = matchInSet(domain, set, rawList);
    if (hit) return { flagged: true, details: `Blacklisted: ${hit}` };
    return { flagged: false, details: 'Clean' };
  } catch (err) {
    return { flagged: false, error: true, details: `Error: ${shortErr(err)}` };
  }
}

// ════════════════════════════════════════════════════════════
// 5. ScamSniffer (GitHub database, 349k+)
// ════════════════════════════════════════════════════════════

async function getScamSnifferList() {
  const now = Date.now();
  if (cache.scamsniffer.data && now - cache.scamsniffer.lastFetch < CACHE_TTL)
    return cache.scamsniffer.data;
  const url = 'https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json';
  let data = await robustGetJson(url, 15);
  if (!data) {
    try {
      const res = await httpGet(url, { timeout: 15000 });
      data = res.data;
    } catch { }
  }
  const rawList = (Array.isArray(data) ? data : []).map(d => d.toLowerCase());
  cache.scamsniffer.data = { set: new Set(rawList), rawList };
  cache.scamsniffer.lastFetch = now;
  return cache.scamsniffer.data;
}

async function checkScamSniffer(domain) {
  try {
    const { set, rawList } = await getScamSnifferList();
    const hit = matchInSet(domain, set, rawList);
    if (hit) return { flagged: true, details: `Blacklisted: ${hit}` };
    return { flagged: false, details: 'Clean' };
  } catch (err) {
    return { flagged: false, error: true, details: `Error: ${shortErr(err)}` };
  }
}

// ════════════════════════════════════════════════════════════
// 6. CryptoScamDB (GitHub YAML blacklist, 9.8k+)
// ════════════════════════════════════════════════════════════

async function getCryptoScamDBList() {
  const now = Date.now();
  if (cache.cryptoscamdb.data && now - cache.cryptoscamdb.lastFetch < CACHE_TTL)
    return cache.cryptoscamdb.data;
  const url = 'https://raw.githubusercontent.com/CryptoScamDB/blacklist/master/data/urls.yaml';
  let yaml;
  // Try axios first
  try {
    const res = await axios.get(url, { timeout: 20000, headers: { 'User-Agent': CHROME_UA } });
    yaml = res.data;
  } catch {
    // curl fallback
    try {
      const out = execSync(`curl -s --connect-timeout 10 --max-time 20 "${url}"`, { maxBuffer: 10*1024*1024, timeout: 25000 });
      yaml = out.toString();
    } catch {
      const res2 = await httpGet(url, { timeout: 15000 });
      yaml = res2.data;
    }
  }
  const entries = [];
  const blocks = yaml.split(/^-\s/m).filter(Boolean);

  for (const block of blocks) {
    const urlMatch  = block.match(/url:\s*'?([^'\n]+)'?/);
    const catMatch  = block.match(/category:\s*'?([^'\n]+)'?/);
    if (urlMatch) {
      let domain = urlMatch[1].trim().toLowerCase();
      domain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
      const cat = (catMatch?.[1] || 'unknown').replace(/'/g, '').trim();
      entries.push({ domain, category: cat });
    }
  }

  const domainSet = new Set(entries.map(e => e.domain));
  const catMap = new Map();
  for (const e of entries) catMap.set(e.domain, e.category);

  cache.cryptoscamdb.data = { set: domainSet, catMap, rawList: [...domainSet] };
  cache.cryptoscamdb.lastFetch = now;
  console.log(`[CryptoScamDB] Loaded ${domainSet.size} domains`);
  return cache.cryptoscamdb.data;
}

async function checkCryptoScamDB(domain) {
  try {
    const { set, catMap, rawList } = await getCryptoScamDBList();
    const hit = matchInSet(domain, set, rawList);
    if (hit) {
      const cat = catMap.get(hit) || 'Scam';
      return { flagged: true, details: `${cat}: ${hit}` };
    }
    return { flagged: false, details: 'Clean' };
  } catch (err) {
    return { flagged: false, error: true, details: `Error: ${shortErr(err)}` };
  }
}

// ════════════════════════════════════════════════════════════
// 7. WalletGuard (ConsenSys/MetaMask-acquired)
// ════════════════════════════════════════════════════════════

const WALLETGUARD_API = 'https://7gsdnppspe.us-east-2.awsapprunner.com';

async function checkWalletGuard(domain) {
  try {
    const url = `${WALLETGUARD_API}/scan?url=https://${domain}`;
    const res = await httpGet(url, { timeout: 6000, retries: 2 });
    const d = res.data;
    if (!d || !d.status) return { flagged: false, error: true, details: 'Bad response' };
    if (d.phishing === 'PHISHING' || d.phishingStatus === 'PHISHING') {
      const risk = d.riskFactors?.[0]?.message || 'Phishing';
      return { flagged: true, details: risk };
    }
    return { flagged: false, details: 'Clean' };
  } catch (err) {
    return { flagged: false, error: true, details: `Error: ${shortErr(err)}` };
  }
}

// ════════════════════════════════════════════════════════════
// 8. SEALIntel — Security Alliance blocklist (107k+ domains, public)
// ════════════════════════════════════════════════════════════

async function getSEALList() {
  const now = Date.now();
  if (cache.seal.data && now - cache.seal.lastFetch < CACHE_TTL)
    return cache.seal.data;
  const url = 'https://raw.githubusercontent.com/security-alliance/blocklists/main/domain.txt';
  let raw = '';
  try {
    const res = await axios.get(url, { timeout: 25000, responseType: 'text', headers: { 'User-Agent': CHROME_UA } });
    raw = res.data;
  } catch {
    try { raw = execSync(`curl -s --max-time 25 "${url}"`, { maxBuffer: 20 * 1024 * 1024 }).toString(); } catch { }
  }
  // plain text, one entry per line: IPs and domains mixed
  const lines = raw.split('\n')
    .map(l => l.trim().toLowerCase())
    .filter(l => l && !l.startsWith('#') && l.includes('.') && !/^\d+\.\d+\.\d+\.\d+$/.test(l));
  cache.seal.data = new Set(lines);
  cache.seal.lastFetch = now;
  console.log(`[SEALIntel] Loaded ${cache.seal.data.size} domains`);
  return cache.seal.data;
}

async function checkSEAL(domain) {
  try {
    const set = await getSEALList();
    const parts = domain.split('.');
    for (let i = 0; i < parts.length - 1; i++) {
      const sub = parts.slice(i).join('.');
      if (set.has(sub)) return { flagged: true, details: 'Malicious' };
    }
    return { flagged: false, details: 'Clean' };
  } catch (err) {
    return { flagged: false, error: true, details: `Error: ${shortErr(err)}` };
  }
}

// ════════════════════════════════════════════════════════════
// 9. Phantom Wallet — phantom/blocklist YAML (public GitHub)
// ════════════════════════════════════════════════════════════

async function getPhantomList() {
  const now = Date.now();
  if (cache.phantom.data && now - cache.phantom.lastFetch < CACHE_TTL)
    return cache.phantom.data;
  // branch is master, format: "  - url: domain.com"
  const url = 'https://raw.githubusercontent.com/phantom/blocklist/master/blocklist.yaml';
  let raw = '';
  try {
    const res = await axios.get(url, { timeout: 20000, responseType: 'text', headers: { 'User-Agent': CHROME_UA } });
    raw = res.data;
  } catch {
    try { raw = execSync(`curl -s --max-time 20 "${url}"`, { maxBuffer: 5 * 1024 * 1024 }).toString(); } catch { }
  }
  // YAML: lines like "  - url: domain.com"
  const domains = new Set(
    raw.split('\n')
      .map(l => { const m = l.match(/url:\s*([^\s'",]+)/i); return m ? m[1].toLowerCase() : ''; })
      .filter(l => l && l.includes('.') && !l.startsWith('---'))
  );
  cache.phantom.data = domains;
  cache.phantom.lastFetch = now;
  console.log(`[Phantom] Loaded ${domains.size} domains`);
  return domains;
}

async function checkPhantom(domain) {
  try {
    const set = await getPhantomList();
    const parts = domain.split('.');
    for (let i = 0; i < parts.length - 1; i++) {
      const sub = parts.slice(i).join('.');
      if (set.has(sub)) return { flagged: true, details: 'Malicious' };
    }
    return { flagged: false, details: 'Clean' };
  } catch (err) {
    return { flagged: false, error: true, details: `Error: ${shortErr(err)}` };
  }
}

// ════════════════════════════════════════════════════════════
// 10. PhishDestroy — free REST API (no key)
// ════════════════════════════════════════════════════════════

async function checkPhishDestroy(domain) {
  try {
    const res = await axios.get(`https://api.destroy.tools/v1/check?domain=${encodeURIComponent(domain)}`, {
      timeout: 8000,
      headers: { 'User-Agent': CHROME_UA, 'Accept': 'application/json' },
    });
    const d = res.data;
    if (d?.threat === true) {
      return { flagged: true, details: 'Malicious' };
    }
    return { flagged: false, details: 'Clean' };
  } catch {
    // curl fallback
    try {
      const out = execSync(
        `curl -s --connect-timeout 6 --max-time 10 "https://api.destroy.tools/v1/check?domain=${encodeURIComponent(domain)}" -H "Accept: application/json"`,
        { timeout: 12000, maxBuffer: 512 * 1024 }
      );
      const d = JSON.parse(out.toString());
      if (d?.threat === true) return { flagged: true, details: 'Malicious' };
      return { flagged: false, details: 'Clean' };
    } catch (err2) {
      return { flagged: false, error: true, details: `Error: ${shortErr(err2)}` };
    }
  }
}

// ════════════════════════════════════════════════════════════
// 11. Rabby Wallet — live POST /v1/wallet/check_origin
// ════════════════════════════════════════════════════════════

async function checkRabby(domain) {
  const body = { origin: `https://${domain}`, user_addr: '0x0000000000000000000000000000000000000000' };
  const headers = {
    'Content-Type': 'application/json',
    'User-Agent': CHROME_UA,
  };
  try {
    const res = await axios.post('https://api.rabby.io/v1/wallet/check_origin', body, {
      headers, timeout: 8000,
    });
    const d = res.data;
    if (d?.decision === 'forbidden' || d?.decision === 'danger') {
      return { flagged: true, details: 'Malicious' };
    }
    if (d?.decision === 'warning') {
      return { flagged: true, details: 'Warning' };
    }
    return { flagged: false, details: 'Clean' };
  } catch {
    try {
      const out = execSync(
        `curl -s --connect-timeout 6 --max-time 10 -X POST "https://api.rabby.io/v1/wallet/check_origin" ` +
        `-H "Content-Type: application/json" ` +
        `-H "User-Agent: ${CHROME_UA}" ` +
        `-d ${JSON.stringify(JSON.stringify(body))}`,
        { timeout: 12000, maxBuffer: 512 * 1024 }
      );
      const d = JSON.parse(out.toString());
      if (d?.decision === 'forbidden' || d?.decision === 'danger') return { flagged: true, details: 'Malicious' };
      if (d?.decision === 'warning') return { flagged: true, details: 'Warning' };
      return { flagged: false, details: 'Clean' };
    } catch (err2) {
      return { flagged: false, error: true, details: `Error: ${shortErr(err2)}` };
    }
  }
}

// ════════════════════════════════════════════════════════════
// 12. Rainbow — eth-phishing-detect config.json (what Rainbow uses)
// ════════════════════════════════════════════════════════════

async function getRainbowList() {
  const now = Date.now();
  if (cache.rainbow.data && now - cache.rainbow.lastFetch < CACHE_TTL)
    return cache.rainbow.data;
  const url = 'https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/master/src/config.json';
  let raw = null;
  try {
    const res = await axios.get(url, { timeout: 20000, headers: { 'User-Agent': CHROME_UA } });
    raw = res.data;
  } catch {
    try {
      const out = execSync(`curl -s --max-time 20 "${url}"`, { maxBuffer: 10 * 1024 * 1024 });
      raw = JSON.parse(out.toString());
    } catch { }
  }
  const bl = new Set((raw?.blacklist || []).map(d => d.toLowerCase()));
  cache.rainbow.data = bl;
  cache.rainbow.lastFetch = now;
  console.log(`[Rainbow] Loaded ${bl.size} domains from eth-phishing-detect config`);
  return bl;
}

async function checkRainbow(domain) {
  try {
    const list = await getRainbowList();
    if (!list || list.size === 0) return { flagged: false, error: true, details: 'List unavailable' };
    if (list.has(domain.toLowerCase())) return { flagged: true, details: 'Malicious' };
    return { flagged: false, details: 'Clean' };
  } catch (err) {
    return { flagged: false, error: true, details: `Error: ${shortErr(err)}` };
  }
}

// ════════════════════════════════════════════════════════════
// 13. TrustWallet — GoPlus Security live API (TrustWallet's real security partner)
// ════════════════════════════════════════════════════════════

async function checkTrustWallet(domain) {
  const gpUrl = `https://api.gopluslabs.io/api/v1/phishing_site?url=${encodeURIComponent('https://' + domain)}`;
  try {
    const res = await axios.get(gpUrl, { timeout: 8000, headers: { 'User-Agent': CHROME_UA } });
    const d = res.data;
    if (d?.code !== 1) return { flagged: false, error: true, details: `GoPlus error: ${d?.message}` };
    const isPhishing = d?.result?.phishing_site === 1;
    return { flagged: isPhishing, details: isPhishing ? 'Malicious' : 'Clean' };
  } catch {
    try {
      const out = execSync(
        `curl -s --connect-timeout 6 --max-time 10 "${gpUrl}" -H "User-Agent: ${CHROME_UA}"`,
        { timeout: 12000, maxBuffer: 256 * 1024 }
      );
      const d = JSON.parse(out.toString());
      if (d?.code !== 1) return { flagged: false, error: true, details: 'GoPlus error' };
      const isPhishing = d?.result?.phishing_site === 1;
      return { flagged: isPhishing, details: isPhishing ? 'Malicious' : 'Clean' };
    } catch (err2) {
      return { flagged: false, error: true, details: `Error: ${shortErr(err2)}` };
    }
  }
}

// ════════════════════════════════════════════════════════════
// 14. Coinbase Wallet — Blockaid via Security Alerts API (what Coinbase uses)
// ════════════════════════════════════════════════════════════

async function checkCoinbase(domain) {
  // Coinbase Wallet uses Blockaid for security — same endpoint MetaMask exposes
  const url = `https://client-side-detection.api.cx.metamask.io/v1/site-security-report?url=${encodeURIComponent('https://' + domain)}&domainName=${encodeURIComponent(domain)}&requestId=coinbase`;
  try {
    const res = await axios.get(url, {
      timeout: 10000,
      headers: {
        'Origin': 'chrome-extension://hnfanknocfeofbddgcijnmhnfnkdnaad',
        'User-Agent': CHROME_UA,
      },
    });
    const verdict = res.data?.result_type;
    if (verdict === 'Malicious' || verdict === 'Warning') return { flagged: true, details: verdict };
    return { flagged: false, details: 'Clean' };
  } catch {
    // Fallback to GoPlus (also used by Coinbase for token security)
    try {
      const gpUrl = `https://api.gopluslabs.io/api/v1/phishing_site?url=${encodeURIComponent('https://' + domain)}`;
      const out = execSync(`curl -s --max-time 8 "${gpUrl}"`, { maxBuffer: 256 * 1024 });
      const d = JSON.parse(out.toString());
      if (d?.code === 1) {
        const isPhishing = d?.result?.phishing_site === 1;
        return { flagged: isPhishing, details: isPhishing ? 'Malicious' : 'Clean' };
      }
    } catch { }
    return { flagged: false, error: true, details: 'Unavailable' };
  }
}

// ── Auto-refresh — background update loops ─────────────────
let refreshTimers = [];

async function refreshLists() {
  const t = Date.now();
  const results = await Promise.allSettled([
    getPhishFortList(),
    getScamSnifferList(),
    getCryptoScamDBList(),
    getRequestBlocklist(),
    getSEALList(),
    getPhantomList(),
    getRainbowList(),
  ]);
  const ok = results.filter(r => r.status === 'fulfilled').length;
  const fail = results.filter(r => r.status === 'rejected').length;
  console.log(`[Refresh] Lists: ${ok} ok, ${fail} fail (${((Date.now() - t) / 1000).toFixed(1)}s)`);
}

async function refreshDiffs() {
  cache.metamask._lastDiffCheck = 0;
  await getMetaMaskData();
}

async function warmup() {
  console.log('[Warmup] Preloading all provider caches...');
  const t = Date.now();
  await Promise.allSettled([
    getMetaMaskData(),
    getRequestBlocklist(),
    getPhishFortList(),
    getScamSnifferList(),
    getCryptoScamDBList(),
    getSEALList(),
    getPhantomList(),
    getRainbowList(),
  ]);

  const mmInfo = cache.metamask.data
    ? `${cache.metamask.data.size} domains, detector: ${cache.metamask.detector ? 'YES' : 'NO'}`
    : 'FAILED';
  const rbInfo = cache.requestBlocklist.data
    ? `${cache.requestBlocklist.data.hashes?.size || 0} hashes`
    : 'FAILED';
  const sealInfo    = cache.seal.data    ? `${cache.seal.data.size} domains`    : 'FAILED';
  const phantomInfo = cache.phantom.data ? `${cache.phantom.data.size} domains`  : 'FAILED';
  const rainbowInfo = cache.rainbow.data ? `${cache.rainbow.data.size} domains`  : 'FAILED';

  console.log(`[Warmup] Done in ${((Date.now() - t) / 1000).toFixed(1)}s`);
  console.log(`[Warmup] MetaMask: ${mmInfo}`);
  console.log(`[Warmup] Request-Blocklist: ${rbInfo}`);
  console.log(`[Warmup] SEALIntel: ${sealInfo}`);
  console.log(`[Warmup] Phantom: ${phantomInfo}`);
  console.log(`[Warmup] Rainbow: ${rainbowInfo}`);
  console.log(`[Warmup] Blockaid SDK: ${blockaidClient ? 'ACTIVE' : 'INACTIVE (no API key)'}`);
  console.log(`[Warmup] TrustWallet: GoPlus live API`);
  console.log(`[Warmup] Coinbase: Blockaid Security Alerts`);

  refreshTimers.push(setInterval(() => {
    refreshDiffs().catch(e => console.error('[AutoRefresh] Diffs error:', e.message));
  }, DIFF_INTERVAL));

  refreshTimers.push(setInterval(() => {
    refreshLists().catch(e => console.error('[AutoRefresh] Lists error:', e.message));
  }, CACHE_TTL));

  console.log('[AutoRefresh] Started — diffs every 60s, lists every 10min');
}

function stopRefresh() {
  refreshTimers.forEach(t => clearInterval(t));
  refreshTimers = [];
  console.log('[AutoRefresh] Stopped');
}

// ── Public API ─────────────────────────────────────────────
async function checkDomain(rawDomain) {
  const domain = cleanDomain(rawDomain);
  if (!domain) return null;

  const startTime = Date.now();

  const [
    metamask, blockaid, chainpatrol, phishfort, scamsniffer,
    cryptoscamdb, walletguard, seal, phantom, phishdestroy, rabby,
    rainbow, trustwallet, coinbase,
  ] = await Promise.all([
    checkMetaMask(domain),
    checkBlockaid(domain),
    checkChainPatrol(domain),
    checkPhishFort(domain),
    checkScamSniffer(domain),
    checkCryptoScamDB(domain),
    checkWalletGuard(domain),
    checkSEAL(domain),
    checkPhantom(domain),
    checkPhishDestroy(domain),
    checkRabby(domain),
    checkRainbow(domain),
    checkTrustWallet(domain),
    checkCoinbase(domain),
  ]);

  const providers = {
    metamask, blockaid, chainpatrol, phishfort, scamsniffer,
    cryptoscamdb, walletguard, seal, phantom, phishdestroy, rabby,
    rainbow, trustwallet, coinbase,
  };
  const flaggedProviders = Object.entries(providers).filter(([, p]) => p.flagged).map(([n]) => n);
  const errorProviders   = Object.entries(providers).filter(([, p]) => p.error).map(([n]) => n);

  return {
    domain,
    timestamp: new Date().toISOString(),
    elapsed:   Date.now() - startTime,
    providers,
    flaggedCount:  flaggedProviders.length,
    errorCount:    errorProviders.length,
    totalCount:    Object.keys(providers).length,
    isAnyFlagged:  flaggedProviders.length > 0,
    flaggedProviders,
    errorProviders,
  };
}

function shortErr(err) {
  if (err.code === 'ECONNABORTED') return 'Timeout';
  if (err.code === 'ENOTFOUND')    return 'DNS fail';
  if (err.code === 'ECONNREFUSED') return 'Refused';
  if (err.response?.status)        return `HTTP ${err.response.status}`;
  return (err.message || 'Unknown').substring(0, 40);
}

// ── Provider registry (ordered) ──────────────────────────────
const PROVIDER_CHECKS = [
  ['metamask',     checkMetaMask],
  ['blockaid',     checkBlockaid],
  ['chainpatrol',  checkChainPatrol],
  ['phishfort',    checkPhishFort],
  ['scamsniffer',  checkScamSniffer],
  ['cryptoscamdb', checkCryptoScamDB],
  ['walletguard',  checkWalletGuard],
  ['seal',         checkSEAL],
  ['phantom',      checkPhantom],
  ['phishdestroy', checkPhishDestroy],
  ['rabby',        checkRabby],
  ['rainbow',      checkRainbow],
  ['trustwallet',  checkTrustWallet],
  ['coinbase',     checkCoinbase],
];

const PROVIDER_NAMES = PROVIDER_CHECKS.map(([name]) => name);

// ── Streaming check — calls onResult(name, result, allSoFar) as each finishes
async function checkDomainStream(rawDomain, onResult) {
  const domain = cleanDomain(rawDomain);
  if (!domain) return null;

  const startTime = Date.now();
  const providers = {};
  let done = 0;

  const promises = PROVIDER_CHECKS.map(([name, fn]) => {
    // Per-provider 8s timeout wrapper
    const withTimeout = Promise.race([
      fn(domain),
      new Promise(resolve => setTimeout(() => resolve({ flagged: false, error: true, details: 'Timeout' }), 8000)),
    ]);

    return withTimeout.then(result => {
      providers[name] = result;
      done++;
      if (onResult) {
        try { onResult(name, result, providers, done); } catch { }
      }
    });
  });

  await Promise.all(promises);

  const flaggedProviders = Object.entries(providers).filter(([, p]) => p.flagged).map(([n]) => n);
  const errorProviders   = Object.entries(providers).filter(([, p]) => p.error).map(([n]) => n);

  return {
    domain,
    timestamp: new Date().toISOString(),
    elapsed:   Date.now() - startTime,
    providers,
    flaggedCount:  flaggedProviders.length,
    errorCount:    errorProviders.length,
    totalCount:    PROVIDER_CHECKS.length,
    isAnyFlagged:  flaggedProviders.length > 0,
    flaggedProviders,
    errorProviders,
  };
}

module.exports = { checkDomain, checkDomainStream, cleanDomain, warmup, stopRefresh, PROVIDER_NAMES };

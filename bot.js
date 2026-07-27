//  Web3 Domain Ban Checker — Telegram Bot
// ============================================================

const TelegramBot = require('node-telegram-bot-api');
const express = require('express');
const { checkDomain, checkDomainStream, cleanDomain, warmup, stopRefresh, PROVIDER_NAMES } = require('./checker');

// ── Config ─────────────────────────────────────────────────
const BOT_TOKEN = process.env.BOT_TOKEN || '8981635845:AAEAYnC8dq5facM4o4S5oghrxY-bunS9yls';
if (!BOT_TOKEN) {
  console.error('BOT_TOKEN not set.');
  process.exit(1);
}

const WEBHOOK_URL = process.env.WEBHOOK_URL || process.env.RENDER_EXTERNAL_URL || (process.env.RAILWAY_PUBLIC_DOMAIN ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}` : '');
const USE_WEBHOOK = !!WEBHOOK_URL;
const PORT = process.env.PORT || 3000;

// Start without polling — polling begins only after warmup
// Force IPv4 to avoid IPv6 ETIMEDOUT in some environments
const bot = new TelegramBot(BOT_TOKEN, USE_WEBHOOK ? {} : {
  request: { agentOptions: { family: 4 } },
});

// ── Rate limiter ───────────────────────────────────────────
const rateMap  = new Map();
const RATE_MAX = 30;
const RATE_WIN = 60_000;

function rateOk(chatId) {
  const now = Date.now();
  let r = rateMap.get(chatId);
  if (!r || now > r.resetAt) {
    r = { count: 0, resetAt: now + RATE_WIN };
    rateMap.set(chatId, r);
  }
  if (r.count >= RATE_MAX) return false;
  r.count++;
  return true;
}

// ── Bulk mode state ────────────────────────────────────────
const bulkWaiting = new Map();

// ── Provider Labels ───────────────────────────────────────────
const LABELS = {
  metamask:     'MetaMask',
  blockaid:     'Blockaid',
  chainpatrol:  'ChainPatrol',
  phishfort:    'PhishFort',
  scamsniffer:  'ScamSniffer',
  cryptoscamdb: 'CryptoScamDB',
  walletguard:  'WalletGuard',
  seal:         'SEALIntel',
  phantom:      'Phantom',
  phishdestroy: 'PhishDestroy',
  rabby:        'Rabby',
  rainbow:      'Rainbow',
  trustwallet:  'TrustWallet',
  coinbase:     'Coinbase',
};

function esc(s) {
  return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function pIcon(p) {
  if (p.flagged) return '🔴';
  return '🟢';
}

// ── Single domain result card (final) ─────────────────────
function formatResult(r) {
  const status = r.isAnyFlagged
    ? `🔴 FLAGGED [${r.flaggedCount}/${r.totalCount}]`
    : `🟢 CLEAN`;

  const entries = Object.entries(r.providers);
  const lines = [
    `┏ <b>${esc(r.domain)}</b> — ${status}`,
  ];

  entries.forEach(([name, prov], idx) => {
    const isLast = idx === entries.length - 1;
    const branch = isLast ? '┗' : '┣';
    const icon = pIcon(prov);
    lines.push(`${branch} ${icon} <b>${LABELS[name] || name}</b>`);
  });

  return lines.join('\n');
}

// ── Live progress message (during scan) ───────────────────
function formatLiveMessage(domain, results, doneCount) {
  const total = PROVIDER_NAMES.length;
  const flaggedCount = Object.values(results).filter(r => r.flagged).length;
  const header = flaggedCount > 0
    ? `┏ <b>${esc(domain)}</b> — ⏳ ${doneCount}/${total} (🔴 ${flaggedCount})`
    : `┏ <b>${esc(domain)}</b> — ⏳ ${doneCount}/${total}`;

  const lines = [header];

  PROVIDER_NAMES.forEach((name, idx) => {
    const isLast = idx === total - 1;
    const branch = isLast ? '┗' : '┣';
    const label = `<b>${LABELS[name] || name}</b>`;

    if (results[name]) {
      const icon = pIcon(results[name]);
      lines.push(`${branch} ${icon} ${label}`);
    } else {
      lines.push(`${branch} ⏳ ${label}`);
    }
  });

  return lines.join('\n');
}

// ── Bulk table ─────────────────────────────────────────────
function formatBulkTable(results) {
  if (!results.length) return '🔴 No valid domains.';

  const flagged = results.filter(r => r.isAnyFlagged);
  const clean   = results.filter(r => !r.isAnyFlagged);

  const lines = [
    `┏ <b>Bulk Check (${results.length} domains)</b>`,
    `┣ 🔴 Flagged: <b>${flagged.length}</b> | 🟢 Clean: <b>${clean.length}</b>`,
    `┃`,
  ];

  flagged.forEach(r => {
    lines.push(`┣ 🔴 <code>${esc(r.domain)}</code> [${r.flaggedCount}/${r.totalCount}]`);
  });

  if (flagged.length && clean.length) {
    lines.push(`┃`);
  }

  clean.forEach((r, idx) => {
    const isLast = idx === clean.length - 1;
    const branch = isLast ? '┗' : '┣';
    lines.push(`${branch} 🟢 <code>${esc(r.domain)}</code>`);
  });

  if (!clean.length && flagged.length) {
    lines[lines.length - 1] = lines[lines.length - 1].replace(/^┣/, '┗');
  }

  return lines.join('\n');
}

// ── Domain regex ───────────────────────────────────────────
const DOMAIN_RE = /^(?:https?:\/\/)?(?:www\.)?([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)(?:[:/].*)?$/;

function looksLikeDomain(text) {
  const t = text.trim();
  if (t.startsWith('/')) return false;
  return DOMAIN_RE.test(t);
}

function extractDomains(text) {
  return text
    .split(/[\n,;\s]+/)
    .map(l => l.trim())
    .filter(l => l && DOMAIN_RE.test(l))
    .map(cleanDomain)
    .filter(Boolean);
}

// ── Bot commands ───────────────────────────────────────────

// /start
bot.onText(/\/start/, (msg) => {
  bot.sendMessage(msg.chat.id, [
    `┏ <b>Domain Checker</b>`,
    `┣ 14 security providers`,
    `┣ MetaMask │ Blockaid │ ChainPatrol │ PhishFort`,
    `┣ ScamSniffer │ CryptoScamDB │ WalletGuard`,
    `┣ SEALIntel │ Phantom │ PhishDestroy │ Rabby`,
    `┣ Rainbow │ TrustWallet │ Coinbase`,
    `┣ /bulk — batch check up to 30 domains`,
    `┗ /help — commands and info`,
  ].join('\n'), { parse_mode: 'HTML' });
});

// /help
bot.onText(/\/help/, (msg) => {
  bot.sendMessage(msg.chat.id, [
    `┏ <b>Help</b>`,
    `┣ Single check: send <code>example.com</code>`,
    `┣ Bulk check: /bulk then list of domains`,
    `┣ Status: 🔴 Flagged | 🟢 Clean`,
    `┗ 14 providers: MetaMask │ Blockaid │ ChainPatrol │ PhishFort │ ScamSniffer │ CryptoScamDB │ WalletGuard │ SEALIntel │ Phantom │ PhishDestroy │ Rabby │ Rainbow │ TrustWallet │ Coinbase`,
  ].join('\n'), { parse_mode: 'HTML' });
});

// /bulk
bot.onText(/\/bulk/, (msg) => {
  const chatId = msg.chat.id;

  if (bulkWaiting.has(chatId)) clearTimeout(bulkWaiting.get(chatId));

  const timeout = setTimeout(() => {
    bulkWaiting.delete(chatId);
    bot.sendMessage(chatId, '🔴 Bulk mode timed out.').catch(() => {});
  }, 120_000);

  bulkWaiting.set(chatId, timeout);

  bot.sendMessage(chatId, [
    `┏ <b>Bulk Mode</b>`,
    `┣ Send domains (one per line, up to 30)`,
    `┗ Auto-cancels in 2 min`,
  ].join('\n'), { parse_mode: 'HTML' });
});

// ── Message handler ────────────────────────────────────────
bot.on('message', async (msg) => {
  if (!msg.text) return;
  const text = msg.text.trim();
  if (text.startsWith('/')) return;

  const chatId = msg.chat.id;

  if (!rateOk(chatId)) {
    return bot.sendMessage(chatId, '🔴 Too many requests. Wait a minute.');
  }

  // Bulk mode
  if (bulkWaiting.has(chatId)) {
    clearTimeout(bulkWaiting.get(chatId));
    bulkWaiting.delete(chatId);

    const domains = [...new Set(extractDomains(text))].slice(0, 30);
    if (!domains.length) {
      return bot.sendMessage(chatId, '🔴 No valid domains found. Send one per line.');
    }

    const scanning = await bot.sendMessage(chatId,
      `Checking <b>${domains.length}</b> domains…`,
      { parse_mode: 'HTML' }
    );

    try {
      const results = [];
      for (let i = 0; i < domains.length; i += 5) {
        const batch = domains.slice(i, i + 5);
        const batchResults = await Promise.all(batch.map(d => checkDomain(d)));
        results.push(...batchResults.filter(Boolean));

        if (results.length % 10 === 0 && results.length < domains.length) {
          await bot.editMessageText(
            `Checking… ${results.length}/${domains.length}`,
            { chat_id: chatId, message_id: scanning.message_id }
          ).catch(() => {});
        }
      }

      const table = formatBulkTable(results);

      if (table.length < 4000) {
        await bot.editMessageText(table, {
          chat_id: chatId, message_id: scanning.message_id, parse_mode: 'HTML',
        });
      } else {
        await bot.editMessageText(
          `Checked <b>${results.length}</b> domains. Sending results…`,
          { chat_id: chatId, message_id: scanning.message_id, parse_mode: 'HTML' }
        );
        const flaggedR = results.filter(r => r.isAnyFlagged);
        const cleanR   = results.filter(r => !r.isAnyFlagged);
        for (const r of flaggedR) {
          await bot.sendMessage(chatId, formatResult(r), { parse_mode: 'HTML' });
        }
        if (cleanR.length) {
          const cleanList = cleanR.map(r => `🟢 <code>${esc(r.domain)}</code>`).join('\n');
          await bot.sendMessage(chatId, `<b>Clean:</b>\n${cleanList}`, { parse_mode: 'HTML' });
        }
      }

      const flaggedDetail = results.filter(r => r.isAnyFlagged).slice(0, 5);
      for (const r of flaggedDetail) {
        await bot.sendMessage(chatId, formatResult(r), { parse_mode: 'HTML' });
      }
    } catch (err) {
      await bot.editMessageText(`🔴 Error: ${err.message}`, {
        chat_id: chatId, message_id: scanning.message_id,
      }).catch(() => {});
    }
    return;
  }

  // Single domain auto-detect
  if (!looksLikeDomain(text)) return;

  const domain = cleanDomain(text);
  if (!domain || domain.length < 4 || !domain.includes('.')) return;

  // Send initial message with all providers pending
  const initMsg = formatLiveMessage(domain, {}, 0);
  const scanning = await bot.sendMessage(chatId, initMsg, { parse_mode: 'HTML' });
  const msgId = scanning.message_id;

  try {
    let lastEditTime = 0;
    let pendingEdit = null;
    const THROTTLE = 400; // ms between edits to avoid TG rate limits

    const result = await checkDomainStream(domain, (name, provResult, allResults, doneCount) => {
      const now = Date.now();
      const total = PROVIDER_NAMES.length;

      // Build live message
      const liveText = doneCount >= total
        ? null  // Final message handled below
        : formatLiveMessage(domain, allResults, doneCount);

      if (!liveText) return;

      // Throttle edits
      if (pendingEdit) clearTimeout(pendingEdit);

      const doEdit = () => {
        lastEditTime = Date.now();
        bot.editMessageText(liveText, {
          chat_id: chatId, message_id: msgId, parse_mode: 'HTML',
        }).catch(() => {});
      };

      const elapsed = now - lastEditTime;
      if (elapsed >= THROTTLE) {
        doEdit();
      } else {
        pendingEdit = setTimeout(doEdit, THROTTLE - elapsed);
      }
    });

    if (pendingEdit) clearTimeout(pendingEdit);

    if (!result) {
      return bot.editMessageText('🔴 Invalid domain.', {
        chat_id: chatId, message_id: msgId,
      });
    }

    // Final message
    await bot.editMessageText(formatResult(result), {
      chat_id: chatId, message_id: msgId, parse_mode: 'HTML',
    });
  } catch (err) {
    if (pendingEdit) clearTimeout(pendingEdit);
    await bot.editMessageText(`🔴 Error: ${err.message}`, {
      chat_id: chatId, message_id: msgId,
    }).catch(() => {});
  }
});

// ── Error handling & Shutdown ──────────────────────────────
if (!USE_WEBHOOK) {
  let fatalRetries = 0;
  bot.on('polling_error', (err) => {
    if (err.code === 'EFATAL') {
      fatalRetries++;
      console.error(`FATAL polling error (${fatalRetries}):`, err.message);
      if (fatalRetries >= 5) {
        console.error('Too many FATAL errors. Exiting.');
        process.exit(1);
      }
      // Retry polling after 5s
      setTimeout(() => {
        bot.startPolling().catch(e => console.error('Restart polling error:', e.message));
      }, 5000);
      return;
    }
    console.error('Polling error:', err.code, err.message);
  });
}

process.on('SIGINT', () => {
  stopRefresh();
  if (!USE_WEBHOOK) bot.stopPolling();
  process.exit(0);
});

process.on('unhandledRejection', (err) => {
  console.error('Unhandled rejection:', err);
});

// ── Startup ────────────────────────────────────────────────
(async () => {
  await warmup();

  if (USE_WEBHOOK) {
    const app = express();
    app.use(express.json());

    app.get('/health', (req, res) => res.json({ status: 'ok', uptime: process.uptime() | 0 }));

    app.post(`/bot${BOT_TOKEN}`, (req, res) => {
      bot.processUpdate(req.body);
      res.sendStatus(200);
    });

    app.listen(PORT, async () => {
      const webhookUrl = `${WEBHOOK_URL}/bot${BOT_TOKEN}`;
      await bot.setWebHook(webhookUrl);
      console.log(`[Bot] Started (webhook) on port ${PORT}`);
      console.log(`[Bot] Webhook: ${webhookUrl}`);
    });
  } else {
    // Delete any existing webhook before polling (prevents 409 conflict)
    try { await bot.deleteWebHook(); } catch { }
    await bot.startPolling({ restart: false });
    console.log('[Bot] Started (polling). Ready to receive messages.');
  }
})();

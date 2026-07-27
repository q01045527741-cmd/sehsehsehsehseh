# 🛡️ Web3 Domain Ban Checker Bot

Telegram bot that checks domains against **6 Web3 security providers** in real-time.

## Providers
| # | Provider | Type |
|---|---|---|
| 1 | 🦊 MetaMask/Blockaid | Stalelist + hot diffs (107k+ domains) |
| 2 | 🔗 ChainPatrol | Live REST API |
| 3 | 🏰 PhishFort | GitHub blacklist |
| 4 | 🐕 ScamSniffer | GitHub blacklist |
| 5 | 🗃️ CryptoScamDB | GitHub YAML (9.8k domains) |
| 6 | 🛡️ WalletGuard | Live API + blocklist + verified sites |

## Deploy to Render (Free)

### 1. Push this repo to GitHub
```bash
# Create new repo on github.com, then:
git remote add origin https://github.com/YOUR_USER/domain-checker-bot.git
git push -u origin main
```

### 2. Create Web Service on Render
1. Go to [dashboard.render.com](https://dashboard.render.com)
2. **New** → **Web Service**
3. Connect your GitHub repo
4. Settings:
   - **Name**: `domain-checker-bot`
   - **Runtime**: `Node`
   - **Build Command**: `npm install`
   - **Start Command**: `node bot.js`
   - **Instance Type**: `Free`

### 3. Set Environment Variables
In Render dashboard → Environment:
| Key | Value |
|---|---|
| `BOT_TOKEN` | `your-telegram-bot-token` |

> `RENDER_EXTERNAL_URL` is set automatically by Render.

### 4. Keep-Alive (optional)
Free Render services sleep after 15min of no requests.
To keep alive, add a free cron ping at [cron-job.org](https://cron-job.org):
- URL: `https://your-app.onrender.com/health`
- Interval: Every 10 minutes

## Local Development
```bash
export BOT_TOKEN="your-token"
node bot.js   # runs in polling mode
```

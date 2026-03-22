# The Intel Desk — API Server

Backend server that runs OSINT tools and streams results to your Squarespace site.

## Deploy to Render.com (recommended)

### Step 1 — Push this folder to GitHub
1. Go to github.com and create a new repository called `intel-desk-api`
2. Upload all files in this folder to that repo

### Step 2 — Connect to Render
1. Go to render.com and sign up / log in
2. Click **New** → **Web Service**
3. Connect your GitHub account and select `intel-desk-api`
4. Render will auto-detect the render.yaml settings
5. Click **Deploy**

### Step 3 — Note your server URL
Once deployed, Render gives you a URL like:
`https://intel-desk-api.onrender.com`

Copy that URL — you'll paste it into your Squarespace card code.

### Step 4 — Optional API keys
Some tools need free API keys for full results:
- **AbuseIPDB**: get a free key at abuseipdb.com/api
  → Add it in Render dashboard → Environment → ABUSEIPDB_KEY

## API Endpoints

All streaming endpoints return Server-Sent Events (SSE).

| Endpoint | Params | Tool |
|---|---|---|
| GET /api/holehe | ?email= | Holehe |
| GET /api/ghunt | ?email= | GHunt |
| GET /api/theharvester | ?domain= | theHarvester |
| GET /api/sherlock | ?username= | Sherlock |
| GET /api/maigret | ?username= | Maigret |
| GET /api/phoneinfoga | ?number= | PhoneInfoga |
| GET /api/ignorant | ?number= | Ignorant |
| GET /api/subfinder | ?domain= | Subfinder |
| GET /api/hudsonrock | ?email= | Hudson Rock (JSON) |
| GET /api/emailrep | ?email= | EmailRep (JSON) |
| GET /api/ipinfo | ?ip= | IPInfo (JSON) |
| GET /api/abuseipdb | ?ip= | AbuseIPDB (JSON) |

## Updating tools

If a tool breaks (usually after a platform update), SSH into Render or trigger a redeploy:
```
pip install --upgrade holehe
pip install --upgrade sherlock-project
```

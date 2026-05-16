## CertSnipe

Monitors certificate transparency logs for a specific AitM phishing attack targeting Duo SSO, as described in my [blog post](https://j027.net/hunting-evilginx/). Uses a local [`certstream-server-go`](https://github.com/d-Rickyy-b/certstream-server-go) instance (via Docker) as the CT data source.

| File | Purpose |
|------|---------|
| `targets.json` | Targeted organizations (Duo ID → name + email). Must be manually populated. |
| `.env.example` | Template for required environment variables. Copy to `.env` before running. |
| `email_template.txt` | Email template for alerts. A default fallback is included. |
| `known_domains.txt` | Known attacker domains, so new certs on these are flagged high-confidence. |
| `known_ips.txt` | Known attacker IPs, so low-confidence matches resolving here are upgraded. |
| `watched_org_ids.txt` | Optional. Org IDs (one per line) whose alerts are also sent to `DISCORD_WEBHOOK_WATCHED`. |

`targets.json` uses this format:

```json
{
  "<duo id>": {
    "name": "<university name>",
    "email": "<university email>"
  }
}
```

## Usage
1. Clone the repository and navigate to the project directory.
2. Create a `.env` file based on the `.env.example` and fill in the required environment variables.
   - `CERTSTREAM_WS_URL` - WebSocket URL of your certstream server. With the included Docker setup on the same machine: `ws://127.0.0.1:8080/`
3. ```docker-compose up -d``` to start the certstream server.
4. (Optional) Create and activate a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
5. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
6. Run the watcher script:
   ```bash
   python watcher.py
   ```

### Without Docker
If you prefer to run certstream-server-go as a standalone binary instead of Docker:
1. Download the release binary from [certstream-server-go releases](https://github.com/d-Rickyy-b/certstream-server-go/releases).
2. Run it with the included config: `./certstream-server-go -config config.yaml`

The `CERTSTREAM_WS_URL` is the same either way: `ws://127.0.0.1:8080/`
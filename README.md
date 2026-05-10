## Certificate Transparency Watcher for AitM Phishing Attacks against Duo

Monitors certificate transparency logs for a specific AitM phishing attack targeting Duo SSO, as described in my [blog post](https://j027.net/hunting-evilginx/). Uses a local [`certstream-server-go`](https://github.com/d-Rickyy-b/certstream-server-go) instance (via Docker) as the CT data source.

| File | Purpose |
|------|---------|
| `targets.json` | Targeted organizations (Duo ID → name + email). Must be manually populated. |
| `.env.example` | Template for required environment variables. Copy to `.env` before running. |
| `email_template.txt` | Email template for alerts. A default fallback is included. |
| `known_domains.txt` | Known attacker domains, so new certs on these are flagged high-confidence. |
| `known_ips.txt` | Known attacker IPs, so low-confidence matches resolving here are upgraded. |

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
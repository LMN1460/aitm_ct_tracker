# CertSnipe

Monitors certificate transparency logs for AitM phishing infrastructure
targeting US universities that use Duo 2FA. Uses certstream-server-go
(Docker) as the CT data source.

## Before committing

Always run from project root with venv active:

    source .venv/bin/activate
    ruff check ct_watcher/ tests/
    ruff format --check ct_watcher/ tests/
    python -m pytest tests/

If `ruff format --check` says files would be reformatted, fix with:

    ruff format ct_watcher/ tests/

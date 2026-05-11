# Examples

Runnable scripts that mirror the [TUTORIAL](../TUTORIAL.md). Pick one
that matches your question.

| File | What it shows | Needs a server? |
|---|---|---|
| `01_sign_and_verify.py` | Sign a `created` event, verify, tamper, watch verify fail | no |
| `02_chain_walk.py` | Build a 3-event chain and re-walk it locally | no |
| `03_full_client.py` | Full roundtrip against phip-server: bootstrap actor → create → push → read | yes |
| `04_bundle_roundtrip.py` | Pack a 2-event chain into a bundle, verify offline | no |

For (3), spin up phip-server first:

```bash
git clone https://github.com/mfgs-us/phip-server
cd phip-server
PHIP_AUTHORITY=tutorial.local docker compose up -d
```

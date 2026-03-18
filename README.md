# Stipul

Stipul is a deterministic enforcement and cryptographic evidence tool for AI agent actions.

## Install

```bash
pip install stipul
```

## Run the demo

```bash
python3 demo/run.py
```

From a source checkout, the demo runs an allowed `filesystem.read` action and denies a `web.search` call to `evil.example.com`.
It then closes the proxy session and prints the preserved session directory, Chronicle history, and verification result for that run.

## Verify the chain

```bash
stipul verify --session-dir /path/to/session --contract /path/to/contract.json --public-key /path/to/runtime_key.pub
```

A passing verification means the authoritative signed `events.jsonl` chain for the session is intact.

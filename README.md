# Personalization demo — frontend

A dependency-free, single-page JS frontend for the [demo-personalization](../demo-personalization)
control server. Train a private LoRA adapter on your own writing, then chat with it —
all inside a Tinfoil enclave.

## Run

Either open `index.html` directly, or serve the folder:

```
python3 -m http.server 5173
```

then visit http://localhost:5173.

## Flow

1. **Demo key** — gates access (stored in `localStorage`).
2. **Encryption key** — your identity; names + decrypts your adapter (kept in
   `sessionStorage` only). On connect we `GET /status`:
   - `none` → **train** view
   - `ready` → **chat** view
   - `training` → progress, polled every 5s
   - `failed` → train view with the error
3. **Train** — add documents in the voice to learn, `POST /train`, poll until ready.
4. **Chat** — ephemeral conversation (cleared on refresh); the full message list is
   sent each turn. Toggle **compare base** to send `use_base: true` and see the base
   model's answer instead of your adapter's.

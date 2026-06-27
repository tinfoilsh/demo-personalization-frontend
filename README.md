# Personalization demo — frontend

A single-page JS frontend for the [demo-personalization](../demo-personalization)
control server. Train a private LoRA adapter on your own writing, then chat with it —
all inside a Tinfoil enclave.

Every request is attested and end-to-end encrypted via the
[tinfoil JS SDK](https://github.com/tinfoilsh/tinfoil-js)'s `SecureClient`: the
enclave is verified against `tinfoilsh/demo-personalization` before any request is
sent, and request bodies are sealed (EHBP/HPKE) to the verified enclave.

## Run

The attesting client is bundled from the `tinfoil` SDK into `vendor/tinfoil.js`.
Rebuild it after changing `vendor-entry.js` or upgrading the SDK:

```
npm install
npm run build:vendor
```

Then serve the folder:

```
python3 -m http.server 5173
```

and visit http://localhost:5173.

## Flow

1. **Demo key** — gates access (stored in `localStorage`).
2. **Encryption key** — your identity; names + decrypts your adapter (kept in
   `sessionStorage` only). On connect we `GET /status`:
   - `none` → **train** view
   - `ready` → **chat** view
   - `training` → progress, polled every 5s
   - `failed` → train view with the error
3. **Train** — drag in `.txt`/`.md` files (or paste text). Each source is chunked
   client-side, then all chunks are sent as `documents` to `POST /train`; polls until
   ready.
4. **Chat** — ephemeral conversation (cleared on refresh); the full message list is
   sent each turn. Toggle **compare base** for a side-by-side view: the adapter and
   base model each get their own panel; `⇈` sends the same prompt to both at once.

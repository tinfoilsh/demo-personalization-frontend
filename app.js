"use strict";

// ── state ──────────────────────────────────────────────────
const LS = { demoKey: "pz.demoKey" };
const SS = { encKey: "pz.encKey" };

// A long throwaway key used only to probe demo-key validity. The server checks
// the demo key before the encryption key, so with a key this long the only way
// /status 401s is a bad demo key.
const DEMO_PROBE_KEY = "__demo_key_probe________";

const state = {
  apiBase: window.DEFAULT_API_BASE,
  demoKey: localStorage.getItem(LS.demoKey) || "",
  encKey: sessionStorage.getItem(SS.encKey) || "",
  adapter: "",
  sources: [], // train inputs: {id, name, chunks}
  messages: [], // adapter conversation: {role, content}
  baseMessages: [], // base-model conversation (compare mode)
  sending: false, // adapter panel busy
  baseSending: false, // base panel busy
  compare: false, // compare-base side-by-side on?
};

// ── secure client (attestation + EHBP) ─────────────────────
// One SecureClient per enclave URL. The Tinfoil shim in front of the control
// server terminates TLS + speaks EHBP, so client.fetch attests the enclave
// (fetches the bundle from ATC, verifies code + enclave measurements against
// the configRepo) and encrypts every request body end-to-end. The demo key
// travels as a header (X-Demo-Key); the encryption key travels in the body,
// sealed by EHBP so only the verified enclave can see it.
let secureClient = null;
let secureClientBase = null;
let attestationError = null;

function getSecureClient() {
  const base = state.apiBase.replace(/\/$/, "");
  if (secureClient && secureClientBase === base) return secureClient;
  secureClient = new Tinfoil.SecureClient({
    enclaveURL: base,
    configRepo: window.TINFOIL_CONFIG_REPO,
  });
  secureClientBase = base;
  attestationError = null;
  // Kick off attestation in the background; client.fetch awaits ready() on the
  // first real request. A failed ready() surfaces as an error on that request.
  secureClient.ready().catch((e) => {
    attestationError = e;
  });
  return secureClient;
}

// ── dom helpers ────────────────────────────────────────────
const $ = (id) => document.getElementById(id);
const VIEWS = ["view-gate", "view-key", "view-train", "view-chat"];
function show(view) {
  VIEWS.forEach((v) => $(v).classList.toggle("hidden", v !== view));
}
function setHidden(el, hidden) {
  el.classList.toggle("hidden", hidden);
}
function busy(btn, on) {
  btn.disabled = on;
  btn.querySelector(".btn-label")?.classList.toggle("hidden", on);
  btn.querySelector(".btn-spinner")?.classList.toggle("hidden", !on);
}

// ── api ────────────────────────────────────────────────────
function headers() {
  // The demo key gates access (fine for the shim/router to see). The encryption
  // key decrypts the user's private adapter — it travels in the encrypted body,
  // never a header, so Tinfoil can't see it. See authBody().
  return {
    "Content-Type": "application/json",
    "X-Demo-Key": state.demoKey,
  };
}

// Build a JSON body that includes the encryption key (EHBP-encrypted, so only
// the verified enclave sees it). Every authenticated endpoint takes this.
function authBody(payload = {}) {
  return JSON.stringify({ ...payload, encryption_key: state.encKey });
}

// All requests go through the attesting SecureClient instead of raw fetch.
// client.fetch resolves the path against the enclave URL, encrypts the body via
// EHBP, and verifies the enclave on the first call (cached thereafter).
async function api(path, opts = {}) {
  const client = getSecureClient();
  const res = await client.fetch(path, {
    ...opts,
    headers: { ...headers(), ...(opts.headers || {}) },
  });
  if (!res.ok) {
    let detail = `${res.status}`;
    try {
      detail = (await res.json()).detail || detail;
    } catch {}
    const err = new Error(detail);
    err.status = res.status;
    throw err;
  }
  return res.status === 204 ? null : res.json();
}

const getStatus = () => api("/status", { method: "POST", body: authBody() });

// Probe demo-key validity with a throwaway encryption key. On success the real
// demo key / api base are committed to `state`; on failure `state` is left
// untouched and the error (with .status) is rethrown. Never trusts a stored key
// blindly — this runs on submit AND on every boot.
async function verifyDemoKey(key, base) {
  const prev = {
    demoKey: state.demoKey,
    encKey: state.encKey,
    apiBase: state.apiBase,
  };
  state.demoKey = key;
  state.apiBase = base;
  state.encKey = DEMO_PROBE_KEY;
  try {
    await getStatus();
    state.encKey = prev.encKey; // keep any real key; drop the probe
  } catch (err) {
    Object.assign(state, prev);
    throw err;
  }
}
const startTraining = (documents) =>
  api("/train", { method: "POST", body: authBody({ documents }) });

async function chatCompletion(messages, useBase) {
  const body = {
    messages,
    stream: false,
    encryption_key: state.encKey,
    ...(useBase ? { use_base: true } : {}),
  };
  const data = await api("/v1/chat/completions", {
    method: "POST",
    body: JSON.stringify(body),
  });
  return data?.choices?.[0]?.message?.content ?? "";
}

// ── identity chip / topbar ─────────────────────────────────
function refreshTopbar(connected) {
  setHidden($("logout-btn"), !connected);
  const chip = $("identity-chip");
  setHidden(chip, !connected);
  if (connected) chip.textContent = state.adapter || "connected";
}

// ── routing after we know /status ──────────────────────────
async function route() {
  let s;
  try {
    s = await getStatus();
  } catch (e) {
    if (e.status === 401) {
      // bad demo key OR bad/short encryption key — bounce appropriately
      logout(e.message);
      return;
    }
    throw e;
  }
  state.adapter = s.adapter || "";
  refreshTopbar(true);

  if (s.status === "ready") {
    enterChat(s);
  } else if (s.status === "training") {
    enterTrain();
    showTrainingProgress();
  } else if (s.status === "failed") {
    enterTrain();
    setText(
      $("train-error"),
      `previous run failed: ${s.error || "unknown error"}`,
    );
    setHidden($("train-error"), false);
  } else {
    enterTrain(); // "none"
  }
}

// ── gate (demo key) ────────────────────────────────────────
$("gate-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  setHidden($("gate-error"), true);
  const key = $("demo-key-input").value.trim();
  if (!key) return;
  const btn = e.target.querySelector("button");
  busy(btn, true);
  try {
    await verifyDemoKey(key, state.apiBase);
  } catch (err) {
    setText(
      $("gate-error"),
      err.status === 401 ? "incorrect demo key" : friendly(err),
    );
    setHidden($("gate-error"), false);
    busy(btn, false);
    return;
  }
  // Good demo key — only now does it become persisted state.
  localStorage.setItem(LS.demoKey, key);
  busy(btn, false);
  show("view-key");
  $("enc-key-input").focus();
});

// ── encryption key ─────────────────────────────────────────
$("key-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  setHidden($("key-error"), true);
  const key = $("enc-key-input").value;
  if (key.length < 8) return;
  state.encKey = key;
  sessionStorage.setItem(SS.encKey, key);
  const btn = e.target.querySelector("button");
  busy(btn, true);
  try {
    await route();
  } catch (err) {
    setText($("key-error"), friendly(err));
    setHidden($("key-error"), false);
  } finally {
    busy(btn, false);
  }
});

// ── train: chunking ────────────────────────────────────────
// Ported verbatim from examples/lovecraft/chunk.py so the frontend produces the
// exact `documents` the trainer expects: pack whole paragraphs (split on "\n")
// up to ~target words, never splitting mid-paragraph, and merge-or-drop a short
// final tail. Each chunk becomes one element of the /train `documents` array.
const CHUNK_TARGET = 300; // words
const CHUNK_MIN = 80; // words

function wordCount(s) {
  const t = s.trim();
  return t ? t.split(/\s+/).length : 0;
}

function chunkText(text, target = CHUNK_TARGET, min = CHUNK_MIN) {
  const paragraphs = text
    .split("\n")
    .map((p) => p.trim())
    .filter(Boolean);
  const chunks = [];
  let buf = [];
  let count = 0;
  for (const para of paragraphs) {
    buf.push(para);
    count += wordCount(para);
    if (count >= target) {
      chunks.push(buf.join("\n"));
      buf = [];
      count = 0;
    }
  }
  if (buf.length) {
    const tail = buf.join("\n");
    if (wordCount(tail) >= min || chunks.length === 0) {
      chunks.push(tail);
    } else {
      chunks[chunks.length - 1] += "\n" + tail;
    }
  }
  return chunks.filter((c) => wordCount(c) >= min);
}

// ── train: sources ─────────────────────────────────────────
// Each source is one input file/paste: {name, text, chunks}. Chunked per-source
// (like running chunk.py per file); the /train payload is all chunks concatenated.
let sourceSeq = 0;

function addSource(name, text) {
  text = text.replace(/\r\n?/g, "\n"); // normalize to \n; matches chunk.py on \n
  if (!text.trim()) return;
  state.sources.push({ id: ++sourceSeq, name, chunks: chunkText(text) });
  renderSources();
}

function removeSource(id) {
  state.sources = state.sources.filter((s) => s.id !== id);
  renderSources();
}

function totalChunks() {
  return state.sources.reduce((n, s) => n + s.chunks.length, 0);
}

function renderSources() {
  const list = $("sources-list");
  list.innerHTML = "";
  for (const s of state.sources) {
    const row = document.createElement("div");
    row.className = "source-item";
    const name = document.createElement("span");
    name.className = "source-name";
    name.textContent = s.name;
    const stat = document.createElement("span");
    const n = s.chunks.length;
    stat.className = "source-stat" + (n ? "" : " warn");
    stat.textContent = n ? `${n} chunk${n === 1 ? "" : "s"}` : "too short";
    const rm = document.createElement("button");
    rm.className = "source-remove";
    rm.type = "button";
    rm.textContent = "×";
    rm.title = "remove";
    rm.addEventListener("click", () => removeSource(s.id));
    row.append(name, stat, rm);
    list.appendChild(row);
  }

  const total = totalChunks();
  const summary = $("chunk-summary");
  setHidden(summary, state.sources.length === 0);
  summary.textContent = `${state.sources.length} source${
    state.sources.length === 1 ? "" : "s"
  } · ${total} training chunk${total === 1 ? "" : "s"} ready`;
  $("train-btn").disabled = total === 0;
}

// ── train: file intake ─────────────────────────────────────
async function intakeFiles(fileList) {
  for (const file of fileList) {
    try {
      addSource(file.name, await file.text());
    } catch {
      // ignore unreadable files
    }
  }
}

const dropzone = $("dropzone");
const fileInput = $("file-input");

dropzone.addEventListener("click", () => fileInput.click());
dropzone.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    fileInput.click();
  }
});
fileInput.addEventListener("change", () => {
  intakeFiles(fileInput.files);
  fileInput.value = ""; // allow re-selecting the same file
});
["dragenter", "dragover"].forEach((ev) =>
  dropzone.addEventListener(ev, (e) => {
    e.preventDefault();
    dropzone.classList.add("dragover");
  }),
);
["dragleave", "drop"].forEach((ev) =>
  dropzone.addEventListener(ev, (e) => {
    e.preventDefault();
    if (ev === "dragleave" && dropzone.contains(e.relatedTarget)) return;
    dropzone.classList.remove("dragover");
  }),
);
dropzone.addEventListener("drop", (e) => {
  if (e.dataTransfer?.files?.length) intakeFiles(e.dataTransfer.files);
});

$("add-paste-btn").addEventListener("click", () => {
  const ta = $("paste-input");
  if (!ta.value.trim()) return;
  addSource(`pasted text ${state.sources.length + 1}`, ta.value);
  ta.value = "";
  $("paste-block").open = false;
});

function enterTrain() {
  refreshTopbar(true);
  setTrainingMode(false); // ensure inputs are visible, progress hidden
  renderSources();
  setHidden($("train-error"), true);
  show("view-train");
}

$("train-btn").addEventListener("click", async () => {
  setHidden($("train-error"), true);
  const documents = state.sources.flatMap((s) => s.chunks);
  if (!documents.length) {
    setText($("train-error"), "add at least one source");
    setHidden($("train-error"), false);
    return;
  }
  busy($("train-btn"), true);
  try {
    await startTraining(documents);
    showTrainingProgress();
  } catch (err) {
    setText($("train-error"), friendly(err));
    setHidden($("train-error"), false);
  } finally {
    busy($("train-btn"), false);
  }
});

let pollTimer = null;

// Hide every input affordance while a job runs; restore them if it fails.
function setTrainingMode(on) {
  for (const id of [
    "dropzone",
    "paste-block",
    "sources-list",
    "chunk-summary",
    "train-btn",
  ]) {
    setHidden($(id), on);
  }
  setHidden($("train-progress"), !on);
}

function showTrainingProgress() {
  setTrainingMode(true);
  pollStatus();
}

async function pollStatus() {
  clearTimeout(pollTimer);
  try {
    const s = await getStatus();
    if (s.status === "ready") {
      enterChat(s);
      return;
    }
    if (s.status === "failed") {
      setTrainingMode(false);
      renderSources(); // restore the correct disabled state on the button
      setText(
        $("train-error"),
        `training failed: ${s.error || "unknown error"}`,
      );
      setHidden($("train-error"), false);
      return;
    }
    $("train-status-text").textContent =
      s.status === "training" ? "training in progress…" : `status: ${s.status}`;
  } catch (err) {
    $("train-status-text").textContent =
      `lost contact (${friendly(err)}) — retrying…`;
  }
  pollTimer = setTimeout(pollStatus, 5000);
}

// ── chat ───────────────────────────────────────────────────
// Compare mode splits the view into two side-by-side panels: the adapter (left,
// always present) and the base model (right, toggled on). Each panel owns its
// own conversation + input. The adapter panel has an extra "send to both" button
// (⇈) that broadcasts its input to both models in parallel.
function enterChat(status) {
  clearTimeout(pollTimer);
  refreshTopbar(true);
  const reward =
    status && status.mean_reward != null
      ? ` · reward ${Number(status.mean_reward).toFixed(3)}`
      : "";
  $("chat-meta").textContent = `${state.adapter}${reward}`;
  $("base-toggle").checked = false;
  setCompareMode(false);
  renderMessages();
  renderBaseMessages();
  show("view-chat");
  $("chat-input").focus();
}

function setCompareMode(on) {
  state.compare = on;
  $("view-chat").classList.toggle("compare", on);
  setHidden($("base-panel"), !on);
  setHidden($("send-both-btn"), !on);
  if (on) renderBaseMessages();
  updateSendBoth();
}

function updateSendBoth() {
  const btn = $("send-both-btn");
  if (btn.classList.contains("hidden")) return;
  btn.disabled = state.sending || state.baseSending;
}

function renderMessages() {
  renderInto(
    $("messages"),
    state.messages,
    "adapter",
    "// say something — your model is listening",
  );
}
function renderBaseMessages() {
  renderInto(
    $("base-messages"),
    state.baseMessages,
    "base",
    "// say something — the base model is listening",
  );
}
function renderInto(box, messages, side, emptyHint) {
  box.innerHTML = "";
  if (!messages.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = emptyHint;
    box.appendChild(empty);
    return;
  }
  for (const m of messages) appendMessageEl(box, m.role, m.content, side);
  box.scrollTop = box.scrollHeight;
}

function appendMessageEl(box, role, content, side) {
  box.querySelector(".empty-state")?.remove();
  const el = document.createElement("div");
  el.className = `msg ${role}${side === "base" && role === "assistant" ? " base" : ""}`;
  const label = document.createElement("div");
  label.className = "msg-role";
  label.textContent =
    role === "user" ? "you" : side === "base" ? "base model" : "your model";
  const bubble = document.createElement("div");
  bubble.className = "msg-bubble";
  bubble.textContent = content;
  el.append(label, bubble);
  box.appendChild(el);
  box.scrollTop = box.scrollHeight;
  return bubble;
}

function wireInput(input, formId) {
  input.addEventListener("input", () => {
    input.style.height = "auto";
    input.style.height = Math.min(input.scrollHeight, 180) + "px";
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      $(formId).requestSubmit();
    }
  });
}

const chatInput = $("chat-input");
const baseChatInput = $("base-chat-input");
wireInput(chatInput, "chat-form");
wireInput(baseChatInput, "base-chat-form");

// Conversation we send to the API: just the real user/assistant turns.
function convoFrom(messages) {
  return messages
    .filter((m) => m.role === "user" || m.role === "assistant")
    .map((m) => ({ role: m.role, content: m.content }));
}

// Send one panel's input to that panel's model only.
async function sendOne(side) {
  const isBase = side === "base";
  const input = $(isBase ? "base-chat-input" : "chat-input");
  const box = isBase ? $("base-messages") : $("messages");
  const messages = isBase ? state.baseMessages : state.messages;
  const busy = isBase ? "baseSending" : "sending";
  const sendBtn = $(isBase ? "base-send-btn" : "send-btn");

  const text = input.value.trim();
  if (!text || state[busy]) return;

  messages.push({ role: "user", content: text });
  appendMessageEl(box, "user", text, side);
  input.value = "";
  input.style.height = "auto";

  state[busy] = true;
  sendBtn.disabled = true;
  updateSendBoth();

  const bubble = appendMessageEl(box, "assistant", "", side);
  bubble.parentElement.classList.add("cursor");
  try {
    const reply = await chatCompletion(convoFrom(messages), isBase);
    bubble.parentElement.classList.remove("cursor");
    bubble.textContent = reply;
    messages.push({ role: "assistant", content: reply });
  } catch (err) {
    bubble.parentElement.classList.remove("cursor");
    bubble.parentElement.classList.add("error");
    bubble.textContent = friendly(err);
    messages.pop(); // drop the failed user turn so retry isn't poisoned
  } finally {
    state[busy] = false;
    sendBtn.disabled = false;
    updateSendBoth();
    box.scrollTop = box.scrollHeight;
    input.focus();
  }
}

// Send the adapter panel's input to both models at once (parallel).
async function sendBoth(text) {
  if (!text || state.sending || state.baseSending) return;

  state.messages.push({ role: "user", content: text });
  state.baseMessages.push({ role: "user", content: text });
  appendMessageEl($("messages"), "user", text, "adapter");
  appendMessageEl($("base-messages"), "user", text, "base");
  $("chat-input").value = "";
  $("chat-input").style.height = "auto";

  state.sending = true;
  state.baseSending = true;
  $("send-btn").disabled = true;
  $("base-send-btn").disabled = true;
  updateSendBoth();

  const adapterBubble = appendMessageEl(
    $("messages"),
    "assistant",
    "",
    "adapter",
  );
  const baseBubble = appendMessageEl(
    $("base-messages"),
    "assistant",
    "",
    "base",
  );
  adapterBubble.parentElement.classList.add("cursor");
  baseBubble.parentElement.classList.add("cursor");

  const adapterConvo = convoFrom(state.messages);
  const baseConvo = convoFrom(state.baseMessages);

  const settle = async (bubble, messages, convo, isBase) => {
    try {
      const reply = await chatCompletion(convo, isBase);
      bubble.parentElement.classList.remove("cursor");
      bubble.textContent = reply;
      messages.push({ role: "assistant", content: reply });
    } catch (err) {
      bubble.parentElement.classList.remove("cursor");
      bubble.parentElement.classList.add("error");
      bubble.textContent = friendly(err);
      messages.pop();
    }
  };

  await Promise.all([
    settle(adapterBubble, state.messages, adapterConvo, false),
    settle(baseBubble, state.baseMessages, baseConvo, true),
  ]);

  state.sending = false;
  state.baseSending = false;
  $("send-btn").disabled = false;
  $("base-send-btn").disabled = false;
  updateSendBoth();
  $("messages").scrollTop = $("messages").scrollHeight;
  $("base-messages").scrollTop = $("base-messages").scrollHeight;
  $("chat-input").focus();
}

$("base-toggle").addEventListener("change", () =>
  setCompareMode($("base-toggle").checked),
);
$("chat-form").addEventListener("submit", (e) => {
  e.preventDefault();
  sendOne("adapter");
});
$("base-chat-form").addEventListener("submit", (e) => {
  e.preventDefault();
  sendOne("base");
});
$("send-both-btn").addEventListener("click", () =>
  sendBoth($("chat-input").value.trim()),
);

$("clear-chat-btn").addEventListener("click", () => {
  state.messages = [];
  state.baseMessages = [];
  renderMessages();
  renderBaseMessages();
  $("chat-input").focus();
});

// ── logout ─────────────────────────────────────────────────
function logout(reason) {
  clearTimeout(pollTimer);
  state.encKey = "";
  state.adapter = "";
  state.messages = [];
  state.baseMessages = [];
  state.sources = [];
  sessionStorage.removeItem(SS.encKey);
  refreshTopbar(false);
  show("view-key");
  $("enc-key-input").value = "";
  $("enc-key-input").focus();
  if (reason) {
    setText($("key-error"), reason);
    setHidden($("key-error"), false);
  }
}
$("logout-btn").addEventListener("click", () => logout());

// ── misc ───────────────────────────────────────────────────
function setText(el, t) {
  el.textContent = t;
}
function friendly(err) {
  if (err instanceof TypeError) {
    return "can't reach the control server — check the url / CORS";
  }
  // SecureClient attestation failures (enclave verification, ATC fetch, etc.).
  // These have a `.name` set by the SDK's error classes.
  if (
    err instanceof Tinfoil.AttestationError ||
    err instanceof Tinfoil.ConfigurationError ||
    err instanceof Tinfoil.FetchError ||
    err instanceof Tinfoil.TinfoilError
  ) {
    return `couldn't verify the secure enclave: ${err.message}`;
  }
  return err.message || String(err);
}

// ── boot ───────────────────────────────────────────────────
// Kick off enclave attestation as early as possible — it takes a few seconds
// (fetch bundle from ATC, verify sigstore + enclave measurements). The first
// client.fetch awaits ready() if it's not done yet.
getSecureClient();

(async function boot() {
  if (!state.demoKey) {
    show("view-gate");
    $("demo-key-input").focus();
    return;
  }
  // A stored demo key is not trusted — re-verify it against the server. If it's
  // stale, wrong, or the server is unreachable, drop back to the gate and say so.
  $("demo-key-input").value = state.demoKey;
  try {
    await verifyDemoKey(state.demoKey, state.apiBase);
  } catch (err) {
    show("view-gate");
    setText(
      $("gate-error"),
      err.status === 401 ? "incorrect demo key" : friendly(err),
    );
    setHidden($("gate-error"), false);
    $("demo-key-input").focus();
    return;
  }
  // Demo key good. Resume the encryption key if we have one, else ask for it.
  show("view-key");
  if (state.encKey) {
    $("enc-key-input").value = state.encKey;
    route().catch((err) => {
      setText($("key-error"), friendly(err));
      setHidden($("key-error"), false);
    });
  } else {
    $("enc-key-input").focus();
  }
})();

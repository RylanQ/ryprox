// RyProx console: an SSH terminal (xterm.js) or a remote desktop
// (Apache Guacamole client). What to connect to is decided by the server.
import { Terminal } from "/assets/xterm.mjs";

const $ = (id) => document.getElementById(id);
const screen = $("screen");

function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (k === "class") e.className = v;
    else e.setAttribute(k, v === true ? "" : v);
  }
  for (const k of kids.flat()) if (k != null) e.append(k instanceof Node ? k : document.createTextNode(String(k)));
  return e;
}

function status(text, bad) {
  $("status").textContent = text;
  $("status").className = bad ? "bad" : "";
}

const wsURL = (q) => `${location.protocol === "https:" ? "wss:" : "ws:"}//${location.host}/ws?${q}`;
let info;

async function start() {
  try { info = await (await fetch("/info", { credentials: "same-origin" })).json(); }
  catch { status("Can't reach RyProx", true); return; }
  document.title = info.name;
  $("title").textContent = `${info.name} · ${info.user}`;
  const needUser = info.askUsername && info.usernameUsed;
  if (!needUser && !info.askPassword) return connect({});
  form(needUser);
}

function form(needUser, error) {
  const user = needUser ? el("input", { autocomplete: "username", required: true, spellcheck: "false", autocapitalize: "off" }) : null;
  const pass = info.askPassword ? el("input", { type: "password", autocomplete: "current-password" }) : null;
  const what = { ssh: "terminal", rdp: "Windows desktop", vnc: "desktop" }[info.kind] || "console";
  const f = el("form", { class: "card" },
    el("h1", {}, `Open ${what}`),
    el("p", {}, info.username ? `Signing in as ${info.username}.` : "Sign in to the machine itself."),
    error ? el("p", { class: "err", role: "alert" }, error) : null,
    user ? el("label", {}, el("span", {}, "Username"), user) : null,
    pass ? el("label", {}, el("span", {}, info.kind === "vnc" ? "Screen sharing password" : "Password"), pass) : null,
    el("button", { type: "submit" }, "Connect"));
  f.addEventListener("submit", (ev) => {
    ev.preventDefault();
    connect({ username: user ? user.value : "", password: pass ? pass.value : "" });
  });
  screen.replaceChildren(f);
  (user || pass)?.focus();
}

async function ticket(creds) {
  const res = await fetch("/session", {
    method: "POST", credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-RyProx": "1" },
    body: JSON.stringify({ ...creds, width: screen.clientWidth, height: screen.clientHeight, dpi: Math.round(96 * (window.devicePixelRatio || 1)) }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || "Couldn't start the session");
  return data.ticket;
}

function ended(reason, creds) {
  status(reason || "Disconnected", true);
  screen.append(el("div", { class: "overlay" }, el("div", { class: "card" },
    el("h1", {}, "Disconnected"), el("p", {}, reason || "The connection closed."),
    el("button", { type: "button", onclick: () => (info.askPassword || (info.askUsername && info.usernameUsed) ? form(info.askUsername && info.usernameUsed) : connect(creds)) }, "Reconnect"))));
}

async function connect(creds) {
  status("Connecting…");
  let t;
  try { t = await ticket(creds); }
  catch (e) { return form(info.askUsername && info.usernameUsed, e.message); }
  if (info.kind === "ssh") return terminal(t, creds);
  return desktop(t, creds);
}

// ---------- SSH ----------
function terminal(t, creds) {
  const box = el("div", { class: "term" });
  screen.replaceChildren(box);
  const term = new Terminal({ cursorBlink: true, fontSize: 14, fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
    theme: { background: "#0f1419" }, scrollback: 5000 });
  term.open(box);
  const ws = new WebSocket(wsURL("ticket=" + encodeURIComponent(t)));
  ws.binaryType = "arraybuffer";
  const fit = () => {
    const probe = el("span", { style: "position:absolute;visibility:hidden;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:14px;white-space:pre" }, "W".repeat(50));
    document.body.append(probe);
    const cw = probe.getBoundingClientRect().width / 50;
    probe.remove();
    const ch = Math.ceil(14 * 1.2);
    const cols = Math.max(20, Math.floor((box.clientWidth - 8) / cw));
    const rows = Math.max(5, Math.floor((box.clientHeight - 8) / ch));
    if (cols !== term.cols || rows !== term.rows) term.resize(cols, rows);
    if (ws.readyState === 1) ws.send(`r${term.cols},${term.rows}`);
  };
  ws.onopen = () => { status("Connected"); fit(); term.focus(); };
  ws.onmessage = (m) => term.write(new Uint8Array(m.data));
  ws.onclose = (e) => ended(e.reason, creds);
  term.onData((d) => { if (ws.readyState === 1) ws.send("d" + d); });
  let timer;
  window.addEventListener("resize", () => { clearTimeout(timer); timer = setTimeout(fit, 100); });
}

// ---------- RDP / VNC ----------
function desktop(t, creds) {
  const G = window.Guacamole;
  if (!G) { status("Remote desktop client failed to load", true); return; }
  const wrap = el("div", { class: "desk", tabindex: "0" });
  screen.replaceChildren(wrap);
  const tunnel = new G.WebSocketTunnel(wsURL("").replace(/\?$/, ""));
  const client = new G.Client(tunnel);
  const display = client.getDisplay();
  wrap.append(display.getElement());

  const rescale = () => {
    const w = display.getWidth(), h = display.getHeight();
    if (w && h) display.scale(Math.min(screen.clientWidth / w, screen.clientHeight / h, 1));
  };
  display.onresize = rescale;

  client.onstatechange = (s) => {
    if (s === 3) { status("Connected"); wrap.focus(); }
    if (s === 5) ended("", creds);
  };
  client.onerror = (e) => { ended(e.message || "The remote desktop closed the connection.", creds); };
  tunnel.onerror = (e) => { ended(e.message || "Connection lost.", creds); };

  const mouse = new G.Mouse(display.getElement());
  const send = (e) => client.sendMouseState(e.state, true);
  mouse.onEach(["mousedown", "mouseup", "mousemove"], send);
  const kb = new G.Keyboard(wrap);
  kb.onkeydown = (k) => { client.sendKeyEvent(1, k); return false; };
  kb.onkeyup = (k) => client.sendKeyEvent(0, k);

  let timer;
  window.addEventListener("resize", () => {
    clearTimeout(timer);
    timer = setTimeout(() => { client.sendSize(screen.clientWidth, screen.clientHeight); rescale(); }, 200);
  });
  window.addEventListener("beforeunload", () => client.disconnect());
  client.connect("ticket=" + encodeURIComponent(t));
}

start();

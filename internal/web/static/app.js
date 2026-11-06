// RyProx dashboard. No frameworks, no build step.
// Safety rule: text from the server is only ever set with textContent (via h()),
// never inserted as HTML, so a hostile hostname or header value can't run script.
"use strict";

// ---------- tiny DOM helper ----------
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "class") el.className = v;
    else if (k === "value") el.value = v;
    else if (k === "checked") el.checked = !!v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
const $app = () => document.getElementById("app");
function mount(...nodes) { $app().replaceChildren(...nodes); }
// Element.replaceChildren turns null into the text "null"; drop empty slots first.
for (const proto of [Element.prototype, DocumentFragment.prototype]) {
  const orig = proto.replaceChildren;
  proto.replaceChildren = function (...nodes) { return orig.apply(this, nodes.filter((n) => n != null && n !== false)); };
}

const brandMark = () => {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 32 32");
  svg.setAttribute("aria-hidden", "true");
  for (const [tag, a] of [
    ["rect", { width: 32, height: 32, rx: 7, fill: "currentColor", opacity: ".14" }],
    ["circle", { cx: 9, cy: 16, r: 3.5, fill: "currentColor" }],
    ["path", { d: "M12.5 16h7", stroke: "#2fb39b", "stroke-width": 3, "stroke-linecap": "round" }],
    ["rect", { x: 19.5, y: 10, width: 6, height: 12, rx: 2, fill: "currentColor" }],
  ]) {
    const e = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const [k, v] of Object.entries(a)) e.setAttribute(k, v);
    svg.append(e);
  }
  return svg;
};

// ---------- API ----------
class ApiError extends Error {
  constructor(status, body) {
    super((body && body.error) || `Request failed (${status})`);
    this.status = status;
    this.field = body && body.field;
  }
}
async function api(method, path, body) {
  const opts = { method, headers: { "X-RyProx": "1" }, credentials: "same-origin" };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(path, opts);
  } catch {
    throw new ApiError(0, { error: "Can't reach RyProx. Check it's running." });
  }
  const data = res.headers.get("Content-Type")?.includes("json") ? await res.json() : null;
  if (res.status === 401 && !path.startsWith("/api/login") && !path.startsWith("/api/setup")) {
    state.user = null;
    go("#/login");
    throw new ApiError(401, data);
  }
  if (!res.ok) throw new ApiError(res.status, data);
  return data;
}

// ---------- toasts & confirm ----------
function toast(msg, kind) {
  const t = h("div", { class: "toast" + (kind === "error" ? " error" : "") }, msg);
  document.getElementById("toasts").append(t);
  setTimeout(() => t.remove(), kind === "error" ? 7000 : 3500);
}
function confirmDialog(title, text, okLabel) {
  return new Promise((resolve) => {
    const d = h("dialog", { "aria-labelledby": "dlg-title" },
      h("h2", { id: "dlg-title" }, title),
      h("p", { class: "muted" }, text),
      h("div", { class: "actions" },
        h("span", { class: "spacer" }),
        h("button", { class: "btn", type: "button", onclick: () => d.close("no") }, "Cancel"),
        h("button", { class: "btn primary", type: "button", onclick: () => d.close("yes") }, okLabel)));
    d.addEventListener("close", () => { resolve(d.returnValue === "yes"); d.remove(); });
    document.body.append(d);
    d.showModal();
  });
}

// ---------- form helpers ----------
function field(label, input, hint) {
  const id = input.id || "f" + Math.random().toString(36).slice(2);
  input.id = id;
  const err = h("span", { class: "err", id: id + "-err", hidden: true });
  input.setAttribute("aria-describedby", id + "-err");
  return h("label", { class: "field", for: id }, h("span", {}, label), input, hint ? h("span", { class: "hint" }, hint) : null, err);
}
// Clear a field's error message as soon as the user edits it.
document.addEventListener("input", (ev) => {
  const el = ev.target;
  if (!(el instanceof HTMLElement) || !el.hasAttribute("aria-invalid")) return;
  el.removeAttribute("aria-invalid");
  const msg = el.id && document.getElementById(el.id + "-err");
  if (msg) { msg.hidden = true; msg.textContent = ""; }
});
function clearErrors(root) {
  root.querySelectorAll(".err").forEach((e) => { e.hidden = true; e.textContent = ""; });
  root.querySelectorAll("[aria-invalid]").forEach((e) => e.removeAttribute("aria-invalid"));
  root.querySelector(".banner.error")?.remove();
}
// showError puts the server's message next to the field it names.
function showError(root, err, fieldMap) {
  const name = err.field && (fieldMap?.[err.field] ?? err.field);
  const input = name && root.querySelector(`[data-field="${CSS.escape(name)}"]`);
  if (input) {
    input.setAttribute("aria-invalid", "true");
    const msg = document.getElementById(input.id + "-err");
    if (msg) { msg.textContent = capitalise(err.message); msg.hidden = false; }
    else toast(capitalise(err.message), "error");
    input.focus();
  } else {
    const b = h("div", { class: "banner error", role: "alert" }, capitalise(err.message));
    root.prepend(b);
    b.scrollIntoView({ block: "nearest" });
  }
}
const capitalise = (s) => (s ? s[0].toUpperCase() + s.slice(1) : s);
function busy(btn, on, label) {
  btn.disabled = on;
  if (on) { btn.dataset.label = btn.textContent; btn.textContent = label || "Working…"; }
  else if (btn.dataset.label) btn.textContent = btn.dataset.label;
}
function toggle(label, desc, checked, attrs) {
  return h("label", { class: "switch" },
    h("input", { type: "checkbox", role: "switch", checked, ...(attrs || {}) }),
    h("span", {}, h("b", {}, label), desc ? h("small", {}, desc) : null));
}
const fmtTime = (s) => {
  const d = new Date(s);
  return isNaN(d) || d.getFullYear() < 2000 ? "—" : d.toLocaleString();
};
const ago = (s) => {
  const d = new Date(s);
  if (isNaN(d) || d.getFullYear() < 2000) return "never";
  const sec = Math.round((Date.now() - d) / 1000);
  if (sec < 60) return "just now";
  if (sec < 3600) return `${Math.round(sec / 60)} min ago`;
  if (sec < 86400) return `${Math.round(sec / 3600)} h ago`;
  return d.toLocaleDateString();
};

// ---------- state & router ----------
const state = { user: null, setupRequired: false, insecure: false, version: "" };
let pollTimer = null;

function go(hash) {
  if (location.hash === hash) render();
  else location.hash = hash;
}
window.addEventListener("hashchange", render);

async function boot() {
  try {
    const s = await api("GET", "/api/state");
    state.setupRequired = s.setupRequired;
    state.user = s.user || null;
    state.insecure = s.insecure;
    state.version = s.version;
  } catch (e) {
    mount(h("main", {}, h("div", { class: "banner error" }, e.message)));
    return;
  }
  render();
}

function render() {
  clearInterval(pollTimer);
  const path = location.hash.replace(/^#/, "") || "/";
  if (state.setupRequired) return setupPage();
  if (!state.user) return path === "/login" ? loginPage() : go("#/login");
  if (path === "/login") return go("#/");
  const m = path.match(/^\/routes\/(new|\d+)$/);
  if (m) return routeEditor(m[1] === "new" ? null : Number(m[1]));
  if (path === "/certificates") return certificatesPage();
  if (path === "/people") return peoplePage();
  if (path === "/settings") return settingsPage();
  if (path === "/activity") return activityPage();
  if (path === "/import") return importPage();
  return routesPage();
}

function shell(current, ...content) {
  const link = (href, label, key) => h("a", { href, "aria-current": current === key ? "page" : null }, label);
  const main = h("main", { id: "main" },
    state.insecure ? h("div", { class: "banner", role: "note" },
      "You're using the dashboard over an unencrypted connection from another computer. " +
      "Use an SSH tunnel, or set an admin domain under Settings so your password is protected.") : null,
    ...content);
  mount(h("div", { class: "shell" },
    h("aside", { class: "side" },
      h("div", { class: "brand" }, brandMark(), "RyProx"),
      h("nav", { class: "nav", "aria-label": "Main" },
        link("#/", "Routes", "routes"),
        link("#/people", "People", "people"),
        link("#/certificates", "Certificates", "certs"),
        link("#/activity", "Activity", "activity"),
        link("#/settings", "Settings", "settings")),
      h("div", { class: "side-foot" },
        h("div", {}, state.user?.username),
        h("button", { type: "button", onclick: logout }, "Sign out"))),
    main));
  document.title = "RyProx";
  return main;
}

async function logout() {
  try { await api("POST", "/api/logout"); } catch { /* signed out anyway */ }
  state.user = null;
  go("#/login");
}

// ---------- auth screens ----------
function authLayout(...content) {
  mount(h("div", { class: "auth" },
    h("div", { class: "auth-art", "aria-hidden": "true" },
      h("div", { class: "brand" }, brandMark(), "RyProx"),
      h("div", { class: "art" },
        h("div", { class: "wire", "data-state": "up" }),
        h("div", { class: "wire", "data-state": "up" }),
        h("div", { class: "wire", "data-state": "off" })),
      h("blockquote", {}, "Your domains, wired to your services. Everything set from here.")),
    h("div", { class: "auth-main" }, h("div", { class: "auth-card" }, ...content))));
}

function loginPage() {
  const user = h("input", { type: "text", autocomplete: "username", required: true, "data-field": "username" });
  const pass = h("input", { type: "password", autocomplete: "current-password", required: true, "data-field": "password" });
  const btn = h("button", { class: "btn primary", type: "submit" }, "Sign in");
  const form = h("form", { novalidate: true },
    field("Username", user), field("Password", pass),
    h("div", { class: "actions" }, btn));
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    clearErrors(form);
    busy(btn, true, "Checking…");
    try {
      const r = await api("POST", "/api/login", { username: user.value, password: pass.value });
      codeStep(r.loginToken);
    } catch (e) {
      busy(btn, false);
      showError(form, e);
    }
  });
  const pkBtn = window.RyPasskey?.supported() ? h("button", { class: "btn", type: "button" }, "Sign in with a passkey") : null;
  pkBtn?.addEventListener("click", async () => {
    clearErrors(form);
    busy(pkBtn, true, "Waiting for your device…");
    try {
      const b = await api("POST", "/api/login/passkey/begin", {});
      const cred = await window.RyPasskey.get(b.options);
      await api("POST", `/api/login/passkey/finish?id=${encodeURIComponent(b.id)}`, cred);
      const st = await api("GET", "/api/state");
      state.user = st.user;
      go("#/");
    } catch (e) {
      busy(pkBtn, false);
      showError(form, e instanceof ApiError ? e : { message: window.RyPasskey.message(e) });
    }
  });
  authLayout(h("h1", {}, "Sign in"), h("p", { class: "lede" }, "Manage your routes and certificates."), form,
    pkBtn ? h("div", { class: "or" }, h("span", {}, "or")) : null, pkBtn);
  user.focus();
}

function codeStep(token) {
  const code = h("input", { type: "text", inputmode: "numeric", autocomplete: "one-time-code", "data-field": "code", maxlength: 20 });
  const btn = h("button", { class: "btn primary", type: "submit" }, "Verify");
  const form = h("form", { novalidate: true },
    field("Authenticator code", code, "The 6-digit code from your authenticator app, or one of your recovery codes."),
    h("div", { class: "actions" }, btn, h("button", { class: "linkish", type: "button", onclick: () => loginPage() }, "Start over")));
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    clearErrors(form);
    busy(btn, true, "Verifying…");
    try {
      const r = await api("POST", "/api/login/verify", { loginToken: token, code: code.value });
      const s = await api("GET", "/api/state");
      state.user = s.user;
      if (r.recoveryCodesLeft != null) toast(`Recovery code used. ${r.recoveryCodesLeft} left; make new ones in Settings.`);
      go("#/");
    } catch (e) {
      busy(btn, false);
      if (e.status === 401 && !e.field) { toast(e.message, "error"); return loginPage(); }
      showError(form, e);
      code.select();
    }
  });
  authLayout(h("h1", {}, "Two-step check"), h("p", { class: "lede" }, "Open your authenticator app."), form);
  code.focus();
}

// Setup: 1 account, 2 authenticator, 3 recovery codes.
function setupPage() {
  const data = {};
  const steps = (n) => h("ol", { class: "steps", "aria-label": `Step ${n} of 3` },
    [1, 2, 3].map((i) => h("li", { class: i <= n ? "done" : "" })));

  const stepAccount = () => {
    const sc = h("input", { type: "text", autocomplete: "off", "data-field": "setupCode", spellcheck: "false", class: "mono" });
    const user = h("input", { type: "text", autocomplete: "username", "data-field": "username", value: "admin" });
    const pass = h("input", { type: "password", autocomplete: "new-password", "data-field": "password", minlength: 12 });
    const btn = h("button", { class: "btn primary", type: "submit" }, "Continue");
    const form = h("form", { novalidate: true },
      field("Setup code", sc, h("span", {}, "Printed in the RyProx logs when it started, like ", h("span", { class: "nowrap mono" }, "ABCD-EFGH-JKMN"), ".")),
      field("Admin username", user),
      field("Password", pass, "At least 12 characters. A short sentence works well."),
      h("div", { class: "actions" }, btn));
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      clearErrors(form);
      if (pass.value.length < 12) return showError(form, { field: "password", message: "password must be at least 12 characters" });
      busy(btn, true);
      try {
        const r = await api("POST", "/api/setup/begin", { setupCode: sc.value, username: user.value });
        Object.assign(data, { setupCode: sc.value, username: user.value, password: pass.value }, r);
        stepTOTP();
      } catch (e) { busy(btn, false); showError(form, e); }
    });
    authLayout(steps(1), h("h1", {}, "Welcome to RyProx"),
      h("p", { class: "lede" }, "Create the admin account. Signing in will need your password and a code from an authenticator app."), form);
    sc.focus();
  };

  const stepTOTP = () => {
    const code = h("input", { type: "text", inputmode: "numeric", autocomplete: "one-time-code", "data-field": "totpCode", maxlength: 6 });
    const btn = h("button", { class: "btn primary", type: "submit" }, "Create account");
    const form = h("form", { novalidate: true },
      h("div", { class: "qr" },
        h("img", { src: data.qr, alt: "QR code for your authenticator app" }),
        h("div", {}, h("p", { class: "muted" }, "Can't scan? Enter this key instead:"), h("div", { class: "secret" }, data.totpSecret))),
      field("Code from the app", code),
      h("div", { class: "actions" }, btn, h("button", { class: "linkish", type: "button", onclick: stepAccount }, "Back")));
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      clearErrors(form);
      busy(btn, true, "Creating…");
      try {
        const r = await api("POST", "/api/setup/finish", {
          setupCode: data.setupCode, username: data.username, password: data.password,
          totpSecret: data.totpSecret, totpCode: code.value,
        });
        data.password = null;
        stepCodes(r.recoveryCodes);
      } catch (e) {
        busy(btn, false);
        showError(form, e, { password: "totpCode", username: "totpCode" });
      }
    });
    authLayout(steps(2), h("h1", {}, "Add your authenticator"),
      h("p", { class: "lede" }, "Scan this with Google Authenticator, 1Password, Aegis or any authenticator app, then enter the code it shows."), form);
    code.focus();
  };

  const stepCodes = (codes) => {
    const text = "RyProx recovery codes\nEach code works once if you lose your authenticator.\n\n" + codes.join("\n") + "\n";
    const saved = h("input", { type: "checkbox" });
    const btn = h("button", { class: "btn primary", type: "button", disabled: true, onclick: async () => {
      const s = await api("GET", "/api/state");
      Object.assign(state, { setupRequired: false, user: s.user });
      go("#/settings");
      toast("Account created. Next, turn on automatic HTTPS.");
    } }, "Go to dashboard");
    saved.addEventListener("change", () => { btn.disabled = !saved.checked; });
    authLayout(steps(3), h("h1", {}, "Save your recovery codes"),
      h("p", { class: "lede" }, "If you lose your phone, each code lets you sign in once. They won't be shown again."),
      h("div", { class: "codes" }, codes.map((c) => h("span", {}, c))),
      h("div", { class: "row" },
        h("button", { class: "btn", type: "button", onclick: () => download("ryprox-recovery-codes.txt", text) }, "Download"),
        h("button", { class: "btn", type: "button", onclick: () => copy(codes.join("\n")) }, "Copy")),
      h("label", { class: "switch mt-l" }, saved, h("span", {}, h("b", {}, "I've saved these somewhere safe"))),
      h("div", { class: "actions" }, btn));
  };

  stepAccount();
}

function download(name, text) {
  const a = h("a", { href: URL.createObjectURL(new Blob([text], { type: "text/plain" })), download: name });
  document.body.append(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
}
async function copy(text) {
  try { await navigator.clipboard.writeText(text); toast("Copied"); }
  catch { toast("Couldn't copy. Select the text and copy it instead.", "error"); }
}

// ---------- routes (the switchboard) ----------
function wireState(route) {
  if (!route.enabled) return "off";
  const hs = route.health || [];
  const down = hs.filter((x) => x.state === "down").length;
  const up = hs.filter((x) => x.state === "up").length;
  if (down && down === hs.length) return "down";
  if (down) return "partial";
  if (up) return "up";
  return "unknown";
}
function certPill(c, httpsOn) {
  if (!httpsOn) return h("span", { class: "pill" }, "HTTP");
  const map = {
    valid: ["ok", c.staging ? "Test certificate" : "HTTPS"],
    pending: ["wait", "Getting certificate"],
    error: ["bad", "Certificate failed"],
    expired: ["bad", "Certificate expired"],
  };
  const [cls, label] = map[c.state] || ["", c.state];
  return h("span", { class: "pill " + cls, title: c.error || "" }, label);
}

function accessPill(a) {
  if (a && a.mode === "public") return h("span", { class: "pill wait", title: "Anyone on the internet can open this site" }, "Public");
  const n = (a && a.users ? a.users.length : 0);
  return h("span", { class: "pill ok", title: "Only chosen people, after signing in" }, n === 1 ? "Private · 1 person" : `Private · ${n} people`);
}

async function routesPage() {
  const board = h("div", { class: "board", "aria-busy": "true" });
  const main = shell("routes",
    h("div", { class: "page-head" },
      h("div", {}, h("h1", {}, "Routes"), h("p", { class: "lede" }, "Each route connects a domain to the services behind it. Changes go live as soon as you save.")),
      h("div", { class: "row" }, h("a", { class: "btn", href: "#/import" }, "Import"), h("a", { class: "btn primary", href: "#/routes/new" }, "Add route"))),
    board);

  const load = async () => {
    let data;
    try { data = await api("GET", "/api/routes"); } catch (e) { if (e.status !== 401) board.replaceChildren(h("div", { class: "banner error" }, e.message)); return; }
    board.removeAttribute("aria-busy");
    if (!data.routes.length) {
      board.replaceChildren(h("div", { class: "empty" },
        h("div", { class: "wire", "data-state": "off" }),
        h("h2", {}, "No routes yet"),
        h("p", {}, "Add a route to send a domain like app.example.com to a service on your network, like http://192.168.1.10:8080."),
        h("a", { class: "btn primary", href: "#/routes/new" }, "Add your first route")));
      return;
    }
    if (!data.httpsEnabled && !main.querySelector(".banner.https")) {
      main.insertBefore(h("div", { class: "banner https" }, "HTTPS is off, so these routes are served over plain HTTP. ",
        h("a", { href: "#/settings" }, "Turn on automatic HTTPS")), board);
    }
    board.replaceChildren(...data.routes.map((r) => routeRow(r, data.httpsEnabled, load)));
  };
  await load();
  pollTimer = setInterval(load, 10000);
}

function routeRow(r, httpsOn, reload) {
  const ws = wireState(r);
  const scheme = httpsOn ? "https" : "http";
  const health = Object.fromEntries((r.health || []).map((x) => [x.url, x]));
  const sw = h("input", { type: "checkbox", role: "switch", checked: r.enabled, "aria-label": `Route ${r.hostname} on` });
  sw.addEventListener("change", async () => {
    sw.disabled = true;
    try {
      await api("POST", `/api/routes/${r.id}/enabled`, { enabled: sw.checked });
      toast(sw.checked ? `${r.hostname} is on` : `${r.hostname} is off`);
      reload();
    } catch (e) { sw.checked = !sw.checked; toast(e.message, "error"); }
    finally { sw.disabled = false; }
  });
  const stateLabel = { up: "All services healthy", partial: "Some services down", down: "All services down", unknown: "No health check", off: "Route is off" }[ws];
  return h("div", { class: "wire-row" + (r.enabled ? "" : " off") },
    h("label", { class: "switch m0" }, sw),
    h("div", { class: "host" },
      h("a", { href: `${scheme}://${r.hostname}`, target: "_blank", rel: "noopener noreferrer" }, r.hostname),
      h("div", { class: "meta" }, certPill(r.cert, httpsOn), " ", accessPill(r.config.access), " ",
        r.config.expiresAt ? h("span", { class: "pill " + (new Date(r.config.expiresAt) < new Date() ? "bad" : "wait"), title: fmtTime(r.config.expiresAt) },
          new Date(r.config.expiresAt) < new Date() ? "Expired" : "Until " + new Date(r.config.expiresAt).toLocaleString([], { dateStyle: "short", timeStyle: "short" })) : null, " ",
        r.config.targets.length > 1 ? (r.config.loadBalancing === "failover" ? "Failover" : "Load balanced") : "")),
    h("div", { class: "wire", "data-state": ws, role: "img", "aria-label": stateLabel, title: stateLabel }),
    r.config.kind === "redirect"
      ? h("ul", { class: "targets", "aria-label": "Redirect" }, h("li", {}, "→ ", r.config.redirect.to, r.config.redirect.keepPath ? "/…" : ""))
      : h("ul", { class: "targets", "aria-label": "Services" },
        [...r.config.targets.map((t) => ["", t]), ...(r.config.paths || []).flatMap((p) => p.targets.map((t) => [p.prefix + " → ", t]))].map(([prefix, t]) => {
          const st = health[t.url];
          const cls = st?.state === "up" ? "up" : st?.state === "down" ? "down" : "";
          const tip = st?.state === "down" ? `Down: ${st.lastError || "not responding"}` : st?.state === "up" ? `Up, ${st.latencyMs} ms` : "Not checked";
          const up = st && st.uptime >= 0 ? h("span", { class: "uptime", title: "Uptime over the last 24 hours" }, `${(st.uptime * 100).toFixed(st.uptime === 1 ? 0 : 1)}%`) : null;
          return h("li", { title: tip }, h("span", { class: "dot " + cls, "aria-label": tip }), prefix, t.url, up);
        })),
    h("div", { class: "tools" }, h("a", { class: "btn small", href: `#/routes/${r.id}` }, "Edit")));
}

// ---------- route editor ----------
function defaultRoute() {
  return {
    hostname: "", enabled: true,
    config: {
      kind: "proxy", targets: [{ url: "" }], paths: [], landingPath: "",
      redirect: { to: "", code: 301, keepPath: true }, rateLimit: { requestsPerMinute: 0 },
      loadBalancing: "round_robin", tlsSkipVerify: false, websockets: true,
      httpsRedirect: true, preserveHost: false, requestHeaders: [], responseHeaders: [],
      healthCheck: { enabled: false, path: "/", intervalSeconds: 15 },
      access: { mode: "private", users: [] },
    },
  };
}

async function routeEditor(id) {
  let route = defaultRoute();
  let people, settings;
  try { [people, settings] = await Promise.all([api("GET", "/api/people"), api("GET", "/api/settings")]); } catch { return; }
  if (id == null) route.config.access.users = [people.me]; // you, to start with
  if (id != null) {
    try {
      const data = await api("GET", "/api/routes");
      const found = data.routes.find((r) => r.id === id);
      if (!found) { toast("That route doesn't exist any more.", "error"); return go("#/"); }
      route = { hostname: found.hostname, enabled: found.enabled, config: structuredClone(found.config) };
      route.config.requestHeaders ||= [];
      route.config.responseHeaders ||= [];
      route.config.access ||= { mode: "private", users: [] };
      route.config.access.users ||= [];
      route.config.kind ||= "proxy";
      route.config.paths ||= [];
      route.config.redirect = route.config.redirect?.to ? route.config.redirect : { to: "", code: 301, keepPath: true };
      route.config.rateLimit ||= { requestsPerMinute: 0 };
      if (!route.config.targets?.length) route.config.targets = [{ url: "" }];
    } catch { return; }
  }
  const c = route.config;
  const form = h("form", { novalidate: true });

  // Basics
  const host = h("input", { type: "text", "data-field": "hostname", value: route.hostname, placeholder: "app.example.com", spellcheck: "false", class: "mono", autocapitalize: "off" });
  const enabled = toggle("Route is on", "Turn off to stop serving this domain without deleting the route.", route.enabled);

  // Access: private by default (zero trust); public is an explicit choice.
  const accessPrivate = h("input", { type: "radio", name: "access", value: "private", checked: c.access.mode !== "public", "data-field": "access.mode" });
  const accessPublic = h("input", { type: "radio", name: "access", value: "public", checked: c.access.mode === "public" });
  const chosen = new Set(c.access.users);
  const peopleList = h("div", { class: "people-pick", "data-field": "access.users", tabindex: "-1" },
    people.people.map((p) => h("label", { class: "pick" },
      h("input", { type: "checkbox", value: String(p.id), checked: chosen.has(p.id) }),
      h("span", {}, p.username, p.id === people.me ? " (you)" : "", p.disabled ? " · disabled" : ""),
      h("span", { class: "muted" }, p.role === "admin" ? "Admin" : "Member"))));
  const noOne = h("div", { class: "warn-inline flush", hidden: true }, "Nobody is chosen, so nobody can open this site.");
  const syncPeople = () => {
    const priv = accessPrivate.checked;
    peopleList.hidden = !priv;
    if (httpsNote) httpsNote.hidden = !priv;
    publicWarn.hidden = priv;
    noOne.hidden = !priv || peopleList.querySelector("input:checked") != null;
  };
  const publicWarn = h("div", { class: "warn-inline flush", hidden: true },
    "Anyone on the internet can open this site, without signing in. Only choose this for things meant to be public, and make sure the app has its own login.");
  peopleList.addEventListener("change", syncPeople);
  const invitePeople = h("p", { class: "muted mt" }, "Need someone else? ", h("a", { href: "#/people" }, "Invite them on the People page"), ".");
  const signInReady = settings.tlsMode === "acme" && (settings.authHostname || settings.adminHostname);
  const httpsNote = signInReady ? null : h("div", { class: "warn-inline flush" },
    "Nobody can sign in to private sites yet: they need automatic HTTPS and a sign-in domain. ",
    h("a", { href: "#/settings" }, "Set them up in Settings"), ".");

  // Targets
  const tlist = h("div", { class: "target-list" });
  const addTarget = (url) => {
    const input = h("input", { type: "text", value: url, placeholder: "http://192.168.1.10:8080", spellcheck: "false", autocapitalize: "off", "aria-label": "Service address" });
    const result = h("div", { class: "test-result", hidden: true });
    const testBtn = h("button", { class: "btn small", type: "button" }, "Test");
    testBtn.addEventListener("click", async () => {
      busy(testBtn, true, "Testing…");
      result.hidden = false;
      result.replaceChildren(h("span", { class: "muted" }, "Connecting…"));
      try {
        const st = await api("POST", "/api/test-target", { url: input.value, tlsSkipVerify: skip.querySelector("input").checked });
        result.replaceChildren(st.state === "up"
          ? h("span", {}, h("span", { class: "dot up" }), ` Reachable in ${st.latencyMs} ms`)
          : h("span", { class: "err" }, h("span", { class: "dot down" }), ` Not reachable: ${st.lastError}`));
      } catch (e) {
        result.replaceChildren(h("span", { class: "err" }, capitalise(e.message)));
      } finally { busy(testBtn, false); }
    });
    const rm = h("button", { class: "btn small", type: "button", "aria-label": "Remove service" }, "Remove");
    const item = h("div", { class: "target-item" }, input, testBtn, rm, result);
    rm.addEventListener("click", () => { if (tlist.children.length > 1) { item.remove(); renumber(); } });
    tlist.append(item);
    renumber();
  };
  const lbWrap = h("div", {});
  const lb = h("select", { "data-field": "loadBalancing" },
    h("option", { value: "round_robin" }, "Spread requests across all services"),
    h("option", { value: "failover" }, "Use the first service; switch only if it's down"));
  lb.value = c.loadBalancing || "round_robin";
  lbWrap.append(field("When there's more than one service", lb));
  const renumber = () => {
    [...tlist.children].forEach((item, i) => {
      const input = item.querySelector("input");
      input.dataset.field = `targets.${i}`;
      input.id = `target-${i}`;
      let err = item.querySelector(".err");
      if (!err) { err = h("span", { class: "err", hidden: true }); item.insertBefore(err, item.querySelector(".test-result")); }
      err.id = `target-${i}-err`;
      input.setAttribute("aria-describedby", err.id);
    });
    lbWrap.hidden = tlist.children.length < 2;
  };
  c.targets.forEach((t) => addTarget(t.url));

  // Options
  const redirect = toggle("Redirect HTTP to HTTPS", "Visitors who type http:// are sent to the secure address.", c.httpsRedirect);
  const ws = toggle("Allow WebSockets", "Needed by many apps for live updates (Home Assistant, chat apps, dashboards).", c.websockets);
  const preserve = toggle("Pass the original domain to the service", "Turn on if the app needs to know which domain it was opened on.", c.preserveHost);
  const skip = toggle("Accept the service's self-signed certificate", "Only for https:// services on your own network.", c.tlsSkipVerify);
  const skipWarn = h("div", { class: "warn-inline", hidden: !c.tlsSkipVerify }, "RyProx won't check the service's certificate, so only use this inside a network you trust.");
  skip.querySelector("input").addEventListener("change", (e) => { skipWarn.hidden = !e.target.checked; });

  // Health check
  const hc = toggle("Check that services are up", "RyProx regularly requests a page and stops sending visitors to services that fail.", c.healthCheck.enabled);
  const hcPath = h("input", { type: "text", "data-field": "healthCheck.path", value: c.healthCheck.path || "/", class: "mono" });
  const hcInt = h("input", { type: "number", min: 5, max: 3600, "data-field": "healthCheck.intervalSeconds", value: c.healthCheck.intervalSeconds || 15 });
  const hcFields = h("div", { class: "two", hidden: !c.healthCheck.enabled }, field("Page to check", hcPath, "For example / or /health"), field("Every (seconds)", hcInt));
  hc.querySelector("input").addEventListener("change", (e) => { hcFields.hidden = !e.target.checked; });

  // Header rules
  const rulesEditor = (rules, prefix, nameHint) => {
    const list = h("div", { class: "rules" });
    const addRule = (rule) => {
      const action = h("select", { "aria-label": "Action" }, h("option", { value: "set" }, "Set"), h("option", { value: "remove" }, "Remove"));
      action.value = rule.action || "set";
      const name = h("input", { type: "text", value: rule.name || "", placeholder: nameHint, "aria-label": "Header name", spellcheck: "false" });
      const value = h("input", { type: "text", value: rule.value || "", placeholder: "Value", "aria-label": "Header value", spellcheck: "false" });
      const rm = h("button", { class: "btn small", type: "button", "aria-label": "Remove rule" }, "Remove");
      const row = h("div", { class: "rule" }, action, name, value, rm);
      const sync = () => { value.disabled = action.value === "remove"; };
      action.addEventListener("change", sync); sync();
      rm.addEventListener("click", () => { row.remove(); renum(); });
      list.append(row);
      renum();
    };
    const renum = () => [...list.children].forEach((row, i) => { row.querySelector("input").dataset.field = `${prefix}.${i}`; });
    rules.forEach(addRule);
    const read = () => [...list.children].map((row) => {
      const [a, n, v] = row.querySelectorAll("select, input");
      return { action: a.value, name: n.value.trim(), value: a.value === "set" ? v.value : "" };
    });
    return { el: h("div", {}, list, h("button", { class: "btn small", type: "button", onclick: () => addRule({}) }, "Add header rule")), read };
  };
  const reqRules = rulesEditor(c.requestHeaders, "requestHeaders", "X-Example");
  const resRules = rulesEditor(c.responseHeaders, "responseHeaders", "X-Frame-Options");

  // What the route does: proxy to services, or redirect elsewhere.
  const kindProxy = h("input", { type: "radio", name: "kind", value: "proxy", checked: c.kind !== "redirect", "data-field": "kind" });
  const kindRedirect = h("input", { type: "radio", name: "kind", value: "redirect", checked: c.kind === "redirect" });
  const rdTo = h("input", { type: "text", "data-field": "redirect.to", value: c.redirect.to, placeholder: "https://example.com", spellcheck: "false", autocapitalize: "off", class: "mono" });
  const rdCode = h("select", { "data-field": "redirect.code" },
    h("option", { value: "301" }, "Permanent (301)"), h("option", { value: "302" }, "Temporary (302)"),
    h("option", { value: "308" }, "Permanent, keep method (308)"), h("option", { value: "307" }, "Temporary, keep method (307)"));
  rdCode.value = String(c.redirect.code || 301);
  const rdKeep = toggle("Keep the rest of the address", "www.example.com/a?b=1 goes to example.com/a?b=1, not just example.com.", c.redirect.keepPath);
  const redirectSection = h("section", { class: "section" },
    h("header", {}, h("h2", {}, "Redirect"), h("p", {}, "Visitors to this domain are sent straight to another address.")),
    field("Send visitors to", rdTo, "The full address, starting with https://"),
    field("Kind of redirect", rdCode, "Use permanent for things like www to the bare domain."),
    rdKeep);

  // Start page and path rules
  const landing = h("input", { type: "text", "data-field": "landingPath", value: c.landingPath || "", placeholder: "/page1", spellcheck: "false", autocapitalize: "off", class: "mono" });
  const plist = h("div", { class: "rules" });
  const addPath = (rule) => {
    const prefix = h("input", { type: "text", value: rule.prefix || "", placeholder: "/api", "aria-label": "Path", spellcheck: "false", autocapitalize: "off", class: "mono" });
    const target = h("input", { type: "text", value: (rule.targets || []).map((t) => t.url).join(", "), placeholder: "http://192.168.1.11:9000", "aria-label": "Service for this path", spellcheck: "false", autocapitalize: "off", class: "mono" });
    const strip = h("label", { class: "pick", title: "Remove the path before sending, so /api/users reaches the service as /users" },
      h("input", { type: "checkbox", checked: !!rule.stripPrefix }), h("span", {}, "Strip"));
    const rm = h("button", { class: "btn small", type: "button", "aria-label": "Remove path rule" }, "Remove");
    const row = h("div", { class: "rule path-rule" }, prefix, target, strip, rm);
    rm.addEventListener("click", () => { row.remove(); renumPaths(); });
    plist.append(row);
    renumPaths();
  };
  const renumPaths = () => [...plist.children].forEach((row, i) => {
    const [p, t] = row.querySelectorAll("input[type=text]");
    p.dataset.field = `paths.${i}.prefix`;
    t.dataset.field = `paths.${i}.targets.0`;
  });
  c.paths.forEach(addPath);
  const readPaths = () => [...plist.children].map((row) => {
    const [p, t] = row.querySelectorAll("input[type=text]");
    return { prefix: p.value.trim(), targets: t.value.split(",").map((u) => u.trim()).filter(Boolean).map((url) => ({ url })),
      stripPrefix: row.querySelector("input[type=checkbox]").checked };
  });

  // Limits and expiry
  const rate = h("input", { type: "number", min: 0, max: 1000000, "data-field": "rateLimit.requestsPerMinute", value: c.rateLimit.requestsPerMinute || 0 });
  const toLocal = (iso) => { const d = new Date(iso); d.setMinutes(d.getMinutes() - d.getTimezoneOffset()); return d.toISOString().slice(0, 16); };
  const temp = toggle("Temporary route", "Stops working at the time you choose. Handy for sharing something for a day.", !!c.expiresAt);
  const expires = h("input", { type: "datetime-local", "data-field": "expiresAt", value: c.expiresAt ? toLocal(c.expiresAt) : toLocal(Date.now() + 86400000) });
  const expiresWrap = h("div", { hidden: !c.expiresAt }, field("Stops working at", expires, "Your local time."));
  temp.querySelector("input").addEventListener("change", (e) => { expiresWrap.hidden = !e.target.checked; });

  const saveBtn = h("button", { class: "btn primary", type: "submit" }, id == null ? "Add route" : "Save changes");
  const delBtn = id == null ? null : h("button", { class: "btn danger", type: "button" }, "Delete route");

  form.append(
    h("section", { class: "section" },
      h("header", {}, h("h2", {}, "Domain")),
      field("Domain name", host, "Point this domain's DNS at this server first."),
      enabled,
      h("label", { class: "switch mt" }, kindProxy, h("span", {}, h("b", {}, "Send to services on my network"), h("small", {}, "A normal reverse proxy route."))),
      h("label", { class: "switch" }, kindRedirect, h("span", {}, h("b", {}, "Redirect to another address"), h("small", {}, "For example www.example.com to example.com.")))),
    redirectSection,
    h("section", { class: "section" },
      h("header", {}, h("h2", {}, "Who can open this site?"), h("p", {}, "RyProx checks every request. People must sign in with their password and authenticator code.")),
      h("label", { class: "switch" }, accessPrivate, h("span", {}, h("b", {}, "Only people I choose"), h("small", {}, "Recommended. Everyone else gets a sign-in page."))),
      peopleList, noOne, httpsNote, invitePeople,
      h("label", { class: "switch mt" }, accessPublic, h("span", {}, h("b", {}, "Anyone on the internet"), h("small", {}, "No sign-in. For public websites."))),
      publicWarn),
    h("section", { class: "section proxy-only" },
      h("header", {}, h("h2", {}, "Services"), h("p", {}, "Where visitors are sent. Use the address you'd type on your own network.")),
      tlist,
      h("button", { class: "btn small", type: "button", onclick: () => addTarget("") }, "Add another service"),
      h("div", { class: "mt" }, lbWrap),
      h("p", { class: "muted mt" }, "If the app lives under a sub-path on its server, include it: http://192.168.1.10:8080/app.")),
    h("section", { class: "section proxy-only" },
      h("header", {}, h("h2", {}, "Pages and paths"), h("p", {}, "Optional. Open a specific page by default, or send parts of the site to other services.")),
      field("Start page", landing, "Visitors who open the bare domain land here, for example /page1. Leave empty for the home page."),
      h("h3", { class: "mt-l" }, "Path rules"),
      h("p", { class: "muted" }, "Requests starting with the path go to its service. The longest matching path wins."),
      plist,
      h("button", { class: "btn small", type: "button", onclick: () => addPath({}) }, "Add path rule")),
    h("section", { class: "section proxy-only" },
      h("header", {}, h("h2", {}, "Options")),
      redirect, ws, preserve, skip, skipWarn),
    h("section", { class: "section" },
      h("header", {}, h("h2", {}, "Limits")),
      field("Requests per minute from one address", rate, "0 means no limit. Visitors over the limit are asked to wait."),
      temp, expiresWrap),
    h("section", { class: "section proxy-only" },
      h("header", {}, h("h2", {}, "Health check")),
      hc, hcFields),
    h("details", { class: "section proxy-only" },
      h("summary", {}, h("b", {}, "Header rules"), h("span", { class: "muted" }, " (advanced)")),
      h("div", { class: "mt" },
        h("h3", {}, "Sent to the service"), h("p", { class: "muted" }, "Add or remove headers on requests going to your service."), reqRules.el,
        h("h3", { class: "mt-l" }, "Sent to visitors"), h("p", { class: "muted" }, "Add or remove headers on responses going back to visitors."), resRules.el)),
    h("div", { class: "actions" }, saveBtn, h("a", { class: "btn", href: "#/" }, "Cancel"), h("span", { class: "spacer" }), delBtn));

  if (route.config.requestHeaders.length || route.config.responseHeaders.length) form.querySelector("details").open = true;

  accessPrivate.addEventListener("change", syncPeople);
  accessPublic.addEventListener("change", syncPeople);
  syncPeople();
  const syncKind = () => {
    const isRedirect = kindRedirect.checked;
    redirectSection.hidden = !isRedirect;
    form.querySelectorAll(".proxy-only").forEach((el) => { el.hidden = isRedirect; });
  };
  kindProxy.addEventListener("change", syncKind);
  kindRedirect.addEventListener("change", syncKind);
  syncKind();

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    clearErrors(form);
    const body = {
      hostname: host.value,
      enabled: enabled.querySelector("input").checked,
      config: {
        kind: kindRedirect.checked ? "redirect" : "proxy",
        redirect: { to: rdTo.value, code: Number(rdCode.value), keepPath: rdKeep.querySelector("input").checked },
        landingPath: landing.value.trim(),
        paths: readPaths(),
        rateLimit: { requestsPerMinute: Number(rate.value) || 0 },
        expiresAt: temp.querySelector("input").checked && expires.value ? new Date(expires.value).toISOString() : null,
        targets: [...tlist.querySelectorAll("input")].map((i) => ({ url: i.value })),
        loadBalancing: lb.value,
        tlsSkipVerify: skip.querySelector("input").checked,
        websockets: ws.querySelector("input").checked,
        httpsRedirect: redirect.querySelector("input").checked,
        preserveHost: preserve.querySelector("input").checked,
        requestHeaders: reqRules.read(),
        responseHeaders: resRules.read(),
        healthCheck: { enabled: hc.querySelector("input").checked, path: hcPath.value, intervalSeconds: Number(hcInt.value) || 15 },
        access: {
          mode: accessPublic.checked ? "public" : "private",
          users: [...peopleList.querySelectorAll("input:checked")].map((i) => Number(i.value)),
        },
      },
    };
    busy(saveBtn, true, "Saving…");
    try {
      await api(id == null ? "POST" : "PUT", id == null ? "/api/routes" : `/api/routes/${id}`, body);
      toast(id == null ? `Route added. ${body.hostname.trim().toLowerCase()} is live.` : "Changes saved and live.");
      go("#/");
    } catch (e) {
      busy(saveBtn, false);
      // Errors on header rules live inside a closed <details>.
      if (e.field && /Headers/.test(e.field)) form.querySelector("details").open = true;
      if (e.field && /^paths\.\d+\.targets\.\d+$/.test(e.field)) e.field = e.field.replace(/targets\.\d+$/, "targets.0");
      if (e.field && /^(requestHeaders|responseHeaders)\.\d+$/.test(e.field)) {
        const el = form.querySelector(`[data-field="${e.field}"]`);
        if (el) { el.setAttribute("aria-invalid", "true"); el.focus(); }
        toast(capitalise(e.message), "error");
        return;
      }
      showError(form, e);
    }
  });

  delBtn?.addEventListener("click", async () => {
    if (!(await confirmDialog("Delete this route?", `${route.hostname} will stop working straight away.`, "Delete route"))) return;
    try {
      await api("DELETE", `/api/routes/${id}`);
      toast("Route deleted.");
      go("#/");
    } catch (e) { toast(e.message, "error"); }
  });

  shell("routes",
    h("div", { class: "page-head" }, h("div", {},
      h("h1", {}, id == null ? "Add route" : route.hostname),
      h("p", { class: "lede" }, id == null ? "Send a domain to a service on your network." : "Edit where this domain goes and how."))),
    form);
  (id == null ? host : saveBtn).focus();
}

// ---------- certificates ----------
async function certificatesPage() {
  const body = h("div", { "aria-busy": "true" });
  shell("certs",
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Certificates"),
      h("p", { class: "lede" }, "RyProx gets a free certificate from Let's Encrypt for each domain and renews it automatically."))),
    body);
  const load = async () => {
    let d;
    try { d = await api("GET", "/api/certificates"); } catch { return; }
    body.removeAttribute("aria-busy");
    const parts = [];
    if (!d.httpsEnabled) parts.push(h("div", { class: "banner" }, "Automatic HTTPS is off. ", h("a", { href: "#/settings" }, "Turn it on in Settings")));
    else if (d.staging) parts.push(h("div", { class: "banner" }, "You're using test certificates. Browsers will show a warning until you switch to real certificates in Settings."));
    if (!d.certificates.length) {
      parts.push(h("div", { class: "empty" }, h("h2", {}, "No domains yet"), h("p", {}, "Certificates appear here when you add a route.")));
    } else {
      parts.push(h("div", { class: "table-wrap" }, h("table", { class: "table" },
        h("thead", {}, h("tr", {}, ["Domain", "Used for", "Status", "Expires", ""].map((x) => h("th", { scope: "col" }, x)))),
        h("tbody", {}, d.certificates.map((c) => h("tr", {},
          h("td", { class: "mono" }, c.host),
          h("td", {}, c.purpose),
          h("td", {}, certPill(c, d.httpsEnabled), c.error ? h("div", { class: "err cert-err" }, c.error) : null),
          h("td", {}, c.notAfter ? fmtTime(c.notAfter) : "—"),
          h("td", {}, d.httpsEnabled && c.state !== "valid"
            ? h("button", { class: "btn small", type: "button", onclick: async (ev) => {
                busy(ev.target, true, "Requesting…");
                try { await api("POST", `/api/certificates/${encodeURIComponent(c.host)}/retry`); toast("Requested. This can take a minute."); }
                catch (e) { toast(e.message, "error"); }
                setTimeout(load, 4000);
              } }, "Try again") : null)))))));
      parts.push(h("p", { class: "muted mt narrow" },
        "If a certificate fails: check the domain's DNS points at this server, and that ports 80 and 443 reach RyProx from the internet."));
    }
    body.replaceChildren(...parts);
  };
  await load();
  pollTimer = setInterval(load, 10000);
}

// ---------- settings ----------
async function settingsPage() {
  let s;
  try { s = await api("GET", "/api/settings"); } catch { return; }

  // HTTPS
  const httpsForm = h("form", { novalidate: true });
  const modeAuto = h("input", { type: "radio", name: "mode", value: "acme", checked: s.tlsMode === "acme" });
  const modeOff = h("input", { type: "radio", name: "mode", value: "off", checked: s.tlsMode !== "acme", "data-field": "tlsMode" });
  const email = h("input", { type: "email", "data-field": "acmeEmail", value: s.acmeEmail, autocomplete: "email" });
  const staging = toggle("Use test certificates", "Recommended while you try things out. Browsers show a warning, but you won't hit Let's Encrypt's limits.", s.acmeStaging);
  const admin = h("input", { type: "text", "data-field": "adminHostname", value: s.adminHostname, placeholder: "ryprox.example.com", class: "mono", spellcheck: "false", autocapitalize: "off" });
  const signin = h("input", { type: "text", "data-field": "authHostname", value: s.authHostname || "", placeholder: "login.example.com", class: "mono", spellcheck: "false", autocapitalize: "off" });
  const acmeBits = h("div", { hidden: s.tlsMode !== "acme" },
    field("Email for Let's Encrypt", email, "Used only for certificate expiry warnings."),
    staging,
    field("Sign-in domain", signin, "Where people sign in to open private sites, e.g. login.example.com. Needs its own DNS record."),
    field("Dashboard domain (optional)", admin, "Open this dashboard at its own domain. Leave empty to only use it from this server. If no sign-in domain is set, people sign in here."));
  const sync = () => { acmeBits.hidden = !modeAuto.checked; };
  modeAuto.addEventListener("change", sync); modeOff.addEventListener("change", sync);
  const saveHttps = h("button", { class: "btn primary", type: "submit" }, "Save HTTPS settings");
  httpsForm.append(
    h("fieldset", { class: "bare" },
      h("legend", { class: "sr" }, "HTTPS mode"),
      h("label", { class: "switch" }, modeAuto, h("span", {}, h("b", {}, "Automatic HTTPS"), h("small", {}, "Free certificates from Let's Encrypt. Needs ports 80 and 443 open to the internet."))),
      h("label", { class: "switch" }, modeOff, h("span", {}, h("b", {}, "HTTP only"), h("small", {}, "For testing, or when another proxy in front of RyProx handles HTTPS.")))),
    acmeBits, h("div", { class: "actions" }, saveHttps));
  httpsForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    clearErrors(httpsForm);
    busy(saveHttps, true, "Saving…");
    try {
      await api("PUT", "/api/settings", {
        tlsMode: modeAuto.checked ? "acme" : "off", acmeEmail: email.value,
        acmeStaging: staging.querySelector("input").checked, adminHostname: admin.value, authHostname: signin.value,
      });
      toast(modeAuto.checked ? "Saved. Certificates are being requested." : "Saved.");
    } catch (e) { showError(httpsForm, e); }
    finally { busy(saveHttps, false); }
  });

  // Password
  const pwForm = h("form", { novalidate: true });
  const cur = h("input", { type: "password", autocomplete: "current-password", "data-field": "current" });
  const nw = h("input", { type: "password", autocomplete: "new-password", "data-field": "new" });
  const pwBtn = h("button", { class: "btn", type: "submit" }, "Change password");
  pwForm.append(field("Current password", cur), field("New password", nw, "At least 12 characters. Other devices will be signed out."), h("div", { class: "actions" }, pwBtn));
  pwForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    clearErrors(pwForm);
    busy(pwBtn, true, "Saving…");
    try {
      await api("POST", "/api/account/password", { current: cur.value, new: nw.value });
      cur.value = nw.value = "";
      toast("Password changed. Other devices were signed out.");
      loadSessions();
    } catch (e) { showError(pwForm, e); }
    finally { busy(pwBtn, false); }
  });

  // Recovery codes
  const rcForm = h("form", { novalidate: true });
  const rcPw = h("input", { type: "password", autocomplete: "current-password", "data-field": "password" });
  const rcBtn = h("button", { class: "btn", type: "submit" }, "Make new recovery codes");
  const rcOut = h("div", {});
  rcForm.append(field("Confirm your password", rcPw, "Your old recovery codes will stop working."), h("div", { class: "actions" }, rcBtn), rcOut);
  rcForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    clearErrors(rcForm);
    busy(rcBtn, true);
    try {
      const r = await api("POST", "/api/account/recovery-codes", { password: rcPw.value });
      rcPw.value = "";
      const text = "RyProx recovery codes\n\n" + r.recoveryCodes.join("\n") + "\n";
      rcOut.replaceChildren(
        h("div", { class: "codes mt" }, r.recoveryCodes.map((c) => h("span", {}, c))),
        h("div", { class: "row" },
          h("button", { class: "btn small", type: "button", onclick: () => download("ryprox-recovery-codes.txt", text) }, "Download"),
          h("button", { class: "btn small", type: "button", onclick: () => copy(r.recoveryCodes.join("\n")) }, "Copy")));
    } catch (e) { showError(rcForm, e); }
    finally { busy(rcBtn, false); }
  });

  // Sessions
  const sessBox = h("div", {});
  const loadSessions = async () => {
    let list;
    try { list = await api("GET", "/api/account/sessions"); } catch { return; }
    sessBox.replaceChildren(h("div", { class: "table-wrap" }, h("table", { class: "table" },
      h("thead", {}, h("tr", {}, ["Device", "Address", "Last active", ""].map((x) => h("th", { scope: "col" }, x)))),
      h("tbody", {}, list.map((x) => h("tr", {},
        h("td", {}, describeUA(x.userAgent), x.current ? h("div", { class: "muted" }, "This device") : null),
        h("td", { class: "mono" }, x.ip),
        h("td", {}, ago(x.lastSeen)),
        h("td", {}, x.current ? null : h("button", { class: "btn small", type: "button", onclick: async () => {
          try { await api("DELETE", `/api/account/sessions/${x.id}`); toast("Signed out that device."); loadSessions(); }
          catch (e) { toast(e.message, "error"); }
        } }, "Sign out"))))))),
      list.length > 1 ? h("div", { class: "actions" }, h("button", { class: "btn", type: "button", onclick: async () => {
        try { await api("POST", "/api/account/sessions/revoke-others"); toast("Other devices signed out."); loadSessions(); }
        catch (e) { toast(e.message, "error"); }
      } }, "Sign out all other devices")) : null);
  };

  const csBox = crowdsecEditor();
  const pkBox = passkeysBox("/api/account/passkeys");
  const tokBox = tokensBox("/api/account/tokens", true);
  const ssoBox = ssoEditor();

  shell("settings",
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Settings"))),
    h("section", { class: "section" }, h("header", {}, h("h2", {}, "HTTPS")), httpsForm),
    h("section", { class: "section" }, h("header", {}, h("h2", {}, "CrowdSec"),
      h("p", {}, "Block addresses that CrowdSec has banned, on every site and the sign-in page.")), csBox),
    h("section", { class: "section" }, h("header", {}, h("h2", {}, "Single sign-on"),
      h("p", {}, "Let people sign in to private sites with Google, Microsoft, Authentik or another OpenID Connect provider. Only people whose email you've set on the People page can sign in this way.")), ssoBox),
    h("section", { class: "section" }, h("header", {}, h("h2", {}, "Password")), pwForm),
    h("section", { class: "section" }, h("header", {}, h("h2", {}, "Recovery codes"), h("p", {}, "Use one to sign in if you lose your authenticator app.")), rcForm),
    h("section", { class: "section" }, h("header", {}, h("h2", {}, "Passkeys"),
      h("p", {}, "Sign in with your fingerprint, face or device PIN instead of a password and code. A passkey only works on the address it was added on.")), pkBox),
    h("section", { class: "section" }, h("header", {}, h("h2", {}, "Access tokens"),
      h("p", {}, "For scripts and apps. A sites token opens your private sites without a browser (send it as Authorization: Bearer <token>). An admin token uses this dashboard's API.")), tokBox),
    h("section", { class: "section" }, h("header", {}, h("h2", {}, "Signed-in devices")), sessBox),
    h("p", { class: "muted" }, `RyProx ${state.version}`));
  loadSessions();
}

// ---------- passkeys & tokens (also used on the sign-in page) ----------
function passkeysBox(base) {
  const box = h("div", {});
  const load = async () => {
    let r;
    try { r = await api("GET", base); } catch { return; }
    const pw = h("input", { type: "password", autocomplete: "current-password", "data-field": "password" });
    const name = h("input", { type: "text", "data-field": "name", placeholder: "My laptop", maxlength: 60 });
    const add = h("button", { class: "btn", type: "submit" }, "Add a passkey");
    const form = h("form", { novalidate: true, class: "mt" },
      h("div", { class: "two" }, field("Name", name), field("Confirm your password", pw)),
      h("div", { class: "actions" }, add));
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      clearErrors(form);
      if (!window.RyPasskey?.supported()) return showError(form, { message: "This browser doesn't support passkeys." });
      busy(add, true, "Waiting for your device…");
      try {
        const opts = await api("POST", base + "/begin", { password: pw.value });
        const cred = await window.RyPasskey.create(opts);
        await api("POST", `${base}/finish?name=${encodeURIComponent(name.value || "Passkey")}`, cred);
        toast("Passkey added.");
        load();
      } catch (e) {
        busy(add, false);
        showError(form, e instanceof ApiError ? e : { message: window.RyPasskey.message(e) });
      }
    });
    box.replaceChildren(
      r.passkeys.length ? h("ul", { class: "plain-list" }, r.passkeys.map((k) => h("li", {},
        h("span", {}, h("b", {}, k.name), h("span", { class: "muted" }, " · added ", ago(k.createdAt), k.lastUsedAt && !k.lastUsedAt.startsWith("0001") ? ", last used " + ago(k.lastUsedAt) : "")),
        h("button", { class: "btn small", type: "button", onclick: async () => {
          if (!(await confirmDialog("Remove this passkey?", `${k.name} won't be able to sign in any more.`, "Remove"))) return;
          try { await api("DELETE", `${base}/${k.id}`); toast("Passkey removed."); load(); } catch (e) { toast(e.message, "error"); }
        } }, "Remove")))) : h("p", { class: "muted" }, "No passkeys yet."),
      form);
  };
  load();
  return box;
}

function tokensBox(base, allowAdmin) {
  const box = h("div", {});
  const out = h("div", {});
  const load = async () => {
    let r;
    try { r = await api("GET", base); } catch { return; }
    const name = h("input", { type: "text", "data-field": "name", placeholder: "Backup script", maxlength: 60 });
    const scope = h("select", { "data-field": "scope" }, h("option", { value: "sites" }, "Open my private sites"),
      allowAdmin ? h("option", { value: "admin" }, "Manage RyProx (admin API)") : null);
    const exp = h("select", { "data-field": "expiresDays" }, h("option", { value: "30" }, "30 days"), h("option", { value: "90" }, "90 days"),
      h("option", { value: "365" }, "1 year"), h("option", { value: "0" }, "Never"));
    const add = h("button", { class: "btn", type: "submit" }, "Create token");
    const form = h("form", { novalidate: true, class: "mt" }, h("div", { class: "three" }, field("Name", name), field("Can", scope), field("Expires after", exp)),
      h("div", { class: "actions" }, add));
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      clearErrors(form);
      busy(add, true);
      try {
        const t = await api("POST", base, { name: name.value, scope: scope.value, expiresDays: Number(exp.value) });
        out.replaceChildren(h("div", { class: "banner" }, h("p", {}, h("b", {}, "Copy this token now. "), "It won't be shown again."),
          h("div", { class: "secret mono" }, t.token),
          h("div", { class: "row" }, h("button", { class: "btn small", type: "button", onclick: () => copy(t.token) }, "Copy"))));
        load();
      } catch (e) { busy(add, false); showError(form, e); }
    });
    const scopeName = { sites: "Opens private sites", admin: "Admin API" };
    box.replaceChildren(out,
      r.tokens.length ? h("ul", { class: "plain-list" }, r.tokens.map((t) => h("li", {},
        h("span", {}, h("b", {}, t.name), h("span", { class: "muted" }, ` · ${scopeName[t.scope] || t.scope}`,
          t.expiresAt && !t.expiresAt.startsWith("0001") ? ` · expires ${new Date(t.expiresAt).toLocaleDateString()}` : " · never expires",
          t.lastUsedAt && !t.lastUsedAt.startsWith("0001") ? ` · used ${ago(t.lastUsedAt)}` : " · never used")),
        h("button", { class: "btn small", type: "button", onclick: async () => {
          if (!(await confirmDialog("Delete this token?", `Anything using "${t.name}" will stop working.`, "Delete"))) return;
          try { await api("DELETE", `${base}/${t.id}`); toast("Token deleted."); out.replaceChildren(); load(); } catch (e) { toast(e.message, "error"); }
        } }, "Delete")))) : h("p", { class: "muted" }, "No tokens yet."),
      form);
  };
  load();
  return box;
}

function crowdsecEditor() {
  const box = h("div", {});
  let timer = null;
  const load = async () => {
    let r;
    try { r = await api("GET", "/api/crowdsec"); } catch { return; }
    const on = toggle("Use CrowdSec", "RyProx asks your CrowdSec Local API for bans every 10 seconds and keeps a copy, so lookups are instant.", r.enabled);
    const url = h("input", { type: "text", "data-field": "url", value: r.url || "http://127.0.0.1:8080", class: "mono", spellcheck: "false" });
    const key = h("input", { type: "password", "data-field": "apiKey", autocomplete: "off", placeholder: r.hasKey ? "Saved (leave empty to keep)" : "" });
    const fields = h("div", { hidden: !r.enabled },
      field("Local API address", url, "Where CrowdSec's Local API listens."),
      field("Bouncer API key", key, h("span", {}, "Create one on the CrowdSec server with ", h("code", {}, "cscli bouncers add ryprox"), ".")));
    on.querySelector("input").addEventListener("change", (e) => { fields.hidden = !e.target.checked; });
    const st = r.status || {};
    const status = r.enabled ? h("p", { class: st.connected ? "muted" : "warn-inline" },
      st.connected ? `Connected. ${st.decisions} active ban${st.decisions === 1 ? "" : "s"}, ${st.blocked} request${st.blocked === 1 ? "" : "s"} blocked since start. Last sync ${ago(st.lastSync)}.`
        : `Not connected${st.lastError ? ": " + st.lastError : " yet"}.`) : null;
    const save = h("button", { class: "btn primary", type: "submit" }, "Save");
    const form = h("form", { novalidate: true }, on, fields, status, h("div", { class: "actions" }, save));
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      clearErrors(form);
      busy(save, true, "Saving…");
      try {
        await api("PUT", "/api/crowdsec", { enabled: on.querySelector("input").checked, url: url.value.trim(), apiKey: key.value.trim() });
        toast("CrowdSec settings saved.");
        clearTimeout(timer);
        timer = setTimeout(load, 1500);
        load();
      } catch (e) { busy(save, false); showError(form, e); }
    });
    box.replaceChildren(form);
  };
  load();
  return box;
}

// ---------- import ----------
async function importPage() {
  const file = h("input", { type: "file", accept: ".sqlite,.db,application/octet-stream", "aria-label": "Nginx Proxy Manager database" });
  const btn = h("button", { class: "btn primary", type: "submit" }, "Read file");
  const out = h("div", {});
  const form = h("form", { novalidate: true },
    h("p", {}, "Upload ", h("code", {}, "database.sqlite"), " from Nginx Proxy Manager's ", h("code", {}, "data"), " folder. Nothing changes until you choose what to import."),
    field("Database file", file), h("div", { class: "actions" }, btn));
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    clearErrors(form);
    if (!file.files[0]) return showError(form, { message: "Choose a file first." });
    busy(btn, true, "Reading…");
    let data;
    try {
      const res = await fetch("/api/import/npm", { method: "POST", headers: { "X-RyProx": "1", "Content-Type": "application/octet-stream" }, body: file.files[0], credentials: "same-origin" });
      data = await res.json();
      if (!res.ok) throw new ApiError(res.status, data);
    } catch (e) { busy(btn, false); return showError(form, e instanceof ApiError ? e : { message: "Couldn't upload the file." }); }
    busy(btn, false);
    if (!data.items.length) { out.replaceChildren(h("p", { class: "muted" }, "No hosts found in that file.")); return; }
    const rows = data.items.map((it) => {
      const r = it.route;
      const cb = h("input", { type: "checkbox", checked: !it.problem, disabled: !!it.problem });
      const where = r.config.kind === "redirect" ? `→ ${r.config.redirect.to}` : r.config.targets.map((t) => t.url).join(", ") +
        (r.config.paths?.length ? ` (+${r.config.paths.length} path rule${r.config.paths.length > 1 ? "s" : ""})` : "");
      const tr = h("tr", {},
        h("td", {}, cb), h("td", { class: "mono" }, r.hostname),
        h("td", { class: "mono wrap-any" }, where),
        h("td", {}, r.config.access.mode === "public" ? "Public" : "Private (you)"),
        h("td", {}, it.problem ? h("span", { class: "err" }, capitalise(it.problem)) : (it.notes || []).map((n) => h("div", { class: "muted" }, capitalise(n)))));
      tr.item = it; tr.cb = cb;
      return tr;
    });
    const go2 = h("button", { class: "btn primary", type: "button" }, "Import selected");
    go2.addEventListener("click", async () => {
      busy(go2, true, "Importing…");
      let ok = 0;
      for (const tr of rows) {
        if (!tr.cb.checked) continue;
        const r = tr.item.route;
        try {
          await api("POST", "/api/routes", { hostname: r.hostname, enabled: r.enabled, config: r.config });
          ok++; tr.cb.checked = false; tr.cb.disabled = true;
          tr.lastChild.replaceChildren(h("span", {}, "Imported"));
        } catch (e) { tr.lastChild.replaceChildren(h("span", { class: "err" }, capitalise(e.message))); }
      }
      busy(go2, false);
      toast(`${ok} route${ok === 1 ? "" : "s"} imported.`);
    });
    out.replaceChildren(
      h("h2", { class: "mt-l" }, "Found"),
      h("p", { class: "muted" }, "Imported sites are private to you at first. Review each one afterwards to choose who can open it."),
      h("div", { class: "table-wrap" }, h("table", { class: "table" },
        h("thead", {}, h("tr", {}, ["", "Domain", "Goes to", "Access", "Notes"].map((x) => h("th", { scope: "col" }, x)))),
        h("tbody", {}, rows))),
      h("div", { class: "actions" }, go2, h("a", { class: "btn", href: "#/" }, "Done")));
  });
  shell("routes",
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Import from Nginx Proxy Manager"),
      h("p", { class: "lede" }, "Bring your proxy hosts and redirects across."))),
    h("section", { class: "section" }, form), out);
}

function ssoEditor() {
  const box = h("div", {});
  const load = async () => {
    let r;
    try { r = await api("GET", "/api/sso"); } catch { return; }
    const list = h("div", {});
    const presets = {
      google: { id: "google", name: "Google", issuer: "https://accounts.google.com" },
      microsoft: { id: "microsoft", name: "Microsoft", issuer: "https://login.microsoftonline.com/<tenant-id>/v2.0" },
      authentik: { id: "authentik", name: "Authentik", issuer: "https://authentik.example.com/application/o/ryprox" },
    };
    const addRow = (p) => {
      const i = list.children.length;
      const f = (k, label, input, hint) => { input.dataset.field = `providers.${i}.${k}`; return field(label, input, hint); };
      const id = h("input", { type: "text", value: p.id || "", class: "mono", spellcheck: "false" });
      const name = h("input", { type: "text", value: p.name || "" });
      const issuer = h("input", { type: "text", value: p.issuer || "", class: "mono", spellcheck: "false", placeholder: "https://accounts.google.com" });
      const cid = h("input", { type: "text", value: p.clientId || "", class: "mono", spellcheck: "false" });
      const secret = h("input", { type: "password", autocomplete: "off", placeholder: p.hasSecret ? "Saved (leave empty to keep)" : "" });
      const trust = toggle("Trust email addresses from this provider", "Only for a provider you control, like your company's Microsoft tenant. Otherwise RyProx needs the provider to confirm the address is verified.", !!p.trustEmail);
      const rm = h("button", { class: "btn small", type: "button" }, "Remove");
      const row = h("div", { class: "sso-row" },
        h("div", { class: "two" }, f("name", "Button label", name), f("id", "ID", id, "Short, lowercase, used in links")),
        f("issuer", "Issuer address", issuer), h("div", { class: "two" }, f("clientId", "Client ID", cid), f("clientSecret", "Client secret", secret)),
        trust, h("div", { class: "actions" }, rm));
      row.read = () => ({ id: id.value, name: name.value, issuer: issuer.value, clientId: cid.value, clientSecret: secret.value, trustEmail: trust.querySelector("input").checked });
      rm.addEventListener("click", () => row.remove());
      list.append(row);
    };
    r.providers.forEach(addRow);
    const save = h("button", { class: "btn primary", type: "submit" }, "Save sign-on providers");
    const form = h("form", { novalidate: true }, list,
      h("div", { class: "row" }, Object.entries(presets).map(([k, p]) => h("button", { class: "btn small", type: "button", onclick: () => addRow(p) }, "Add " + p.name)),
        h("button", { class: "btn small", type: "button", onclick: () => addRow({}) }, "Add other")),
      r.callbackUrl ? h("p", { class: "muted mt" }, "In the provider, set the redirect URI to ", h("code", {}, r.callbackUrl), ".")
        : h("p", { class: "warn-inline" }, "Set a sign-in domain above first; providers send people back there."),
      h("div", { class: "actions" }, save));
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      clearErrors(form);
      busy(save, true, "Saving…");
      try {
        await api("PUT", "/api/sso", { providers: [...list.children].map((row) => row.read()) });
        toast("Sign-on providers saved.");
        load();
      } catch (e) { busy(save, false); showError(form, e); }
    });
    box.replaceChildren(form);
  };
  load();
  return box;
}

function describeUA(ua) {
  if (!ua) return "Unknown device";
  const browser = /Edg\//.test(ua) ? "Edge" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "Browser";
  const os = /Windows/.test(ua) ? "Windows" : /iPhone|iPad/.test(ua) ? "iOS" : /Mac OS X/.test(ua) ? "macOS" : /Android/.test(ua) ? "Android" : /Linux/.test(ua) ? "Linux" : "";
  return os ? `${browser} on ${os}` : browser;
}

// ---------- people ----------
async function peoplePage() {
  const body = h("div", { "aria-busy": "true" });
  shell("people",
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "People"),
      h("p", { class: "lede" }, "Everyone who can sign in. Members can only open the private sites you give them; admins can also manage RyProx."))),
    body);

  const load = async () => {
    let data, routes;
    try { [data, routes] = await Promise.all([api("GET", "/api/people"), api("GET", "/api/routes")]); } catch { return; }
    body.removeAttribute("aria-busy");
    const privateRoutes = routes.routes.filter((r) => !r.config.access || r.config.access.mode !== "public");

    // Invite form
    const name = h("input", { type: "text", "data-field": "username", autocomplete: "off", spellcheck: "false", autocapitalize: "off" });
    const role = h("select", { "data-field": "role" }, h("option", { value: "member" }, "Member"), h("option", { value: "admin" }, "Admin"));
    const sites = h("div", { class: "people-pick inset", "data-field": "routes", tabindex: "-1" },
      privateRoutes.length ? privateRoutes.map((r) => h("label", { class: "pick" },
        h("input", { type: "checkbox", value: String(r.id) }), h("span", { class: "mono" }, r.hostname)))
        : h("p", { class: "muted" }, "No private sites yet. You can give access later from each route."));
    const sendBtn = h("button", { class: "btn primary", type: "submit" }, "Create invite link");
    const result = h("div", {});
    const form = h("form", { novalidate: true },
      h("div", { class: "two" }, field("Username", name, "Letters, numbers, dots, dashes and underscores."),
        field("Role", role, "Admins can also manage RyProx.")),
      h("div", { class: "field" }, h("span", {}, "Sites they can open"), sites),
      h("div", { class: "actions" }, sendBtn), result);
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      clearErrors(form);
      busy(sendBtn, true, "Creating…");
      try {
        const r = await api("POST", "/api/invites", {
          username: name.value, role: role.value,
          routes: [...sites.querySelectorAll("input:checked")].map((i) => Number(i.value)),
        });
        const link = r.url || (location.origin + r.path);
        result.replaceChildren(h("div", { class: "invite-link" },
          h("p", {}, h("b", {}, `Send this link to ${r.invite.username}.`), " It works once and expires in 7 days. It won't be shown again."),
          h("div", { class: "row" }, h("input", { type: "text", readonly: true, value: link, class: "mono", "aria-label": "Invite link", onfocus: (e) => e.target.select() }),
            h("button", { class: "btn", type: "button", onclick: () => copy(link) }, "Copy")),
          r.https ? null : h("p", { class: "warn-inline flush0" },
            "This link only works from this computer, because there's no sign-in domain yet. Turn on automatic HTTPS and set a sign-in domain in Settings, then create a new invite.")));
        name.value = "";
        sites.querySelectorAll("input").forEach((i) => { i.checked = false; });
        loadLists();
      } catch (e) { showError(form, e); }
      finally { busy(sendBtn, false); }
    });

    const lists = h("div", {});
    const loadLists = async () => {
      let d;
      try { d = await api("GET", "/api/people"); } catch { return; }
      lists.replaceChildren(
        h("div", { class: "table-wrap" }, h("table", { class: "table" },
          h("thead", {}, h("tr", {}, ["Person", "Role", "Private sites", "Last signed in", ""].map((x) => h("th", { scope: "col" }, x)))),
          h("tbody", {}, d.people.map((p) => personRow(p, d.me, loadLists))))),
        d.invites.length ? h("section", { class: "section mt" },
          h("header", {}, h("h2", {}, "Waiting to join")),
          h("div", { class: "table-wrap" }, h("table", { class: "table" },
            h("thead", {}, h("tr", {}, ["Username", "Role", "Invited by", "Expires", ""].map((x) => h("th", { scope: "col" }, x)))),
            h("tbody", {}, d.invites.map((i) => h("tr", {},
              h("td", {}, i.username), h("td", {}, i.role === "admin" ? "Admin" : "Member"), h("td", {}, i.createdBy),
              h("td", {}, fmtTime(i.expiresAt)),
              h("td", {}, h("button", { class: "btn small", type: "button", onclick: async () => {
                try { await api("DELETE", `/api/invites/${i.id}`); toast("Invite cancelled."); loadLists(); }
                catch (e) { toast(e.message, "error"); }
              } }, "Cancel invite")))))))) : null);
    };

    body.replaceChildren(
      h("section", { class: "section" }, h("header", {}, h("h2", {}, "Invite someone"),
        h("p", {}, "They choose their own password and set up an authenticator app. You never see either.")), form),
      lists);
    loadLists();
  };
  await load();
}

function personRow(p, me, reload) {
  const self = p.id === me;
  const role = h("select", { "aria-label": `Role for ${p.username}`, disabled: self },
    h("option", { value: "member" }, "Member"), h("option", { value: "admin" }, "Admin"));
  role.value = p.role;
  const save = async (changes, msg) => {
    try {
      await api("PUT", `/api/people/${p.id}`, { role: p.role, disabled: p.disabled, ...changes });
      toast(msg);
    } catch (e) { toast(e.message, "error"); }
    reload();
  };
  role.addEventListener("change", () => save({ role: role.value }, `${p.username} is now ${role.value === "admin" ? "an admin" : "a member"}.`));
  return h("tr", { class: p.disabled ? "row-off" : "" },
    h("td", {}, h("b", {}, p.username), self ? h("div", { class: "muted" }, "You") : null, p.disabled ? h("div", { class: "err" }, "Disabled") : null,
      h("div", {}, h("button", { class: "linkish small", type: "button", title: "Used to match their single sign-on account", onclick: () => editEmail(p, reload) },
        p.email || "Add email for sign-on"))),
    h("td", {}, role),
    h("td", {}, p.sites.length ? h("div", { class: "mono small-list" }, p.sites.map((x) => h("div", {}, x))) : h("span", { class: "muted" }, "None")),
    h("td", {}, ago(p.lastLoginAt)),
    h("td", {}, self ? null : h("div", { class: "row" },
      h("button", { class: "btn small", type: "button", onclick: () =>
        save({ disabled: !p.disabled }, p.disabled ? `${p.username} can sign in again.` : `${p.username} is disabled and signed out everywhere.`) },
        p.disabled ? "Enable" : "Disable"),
      h("button", { class: "btn small danger", type: "button", onclick: async () => {
        if (!(await confirmDialog(`Remove ${p.username}?`, "They're signed out everywhere and taken off every site. This can't be undone.", "Remove"))) return;
        try { await api("DELETE", `/api/people/${p.id}`); toast(`${p.username} removed.`); }
        catch (e) { toast(e.message, "error"); }
        reload();
      } }, "Remove"))));
}

async function editEmail(p, reload) {
  const input = h("input", { type: "email", value: p.email || "", "data-field": "email", placeholder: "name@example.com", autocomplete: "off" });
  const ok = h("button", { class: "btn primary", type: "submit" }, "Save");
  const form = h("form", { novalidate: true, method: "dialog" },
    h("h2", {}, `Sign-on email for ${p.username}`),
    h("p", { class: "muted" }, "When they sign in with Google, Microsoft or another provider, RyProx matches this address. Leave empty to turn single sign-on off for them."),
    field("Email", input),
    h("div", { class: "actions" }, ok, h("button", { class: "btn", type: "button", onclick: () => dlg.close() }, "Cancel")));
  const dlg = h("dialog", { class: "dialog" }, form);
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    clearErrors(form);
    busy(ok, true);
    try {
      await api("PUT", `/api/people/${p.id}/email`, { email: input.value.trim() });
      dlg.close();
      toast("Email saved.");
      reload();
    } catch (e) { busy(ok, false); showError(form, e); }
  });
  dlg.addEventListener("close", () => dlg.remove());
  document.body.append(dlg);
  dlg.showModal();
  input.focus();
}

// ---------- activity ----------
const actionText = {
  "setup.complete": "Created the admin account", login: "Signed in", logout: "Signed out",
  "route.create": "Added route", "route.update": "Changed route", "route.delete": "Deleted route",
  "route.enable": "Turned on route", "route.disable": "Turned off route",
  "settings.update": "Changed HTTPS settings", "certificate.retry": "Requested certificate",
  "account.password": "Changed password", "account.recovery_codes": "Made new recovery codes",
  "session.revoke": "Signed out a device", "session.revoke_others": "Signed out other devices",
  "admin.reset": "Reset the admin account",
  "user.invite": "Invited someone", "user.invite_cancel": "Cancelled an invite", "user.joined": "Joined",
  "user.update": "Changed someone's access", "user.delete": "Removed someone", "access.denied": "Was refused access",
};
async function activityPage() {
  const body = h("div", { "aria-busy": "true" });
  shell("activity",
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Activity"), h("p", { class: "lede" }, "Every change and sign-in, newest first.")),
      h("div", { class: "row" }, h("a", { class: "btn", href: "/api/activity/export?format=csv", download: "" }, "Export CSV"),
        h("a", { class: "btn", href: "/api/activity/export?format=json", download: "" }, "Export JSON"))),
    body);
  let list;
  try { list = await api("GET", "/api/activity"); } catch { return; }
  body.removeAttribute("aria-busy");
  body.replaceChildren(list.length ? h("div", { class: "table-wrap" }, h("table", { class: "table" },
    h("thead", {}, h("tr", {}, ["When", "Who", "What", "Address"].map((x) => h("th", { scope: "col" }, x)))),
    h("tbody", {}, list.map((e) => h("tr", {},
      h("td", { class: "nowrap" }, fmtTime(e.at)),
      h("td", {}, e.actor),
      h("td", {}, actionText[e.action] || e.action, e.detail ? h("div", { class: "muted mono wrap-any" }, e.detail) : null),
      h("td", { class: "mono" }, e.ip || "—")))))) : h("div", { class: "empty" }, h("p", {}, "Nothing yet.")));
}

boot();

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
  if (path === "/settings") return settingsPage();
  if (path === "/activity") return activityPage();
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
  authLayout(h("h1", {}, "Sign in"), h("p", { class: "lede" }, "Manage your routes and certificates."), form);
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

async function routesPage() {
  const board = h("div", { class: "board", "aria-busy": "true" });
  const main = shell("routes",
    h("div", { class: "page-head" },
      h("div", {}, h("h1", {}, "Routes"), h("p", { class: "lede" }, "Each route connects a domain to the services behind it. Changes go live as soon as you save.")),
      h("a", { class: "btn primary", href: "#/routes/new" }, "Add route")),
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
      h("div", { class: "meta" }, certPill(r.cert, httpsOn), " ",
        r.config.targets.length > 1 ? (r.config.loadBalancing === "failover" ? "Failover" : "Load balanced") : "")),
    h("div", { class: "wire", "data-state": ws, role: "img", "aria-label": stateLabel, title: stateLabel }),
    h("ul", { class: "targets", "aria-label": "Services" },
      r.config.targets.map((t) => {
        const st = health[t.url];
        const cls = st?.state === "up" ? "up" : st?.state === "down" ? "down" : "";
        const tip = st?.state === "down" ? `Down: ${st.lastError || "not responding"}` : st?.state === "up" ? `Up, ${st.latencyMs} ms` : "Not checked";
        return h("li", { title: tip }, h("span", { class: "dot " + cls, "aria-label": tip }), t.url);
      })),
    h("div", { class: "tools" }, h("a", { class: "btn small", href: `#/routes/${r.id}` }, "Edit")));
}

// ---------- route editor ----------
function defaultRoute() {
  return {
    hostname: "", enabled: true,
    config: {
      targets: [{ url: "" }], loadBalancing: "round_robin", tlsSkipVerify: false, websockets: true,
      httpsRedirect: true, preserveHost: false, requestHeaders: [], responseHeaders: [],
      healthCheck: { enabled: false, path: "/", intervalSeconds: 15 },
    },
  };
}

async function routeEditor(id) {
  let route = defaultRoute();
  if (id != null) {
    try {
      const data = await api("GET", "/api/routes");
      const found = data.routes.find((r) => r.id === id);
      if (!found) { toast("That route doesn't exist any more.", "error"); return go("#/"); }
      route = { hostname: found.hostname, enabled: found.enabled, config: structuredClone(found.config) };
      route.config.requestHeaders ||= [];
      route.config.responseHeaders ||= [];
    } catch { return; }
  }
  const c = route.config;
  const form = h("form", { novalidate: true });

  // Basics
  const host = h("input", { type: "text", "data-field": "hostname", value: route.hostname, placeholder: "app.example.com", spellcheck: "false", class: "mono", autocapitalize: "off" });
  const enabled = toggle("Route is on", "Turn off to stop serving this domain without deleting the route.", route.enabled);

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

  const saveBtn = h("button", { class: "btn primary", type: "submit" }, id == null ? "Add route" : "Save changes");
  const delBtn = id == null ? null : h("button", { class: "btn danger", type: "button" }, "Delete route");

  form.append(
    h("section", { class: "section" },
      h("header", {}, h("h2", {}, "Domain")),
      field("Domain name", host, "Point this domain's DNS at this server first."),
      enabled),
    h("section", { class: "section" },
      h("header", {}, h("h2", {}, "Services"), h("p", {}, "Where visitors are sent. Use the address you'd type on your own network.")),
      tlist,
      h("button", { class: "btn small", type: "button", onclick: () => addTarget("") }, "Add another service"),
      h("div", { class: "mt" }, lbWrap)),
    h("section", { class: "section" },
      h("header", {}, h("h2", {}, "Options")),
      redirect, ws, preserve, skip, skipWarn),
    h("section", { class: "section" },
      h("header", {}, h("h2", {}, "Health check")),
      hc, hcFields),
    h("details", { class: "section" },
      h("summary", {}, h("b", {}, "Header rules"), h("span", { class: "muted" }, " (advanced)")),
      h("div", { class: "mt" },
        h("h3", {}, "Sent to the service"), h("p", { class: "muted" }, "Add or remove headers on requests going to your service."), reqRules.el,
        h("h3", { class: "mt-l" }, "Sent to visitors"), h("p", { class: "muted" }, "Add or remove headers on responses going back to visitors."), resRules.el)),
    h("div", { class: "actions" }, saveBtn, h("a", { class: "btn", href: "#/" }, "Cancel"), h("span", { class: "spacer" }), delBtn));

  if (route.config.requestHeaders.length || route.config.responseHeaders.length) form.querySelector("details").open = true;

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    clearErrors(form);
    const body = {
      hostname: host.value,
      enabled: enabled.querySelector("input").checked,
      config: {
        targets: [...tlist.querySelectorAll("input")].map((i) => ({ url: i.value })),
        loadBalancing: lb.value,
        tlsSkipVerify: skip.querySelector("input").checked,
        websockets: ws.querySelector("input").checked,
        httpsRedirect: redirect.querySelector("input").checked,
        preserveHost: preserve.querySelector("input").checked,
        requestHeaders: reqRules.read(),
        responseHeaders: resRules.read(),
        healthCheck: { enabled: hc.querySelector("input").checked, path: hcPath.value, intervalSeconds: Number(hcInt.value) || 15 },
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
  const acmeBits = h("div", { hidden: s.tlsMode !== "acme" },
    field("Email for Let's Encrypt", email, "Used only for certificate expiry warnings."),
    staging,
    field("Admin dashboard domain (optional)", admin, "Open this dashboard securely at its own domain. Leave empty to only use it from this server."));
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
        acmeStaging: staging.querySelector("input").checked, adminHostname: admin.value,
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

  shell("settings",
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Settings"))),
    h("section", { class: "section" }, h("header", {}, h("h2", {}, "HTTPS")), httpsForm),
    h("section", { class: "section" }, h("header", {}, h("h2", {}, "Password")), pwForm),
    h("section", { class: "section" }, h("header", {}, h("h2", {}, "Recovery codes"), h("p", {}, "Use one to sign in if you lose your authenticator app.")), rcForm),
    h("section", { class: "section" }, h("header", {}, h("h2", {}, "Signed-in devices")), sessBox),
    h("p", { class: "muted" }, `RyProx ${state.version}`));
  loadSessions();
}

function describeUA(ua) {
  if (!ua) return "Unknown device";
  const browser = /Edg\//.test(ua) ? "Edge" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "Browser";
  const os = /Windows/.test(ua) ? "Windows" : /iPhone|iPad/.test(ua) ? "iOS" : /Mac OS X/.test(ua) ? "macOS" : /Android/.test(ua) ? "Android" : /Linux/.test(ua) ? "Linux" : "";
  return os ? `${browser} on ${os}` : browser;
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
};
async function activityPage() {
  const body = h("div", { "aria-busy": "true" });
  shell("activity",
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Activity"), h("p", { class: "lede" }, "Every change and sign-in, newest first."))),
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

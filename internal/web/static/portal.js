// RyProx sign-in page. Served only on RyProx's sign-in domain (and the local
// dashboard, for accepting invites), never on a route's own domain.
// Server text is only ever placed with textContent.
"use strict";

const BASE = "/.ryprox/";

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "class") el.className = v;
    else if (k === "value") el.value = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

async function api(path, body, method) {
  const opts = { method: method || (body === undefined ? "GET" : "POST"), headers: { "X-RyProx": "1" }, credentials: "same-origin" };
  if (body !== undefined) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
  let res;
  try { res = await fetch(BASE + "api/" + path, opts); }
  catch { throw Object.assign(new Error("Can't reach the server. Check your connection."), { status: 0 }); }
  const data = res.headers.get("Content-Type")?.includes("json") ? await res.json() : null;
  if (!res.ok) throw Object.assign(new Error((data && data.error) || `Request failed (${res.status})`), { status: res.status, field: data && data.field, denied: data && data.denied });
  return data;
}

const cap = (s) => (s ? s[0].toUpperCase() + s.slice(1) : s);
const params = new URLSearchParams(location.search);
const site = params.get("site") || "";
const rd = params.get("rd") || "/";

function field(label, input, hint) {
  input.id ||= "f" + Math.random().toString(36).slice(2);
  const err = h("span", { class: "err", id: input.id + "-err", hidden: true });
  input.setAttribute("aria-describedby", err.id);
  return h("label", { class: "field", for: input.id }, h("span", {}, label), input, hint ? h("span", { class: "hint" }, hint) : null, err);
}
function showError(form, e) {
  form.querySelectorAll(".err").forEach((x) => { x.hidden = true; });
  form.querySelector(".banner.error")?.remove();
  const input = e.field && form.querySelector(`[data-field="${CSS.escape(e.field)}"]`);
  const msg = input && document.getElementById(input.id + "-err");
  if (msg) { msg.textContent = cap(e.message); msg.hidden = false; input.focus(); return; }
  form.prepend(h("div", { class: "banner error", role: "alert" }, cap(e.message)));
}
function busy(btn, on, label) {
  btn.disabled = on;
  if (on) { btn.dataset.label = btn.textContent; btn.textContent = label; } else if (btn.dataset.label) btn.textContent = btn.dataset.label;
}

let state = {};

function layout(...content) {
  document.getElementById("app").replaceChildren(h("div", { class: "auth" },
    h("div", { class: "auth-art", "aria-hidden": "true" },
      h("div", { class: "brand" }, "RyProx"),
      h("div", { class: "art" },
        h("div", { class: "wire", "data-state": "up" }),
        h("div", { class: "wire", "data-state": "off" })),
      h("blockquote", {}, "Sign in once here to open the private sites you've been given.")),
    h("div", { class: "auth-main" }, h("div", { class: "auth-card" },
      state.secure === false ? h("div", { class: "banner error" }, "This page isn't using HTTPS, so signing in is turned off to protect your password.") : null,
      site ? h("p", { class: "muted mono" }, `Signing in to ${site}`) : null,
      ...content))));
}

// Ask for a one-time code for the site and go there.
async function continueToSite() {
  try {
    const r = await api("continue", { site, rd });
    location.replace(r.url);
  } catch (e) {
    if (e.denied) return deniedPage();
    if (e.status === 401) return loginPage();
    layout(h("h1", {}, "Can't open this site"), h("p", { class: "lede" }, cap(e.message)));
  }
}

function afterSignIn() {
  if (site) return continueToSite();
  return sitesPage();
}

function loginPage() {
  const user = h("input", { type: "text", autocomplete: "username", "data-field": "username" });
  const pass = h("input", { type: "password", autocomplete: "current-password", "data-field": "password" });
  const btn = h("button", { class: "btn primary", type: "submit" }, "Continue");
  const form = h("form", { novalidate: true }, field("Username", user), field("Password", pass), h("div", { class: "actions" }, btn));
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    busy(btn, true, "Checking…");
    try {
      const r = await api("login", { username: user.value, password: pass.value });
      codePage(r.loginToken);
    } catch (e) { busy(btn, false); showError(form, e); }
  });
  // Passkeys and single sign-on.
  const extras = [];
  if (window.RyPasskey?.supported()) {
    const pk = h("button", { class: "btn", type: "button" }, "Sign in with a passkey");
    pk.addEventListener("click", async () => {
      busy(pk, true, "Waiting for your device…");
      try {
        const b = await api("login/passkey/begin", {});
        const cred = await window.RyPasskey.get(b.options);
        await api(`login/passkey/finish?id=${encodeURIComponent(b.id)}`, cred);
        state = await api("state");
        afterSignIn();
      } catch (e) {
        busy(pk, false);
        showError(form, e.status !== undefined ? e : { message: window.RyPasskey.message(e) });
      }
    });
    extras.push(pk);
  }
  for (const p of state.sso || []) {
    const q = new URLSearchParams();
    if (site) { q.set("site", site); q.set("rd", rd); }
    extras.push(h("a", { class: "btn", href: `${BASE}sso/${encodeURIComponent(p.id)}/start${q.toString() ? "?" + q : ""}` }, `Continue with ${p.name}`));
  }
  layout(h("h1", {}, "Sign in"), h("p", { class: "lede" }, "Use your RyProx account."), form,
    extras.length ? [h("div", { class: "or" }, h("span", {}, "or")), h("div", { class: "sso-buttons" }, extras)] : null);
  user.focus();
}

function codePage(token) {
  const code = h("input", { type: "text", inputmode: "numeric", autocomplete: "one-time-code", "data-field": "code", maxlength: 20 });
  const btn = h("button", { class: "btn primary", type: "submit" }, "Verify");
  const form = h("form", { novalidate: true },
    field("Authenticator code", code, "The 6-digit code from your authenticator app, or a recovery code."),
    h("div", { class: "actions" }, btn, h("button", { class: "linkish", type: "button", onclick: loginPage }, "Start over")));
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    busy(btn, true, "Verifying…");
    try {
      await api("login/verify", { loginToken: token, code: code.value });
      state = await api("state");
      afterSignIn();
    } catch (e) {
      busy(btn, false);
      if (e.status === 401 && !e.field) return loginPage();
      showError(form, e);
      code.select();
    }
  });
  layout(h("h1", {}, "Two-step check"), h("p", { class: "lede" }, "Open your authenticator app."), form);
  code.focus();
}

function sitesPage() {
  const sites = state.sites || [];
  layout(h("h1", {}, `Signed in as ${state.user}`),
    sites.length
      ? [h("p", { class: "lede" }, "Your sites:"),
         h("ul", { class: "site-list" }, sites.map((s) => h("li", {}, h("a", { href: "https://" + s + "/", class: "mono" }, s))))]
      : h("p", { class: "lede" }, "You haven't been given any sites yet."),
    h("div", { class: "actions" }, h("a", { class: "btn", href: BASE + "logout" }, "Sign out")),
    h("details", { class: "mt-l" }, h("summary", {}, h("b", {}, "Passkeys")),
      h("p", { class: "muted" }, "Sign in here with your fingerprint, face or device PIN instead of a password and code."), passkeys()),
    h("details", { class: "mt" }, h("summary", {}, h("b", {}, "Access tokens")),
      h("p", { class: "muted" }, "For scripts and apps that open your sites without a browser. Send the token as Authorization: Bearer <token>."), tokens()));
}

function passkeys() {
  const box = h("div", {});
  const load = async () => {
    let r;
    try { r = await api("passkeys"); } catch { return; }
    const pw = h("input", { type: "password", autocomplete: "current-password", "data-field": "password" });
    const name = h("input", { type: "text", "data-field": "name", placeholder: "My phone", maxlength: 60 });
    const add = h("button", { class: "btn", type: "submit" }, "Add a passkey");
    const form = h("form", { novalidate: true }, field("Name", name), field("Confirm your password", pw), h("div", { class: "actions" }, add));
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      if (!window.RyPasskey?.supported()) return showError(form, { message: "This browser doesn't support passkeys." });
      busy(add, true, "Waiting for your device…");
      try {
        const opts = await api("passkeys/begin", { password: pw.value });
        const cred = await window.RyPasskey.create(opts);
        await api(`passkeys/finish?name=${encodeURIComponent(name.value || "Passkey")}`, cred);
        load();
      } catch (e) { busy(add, false); showError(form, e.status !== undefined ? e : { message: window.RyPasskey.message(e) }); }
    });
    box.replaceChildren(
      h("ul", { class: "plain-list" }, r.passkeys.map((k) => h("li", {}, h("span", {}, k.name),
        h("button", { class: "btn small", type: "button", onclick: async () => { await api(`passkeys/${k.id}`, undefined, "DELETE").catch(() => {}); load(); } }, "Remove")))),
      form);
  };
  load();
  return box;
}

function tokens() {
  const box = h("div", {});
  const out = h("div", {});
  const load = async () => {
    let r;
    try { r = await api("tokens"); } catch { return; }
    const name = h("input", { type: "text", "data-field": "name", placeholder: "Backup script", maxlength: 60 });
    const exp = h("select", { "data-field": "expiresDays" }, h("option", { value: "30" }, "30 days"), h("option", { value: "90" }, "90 days"),
      h("option", { value: "365" }, "1 year"), h("option", { value: "0" }, "Never"));
    const add = h("button", { class: "btn", type: "submit" }, "Create token");
    const form = h("form", { novalidate: true }, field("Name", name), field("Expires after", exp), h("div", { class: "actions" }, add));
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      busy(add, true);
      try {
        const t = await api("tokens", { name: name.value, scope: "sites", expiresDays: Number(exp.value) });
        out.replaceChildren(h("div", { class: "banner" }, h("p", {}, h("b", {}, "Copy this token now. "), "It won't be shown again."), h("div", { class: "secret" }, t.token)));
        load();
      } catch (e) { busy(add, false); showError(form, e); }
    });
    box.replaceChildren(out,
      h("ul", { class: "plain-list" }, r.tokens.map((t) => h("li", {}, h("span", {}, t.name),
        h("button", { class: "btn small", type: "button", onclick: async () => { await api(`tokens/${t.id}`, undefined, "DELETE").catch(() => {}); out.replaceChildren(); load(); } }, "Delete")))),
      form);
  };
  load();
  return box;
}

function deniedPage() {
  layout(h("h1", {}, "No access"),
    h("p", { class: "lede" }, `You're signed in as ${state.user || "someone"}, but this account hasn't been given access to ${site || "this site"}. Ask whoever runs it to add you.`),
    h("div", { class: "actions" }, h("a", { class: "btn", href: BASE + "logout" }, "Sign in as someone else")));
}

async function logoutPage() {
  try { await api("logout", {}); } catch { /* signed out anyway */ }
  state.user = null;
  layout(h("h1", {}, "Signed out"), h("p", { class: "lede" }, "You've been signed out."),
    h("div", { class: "actions" }, h("a", { class: "btn primary", href: BASE + "login" }, "Sign in")));
}

async function invitePage() {
  // Keep the invite token out of the address bar and browser history.
  const token = decodeURIComponent(location.hash.slice(1));
  history.replaceState(null, "", location.pathname);
  let inv;
  try { inv = await api("invite/begin", { token }); }
  catch (e) { return layout(h("h1", {}, "Invite not valid"), h("p", { class: "lede" }, cap(e.message))); }
  const pass = h("input", { type: "password", autocomplete: "new-password", "data-field": "password", minlength: 12 });
  const code = h("input", { type: "text", inputmode: "numeric", autocomplete: "one-time-code", "data-field": "totpCode", maxlength: 6 });
  const btn = h("button", { class: "btn primary", type: "submit" }, "Create account");
  const form = h("form", { novalidate: true },
    field("Username", h("input", { type: "text", value: inv.username, readonly: true, autocomplete: "username" })),
    field("Choose a password", pass, "At least 12 characters. A short sentence works well."),
    h("p", { class: "muted" }, "Scan this with an authenticator app (Google Authenticator, 1Password, Aegis…), then enter the code it shows."),
    h("div", { class: "qr" }, h("img", { src: inv.qr, alt: "QR code for your authenticator app" }),
      h("div", {}, h("p", { class: "muted" }, "Can't scan? Enter this key:"), h("div", { class: "secret" }, inv.totpSecret))),
    field("Code from the app", code),
    h("div", { class: "actions" }, btn));
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    if (pass.value.length < 12) return showError(form, { field: "password", message: "password must be at least 12 characters" });
    busy(btn, true, "Creating…");
    try {
      const r = await api("invite/finish", { token, password: pass.value, totpSecret: inv.totpSecret, totpCode: code.value });
      codesPage(r);
    } catch (e) { busy(btn, false); showError(form, e); }
  });
  layout(h("h1", {}, "You're invited"), h("p", { class: "lede" }, "Set up your account to open the sites you've been given."), form);
  pass.focus();
}

function codesPage(r) {
  const text = "RyProx recovery codes\nEach code works once if you lose your authenticator.\n\n" + r.recoveryCodes.join("\n") + "\n";
  const done = h("button", { class: "btn primary", type: "button", disabled: true, onclick: async () => {
    if (r.signedIn) { state = await api("state"); return sitesPage(); }
    layout(h("h1", {}, "Your account is ready"), h("p", { class: "lede" }, "Open any site you've been given and sign in with your username, password and authenticator code."));
  } }, "Continue");
  const saved = h("input", { type: "checkbox" });
  saved.addEventListener("change", () => { done.disabled = !saved.checked; });
  const dl = h("button", { class: "btn", type: "button", onclick: () => {
    const a = h("a", { href: URL.createObjectURL(new Blob([text], { type: "text/plain" })), download: "recovery-codes.txt" });
    document.body.append(a); a.click(); setTimeout(() => a.remove(), 1000);
  } }, "Download");
  layout(h("h1", {}, "Save your recovery codes"),
    h("p", { class: "lede" }, "If you lose your phone, each code lets you sign in once. They won't be shown again."),
    h("div", { class: "codes" }, r.recoveryCodes.map((c) => h("span", {}, c))),
    h("div", { class: "row" }, dl),
    h("label", { class: "switch mt-l" }, saved, h("span", {}, h("b", {}, "I've saved these somewhere safe"))),
    h("div", { class: "actions" }, done));
}

async function boot() {
  try { state = await api("state"); } catch { state = {}; }
  const page = location.pathname.slice(BASE.length).replace(/\/$/, "");
  if (page === "invite") return invitePage();
  if (page === "logout") return logoutPage();
  if (!state.signInDomain) {
    return layout(h("h1", {}, "Sign in on your site"), h("p", { class: "lede" }, "Open the site you want to use; it will send you to the right sign-in page."));
  }
  if (page === "denied") return state.user ? deniedPage() : loginPage();
  if (state.user) return afterSignIn();
  loginPage();
}

boot();

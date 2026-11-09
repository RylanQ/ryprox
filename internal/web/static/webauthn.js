// Passkey helpers shared by the dashboard and the sign-in page. They turn
// the server's JSON options into what the browser's WebAuthn API expects,
// and the browser's answer back into JSON.
"use strict";

(() => {
  const dec = (s) => {
    const b = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
    return Uint8Array.from(b, (c) => c.charCodeAt(0)).buffer;
  };
  const enc = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  function toJSON(cred) {
    const r = cred.response;
    const out = {
      id: cred.id, rawId: enc(cred.rawId), type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
      response: { clientDataJSON: enc(r.clientDataJSON) },
    };
    if (r.attestationObject) {
      out.response.attestationObject = enc(r.attestationObject);
      if (r.getTransports) out.response.transports = r.getTransports();
    } else {
      out.response.authenticatorData = enc(r.authenticatorData);
      out.response.signature = enc(r.signature);
      if (r.userHandle) out.response.userHandle = enc(r.userHandle);
    }
    return out;
  }

  window.RyPasskey = {
    supported: () => !!window.PublicKeyCredential && !!navigator.credentials,
    async create(options) {
      const pk = structuredClone(options.publicKey);
      pk.challenge = dec(pk.challenge);
      pk.user.id = dec(pk.user.id);
      (pk.excludeCredentials || []).forEach((c) => { c.id = dec(c.id); });
      return toJSON(await navigator.credentials.create({ publicKey: pk }));
    },
    async get(options) {
      const pk = structuredClone(options.publicKey);
      pk.challenge = dec(pk.challenge);
      (pk.allowCredentials || []).forEach((c) => { c.id = dec(c.id); });
      return toJSON(await navigator.credentials.get({ publicKey: pk, mediation: options.mediation }));
    },
    // A friendly message for the errors people actually hit.
    message(e) {
      if (e && e.name === "NotAllowedError") return "Cancelled, or the passkey wasn't available.";
      if (e && e.name === "InvalidStateError") return "This device already has a passkey for this account.";
      return (e && e.message) || "Something went wrong with the passkey.";
    },
  };
})();

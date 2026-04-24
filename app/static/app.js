/* ============================================================
   Secure Vault — Frontend Application Logic
   ============================================================ */
(function () {
  "use strict";

  const API = "";  // same-origin

  // ─── State ───
  let sessionToken = null;
  let currentUserId = null;
  let rsaPrivateKey = null;   // { d, n }
  let eccPrivateKey = null;   // integer

  // ─── DOM refs ───
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);

  // pages
  const pageAuth  = $("#pageAuth");
  const pageVault = $("#pageVault");
  const navAuth   = $("#navAuth");
  const navVault  = $("#navVault");

  // register
  const registerForm  = $("#registerForm");
  const keyDisplay    = $("#keyDisplay");

  // login
  const loginStep1Form = $("#loginStep1Form");
  const loginStep2Form = $("#loginStep2Form");

  // vault
  const uploadForm     = $("#uploadForm");
  const downloadForm   = $("#downloadForm");
  const fileInput      = $("#fileInput");
  const fileDrop       = $("#fileDrop");
  const fileName       = $("#fileName");
  const uploadResult   = $("#uploadResult");
  const downloadResult = $("#downloadResult");
  const vaultList      = $("#vaultList");
  const toggleKeysBtn  = $("#toggleKeysBtn");
  const keysInner      = $("#keysInner");
  const downloadPreview= $("#downloadPreview");

  toggleKeysBtn?.addEventListener("click", () => {
    keysInner.classList.toggle("hidden");
  });

  // ─── Navigation ───
  $$(".nav-btn[data-page]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const page = btn.dataset.page;
      $$(".nav-btn[data-page]").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      $$(".page").forEach((p) => p.classList.remove("active"));
      $(`#page${page.charAt(0).toUpperCase() + page.slice(1)}`).classList.add("active");
    });
  });

  // ─── Toast ───
  function toast(msg, type = "success") {
    const el = $("#toast");
    el.textContent = msg;
    el.className = `toast show ${type}`;
    setTimeout(() => (el.className = "toast hidden"), 3500);
  }

  // ─── Helpers ───
  function setLoading(btn, loading) {
    const text = btn.querySelector(".btn-text");
    const spin = btn.querySelector(".spinner");
    if (loading) {
      text?.classList.add("hidden");
      spin?.classList.remove("hidden");
      btn.disabled = true;
    } else {
      text?.classList.remove("hidden");
      spin?.classList.add("hidden");
      btn.disabled = false;
    }
  }

  async function api(method, path, body, isFormData = false) {
    const headers = {};
    if (sessionToken) headers["Authorization"] = `Bearer ${sessionToken}`;
    if (!isFormData) headers["Content-Type"] = "application/json";

    const resp = await fetch(`${API}${path}`, {
      method,
      headers,
      body: isFormData ? body : (body ? JSON.stringify(body) : undefined),
    });

    const contentType = resp.headers.get("content-type") || "";
    let data;
    if (contentType.includes("application/json")) {
      data = await resp.json();
    } else {
      data = await resp.blob();
    }

    return { ok: resp.ok, status: resp.status, data };
  }

  function updateLoginStatus() {
    const dot = $(".status-dot");
    const txt = $(".status-text");
    if (sessionToken) {
      dot.classList.add("online");
      dot.classList.remove("offline");
      txt.textContent = `User #${currentUserId}`;
    } else {
      dot.classList.remove("online");
      dot.classList.add("offline");
      txt.textContent = "Not logged in";
    }
  }

  // ─── Copy buttons ───
  document.addEventListener("click", (e) => {
    if (e.target.classList.contains("btn-copy")) {
      const target = $(` #${e.target.dataset.target}`);
      if (target) {
        navigator.clipboard.writeText(target.value);
        toast("Copied to clipboard!");
      }
    }
  });

  // ═══════════════════════════════════════════
  //  REGISTER
  // ═══════════════════════════════════════════
  registerForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = $("#regSubmit");
    setLoading(btn, true);

    const { ok, data } = await api("POST", "/register", {
      username: $("#regUsername").value.trim(),
      password: $("#regPassword").value,
      email:    $("#regEmail").value.trim(),
    });

    setLoading(btn, false);

    if (!ok) {
      toast(data.detail || "Registration failed", "error");
      return;
    }

    toast("Registration successful!");

    // show keys on registration card
    $("#rsaPrivKeyOut").value = data.rsa_private_key;
    $("#eccPrivKeyOut").value = data.ecc_private_key;
    $("#rsaPubKeyOut").value  = data.rsa_public_key;
    keyDisplay.classList.remove("hidden");

    // AUTO-FILL keys on the vault page so user doesn't have to copy-paste
    $("#userRsaPriv").value = data.rsa_private_key;
    const eccD = JSON.parse(data.ecc_private_key).d;
    $("#userEccPriv").value = String(eccD);
    loadKeysFromInputs();
    updateKeysStatus();

    // pre-fill login
    $("#loginUsername").value = $("#regUsername").value;
    $("#loginEmail").value   = $("#regEmail").value;
  });

  // ═══════════════════════════════════════════
  //  LOGIN STEP 1
  // ═══════════════════════════════════════════
  loginStep1Form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = $("#login1Submit");
    setLoading(btn, true);

    const { ok, data } = await api("POST", "/login/step1", {
      username: $("#loginUsername").value.trim(),
      password: $("#loginPassword").value,
      email:    $("#loginEmail").value.trim(),
    });

    setLoading(btn, false);

    if (!ok) {
      toast(data.detail || "Login failed", "error");
      return;
    }

    currentUserId = data.user_id;
    toast("Password verified! Check terminal for OTP.");
    loginStep1Form.classList.add("hidden");
    loginStep2Form.classList.remove("hidden");
  });

  // ═══════════════════════════════════════════
  //  LOGIN STEP 2
  // ═══════════════════════════════════════════
  loginStep2Form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = $("#login2Submit");
    setLoading(btn, true);

    const { ok, data } = await api("POST", "/login/step2", {
      user_id:  currentUserId,
      otp_code: $("#otpCode").value.trim(),
    });

    setLoading(btn, false);

    if (!ok) {
      toast(data.detail || "OTP verification failed", "error");
      return;
    }

    sessionToken = data.token;
    toast("Logged in successfully! 🎉");
    updateLoginStatus();

    loginStep2Form.classList.add("hidden");

    // switch to vault page
    navVault.click();
  });

  // ─── Watch key fields ───
  function loadKeysFromInputs() {
    try {
      const raw = $("#userRsaPriv").value.trim();
      if (raw) {
        const matchD = raw.match(/"d"\s*:\s*(\d+)/);
        const matchN = raw.match(/"n"\s*:\s*(\d+)/);
        if (matchD && matchN) {
          rsaPrivateKey = { d: matchD[1], n: matchN[1] };
        } else {
          rsaPrivateKey = null;
        }
      } else {
        rsaPrivateKey = null;
      }
    } catch (_) {}
    try {
      const raw = $("#userEccPriv").value.trim();
      if (raw) eccPrivateKey = raw; // keep as string!
      else eccPrivateKey = null;
    } catch (_) {}
    updateKeysStatus();
  }

  function updateKeysStatus() {
    const el = $("#keysStatus");
    if (!el) return;
    if (rsaPrivateKey && eccPrivateKey) {
      el.textContent = "✅ Keys loaded — ready for upload & download";
      el.classList.add("keys-status-ok");
    } else {
      el.textContent = "⚠️ Keys not set — upload/download will fail without them";
      el.classList.remove("keys-status-ok");
    }
  }

  $("#userRsaPriv").addEventListener("input", loadKeysFromInputs);
  $("#userEccPriv").addEventListener("input", loadKeysFromInputs);

  // ═══════════════════════════════════════════
  //  FILE DROP
  // ═══════════════════════════════════════════
  fileInput.addEventListener("change", () => {
    if (fileInput.files.length) {
      fileName.textContent = fileInput.files[0].name;
      $("#uploadSubmit").disabled = false;
    }
  });
  fileDrop.addEventListener("dragover", (e) => { e.preventDefault(); fileDrop.classList.add("dragover"); });
  fileDrop.addEventListener("dragleave", () => fileDrop.classList.remove("dragover"));
  fileDrop.addEventListener("drop", (e) => {
    e.preventDefault();
    fileDrop.classList.remove("dragover");
    if (e.dataTransfer.files.length) {
      fileInput.files = e.dataTransfer.files;
      fileName.textContent = e.dataTransfer.files[0].name;
      $("#uploadSubmit").disabled = false;
    }
  });

  // ═══════════════════════════════════════════
  //  UPLOAD
  // ═══════════════════════════════════════════
  uploadForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!sessionToken) { toast("Please login first", "error"); return; }
    loadKeysFromInputs();
    if (!eccPrivateKey) { toast("Paste your ECC private key first (🔑 card above)", "error"); return; }

    const btn = $("#uploadSubmit");
    setLoading(btn, true);

    const fd = new FormData();
    fd.append("file", fileInput.files[0]);
    fd.append("ecc_private_key", String(eccPrivateKey || 0));

    const { ok, data } = await api("POST", "/vault/upload", fd, true);
    setLoading(btn, false);

    uploadResult.classList.remove("hidden", "error");
    if (!ok) {
      uploadResult.classList.add("error");
      uploadResult.textContent = `Error: ${data.detail || JSON.stringify(data)}`;
      toast("Upload failed", "error");
      return;
    }

    uploadResult.innerHTML =
      `✅ <strong>Vault ID:</strong> ${data.vault_id}<br>` +
      `<strong>MAC:</strong> ${data.mac}<br>` +
      `<strong>Message:</strong> ${data.message}`;
    toast("File encrypted & uploaded!");
    refreshVaultList();
  });

  // ═══════════════════════════════════════════
  //  DOWNLOAD
  // ═══════════════════════════════════════════
  downloadForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!sessionToken) { toast("Please login first", "error"); return; }
    loadKeysFromInputs();

    const btn = $("#downloadSubmit");
    setLoading(btn, true);

    const vid = $("#vaultId").value;
    let qs = "";
    if (rsaPrivateKey) {
      qs = `?rsa_private_key_d=${rsaPrivateKey.d}&rsa_private_key_n=${rsaPrivateKey.n}`;
    }

    const { ok, status, data } = await api("GET", `/vault/download/${vid}${qs}`);
    setLoading(btn, false);

    downloadResult.classList.remove("hidden", "error");
    if (!ok) {
      downloadResult.classList.add("error");
      const msg = (data instanceof Blob)
        ? await data.text()
        : (data.detail || JSON.stringify(data));
      downloadResult.textContent = `Error (${status}): ${msg}`;
      toast("Download failed", "error");
      return;
    }

    // data is a Blob
    const buf = await data.arrayBuffer();
    const arr = new Uint8Array(buf);

    let isImage = false;
    let isText = true;
    if (arr.length >= 4) {
      if (arr[0]===0x89 && arr[1]===0x50 && arr[2]===0x4e && arr[3]===0x47) isImage = true;
      if (arr[0]===0xff && arr[1]===0xd8) isImage = true;
      if (arr[0]===0x47 && arr[1]===0x49 && arr[2]===0x46) isImage = true;
    }
    for (let i = 0; i < Math.min(arr.length, 100); i++) {
      if (arr[i] === 0 || (arr[i] < 32 && arr[i] !== 9 && arr[i] !== 10 && arr[i] !== 13)) {
        isText = false; break;
      }
    }

    const url = URL.createObjectURL(new Blob([buf]));
    const downloadPreview = $("#downloadPreview");
    downloadPreview.classList.remove("hidden");
    
    let previewHtml = "";
    if (isImage) {
      previewHtml = `<img src="${url}" style="max-width:100%; max-height:400px; border-radius:4px; box-shadow:0 4px 6px rgba(0,0,0,0.3);" />`;
    } else if (isText) {
      const text = new TextDecoder("utf-8").decode(arr.slice(0, 5000));
      // Basic escape:
      const safeText = text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
      previewHtml = `<pre style="max-height:300px; overflow:auto; text-align:left; background:#1e1e1e; padding:1rem; border-radius:6px; color:#ddd;">${safeText}${arr.length > 5000 ? "\\n...(truncated)" : ""}</pre>`;
    } else {
      previewHtml = `<div class="dim" style="font-size:3rem; margin-bottom:10px;">📦</div><p class="dim" style="margin:0;">Binary File Preview Not Supported</p>`;
    }

    downloadPreview.innerHTML = `
      <h3 style="margin-top:0;">File Preview</h3>
      ${previewHtml}
      <div style="margin-top:1.5rem;">
        <a href="${url}" download="decrypted_vault_${vid}.bin" class="btn btn-primary" style="display:inline-block; text-decoration:none;">Download File to Disk</a>
      </div>
    `;

    downloadResult.innerHTML = `✅ File decrypted successfully!`;
    toast("File decrypted successfully!");
  });

  // ═══════════════════════════════════════════
  //  VAULT LIST (simple fetch)
  // ═══════════════════════════════════════════
  async function refreshVaultList() {
    if (!sessionToken) return;
    vaultList.innerHTML = '<p class="dim">Loading…</p>';
    
    const { ok, data } = await api("GET", "/vault/list");
    if (!ok) {
      vaultList.innerHTML = '<p class="dim" style="color:var(--danger)">Failed to load entries</p>';
      return;
    }

    const items = data.entries.map(e => e.id);
    if (items.length === 0) {
      vaultList.innerHTML = '<p class="dim">No vault entries yet. Upload something!</p>';
      return;
    }
    
    vaultList.innerHTML = items.map((id) => `
      <div class="vault-item">
        <span class="vault-item-id">#${id}</span>
        <span class="vault-item-sig">Encrypted entry</span>
        <div class="vault-item-actions">
          <button class="btn btn-small btn-secondary" onclick="document.querySelector('#vaultId').value=${id}; document.querySelector('#downloadForm').scrollIntoView({behavior:'smooth'});">
            Select
          </button>
        </div>
      </div>
    `).join("");
  }

  $("#refreshVault").addEventListener("click", refreshVaultList);

  // init
  updateLoginStatus();
})();

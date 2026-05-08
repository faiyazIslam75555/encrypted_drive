(function () {
  "use strict";

  const API = "";
  let sessionToken = null;
  let currentUserId = null;
  let eccPrivateKey = null;

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);

  // ─── Persistence ───
  function saveSession() {
    localStorage.setItem("vault_session", JSON.stringify({
      token: sessionToken,
      userId: currentUserId,
      masterKey: eccPrivateKey
    }));
  }

  function loadSession() {
    const saved = localStorage.getItem("vault_session");
    if (saved) {
      try {
        const data = JSON.parse(saved);
        sessionToken = data.token;
        currentUserId = data.userId;
        eccPrivateKey = data.masterKey;
        
        if (eccPrivateKey && $("#userEccPriv")) {
          $("#userEccPriv").value = eccPrivateKey;
        }
        updateLoginStatus();
        
        // If we have a session, move to vault page automatically
        if (sessionToken) {
           $("#navVault")?.click();
        }
      } catch(e) { 
        localStorage.removeItem("vault_session"); 
      }
    }
  }

  function logout() {
    sessionToken = null;
    currentUserId = null;
    eccPrivateKey = null;
    localStorage.removeItem("vault_session");
    updateLoginStatus();
    $("#navAuth")?.click();
    toast("Session Terminated", "error");
  }

  // ─── UI ───
  function toast(msg, type = "success") {
    const el = $("#toast");
    if (!el) return;
    el.className = `toast ${type} show`;
    el.innerHTML = `<span>${type === "success" ? "⚡" : "⚠️"}</span> <span>${msg}</span>`;
    setTimeout(() => el.classList.remove("show"), 4000);
  }

  function updateLoginStatus() {
    const dot = $(".status-dot");
    const txt = $(".status-text");
    const navV = $("#navVault");

    if (sessionToken) {
      if (dot) dot.style.background = "var(--success)";
      if (txt) txt.textContent = `Node: ID-${currentUserId}`;
      if (navV) navV.classList.remove("hidden");
    } else {
      if (dot) dot.style.background = "var(--danger)";
      if (txt) txt.textContent = "Disconnected";
      if (navV) navV.classList.add("hidden");
    }
  }

  async function api(method, path, body, isFormData = false) {
    const headers = {};
    if (sessionToken) headers["Authorization"] = `Bearer ${sessionToken}`;
    if (!isFormData) headers["Content-Type"] = "application/json";

    try {
      const resp = await fetch(`${API}${path}`, {
        method,
        headers,
        body: isFormData ? body : (body ? JSON.stringify(body) : undefined),
      });

      if (resp.status === 401) {
        logout();
        return { ok: false, data: { detail: "Session Expired" } };
      }

      const contentType = resp.headers.get("content-type") || "";
      let data;
      if (contentType.includes("application/json")) {
        data = await resp.json();
      } else {
        data = { detail: await resp.text() };
      }
      return { ok: resp.ok, data };
    } catch (err) {
      return { ok: false, data: { detail: "Network Error" } };
    }
  }

  // ─── Navigation ───
  $$(".nav-btn[data-page]").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      const page = btn.dataset.page;
      
      if (page === "vault" && !sessionToken) {
        toast("Neural Authentication Required", "error");
        return;
      }

      $$(".nav-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      $$(".page").forEach(p => p.classList.remove("active"));
      $(`#page${page.charAt(0).toUpperCase() + page.slice(1)}`).classList.add("active");
      
      if (page === "vault") refreshVaultList();
    });
  });

  // ─── Auth ───
  $("#registerForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = $("#regSubmit");
    if (btn) btn.disabled = true;

    const { ok, data } = await api("POST", "/register", {
      username: $("#regUsername").value,
      password: $("#regPassword").value,
      email: $("#regEmail").value
    });

    if (btn) btn.disabled = false;
    if (!ok) return toast(data.detail || "Registration failed", "error");

    toast("Master Key Generated!");
    $("#eccPrivKeyOut").value = data.ecc_private_key;
    $("#keyDisplay").classList.remove("hidden");
    eccPrivateKey = data.ecc_private_key;
    if ($("#userEccPriv")) $("#userEccPriv").value = eccPrivateKey;
    saveSession();
  });

  $("#loginStep1Form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const { ok, data } = await api("POST", "/login/step1", {
      email: $("#loginEmail").value,
      password: $("#loginPassword").value
    });
    if (!ok) return toast(data.detail, "error");
    currentUserId = data.user_id;
    $("#loginStep1Form").classList.add("hidden");
    $("#loginStep2Form").classList.remove("hidden");
    toast("Phase 1 verified. Check OTP.");
  });

  $("#loginStep2Form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const { ok, data } = await api("POST", "/login/step2", {
      user_id: currentUserId,
      otp_code: $("#otpCode").value
    });
    if (!ok) return toast(data.detail, "error");
    sessionToken = data.token;
    saveSession();
    toast("Access Granted");
    updateLoginStatus();
    $("#navVault")?.click();
  });

  // ─── Vault ───
  $("#syncKeysBtn")?.addEventListener("click", (e) => {
    e.preventDefault();
    eccPrivateKey = $("#userEccPriv").value.trim();
    if (eccPrivateKey) {
      saveSession();
      toast("Master Core Synchronized");
    }
  });

  $("#secureResetBtn")?.addEventListener("click", async (e) => {
    e.preventDefault();
    if (!confirm("Permanently delete ALL encrypted data?")) return;
    const { ok } = await api("POST", "/vault/reset", { ecc_private_key: $("#userEccPriv").value });
    if (ok) {
      toast("Vault Wiped");
      refreshVaultList();
    }
  });

  $("#uploadForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const file = $("#fileInput").files[0];
    if (!file) return toast("No file selected", "error");
    
    const fd = new FormData();
    fd.append("file", file);
    fd.append("ecc_private_key", $("#userEccPriv").value);
    
    toast("Applying Neural Encryption...");
    const { ok } = await api("POST", "/vault/upload", fd, true);
    if (ok) {
      toast("Payload Secured");
      refreshVaultList();
    }
  });

  async function refreshVaultList() {
    const { ok, data } = await api("GET", "/vault/list");
    if (!ok) return;
    const list = $("#vaultList");
    if (!list) return;
    list.innerHTML = data.entries.map(e => `
      <div class="vault-item">
        <span>Sequence ID: #${e.id}</span>
        <button type="button" class="btn btn-secondary btn-small" onclick="window.retrieveFile(${e.id})">Decrypt</button>
      </div>
    `).join("");
  }

  // ─── Manual Retrieval Form ───
  $("#downloadForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const id = $("#vaultId").value;
    if (id) window.retrieveFile(id);
  });

  window.retrieveFile = async (id) => {
    const keyInput = $("#userEccPriv");
    const key = keyInput ? keyInput.value.trim() : eccPrivateKey;
    
    if (!key) return toast("Master Key Required for Decryption", "error");
    
    const previewEl = $("#downloadPreview");
    toast("Initiating Neural Decryption Sequence...");
    const { ok, data } = await api("GET", `/vault/download/${id}?ecc_private_key=${encodeURIComponent(key)}`);
    
    if (ok) {
      toast("Reassembling Asymmetric Chunks...");
      try {
        const bytes = new Uint8Array(data.data_hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
        const blob = new Blob([bytes]);
        const url = URL.createObjectURL(blob);
        
        // ---- NEURAL PREVIEWER ----
        const ext = data.filename.split('.').pop().toLowerCase();
        previewEl.classList.remove("hidden");
        previewEl.innerHTML = `
          <div style="text-align:center;">
            <p class="subtitle" style="margin-bottom:1rem;">Recovered: <strong>${data.filename}</strong></p>
            ${['png','jpg','jpeg','gif'].includes(ext) ? `<img src="${url}" style="max-width:100%; border-radius:8px; border:1px solid var(--accent);" />` : ''}
            ${['txt','md','js','py','json'].includes(ext) ? `<pre style="text-align:left; max-height:200px; overflow:auto; padding:1rem; background:#000; color:var(--success); border-radius:8px;">${new TextDecoder().decode(bytes)}</pre>` : ''}
            <div style="margin-top:1.5rem;">
               <a href="${url}" download="${data.filename}" class="btn btn-primary btn-small">Download ${data.filename}</a>
            </div>
          </div>
        `;

        toast("Neural Decryption Complete");
      } catch (err) {
        toast("Reassembly failed: Data corruption or invalid key", "error");
      }
    } else {
      toast(data.detail || "Neural retrieval failed", "error");
    }
  };
分析过程：
1. 更新了后端 `vault.py` 以支持加密文件名存储。
2. 更新了前端 `app.js` 的 `retrieveFile` 函数，使其使用后端返回的原始文件名。
3. 实现了 `downloadPreview` 区域的预览逻辑，支持常见图片格式和文本格式。
4. 现在下载时会使用原始文件名，而不是 `file_id.bin`。

  // ─── File Handling ───
  const fInput = $("#fileInput");
  const fName = $("#fileName");
  const uSubmit = $("#uploadSubmit");

  fInput?.addEventListener("change", () => {
    if (fInput.files.length) {
      fName.textContent = fInput.files[0].name;
      if (uSubmit) uSubmit.disabled = false;
    }
  });

  // ─── Initialization ───
  $("#refreshVault")?.addEventListener("click", (e) => {
    e.preventDefault();
    refreshVaultList();
  });

  loadSession();

})();

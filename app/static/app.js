(function () {
  "use strict";
  const API = "";
  let sessionToken = null, currentUserId = null, eccPrivateKey = null, currentView = "my-drive";
  const $ = s => document.querySelector(s), $$ = s => document.querySelectorAll(s);

  function saveSession() { localStorage.setItem("ds", JSON.stringify({ t: sessionToken, u: currentUserId, k: eccPrivateKey })); }
  function loadSession() {
    try { const d = JSON.parse(localStorage.getItem("ds")); sessionToken = d.t; currentUserId = d.u; eccPrivateKey = d.k; } catch { }
  }
  function toast(msg, type = "success") {
    const t = document.createElement("div");
    t.className = `toast toast-${type}`;
    t.innerHTML = msg; 
    $("#toastContainer").appendChild(t);
    setTimeout(() => t.remove(), 5000);
  }
  window.toast = toast;

  async function api(method, path, body, isForm = false) {
    const h = {}; if (sessionToken) h["Authorization"] = `Bearer ${sessionToken}`;
    if (!isForm) h["Content-Type"] = "application/json";
    try {
      const r = await fetch(API + path, { method, headers: h, body: isForm ? body : (body ? JSON.stringify(body) : undefined) });
      if (r.status === 401) { logout(); return { ok: false, data: {} }; }
      const d = (r.headers.get("content-type") || "").includes("json") ? await r.json() : {};
      return { ok: r.ok, data: d };
    } catch { return { ok: false, data: {} }; }
  }

  // ── Auth ──
  function showAuth() { $("#authOverlay").style.display = "flex"; $("#driveApp").style.display = "none"; }
  function showApp() {
    $("#authOverlay").style.display = "none"; $("#driveApp").style.display = "grid";
    fetchUser(); checkBanner(); refreshFiles();
    if (!eccPrivateKey) setTimeout(() => { openSettings(); toast("Enter Master Key", "error"); }, 500);
  }
  function logout() { sessionToken = currentUserId = eccPrivateKey = null; localStorage.removeItem("ds"); showAuth(); }

  $$(".auth-tab").forEach(t => t.addEventListener("click", () => {
    $$(".auth-tab").forEach(x => x.classList.remove("active")); t.classList.add("active");
    $$(".auth-form").forEach(f => f.style.display = "none");
    const f = $(`[data-form="${t.dataset.tab}"]`); if (f) f.style.display = "flex";
    $("#keyDisplay").style.display = "none";
  }));

  $("#registerForm")?.addEventListener("submit", async e => {
    e.preventDefault();
    const { ok, data } = await api("POST", "/register", { username: $("#regUsername").value, password: $("#regPassword").value, email: $("#regEmail").value });
    if (!ok) return toast(data.detail || "Failed", "error");
    eccPrivateKey = data.ecc_private_key; $("#eccPrivKeyOut").value = eccPrivateKey;
    $("#registerForm").style.display = "none"; $("#keyDisplay").style.display = "block"; toast("Account created!");
  });
  $("#copyKeyBtn")?.addEventListener("click", () => navigator.clipboard.writeText($("#eccPrivKeyOut").value).then(() => toast("Copied!")));
  $("#keySavedBtn")?.addEventListener("click", () => { $("#keyDisplay").style.display = "none"; $("#tabLogin").click(); });

  $("#loginStep1Form")?.addEventListener("submit", async e => {
    e.preventDefault();
    const { ok, data } = await api("POST", "/login/step1", { email: $("#loginEmail").value, password: $("#loginPassword").value });
    if (!ok) return toast(data.detail || "Failed", "error");
    currentUserId = data.user_id; $("#loginStep1Form").style.display = "none"; $("#loginStep2Form").style.display = "flex";
  });
  $("#loginStep2Form")?.addEventListener("submit", async e => {
    e.preventDefault();
    const { ok, data } = await api("POST", "/login/step2", { user_id: currentUserId, otp_code: $("#otpCode").value });
    if (!ok) return toast(data.detail || "Failed", "error");
    sessionToken = data.token; saveSession(); showApp();
  });

  async function fetchUser() {
    const kp = eccPrivateKey ? `?ecc_private_key=${encodeURIComponent(eccPrivateKey)}` : "";
    const { ok, data } = await api("GET", `/me${kp}`);
    if (!ok) return;
    currentUserId = data.user_id;
    const n = data.username || `User ${data.user_id}`;
    $("#userAvatar").textContent = n[0].toUpperCase();
    $("#dropdownAvatar").textContent = n[0].toUpperCase();
    $("#dropdownName").textContent = n;
    $("#dropdownEmail").textContent = data.email || `ID: ${data.user_id}`;
  }

  $("#userAvatar")?.addEventListener("click", e => { e.stopPropagation(); const d = $("#userDropdown"); d.style.display = d.style.display === "none" ? "block" : "none"; });
  document.addEventListener("click", () => { const d = $("#userDropdown"); if (d) d.style.display = "none"; });
  $("#logoutBtn")?.addEventListener("click", logout);

  // ── Key Banner ──
  function checkBanner() { const b = $("#keyBanner"); if (b) b.style.display = eccPrivateKey ? "none" : "flex"; }
  $("#keyBannerBtn")?.addEventListener("click", openSettings);

  // ── Settings ──
  function openSettings() { $("#settingsModal").style.display = "flex"; if (eccPrivateKey) $("#userEccPriv").value = eccPrivateKey; }
  $("#settingsBtn")?.addEventListener("click", openSettings);
  $("#closeSettingsModal")?.addEventListener("click", () => $("#settingsModal").style.display = "none");
  $("#syncKeysBtn")?.addEventListener("click", () => {
    eccPrivateKey = $("#userEccPriv").value.trim(); if (!eccPrivateKey) return toast("Enter key", "error");
    saveSession(); checkBanner(); $("#settingsModal").style.display = "none"; fetchUser(); refreshFiles(); toast("Key synced!");
  });
  $("#secureResetBtn")?.addEventListener("click", async () => {
    if (!confirm("Delete ALL files?")) return;
    const { ok } = await api("POST", "/vault/reset"); if (ok) { toast("Deleted"); refreshFiles(); }
  });

  // ── Upload ──
  $("#uploadTrigger")?.addEventListener("click", () => {
    if (!eccPrivateKey) { openSettings(); return toast("Set key first", "error"); }
    $("#fileInput").value = ""; $("#uploadDrop").style.display = "flex";
    $("#uploadFileInfo").style.display = "none"; $("#uploadSubmit").disabled = true;
    $("#uploadModal").style.display = "flex";
  });
  $("#closeUploadModal")?.addEventListener("click", () => $("#uploadModal").style.display = "none");
  $("#uploadDrop")?.addEventListener("click", () => $("#fileInput").click());
  $("#fileInput")?.addEventListener("change", () => {
    const f = $("#fileInput").files[0]; if (!f) return;
    $("#uploadDrop").style.display = "none"; $("#uploadFileInfo").style.display = "flex";
    $("#uploadFileName").textContent = f.name; $("#uploadFileSize").textContent = fmtSize(f.size);
    $("#uploadSubmit").disabled = false;
  });
  $("#clearFileBtn")?.addEventListener("click", () => {
    $("#fileInput").value = ""; $("#uploadDrop").style.display = "flex";
    $("#uploadFileInfo").style.display = "none"; $("#uploadSubmit").disabled = true;
  });
  $("#uploadForm")?.addEventListener("submit", async e => {
    e.preventDefault(); const fd = new FormData();
    fd.append("file", $("#fileInput").files[0]); fd.append("ecc_private_key", eccPrivateKey);
    const btn = $("#uploadSubmit"); btn.disabled = true; btn.textContent = "Encrypting...";
    const { ok } = await api("POST", "/vault/upload", fd, true);
    btn.disabled = false; btn.innerHTML = '<span class="material-icons-outlined">upload</span> Encrypt & Upload';
    if (ok) { toast("Uploaded!"); $("#uploadModal").style.display = "none"; refreshFiles(); }
    else toast("Upload failed", "error");
  });

  // ── Share Modal (one-click) ──
  let shareFileId = null;
  window._openShareModal = id => {
    if (!eccPrivateKey) { openSettings(); return toast("Set key first", "error"); }
    shareFileId = id; $("#userSearchResults").innerHTML = ""; $("#userSearchInput").value = "";
    $("#shareModal").style.display = "flex";
    // Auto-search on open
    doUserSearch();
  };
  $("#closeShareModal")?.addEventListener("click", () => $("#shareModal").style.display = "none");

  $("#userSearchBtn")?.addEventListener("click", doUserSearch);
  async function doUserSearch() {
    const { ok, data } = await api("GET", "/users/search");
    if (!ok || !data.length) { $("#userSearchResults").innerHTML = '<p style="padding:1rem;color:var(--text-secondary);">No other users found.</p>'; return; }
    $("#userSearchResults").innerHTML = data.map(u => `
      <div style="display:flex;justify-content:space-between;align-items:center;padding:0.75rem 1rem;border-bottom:1px solid var(--border);">
        <div><strong>${u.name}</strong> <span style="color:var(--text-secondary);font-size:0.8rem;">(ID #${u.id})</span><br><small style="color:var(--text-secondary);">RSA Key ✓</small></div>
        <button class="btn-primary" style="font-size:0.85rem;" data-uid="${u.id}" data-pubkey='${u.public_key.replace(/'/g, "\\'")}' onclick="window._shareNow(this)">Share Now</button>
      </div>`).join("");
  }

  window._shareNow = async btn => {
    const uid = parseInt(btn.dataset.uid), pubkey = btn.dataset.pubkey;
    btn.disabled = true; btn.textContent = "Encrypting...";
    const { ok, data } = await api("POST", "/share/send", {
      vault_id: shareFileId, target_user_id: uid, target_pub_key: pubkey, ecc_private_key: eccPrivateKey
    });
    if (ok) { toast("File shared!"); $("#shareModal").style.display = "none"; }
    else { toast(data.detail || "Failed", "error"); btn.disabled = false; btn.textContent = "Share Now"; }
  };

  async function deriveFullKeyPackage(key) {
    // Instead of doing slow math in JS, we ask the server for our derived package
    const { ok, data } = await api("GET", `/me?ecc_private_key=${encodeURIComponent(key)}`);
    if (ok) return data.keys;
    return null;
  }

  // ── File List ──
  async function refreshFiles() {
    const list = $("#fileList"); if (!list) return;

    // ── SHARING CENTER ──
    if (currentView === "sharing-center") {
      const [usersRes, filesRes, receivedRes, sentReqRes] = await Promise.all([
        api("GET", "/users/search"),
        api("GET", `/vault/list${eccPrivateKey ? "?ecc_private_key=" + encodeURIComponent(eccPrivateKey) : ""}`),
        api("GET", "/share/requests/received"),
        api("GET", "/share/requests/sent")
      ]);
      const users = usersRes.ok ? usersRes.data : [];
      const myFiles = filesRes.ok ? (filesRes.data.entries || []) : [];
      const received = receivedRes.ok ? receivedRes.data : [];
      const sentReqs = sentReqRes.ok ? sentReqRes.data : [];

      const pending = received.filter(r => r.status === "pending");
      const others = received.filter(r => r.status !== "pending" && r.status !== "rejected");

      list.innerHTML = `<div style="padding:1.5rem;max-width:760px;">

        ${pending.length || others.length ? `
        <div style="background:var(--surface-2);border:1px solid var(--border);border-radius:12px;padding:1.25rem;margin-bottom:1.5rem;">
          <h4 style="margin:0 0 1rem;color:var(--accent);"><span class="material-icons-outlined" style="vertical-align:middle;font-size:1.1rem;">notifications_active</span> Incoming Requests</h4>
          
          ${pending.map(r => `
            <div style="display:flex;justify-content:space-between;align-items:center;padding:0.75rem;background:var(--surface);border-radius:8px;margin-bottom:0.5rem;border-left:4px solid var(--accent);">
              <div><strong>${esc(r.sender_name)}</strong> wants to share a file</div>
              <div style="display:flex;gap:0.5rem;">
                <button class="btn-primary" style="font-size:0.8rem;" onclick="window._acceptReq(${r.id})">✓ Accept</button>
                <button class="btn-icon" style="color:#ef4444;" onclick="window._rejectReq(${r.id})"><span class="material-icons-outlined">close</span></button>
              </div>
            </div>`).join("")}

          ${others.map(r => `
            <div style="display:flex;justify-content:space-between;align-items:center;padding:0.75rem;background:rgba(34,197,94,0.05);border-radius:8px;margin-bottom:0.5rem;border:1px dashed rgba(34,197,94,0.2);">
              <div style="color:var(--text-secondary);">Accepted from <strong>${esc(r.sender_name)}</strong></div>
              <div style="display:flex;align-items:center;color:#22c55e;gap:0.25rem;font-size:0.8rem;font-weight:600;">
                <span class="material-icons-outlined" style="font-size:1rem;">check</span> ${r.status.toUpperCase()}
              </div>
            </div>`).join("")}
        </div>` : ""}

        <h4 style="margin-bottom:1rem;"><span class="material-icons-outlined" style="vertical-align:middle;">person_search</span> Find & Request Users</h4>
        <div style="display:flex;gap:0.5rem;margin-bottom:1rem;">
          <input id="scSearch" class="settings-input" placeholder="Type a username..." style="flex:1;" />
          <button class="btn-primary" onclick="window._scDoSearch()"><span class="material-icons-outlined">search</span> Search</button>
        </div>
        <div id="scUserList"><p style="color:var(--text-secondary);">Click Search to find users.</p></div>

        ${sentReqs.length ? `
        <div style="margin-top:2rem;border-top:1px solid var(--border);padding-top:1.5rem;">
          <h4 style="margin-bottom:1rem;"><span class="material-icons-outlined" style="vertical-align:middle;">outbound</span> My Sent Requests</h4>
          ${sentReqs.map(r => `
            <div class="file-item">
              <div class="file-name"><span class="material-icons-outlined" style="color:var(--accent);">send</span><span>Request to <strong>${esc(r.receiver_name)}</strong></span></div>
              <span class="file-size" style="color:${r.status === "accepted" ? "#22c55e" : r.status === "rejected" ? "#ef4444" : "var(--text-secondary)"};">${r.status}</span>
              ${r.status === "accepted" ? `
                <div style="display:flex;gap:0.5rem;align-items:center;">
                  <select id="sendFile${r.id}" style="padding:0.35rem;border-radius:6px;background:var(--surface);color:var(--text);border:1px solid var(--border);font-size:0.8rem;">
                    <option value="">Pick file...</option>
                    ${myFiles.map(f => `<option value="${f.id}">${esc(f.filename)}</option>`).join("")}
                  </select>
                  <button class="btn-primary" style="font-size:0.8rem;white-space:nowrap;" onclick="window._sendFile(${r.id}, this)">Encrypt & Send</button>
                </div>` : ""}
            </div>`).join("")}
        </div>` : ""}
      </div>`;

      const ucont = $("#scUserList");
      window._scDoSearch = () => {
        const filter = ($("#scSearch")?.value || "").toLowerCase();
        const filtered = filter ? users.filter(u => u.name.toLowerCase().includes(filter)) : users;
        if (!filtered.length) { ucont.innerHTML = '<p style="color:var(--text-secondary);">No users found.</p>'; return; }
        ucont.innerHTML = filtered.map(u => `
          <div style="display:flex;align-items:center;justify-content:space-between;padding:0.9rem 1rem;margin-bottom:0.5rem;background:var(--surface-2);border-radius:10px;">
            <div style="display:flex;align-items:center;gap:0.75rem;">
              <div style="width:38px;height:38px;border-radius:50%;background:linear-gradient(135deg,var(--accent),#8b5cf6);display:flex;align-items:center;justify-content:center;color:#fff;font-weight:700;">${(u.name || "?")[0].toUpperCase()}</div>
              <div><strong>${esc(u.name)}</strong><br><small style="color:var(--text-secondary);">ID #${u.id}</small></div>
            </div>
            <button class="btn-primary" style="font-size:0.85rem;" onclick="window._sendReq(${u.id}, this)">
              <span class="material-icons-outlined" style="font-size:1rem;">person_add</span> Send Request
            </button>
          </div>`).join("");
        setTimeout(() => { $("#scSearch")?.addEventListener("keydown", e => { if (e.key === "Enter") window._scDoSearch(); }); }, 0);
      };
      return;
    }

    // ── SHARED WITH ME ──
    if (currentView === "shared") {
      const { ok, data } = await api("GET", "/share/inbox");
      if (!ok) return;
      $("#storageText").textContent = `${data.length} shared`;
      list.innerHTML = data.length ? data.map(s => `
        <div class="file-item">
          <div class="file-name"><span class="material-icons-outlined" style="color:var(--accent);">share</span><span>Shared File #${s.vault_id} · from User #${s.from_id}</span></div>
          <span class="file-date">${fmtDate(s.date)}</span><span class="file-size"></span>
          <div class="file-actions">
            <button class="btn-icon" title="Decrypt & Download" onclick="window._dlShared(${s.id})"><span class="material-icons-outlined">download</span></button>
          </div>
        </div>`).join("") : '<div class="empty-state"><span class="material-icons-outlined empty-icon">people</span><h3>Nothing shared yet</h3><p>Files shared with you appear here</p></div>';
      return;
    }

    // ── MY DRIVE (default) ──
    const kp = eccPrivateKey ? `?ecc_private_key=${encodeURIComponent(eccPrivateKey)}` : "";
    const { ok, data } = await api("GET", `/vault/list${kp}`);
    if (!ok) return;
    const entries = data.entries || [];
    $("#storageText").textContent = `${entries.length} file${entries.length !== 1 ? "s" : ""} encrypted`;
    list.innerHTML = entries.length ? entries.map(f => `
      <div class="file-item">
        <div class="file-name"><span class="material-icons-outlined ${iconClass(f.filename)}">${iconName(f.filename)}</span><span>${esc(f.filename)}</span></div>
        <span class="file-date">${fmtDate(f.uploaded_at)}</span>
        <span class="file-size">${fmtSize(f.file_size)}</span>
        <div class="file-actions">
          <button class="btn-icon" title="Rename" onclick="window._renameFile(${f.id}, '${esc(f.filename)}')"><span class="material-icons-outlined">edit</span></button>
          <button class="btn-icon" title="Download" onclick="window._dlFile(${f.id})"><span class="material-icons-outlined">download</span></button>
          <button class="btn-icon" title="Share" onclick="window._openShareModal(${f.id})"><span class="material-icons-outlined">share</span></button>
          <button class="btn-icon" title="Delete" onclick="window._delFile(${f.id})"><span class="material-icons-outlined">delete</span></button>
        </div>
      </div>`).join("") : '<div class="empty-state"><span class="material-icons-outlined empty-icon">cloud_upload</span><h3>No files</h3><p>Upload your first file</p></div>';
  }

  // ── Phase 1: Send Request ──
  window._sendReq = async (uid, btn) => {
    btn.disabled = true; btn.textContent = "Sending...";
    const { ok, data } = await api("POST", `/share/request/${uid}`);
    btn.disabled = false; btn.innerHTML = '<span class="material-icons-outlined" style="font-size:1rem;">person_add</span> Send Request';
    if (ok) { toast("Request sent!"); refreshFiles(); }
    else toast(data.detail || "Failed", "error");
  };

  // ── Phase 2: Accept / Reject ──
  window._acceptReq = async (id) => {
    const { ok } = await api("POST", `/share/request/accept/${id}`);
    if (ok) { toast("Request accepted!"); refreshFiles(); }
  };
  window._rejectReq = async (id) => {
    const { ok } = await api("POST", `/share/request/reject/${id}`);
    if (ok) { toast("Request rejected.", "error"); refreshFiles(); }
  };

  // ── Phase 3: Encrypt & Send File ──
  window._sendFile = async (requestId, btn) => {
    const sel = $(`#sendFile${requestId}`);
    if (!sel || !sel.value) return toast("Pick a file first!", "error");
    if (!eccPrivateKey) return toast("Set your Master Key first", "error");
    btn.disabled = true; btn.textContent = "Encrypting...";
    const { ok, data } = await api("POST", "/share/send", {
      request_id: requestId, vault_id: parseInt(sel.value), ecc_private_key: eccPrivateKey
    });
    btn.disabled = false; btn.textContent = "Encrypt & Send";
    if (ok) { toast("File encrypted & sent!"); refreshFiles(); }
    else toast(data.detail || "Failed", "error");
  };


  // ── File Actions ──
  window._dlFile = async id => {
    if (!eccPrivateKey) return toast("Set key first", "error");
    showDecrypt(); const { ok, data } = await api("GET", `/vault/download/${id}?ecc_private_key=${encodeURIComponent(eccPrivateKey)}`);
    hideDecrypt(); if (!ok) return toast(data.detail || "Failed", "error");
    preview(data.filename, hex2bytes(data.data_hex));
  };
  window._dlShared = async id => {
    if (!eccPrivateKey) return toast("Set key first", "error");
    showDecrypt("Decrypting shared file..."); const { ok, data } = await api("GET", `/share/download/${id}?ecc_private_key=${encodeURIComponent(eccPrivateKey)}`);
    hideDecrypt(); if (!ok) return toast(data.detail || "Failed", "error");
    if (data.mac_verified) {
      toast(`
        <div style="text-align:left;">
          <div style="font-weight:bold;color:#22c55e;margin-bottom:2px;">🛡️ Data Integrity Audit: 100% Verified</div>
          <div style="font-size:0.75rem;opacity:0.9;">Cryptographic MAC match confirmed. No data corruption detected during transit.</div>
        </div>
      `, "success");
    }
  };
  window._delFile = async id => {
    if (!confirm("Delete permanently?")) return;
    const { ok } = await api("DELETE", `/vault/${id}`);
    if (ok) { toast("Deleted"); refreshFiles(); }
  };

  // ── Preview ──
  function preview(name, bytes) {
    const url = URL.createObjectURL(new Blob([bytes])), ext = (name || "").split(".").pop().toLowerCase();
    let h = ["png", "jpg", "jpeg", "gif", "webp"].includes(ext) ? `<img src="${url}" style="max-width:100%;border-radius:8px;" />` : `<pre style="max-height:400px;overflow:auto;">${esc(new TextDecoder().decode(bytes))}</pre>`;
    h += `<div style="margin-top:1rem;text-align:center;"><a href="${url}" download="${esc(name)}" class="btn-primary"><span class="material-icons-outlined">download</span> Save ${esc(name)}</a></div>`;
    $("#previewContent").innerHTML = h; $("#previewTitle").textContent = name; $("#previewModal").style.display = "flex";
  }
  $("#closePreviewModal")?.addEventListener("click", () => $("#previewModal").style.display = "none");

  // ── Decrypt Overlay ──
  function showDecrypt(t) { $("#decryptOverlay").style.display = "flex"; $("#decryptTitle").textContent = t || "Decrypting..."; }
  function hideDecrypt() { setTimeout(() => $("#decryptOverlay").style.display = "none", 400); }

  // ── Helpers ──
  function hex2bytes(hex) { return new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16))); }
  function fmtSize(b) { if (!b) return "--"; return b < 1024 ? b + " B" : b < 1048576 ? (b / 1024).toFixed(1) + " KB" : (b / 1048576).toFixed(1) + " MB"; }
  function fmtDate(iso) { if (!iso) return "--"; try { return new Date(iso).toLocaleDateString("en-US", { month: "short", day: "numeric" }); } catch { return "--"; } }
  function esc(s) { return (s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }
  function iconName(f) { if (!f) return "description"; const e = f.split(".").pop().toLowerCase(); return { png: "image", jpg: "image", jpeg: "image", gif: "image", pdf: "picture_as_pdf", txt: "description", md: "description", js: "code", py: "code", zip: "folder_zip" }[e] || "description"; }
  function iconClass(f) { if (!f) return ""; const e = f.split(".").pop().toLowerCase(); return ["png", "jpg", "jpeg", "gif", "webp"].includes(e) ? "file-icon-img" : ["pdf"].includes(e) ? "file-icon-pdf" : ""; }

  window._renameFile = async (id, oldName) => {
    const newName = prompt("Enter new filename:", oldName);
    if (!newName || newName === oldName) return;
    if (!eccPrivateKey) return toast("Set key first", "error");
    
    // Encrypt the new name locally
    const keys = deriveFullKeyPackage(eccPrivateKey);
    const m = BigInt("0x" + Array.from(new TextEncoder().encode(newName)).map(b => b.toString(16).padStart(2, '0')).join(''));
    const enc = "0x" + power(m, BigInt(keys.rsa_pub[0]), BigInt(keys.rsa_pub[1])).toString(16);
    
    const { ok } = await api("POST", `/vault/rename/${id}`, { new_name_encrypted: enc });
    if (ok) { toast("Renamed"); refreshFiles(); }
  };

  window._updateProfile = async () => {
    const newName = prompt("Enter new display name:");
    if (!newName) return;
    const { ok } = await api("POST", "/profile/update", { display_name: newName });
    if (ok) { toast("Profile updated"); refreshFiles(); }
  };
  // ── Nav ──
  $$(".sidebar-item").forEach(item => item.addEventListener("click", () => {
    $$(".sidebar-item").forEach(i => i.classList.remove("active")); item.classList.add("active");
    currentView = item.dataset.view; $("#viewTitle").textContent = item.innerText; refreshFiles();
  }));

  $("#refreshBtn")?.addEventListener("click", () => refreshFiles());
  $("#searchInput")?.addEventListener("input", e => {
    const q = e.target.value.toLowerCase();
    $$(".file-item").forEach(i => { i.style.display = (i.querySelector(".file-name")?.textContent.toLowerCase() || "").includes(q) ? "" : "none"; });
  });

  // ── Close modals on backdrop ──
  $$(".modal-backdrop").forEach(b => b.addEventListener("click", e => { if (e.target === b) b.style.display = "none"; }));

  // ── Init ──
  loadSession(); if (sessionToken) showApp(); else showAuth();
})();

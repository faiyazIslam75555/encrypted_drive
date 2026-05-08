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
    localStorage.setItem("drive_session", JSON.stringify({
      token: sessionToken, userId: currentUserId, masterKey: eccPrivateKey
    }));
  }
  function loadSession() {
    const s = localStorage.getItem("drive_session");
    if (!s) return;
    try {
      const d = JSON.parse(s);
      sessionToken = d.token; currentUserId = d.userId; eccPrivateKey = d.masterKey;
      if (eccPrivateKey && $("#userEccPriv")) $("#userEccPriv").value = eccPrivateKey;
    } catch { localStorage.removeItem("drive_session"); }
  }

  // ─── Toast ───
  function toast(msg, type = "success") {
    const el = $("#toast"); if (!el) return;
    el.className = `toast ${type} show`;
    el.textContent = msg;
    setTimeout(() => el.classList.remove("show"), 3500);
  }

  // ─── API Helper ───
  async function api(method, path, body, isFormData = false) {
    const headers = {};
    if (sessionToken) headers["Authorization"] = `Bearer ${sessionToken}`;
    if (!isFormData) headers["Content-Type"] = "application/json";
    try {
      const resp = await fetch(`${API}${path}`, {
        method, headers,
        body: isFormData ? body : (body ? JSON.stringify(body) : undefined),
      });
      if (resp.status === 401) { logout(); return { ok: false, data: { detail: "Session expired" } }; }
      const ct = resp.headers.get("content-type") || "";
      const data = ct.includes("json") ? await resp.json() : { detail: await resp.text() };
      return { ok: resp.ok, data };
    } catch { return { ok: false, data: { detail: "Network Error" } }; }
  }

  // ─── Auth UI ───
  function showAuthOverlay() {
    $("#authOverlay").style.display = "flex";
    $("#driveApp").style.display = "none";
  }
  function showDriveApp() {
    $("#authOverlay").style.display = "none";
    $("#driveApp").style.display = "grid";
    fetchUserInfo();
    checkKeyBanner();
    refreshFiles();
    // Auto-open settings if no key set
    if (!eccPrivateKey) {
      setTimeout(() => {
        openSettings();
        toast("Please enter your Master Key to decrypt files", "error");
      }, 500);
    }
  }
  function logout() {
    sessionToken = null; currentUserId = null; eccPrivateKey = null;
    localStorage.removeItem("drive_session");
    showAuthOverlay();
    toast("Signed out", "error");
  }

  // Auth Tabs
  $$(".auth-tab").forEach(tab => {
    tab.addEventListener("click", () => {
      $$(".auth-tab").forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      const target = tab.dataset.tab;
      $$(".auth-form").forEach(f => f.style.display = "none");
      const form = $(`[data-form="${target}"]`);
      if (form) form.style.display = "flex";
      $("#keyDisplay").style.display = "none";
    });
  });

  // Register
  $("#registerForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = $("#regSubmit"); btn.disabled = true;
    const { ok, data } = await api("POST", "/register", {
      username: $("#regUsername").value,
      password: $("#regPassword").value,
      email: $("#regEmail").value
    });
    btn.disabled = false;
    if (!ok) return toast(data.detail || "Registration failed", "error");
    toast("Account created!");
    eccPrivateKey = data.ecc_private_key;
    $("#eccPrivKeyOut").value = eccPrivateKey;
    $("#registerForm").style.display = "none";
    $("#keyDisplay").style.display = "block";
  });

  // Copy key
  $("#copyKeyBtn")?.addEventListener("click", () => {
    const key = $("#eccPrivKeyOut").value;
    navigator.clipboard.writeText(key).then(() => toast("Key copied!"));
  });

  // Key saved -> go to login
  $("#keySavedBtn")?.addEventListener("click", () => {
    $("#keyDisplay").style.display = "none";
    $("#tabLogin").click();
  });

  // Login Step 1
  $("#loginStep1Form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = $("#login1Submit"); btn.disabled = true;
    const { ok, data } = await api("POST", "/login/step1", {
      email: $("#loginEmail").value, password: $("#loginPassword").value
    });
    btn.disabled = false;
    if (!ok) return toast(data.detail || "Invalid credentials", "error");
    currentUserId = data.user_id;
    $("#loginStep1Form").style.display = "none";
    $("#loginStep2Form").style.display = "flex";
    toast("Check console for OTP code");
  });

  // Login Step 2
  $("#loginStep2Form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = $("#login2Submit"); btn.disabled = true;
    const { ok, data } = await api("POST", "/login/step2", {
      user_id: currentUserId, otp_code: $("#otpCode").value
    });
    btn.disabled = false;
    if (!ok) return toast(data.detail || "Invalid OTP", "error");
    sessionToken = data.token;
    saveSession();
    toast("Welcome back!");
    showDriveApp();
  });

  // ─── User Info ───
  function setUserDisplay(name, email) {
    const initial = (name || "U").charAt(0).toUpperCase();
    $("#userAvatar").textContent = initial;
    $("#dropdownAvatar").textContent = initial;
    $("#dropdownName").textContent = name || `User ${currentUserId}`;
    $("#dropdownEmail").textContent = email || `ID: ${currentUserId || "--"}`;
  }

  async function fetchUserInfo() {
    setUserDisplay(null, null); // show defaults first
    const keyParam = eccPrivateKey ? `?ecc_private_key=${encodeURIComponent(eccPrivateKey)}` : "";
    const { ok, data } = await api("GET", `/me${keyParam}`);
    if (ok) {
      currentUserId = data.user_id;
      setUserDisplay(data.username || `User ${data.user_id}`, data.email || `Role: ${data.role}`);
    }
  }

  // User menu toggle
  $("#userAvatar")?.addEventListener("click", (e) => {
    e.stopPropagation();
    const dd = $("#userDropdown");
    dd.style.display = dd.style.display === "none" ? "block" : "none";
  });
  document.addEventListener("click", () => { if ($("#userDropdown")) $("#userDropdown").style.display = "none"; });
  $("#logoutBtn")?.addEventListener("click", logout);

  // ─── Key Banner ───
  function checkKeyBanner() {
    const banner = $("#keyBanner");
    if (!banner) return;
    banner.style.display = eccPrivateKey ? "none" : "flex";
  }
  $("#keyBannerBtn")?.addEventListener("click", () => openSettings());

  // ─── Settings Modal ───
  function openSettings() {
    $("#settingsModal").style.display = "flex";
    if (eccPrivateKey) $("#userEccPriv").value = eccPrivateKey;
  }
  $("#settingsBtn")?.addEventListener("click", openSettings);
  $("#closeSettingsModal")?.addEventListener("click", () => { $("#settingsModal").style.display = "none"; });

  $("#syncKeysBtn")?.addEventListener("click", () => {
    eccPrivateKey = $("#userEccPriv").value.trim();
    if (!eccPrivateKey) return toast("Please enter your key", "error");
    saveSession();
    checkKeyBanner();
    toast("Key synced! Refreshing files...");
    $("#settingsModal").style.display = "none";
    fetchUserInfo();
    refreshFiles();
  });

  $("#secureResetBtn")?.addEventListener("click", async () => {
    if (!confirm("Permanently delete ALL your encrypted files?")) return;
    const { ok } = await api("POST", "/vault/reset");
    if (ok) { toast("All files deleted"); refreshFiles(); }
    else toast("Reset failed", "error");
  });

  // ─── Upload Modal ───
  function openUploadModal() {
    if (!eccPrivateKey) { toast("Set your Master Key in Settings first", "error"); openSettings(); return; }
    $("#uploadModal").style.display = "flex";
    resetUploadForm();
  }
  function resetUploadForm() {
    $("#fileInput").value = "";
    $("#uploadDrop").style.display = "flex";
    $("#uploadFileInfo").style.display = "none";
    $("#uploadSubmit").disabled = true;
  }

  $("#uploadTrigger")?.addEventListener("click", openUploadModal);
  $("#emptyUploadBtn")?.addEventListener("click", openUploadModal);
  $("#closeUploadModal")?.addEventListener("click", () => { $("#uploadModal").style.display = "none"; });

  // File selection
  $("#uploadDrop")?.addEventListener("click", () => $("#fileInput").click());
  $("#uploadDrop")?.addEventListener("dragover", (e) => { e.preventDefault(); e.currentTarget.classList.add("dragover"); });
  $("#uploadDrop")?.addEventListener("dragleave", (e) => { e.currentTarget.classList.remove("dragover"); });
  $("#uploadDrop")?.addEventListener("drop", (e) => {
    e.preventDefault(); e.currentTarget.classList.remove("dragover");
    if (e.dataTransfer.files.length) { $("#fileInput").files = e.dataTransfer.files; showSelectedFile(); }
  });

  $("#fileInput")?.addEventListener("change", showSelectedFile);
  function showSelectedFile() {
    const file = $("#fileInput").files[0];
    if (!file) return;
    $("#uploadDrop").style.display = "none";
    $("#uploadFileInfo").style.display = "flex";
    $("#uploadFileName").textContent = file.name;
    $("#uploadFileSize").textContent = formatSize(file.size);
    $("#uploadFileIcon").textContent = getFileIconName(file.name);
    $("#uploadSubmit").disabled = false;
  }
  $("#clearFileBtn")?.addEventListener("click", resetUploadForm);

  // Upload submit
  $("#uploadForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const file = $("#fileInput").files[0];
    if (!file) return;
    const btn = $("#uploadSubmit"); btn.disabled = true;
    btn.innerHTML = '<span class="material-icons-outlined">hourglass_top</span> Encrypting...';
    const fd = new FormData();
    fd.append("file", file);
    fd.append("ecc_private_key", eccPrivateKey);
    const { ok } = await api("POST", "/vault/upload", fd, true);
    btn.disabled = false;
    btn.innerHTML = '<span class="material-icons-outlined">upload</span> Encrypt & Upload';
    if (ok) {
      toast("File encrypted & uploaded!");
      $("#uploadModal").style.display = "none";
      refreshFiles();
    } else { toast("Upload failed", "error"); }
  });

  // ─── File List ───
  async function refreshFiles() {
    const list = $("#fileList");
    if (!list) return;
    const keyParam = eccPrivateKey ? `?ecc_private_key=${encodeURIComponent(eccPrivateKey)}` : "";
    const { ok, data } = await api("GET", `/vault/list${keyParam}`);
    if (!ok) return;

    const entries = data.entries || [];
    $("#storageText").textContent = `${entries.length} file${entries.length !== 1 ? "s" : ""} encrypted`;

    if (entries.length === 0) {
      list.innerHTML = `
        <div class="empty-state">
          <span class="material-icons-outlined empty-icon">cloud_upload</span>
          <h3>No files yet</h3>
          <p>Upload your first file to get started</p>
          <button class="btn-primary" onclick="document.getElementById('uploadTrigger').click()">
            <span class="material-icons-outlined">upload_file</span> Upload File
          </button>
        </div>`;
      return;
    }

    list.innerHTML = entries.map(f => {
      const icon = getFileIconName(f.filename);
      const iconClass = getFileIconClass(f.filename);
      const date = formatDate(f.uploaded_at);
      const size = formatSize(f.file_size || 0);
      return `
        <div class="file-item" data-id="${f.id}">
          <div class="file-name">
            <span class="material-icons-outlined ${iconClass}">${icon}</span>
            <span>${escapeHtml(f.filename)}</span>
          </div>
          <span class="file-date">${date}</span>
          <span class="file-size">${size}</span>
          <div class="file-actions">
            <button class="btn-icon" title="Download" onclick="event.stopPropagation(); window._downloadFile(${f.id})">
              <span class="material-icons-outlined">download</span>
            </button>
            <button class="btn-icon" title="Delete" onclick="event.stopPropagation(); window._deleteFile(${f.id})">
              <span class="material-icons-outlined">delete</span>
            </button>
          </div>
        </div>`;
    }).join("");
  }

  // ─── Download with Progress Bar ───
  function setDecryptProgress(percent, stage) {
    const bar = $("#decryptBar");
    const pct = $("#decryptPercent");
    const stg = $("#decryptStage");
    if (bar) bar.style.width = percent + "%";
    if (pct) pct.textContent = percent + "%";
    if (stg) stg.textContent = stage;
  }

  function showDecryptOverlay() {
    const overlay = $("#decryptOverlay");
    const box = overlay?.querySelector(".decrypt-box");
    if (box) box.classList.remove("complete");
    if (overlay) overlay.style.display = "flex";
    $("#decryptTitle").textContent = "Decrypting File...";
    setDecryptProgress(0, "Initializing asymmetric pipeline");
  }

  function hideDecryptOverlay(delay = 600) {
    setTimeout(() => {
      const overlay = $("#decryptOverlay");
      if (overlay) overlay.style.display = "none";
    }, delay);
  }

  window._downloadFile = async (id) => {
    if (!eccPrivateKey) { toast("Set your Master Key first", "error"); openSettings(); return; }

    showDecryptOverlay();

    // Stage 1: Fetching encrypted payload
    setDecryptProgress(15, "Fetching encrypted payload from vault...");
    await new Promise(r => setTimeout(r, 400));

    setDecryptProgress(30, "Deriving RSA key pair from Master Key...");
    await new Promise(r => setTimeout(r, 300));

    const { ok, data } = await api("GET", `/vault/download/${id}?ecc_private_key=${encodeURIComponent(eccPrivateKey)}`);

    if (!ok) {
      hideDecryptOverlay(0);
      toast(data.detail || "Download failed", "error");
      return;
    }

    // Stage 2: Decrypting chunks
    setDecryptProgress(50, "Decrypting RSA-encrypted chunks...");
    await new Promise(r => setTimeout(r, 400));

    setDecryptProgress(65, "Recovering original filename...");
    await new Promise(r => setTimeout(r, 300));

    try {
      setDecryptProgress(80, "Reassembling file from decrypted blocks...");
      await new Promise(r => setTimeout(r, 300));

      const bytes = new Uint8Array(data.data_hex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
      const blob = new Blob([bytes]);
      const url = URL.createObjectURL(blob);
      const ext = (data.filename || "").split('.').pop().toLowerCase();

      setDecryptProgress(95, "Verifying digital signature (ECDSA)...");
      await new Promise(r => setTimeout(r, 300));

      // Complete
      setDecryptProgress(100, "Decryption complete!");
      $("#decryptTitle").textContent = "File Recovered!";
      const box = $("#decryptOverlay")?.querySelector(".decrypt-box");
      if (box) box.classList.add("complete");

      await new Promise(r => setTimeout(r, 500));
      hideDecryptOverlay(0);

      // Show preview modal
      const previewEl = $("#previewContent");
      $("#previewTitle").textContent = data.filename;
      let html = "";
      if (['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg'].includes(ext)) {
        html = `<img src="${url}" alt="${escapeHtml(data.filename)}" />`;
      } else if (['txt', 'md', 'js', 'py', 'json', 'csv', 'html', 'css', 'xml', 'log'].includes(ext)) {
        html = `<pre>${escapeHtml(new TextDecoder().decode(bytes))}</pre>`;
      } else {
        html = `<p style="text-align:center;color:var(--text-secondary);">Preview not available for .${ext} files</p>`;
      }
      html += `<div class="preview-download"><a href="${url}" download="${escapeHtml(data.filename)}" class="btn-primary"><span class="material-icons-outlined">download</span> Download ${escapeHtml(data.filename)}</a></div>`;
      previewEl.innerHTML = html;
      $("#previewModal").style.display = "flex";
      toast("File decrypted!");
    } catch {
      hideDecryptOverlay(0);
      toast("Decryption failed", "error");
    }
  };

  $("#closePreviewModal")?.addEventListener("click", () => { $("#previewModal").style.display = "none"; });

  // ─── Delete ───
  window._deleteFile = async (id) => {
    if (!confirm("Delete this file permanently?")) return;
    const { ok } = await api("DELETE", `/vault/${id}`);
    if (ok) { toast("File deleted"); refreshFiles(); }
    else toast("Delete failed", "error");
  };

  // ─── Search ───
  $("#searchInput")?.addEventListener("input", (e) => {
    const query = e.target.value.toLowerCase();
    $$(".file-item").forEach(item => {
      const name = item.querySelector(".file-name")?.textContent.toLowerCase() || "";
      item.style.display = name.includes(query) ? "" : "none";
    });
  });

  // ─── Refresh ───
  $("#refreshBtn")?.addEventListener("click", () => refreshFiles());

  // ─── Helpers ───
  function getFileIconName(filename) {
    if (!filename) return "description";
    const ext = filename.split('.').pop().toLowerCase();
    const map = {
      png: "image", jpg: "image", jpeg: "image", gif: "image", webp: "image", svg: "image",
      pdf: "picture_as_pdf",
      doc: "description", docx: "description", txt: "description", md: "description",
      xls: "table_chart", xlsx: "table_chart", csv: "table_chart",
      mp3: "audiotrack", wav: "audiotrack", mp4: "movie", avi: "movie",
      js: "code", py: "code", html: "code", css: "code", json: "code", xml: "code",
      zip: "folder_zip", rar: "folder_zip", "7z": "folder_zip",
    };
    return map[ext] || "description";
  }
  function getFileIconClass(filename) {
    if (!filename) return "file-icon-generic";
    const ext = filename.split('.').pop().toLowerCase();
    if (["png", "jpg", "jpeg", "gif", "webp", "svg"].includes(ext)) return "file-icon-img";
    if (ext === "pdf") return "file-icon-pdf";
    if (["doc", "docx", "txt", "md"].includes(ext)) return "file-icon-doc";
    if (["xls", "xlsx", "csv"].includes(ext)) return "file-icon-sheet";
    if (["mp3", "wav", "mp4", "avi"].includes(ext)) return "file-icon-media";
    if (["js", "py", "html", "css", "json", "xml"].includes(ext)) return "file-icon-code";
    return "file-icon-generic";
  }
  function formatSize(bytes) {
    if (!bytes || bytes === 0) return "--";
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / 1048576).toFixed(1) + " MB";
  }
  function formatDate(iso) {
    if (!iso) return "--";
    try {
      const d = new Date(iso);
      return d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
    } catch { return iso; }
  }
  function escapeHtml(str) {
    if (!str) return "";
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  // Close modals on backdrop click
  $$(".modal-backdrop").forEach(backdrop => {
    backdrop.addEventListener("click", (e) => {
      if (e.target === backdrop) backdrop.style.display = "none";
    });
  });

  // ─── Sidebar Navigation ───
  let currentView = "my-drive";
  $$(".sidebar-item").forEach(item => {
    item.addEventListener("click", (e) => {
      e.preventDefault();
      $$(".sidebar-item").forEach(i => i.classList.remove("active"));
      item.classList.add("active");
      currentView = item.dataset.view;
      const titles = { "my-drive": "My Drive", "recent": "Recent Files", "encrypted": "Encrypted Files" };
      $("#viewTitle").textContent = titles[currentView] || "My Drive";
      refreshFiles();
    });
  });

  // ─── Init ───
  loadSession();
  if (sessionToken) { showDriveApp(); }
  else { showAuthOverlay(); }

})();

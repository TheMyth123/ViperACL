/**
 * ViperACL Shared Sidebar & Global Modals Manager
 *
 * Provides sidebar drawer rendering (with project switching & custom delete modal),
 * New Project modal orchestration (name-only creation, duplicate rejection, and redirection),
 * Settings modal orchestration, and system status synchronization.
 */

let pendingDeleteCallback = null;

// Show error inside the New Project Modal
function showNewProjectError(message) {
  const errorBox = document.getElementById("new-project-error");
  const errorText = document.getElementById("new-project-error-text");
  const nameInput = document.getElementById("project-name-input");
  if (errorBox && errorText) {
    errorText.textContent = message;
    errorBox.classList.remove("hidden");
  }
  if (nameInput) {
    nameInput.classList.add("border-red-500", "focus:border-red-500", "focus:ring-red-500");
    nameInput.classList.remove("border-outline-variant", "focus:border-primary", "focus:ring-primary");
    nameInput.focus();
  }
}

function hideConnectionResult() {
  const resultBox = document.getElementById("test-connection-result");
  if (resultBox) {
    resultBox.classList.add("hidden");
    resultBox.className = "hidden text-[11px] font-jetbrains px-2.5 py-1.5 rounded border leading-snug flex items-center gap-1.5 transition-all";
  }
}

function showConnectionResult(msg, type = "info") {
  const resultBox = document.getElementById("test-connection-result");
  const resultIcon = document.getElementById("test-connection-icon");
  const resultText = document.getElementById("test-connection-text");
  if (!resultBox || !resultText) return;

  resultBox.className = "text-[11px] font-jetbrains px-2.5 py-1.5 rounded border leading-snug flex items-center gap-1.5 transition-all";

  if (type === "success") {
    resultBox.classList.add("bg-emerald-950/60", "border-emerald-500/50", "text-emerald-300");
    if (resultIcon) resultIcon.textContent = "check_circle";
  } else if (type === "error") {
    resultBox.classList.add("bg-rose-950/60", "border-rose-500/50", "text-rose-300");
    if (resultIcon) resultIcon.textContent = "cancel";
  } else if (type === "warning") {
    resultBox.classList.add("bg-amber-950/60", "border-amber-500/50", "text-amber-300");
    if (resultIcon) resultIcon.textContent = "warning";
  } else {
    resultBox.classList.add("bg-surface-container-high", "border-outline-variant", "text-on-surface-variant");
    if (resultIcon) resultIcon.textContent = "info";
  }
  resultText.textContent = msg;
}

// Clear error inside the New Project Modal
function clearNewProjectError() {
  const errorBox = document.getElementById("new-project-error");
  const nameInput = document.getElementById("project-name-input");
  if (errorBox) {
    errorBox.classList.add("hidden");
  }
  if (nameInput) {
    nameInput.classList.remove("border-red-500", "focus:border-red-500", "focus:ring-red-500");
    nameInput.classList.add("border-outline-variant", "focus:border-primary", "focus:ring-primary");
  }
}

// Modal Utility Functions
function openNewProjectModal() {
  const modal = document.getElementById("new-project-modal");
  const box = document.getElementById("new-project-modal-box");
  const nameInput = document.getElementById("project-name-input");
  const dcIpInput = document.getElementById("project-dc-ip-input");
  const footholdUserInput = document.getElementById("project-foothold-user-input");
  const footholdPassInput = document.getElementById("project-foothold-pass-input");
  const counter = document.getElementById("project-name-counter");
  const submitBtn = document.getElementById("submit-new-project-btn");
  const btnLabel = document.getElementById("new-project-btn-label");

  clearNewProjectError();
  hideConnectionResult();
  if (nameInput) nameInput.value = "";
  if (dcIpInput) dcIpInput.value = "";
  if (footholdUserInput) footholdUserInput.value = "";
  if (footholdPassInput) {
    footholdPassInput.value = "";
    footholdPassInput.type = "password";
  }
  const passIcon = document.getElementById("toggle-new-proj-pass-icon");
  if (passIcon) passIcon.textContent = "visibility";

  if (counter) counter.textContent = "0 / 64";
  if (submitBtn) submitBtn.disabled = false;
  if (btnLabel) btnLabel.textContent = "Create Project";

  if (modal) {
    modal.classList.remove("hidden");
    requestAnimationFrame(() => {
      modal.classList.remove("opacity-0");
      if (box) {
        box.classList.remove("scale-95", "opacity-0");
        box.classList.add("scale-100", "opacity-100");
      }
      setTimeout(() => {
        if (nameInput) nameInput.focus();
      }, 100);
    });
  }
}

function closeNewProjectModal(e) {
  if (e && typeof e.preventDefault === "function") e.preventDefault();
  const modal = document.getElementById("new-project-modal");
  const box = document.getElementById("new-project-modal-box");
  if (modal) {
    modal.classList.add("opacity-0");
    if (box) {
      box.classList.remove("scale-100", "opacity-100");
      box.classList.add("scale-95", "opacity-0");
    }
    setTimeout(() => {
      modal.classList.add("hidden");
      clearNewProjectError();
      hideConnectionResult();
    }, 200);
  }
}

function openSettingsModal(e) {
  if (e && typeof e.preventDefault === "function") e.preventDefault();
  if (e && typeof e.stopPropagation === "function") e.stopPropagation();
  const modal = document.getElementById("settings-modal");
  const box = document.getElementById("settings-modal-box");
  const privescPassInput = document.getElementById("settings-privesc-default-password");
  const privescPassIcon = document.getElementById("toggle-privesc-pass-icon");
  if (privescPassInput) privescPassInput.type = "password";
  if (privescPassIcon) privescPassIcon.textContent = "visibility";
  if (modal) {
    modal.classList.remove("hidden");
    requestAnimationFrame(() => {
      modal.classList.remove("opacity-0");
      if (box) {
        box.classList.remove("scale-95", "opacity-0");
        box.classList.add("scale-100", "opacity-100");
      }
    });
  }
  return false;
}

function getPrivescPasswordPolicyError(password) {
  const value = String(password || "");
  if (value.length < 12 || value.length > 64) {
    return "Policy wrong: use 12-64 characters.";
  }
  if (/\s/.test(value)) {
    return "Policy wrong: spaces are not allowed.";
  }
  if (!/[A-Z]/.test(value)) {
    return "Policy wrong: include at least one uppercase letter.";
  }
  if (!/[a-z]/.test(value)) {
    return "Policy wrong: include at least one lowercase letter.";
  }
  if (!/\d/.test(value)) {
    return "Policy wrong: include at least one number.";
  }
  if (!/[^A-Za-z0-9]/.test(value)) {
    return "Policy wrong: include at least one special character.";
  }
  if (["p@ssw0rd!", "password123!", "changeme123!"].includes(value.toLowerCase())) {
    return "Policy wrong: password is too common.";
  }
  return "";
}

function setPrivescPasswordError(message) {
  const input = document.getElementById("settings-privesc-default-password");
  const error = document.getElementById("settings-privesc-password-error");
  if (input) {
    input.classList.add("border-red-500", "focus:border-red-500", "focus:ring-red-500");
    input.classList.remove("border-outline-variant", "focus:border-primary", "focus:ring-primary");
  }
  if (error) {
    error.textContent = message;
    error.classList.remove("hidden");
  }
}

function clearPrivescPasswordError() {
  const input = document.getElementById("settings-privesc-default-password");
  const error = document.getElementById("settings-privesc-password-error");
  if (input) {
    input.classList.remove("border-red-500", "focus:border-red-500", "focus:ring-red-500");
    input.classList.add("border-outline-variant", "focus:border-primary", "focus:ring-primary");
  }
  if (error) {
    error.textContent = "";
    error.classList.add("hidden");
  }
}

function closeSettingsModal(e) {
  if (e && typeof e.preventDefault === "function") e.preventDefault();
  if (e && typeof e.stopPropagation === "function") e.stopPropagation();
  const modal = document.getElementById("settings-modal");
  const box = document.getElementById("settings-modal-box");
  if (modal) {
    modal.classList.add("opacity-0");
    if (box) {
      box.classList.remove("scale-100", "opacity-100");
      box.classList.add("scale-95", "opacity-0");
    }
    setTimeout(() => {
      modal.classList.add("hidden");
    }, 200);
  }
  return false;
}

// Custom Delete Confirmation Modal Orchestration
function openCustomDeleteModal(projName, onConfirm) {
  pendingDeleteCallback = onConfirm;
  const modal = document.getElementById("delete-project-modal");
  const box = document.getElementById("delete-project-modal-box");
  const nameLabel = document.getElementById("delete-modal-project-name");
  
  if (nameLabel) nameLabel.textContent = projName;
  if (modal) {
    modal.classList.remove("hidden");
    requestAnimationFrame(() => {
      modal.classList.remove("opacity-0");
      if (box) {
        box.classList.remove("scale-95", "opacity-0");
        box.classList.add("scale-100", "opacity-100");
      }
    });
  }
}

function closeCustomDeleteModal() {
  pendingDeleteCallback = null;
  const modal = document.getElementById("delete-project-modal");
  const box = document.getElementById("delete-project-modal-box");
  if (modal) {
    modal.classList.add("opacity-0");
    if (box) {
      box.classList.remove("scale-100", "opacity-100");
      box.classList.add("scale-95", "opacity-0");
    }
    setTimeout(() => {
      modal.classList.add("hidden");
    }, 200);
  }
}

// Render Projects Drawer with selection and delete triggers
function renderGlobalProjectsDrawer(projects, activeProjectId, onProjectDeleted) {
  const drawer = document.getElementById("projects-drawer");
  if (!drawer) return;

  const activeProjects = (projects || []).filter((p) => !p.is_deleted && p.status !== "Deleted");

  if (activeProjects.length === 0) {
    drawer.innerHTML = '<div class="text-xs text-on-surface-variant italic px-3 py-1">No saved projects</div>';
    return;
  }

  drawer.innerHTML = "";

  activeProjects.forEach((proj) => {
    const isCurrent = proj.project_id === activeProjectId;
    const item = document.createElement("div");
    item.className = `flex items-center justify-between p-2 px-2.5 rounded text-xs transition-all group cursor-pointer ${
      isCurrent
        ? "bg-primary/15 border border-primary/40 text-on-surface font-semibold"
        : "text-on-surface-variant hover:text-on-surface hover:bg-surface-container-high border border-outline-variant/30"
    }`;
    item.title = `Switch to project: ${proj.name || proj.project_id}`;
    item.innerHTML = `
      <div class="flex items-center gap-2 overflow-hidden flex-1 select-none">
        <span class="w-1.5 h-1.5 rounded-full flex-shrink-0 ${isCurrent ? 'bg-primary shadow-[0_0_6px_#4edea3]' : 'bg-primary/40'}"></span>
        <div class="truncate">
          <div class="truncate ${isCurrent ? 'text-primary font-bold' : 'text-on-surface font-medium'}">${proj.name || proj.project_id}</div>
          <div class="text-[10px] text-on-surface-variant opacity-70">${proj.nodes || 0} nodes · ${proj.relationships || 0} rels</div>
        </div>
      </div>
      <button class="delete-proj-btn opacity-0 group-hover:opacity-100 text-on-surface-variant hover:text-error p-1 transition-opacity cursor-pointer flex-shrink-0" data-id="${proj.project_id}" title="Delete project (clears graph DB, retains metadata evidence)">
        <span class="material-symbols-outlined text-sm pointer-events-none">delete</span>
      </button>
    `;

    // Click project row to switch active project and navigate to /workspace
    item.addEventListener("click", async (e) => {
      if (e.target.closest(".delete-proj-btn")) return;
      try {
        const res = await fetch("/api/projects/select", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ project_id: proj.project_id }),
        });
        const data = await res.json();
        if (res.ok) {
          window.location.href = data.redirect_url || "/workspace";
        } else {
          alert(`Failed to select project: ${data.detail || "Error"}`);
        }
      } catch (err) {
        console.error("Failed to select project:", err);
      }
    });

    // Click trash icon to open custom delete modal
    const delBtn = item.querySelector(".delete-proj-btn");
    if (delBtn) {
      delBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        openCustomDeleteModal(proj.name || proj.project_id, () => {
          // Smooth collapse animation
          item.style.transition = "all 0.35s cubic-bezier(0.4, 0, 0.2, 1)";
          item.style.opacity = "0";
          item.style.transform = "translateY(-8px)";
          item.style.maxHeight = "0px";
          item.style.paddingTop = "0px";
          item.style.paddingBottom = "0px";
          item.style.marginTop = "0px";
          item.style.marginBottom = "0px";
          item.style.overflow = "hidden";

          setTimeout(async () => {
            try {
              const res = await fetch(`/api/projects/${proj.project_id}`, { method: "DELETE" });
              if (!res.ok) {
                const err = await res.json();
                alert(`Failed to delete project: ${err.detail || "Error"}`);
                fetchGlobalProjects();
                return;
              }
              fetchGlobalProjects();
              if (typeof onProjectDeleted === "function") {
                onProjectDeleted(proj.project_id);
              }
              if (window.refreshHealth && typeof window.refreshHealth === "function") {
                window.refreshHealth();
              }
              // If deleted project was active on workspace page, reload page
              if (isCurrent && window.location.pathname.includes("workspace")) {
                window.location.reload();
              }
            } catch (err) {
              alert(`Error deleting project: ${err.message}`);
              fetchGlobalProjects();
            }
          }, 350);
        });
      });
    }

    drawer.appendChild(item);
  });
}

// Fetch Projects for Sidebar
async function fetchGlobalProjects() {
  try {
    const res = await fetch("/api/projects");
    const data = await res.json();
    if (data.status === "ok") {
      renderGlobalProjectsDrawer(data.projects, data.active_project_id);
    }
  } catch (err) {
    console.error("Failed to fetch sidebar projects:", err);
  }
}

// Test Neo4j Database Connection
async function testGlobalDatabaseConnection() {
  const uri = document.getElementById("settings-db-uri")?.value?.trim();
  const username = document.getElementById("settings-db-user")?.value?.trim();
  const password = document.getElementById("settings-db-pass")?.value;
  const database = document.getElementById("settings-db-name")?.value?.trim();
  const feedback = document.getElementById("test-db-feedback");

  if (!feedback) return;
  feedback.classList.remove("hidden");
  feedback.innerHTML = `<span class="text-on-surface-variant font-bold">Testing connection ...</span>`;

  try {
    const res = await fetch("/api/neo4j/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ uri, username, password, database }),
    });

    const data = await res.json();
    if (data.status === "ok" && data.connected) {
      feedback.innerHTML = `
        <div class="text-primary font-bold">✓ ${data.message}</div>
        <div class="text-on-surface-variant font-medium mt-1">📊 ${data.details || `Total Nodes: ${data.nodes}`}</div>
      `;
    } else {
      feedback.innerHTML = `<div class="text-error font-bold">✗ ${data.message || "Connection failed"}</div>`;
    }
  } catch (err) {
    feedback.innerHTML = `<div class="text-error font-bold">✗ Error: ${err.message}</div>`;
  }
}

// Wire Global Sidebar Events
function initSidebarEvents() {
  // ESC Key Listener to close Modals
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" || e.code === "Escape") {
      const deleteModal = document.getElementById("delete-project-modal");
      if (deleteModal && !deleteModal.classList.contains("hidden")) {
        closeCustomDeleteModal();
      }
      const settingsModal = document.getElementById("settings-modal");
      if (settingsModal && !settingsModal.classList.contains("hidden")) {
        closeSettingsModal(e);
      }
      const newProjModal = document.getElementById("new-project-modal");
      if (newProjModal && !newProjModal.classList.contains("hidden")) {
        closeNewProjectModal(e);
      }
      const editTargetModal = document.getElementById("edit-target-modal");
      if (editTargetModal && !editTargetModal.classList.contains("hidden")) {
        if (typeof window.hideEditTargetModal === "function") {
          window.hideEditTargetModal();
        } else {
          editTargetModal.classList.add("opacity-0");
          setTimeout(() => editTargetModal.classList.add("hidden"), 200);
        }
      }
      const overwriteModal = document.getElementById("confirm-overwrite-modal");
      if (overwriteModal && !overwriteModal.classList.contains("hidden")) {
        if (typeof window.hideOverwriteModal === "function") {
          window.hideOverwriteModal();
        } else {
          overwriteModal.classList.add("opacity-0");
          setTimeout(() => overwriteModal.classList.add("hidden"), 200);
        }
      }
    }
  });

  // Custom Delete Modal Actions
  const cancelDeleteBtn = document.getElementById("cancel-delete-modal-btn");
  if (cancelDeleteBtn) {
    cancelDeleteBtn.addEventListener("click", () => closeCustomDeleteModal());
  }

  const confirmDeleteBtn = document.getElementById("confirm-delete-modal-btn");
  if (confirmDeleteBtn) {
    confirmDeleteBtn.addEventListener("click", () => {
      if (typeof pendingDeleteCallback === "function") {
        const callback = pendingDeleteCallback;
        closeCustomDeleteModal();
        callback();
      }
    });
  }

  // New Project Triggers
  const openNewProjBtn = document.getElementById("open-new-project-modal-btn");
  if (openNewProjBtn) {
    openNewProjBtn.addEventListener("click", () => openNewProjectModal());
  }

  const closeModalBtn = document.getElementById("close-modal-btn");
  if (closeModalBtn) {
    closeModalBtn.addEventListener("click", (e) => closeNewProjectModal(e));
  }

  const cancelModalBtn = document.getElementById("cancel-modal-btn");
  if (cancelModalBtn) {
    cancelModalBtn.addEventListener("click", (e) => closeNewProjectModal(e));
  }

  // Character Counter & Live Validation Listener
  const nameInput = document.getElementById("project-name-input");
  const nameCounter = document.getElementById("project-name-counter");
  if (nameInput) {
    nameInput.addEventListener("input", () => {
      const currentLen = nameInput.value.length;
      if (nameCounter) {
        nameCounter.textContent = `${currentLen} / 64`;
      }
      clearNewProjectError();
    });
  }

  // New Project Password Toggle
  const togglePassBtn = document.getElementById("toggle-new-proj-pass-btn");
  const passInput = document.getElementById("project-foothold-pass-input");
  const passIcon = document.getElementById("toggle-new-proj-pass-icon");
  if (togglePassBtn && passInput && passIcon) {
    togglePassBtn.addEventListener("click", () => {
      const isPass = passInput.type === "password";
      passInput.type = isPass ? "text" : "password";
      passIcon.textContent = isPass ? "visibility_off" : "visibility";
    });
  }

  // 1. Ping DC Button Handler
  const btnTestPing = document.getElementById("btn-test-ping-dc");
  const pingIcon = document.getElementById("test-ping-icon");
  const pingLabel = document.getElementById("test-ping-label");

  if (btnTestPing) {
    btnTestPing.addEventListener("click", async () => {
      const dcIpInput = document.getElementById("project-dc-ip-input");
      const dcIp = dcIpInput ? dcIpInput.value.trim() : "";
      if (!dcIp) {
        showConnectionResult("Enter a Domain Controller IP to test connectivity.", "warning");
        if (dcIpInput) dcIpInput.focus();
        return;
      }

      btnTestPing.disabled = true;
      if (pingIcon) {
        pingIcon.textContent = "refresh";
        pingIcon.classList.add("animate-spin");
      }
      if (pingLabel) pingLabel.textContent = "Pinging...";
      hideConnectionResult();

      try {
        const res = await fetch("/api/projects/test/ping", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ dc_ip: dcIp }),
        });
        const data = await res.json();
        if (res.ok && data.status === "ok") {
          showConnectionResult(data.message || "Successfully connected to Domain Controller.", "success");
        } else {
          const err = data.detail || data.message || "Failed to connect: DC unreachable";
          showConnectionResult(err, "error");
        }
      } catch (err) {
        showConnectionResult("Failed to connect: DC unreachable", "error");
      } finally {
        btnTestPing.disabled = false;
        if (pingIcon) {
          pingIcon.textContent = "cell_tower";
          pingIcon.classList.remove("animate-spin");
        }
        if (pingLabel) pingLabel.textContent = "Ping DC";
      }
    });
  }

  // 2. Verify Foothold Creds Button Handler
  const btnTestFoothold = document.getElementById("btn-test-foothold-creds");
  const fhIcon = document.getElementById("test-foothold-icon");
  const fhLabel = document.getElementById("test-foothold-label");

  if (btnTestFoothold) {
    btnTestFoothold.addEventListener("click", async () => {
      const dcIpInput = document.getElementById("project-dc-ip-input");
      const footholdUserInput = document.getElementById("project-foothold-user-input");
      const footholdPassInput = document.getElementById("project-foothold-pass-input");

      const dcIp = dcIpInput ? dcIpInput.value.trim() : "";
      let footholdUser = footholdUserInput ? footholdUserInput.value.trim() : "";
      const footholdPass = footholdPassInput ? footholdPassInput.value : "";

      if (!dcIp) {
        showConnectionResult("Foothold verification failed: DC unreachable", "warning");
        if (dcIpInput) dcIpInput.focus();
        return;
      }
      if (!footholdUser) {
        showConnectionResult("Enter a foothold username to verify.", "warning");
        if (footholdUserInput) footholdUserInput.focus();
        return;
      }
      if (!footholdPass) {
        showConnectionResult("Enter the foothold account password.", "warning");
        if (footholdPassInput) footholdPassInput.focus();
        return;
      }

      // Strip domain prefix if user entered DOMAIN\user or user@domain
      if (footholdUser.includes("\\")) {
        footholdUser = footholdUser.split("\\").pop().trim();
      }
      if (footholdUser.includes("@")) {
        footholdUser = footholdUser.split("@")[0].trim();
      }

      btnTestFoothold.disabled = true;
      if (fhIcon) {
        fhIcon.textContent = "refresh";
        fhIcon.classList.add("animate-spin");
      }
      if (fhLabel) fhLabel.textContent = "Verifying...";
      hideConnectionResult();

      try {
        const res = await fetch("/api/projects/test/foothold", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            dc_ip: dcIp,
            foothold_username: footholdUser,
            foothold_password: footholdPass,
          }),
        });
        const data = await res.json();
        if (res.ok && data.status === "ok") {
          showConnectionResult(data.message || `Successfully bound with foothold account '${footholdUser}'.`, "success");
        } else {
          const err = data.detail || data.message || "Foothold verification failed: Invalid credentials";
          showConnectionResult(err, "error");
        }
      } catch (err) {
        showConnectionResult("Foothold verification failed: DC unreachable", "error");
      } finally {
        btnTestFoothold.disabled = false;
        if (fhIcon) {
          fhIcon.textContent = "verified_user";
          fhIcon.classList.remove("animate-spin");
        }
        if (fhLabel) fhLabel.textContent = "Verify Foothold Creds";
      }
    });
  }

  // New Project Form Submit
  const newProjForm = document.getElementById("new-project-form");
  if (newProjForm) {
    newProjForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const rawName = nameInput ? nameInput.value : "";
      const cleaned = rawName.trim();

      const dcIpInput = document.getElementById("project-dc-ip-input");
      const footholdUserInput = document.getElementById("project-foothold-user-input");
      const footholdPassInput = document.getElementById("project-foothold-pass-input");

      const dcIp = dcIpInput ? dcIpInput.value.trim() : "";
      let footholdUser = footholdUserInput ? footholdUserInput.value.trim() : "";
      const footholdPass = footholdPassInput ? footholdPassInput.value : "";

      // Strip domain prefix if user entered DOMAIN\user or user@domain
      if (footholdUser.includes("\\")) {
        footholdUser = footholdUser.split("\\").pop().trim();
      }
      if (footholdUser.includes("@")) {
        footholdUser = footholdUser.split("@")[0].trim();
      }

      // Client-side Security & Length Pre-validation
      if (!cleaned || cleaned.length < 3) {
        showNewProjectError("Project name must be at least 3 characters long.");
        return;
      }
      if (cleaned.length > 64) {
        showNewProjectError("Project name cannot exceed 64 characters.");
        return;
      }
      if (/[<>"'\\/`;\0]/.test(cleaned)) {
        showNewProjectError("Project name contains disallowed or invalid characters.");
        return;
      }
      if (!/^[a-zA-Z0-9_\-\. ()\[\]]+$/.test(cleaned)) {
        showNewProjectError("Use only letters, numbers, spaces, dashes, dots, underscores, or parentheses.");
        return;
      }

      if (dcIp && (/[<>"'\\/`;\0 ]/.test(dcIp) || !/^[a-zA-Z0-9_\-\.:]{1,128}$/.test(dcIp))) {
        showNewProjectError("Domain Controller IP or hostname contains invalid characters.");
        return;
      }

      if (footholdUser && (/[<>"'\\/`;\0 ]/.test(footholdUser) || !/^[a-zA-Z0-9_\-\.]{1,64}$/.test(footholdUser))) {
        showNewProjectError("Foothold username must contain only letters, numbers, dots, dashes, or underscores.");
        return;
      }

      const submitBtn = document.getElementById("submit-new-project-btn");
      const btnLabel = document.getElementById("new-project-btn-label");
      if (submitBtn) submitBtn.disabled = true;
      if (btnLabel) btnLabel.textContent = "Creating...";

      try {
        const res = await fetch("/api/projects/create", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            name: cleaned,
            dc_ip: dcIp,
            foothold_username: footholdUser,
            foothold_password: footholdPass,
          }),
        });

        const data = await res.json();

        if (!res.ok) {
          // Handle duplicate name (409) or validation failure (400/422)
          const errorMsg = data.detail || (data.message ? data.message : "Failed to create project");
          showNewProjectError(errorMsg);
          if (submitBtn) submitBtn.disabled = false;
          if (btnLabel) btnLabel.textContent = "Create Project";
          return;
        }

        // Project created successfully -> redirect to workspace
        closeNewProjectModal();
        window.location.href = data.redirect_url || "/workspace";
      } catch (err) {
        showNewProjectError(`Network or server error: ${err.message}`);
        if (submitBtn) submitBtn.disabled = false;
        if (btnLabel) btnLabel.textContent = "Create Project";
      }
    });
  }

  // Settings Triggers
  const openSettingsBtn = document.getElementById("open-settings-btn");
  if (openSettingsBtn) {
    openSettingsBtn.addEventListener("click", (e) => openSettingsModal(e));
  }

  const closeSettingsBtn = document.getElementById("close-settings-modal-btn");
  if (closeSettingsBtn) {
    closeSettingsBtn.addEventListener("click", (e) => closeSettingsModal(e));
  }

  const cancelSettingsBtn = document.getElementById("cancel-settings-btn");
  if (cancelSettingsBtn) {
    cancelSettingsBtn.addEventListener("click", (e) => closeSettingsModal(e));
  }

  const saveSettingsBtn = document.getElementById("save-settings-btn");
  if (saveSettingsBtn) {
    saveSettingsBtn.addEventListener("click", async (e) => {
      const privescPasswordInput = document.getElementById("settings-privesc-default-password");
      const privescError = getPrivescPasswordPolicyError(privescPasswordInput?.value);
      if (privescError) {
        const privescTabBtn = document.querySelector('[data-tab="tab-privesc"]');
        if (privescTabBtn) privescTabBtn.click();
        if (privescPasswordInput) privescPasswordInput.focus();
        setPrivescPasswordError(privescError);
        return;
      }
      clearPrivescPasswordError();

      saveSettingsBtn.disabled = true;
      const originalText = saveSettingsBtn.innerHTML;
      saveSettingsBtn.innerHTML = `<span class="material-symbols-outlined text-sm pointer-events-none animate-spin">refresh</span> Saving...`;

      const payload = {
        neo4j_uri: document.getElementById("settings-db-uri")?.value?.trim(),
        neo4j_username: document.getElementById("settings-db-user")?.value?.trim(),
        neo4j_password: document.getElementById("settings-db-pass")?.value,
        neo4j_database: document.getElementById("settings-db-name")?.value?.trim(),
        pathfinder_default_mode: document.getElementById("settings-default-mode")?.value,
        pathfinder_max_hops: document.getElementById("settings-max-hops")?.value,
        pathfinder_ml_threshold: document.getElementById("settings-ml-threshold")?.value,
        privesc_default_change_password: document.getElementById("settings-privesc-default-password")?.value,
      };

      try {
        const res = await fetch("/api/settings/save", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        
        if (res.ok) {
          if (typeof window.refreshHealth === 'function') {
            window.refreshHealth();
          }
          closeSettingsModal(e);
        } else {
          const data = await res.json().catch(() => ({}));
          const message = data.message || "Failed to save settings";
          const normalizedMessage = message.toLowerCase();
          if (normalizedMessage.includes("policy wrong") || normalizedMessage.includes("password")) {
            const privescTabBtn = document.querySelector('[data-tab="tab-privesc"]');
            if (privescTabBtn) privescTabBtn.click();
            if (privescPasswordInput) privescPasswordInput.focus();
            setPrivescPasswordError(message);
          } else {
            alert(message);
          }
        }
      } catch (err) {
        alert("Error saving settings: " + err.message);
      } finally {
        saveSettingsBtn.disabled = false;
        saveSettingsBtn.innerHTML = originalText;
      }
    });
  }

  // Test DB Connection
  const btnTestDb = document.getElementById("btn-test-db");
  if (btnTestDb) {
    btnTestDb.addEventListener("click", () => testGlobalDatabaseConnection());
  }

  const togglePrivescPassBtn = document.getElementById("toggle-privesc-pass-btn");
  if (togglePrivescPassBtn) {
    togglePrivescPassBtn.addEventListener("click", () => {
      const input = document.getElementById("settings-privesc-default-password");
      const icon = document.getElementById("toggle-privesc-pass-icon");
      if (!input || !icon) return;
      const isHidden = input.type === "password";
      input.type = isHidden ? "text" : "password";
      icon.textContent = isHidden ? "visibility_off" : "visibility";
    });
  }

  const privescPasswordInput = document.getElementById("settings-privesc-default-password");
  if (privescPasswordInput) {
    privescPasswordInput.addEventListener("input", clearPrivescPasswordError);
  }

  // Settings Tab Switcher
  const settingsTabBtns = document.querySelectorAll(".settings-tab-btn");
  const settingsPanels = document.querySelectorAll(".settings-panel");
  settingsTabBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      const targetTab = btn.dataset.tab;
      settingsTabBtns.forEach((b) => {
        if (b === btn) {
          b.className = "settings-tab-btn w-full flex items-center gap-2.5 px-3 py-2 rounded text-xs font-bold text-left transition-colors bg-primary/15 text-primary border border-primary/30 cursor-pointer";
        } else {
          b.className = "settings-tab-btn w-full flex items-center gap-2.5 px-3 py-2 rounded text-xs font-bold text-left transition-colors text-on-surface-variant hover:text-on-surface hover:bg-surface-container-high cursor-pointer";
        }
      });

      settingsPanels.forEach((panel) => {
        if (panel.id === targetTab) {
          panel.classList.remove("hidden");
        } else {
          panel.classList.add("hidden");
        }
      });
    });
  });

  // Initial fetch of project drawer items
  fetchGlobalProjects();
}

// Expose functions globally for page-level scripts
window.fetchGlobalProjects = fetchGlobalProjects;
window.openNewProjectModal = openNewProjectModal;
window.closeNewProjectModal = closeNewProjectModal;
window.openSettingsModal = openSettingsModal;
window.closeSettingsModal = closeSettingsModal;

// Auto-run on DOMContentLoaded or immediately if DOM is ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initSidebarEvents);
} else {
  initSidebarEvents();
}


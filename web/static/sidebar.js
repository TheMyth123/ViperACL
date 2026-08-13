/**
 * ViperACL Shared Sidebar & Global Modals Manager
 *
 * Provides sidebar drawer rendering (with delete project buttons),
 * New Project modal orchestration, Settings modal orchestration,
 * and Custom Delete Confirmation modal orchestration across all pages.
 */

let pendingDeleteCallback = null;

// Modal Utility Functions
function openNewProjectModal() {
  const modal = document.getElementById("new-project-modal");
  if (modal) modal.classList.remove("hidden");
}

function closeNewProjectModal() {
  const modal = document.getElementById("new-project-modal");
  if (modal) modal.classList.add("hidden");
}

function openSettingsModal(e) {
  if (e && typeof e.preventDefault === "function") e.preventDefault();
  if (e && typeof e.stopPropagation === "function") e.stopPropagation();
  const modal = document.getElementById("settings-modal");
  const box = document.getElementById("settings-modal-box");
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

// Render Projects Drawer with Custom Delete Confirmation Modal Trigger
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
    const item = document.createElement("div");
    item.className = "flex items-center justify-between p-2 px-2.5 rounded text-xs text-on-surface-variant hover:text-on-surface hover:bg-surface-container-high border border-outline-variant/30 transition-colors group cursor-default";
    item.innerHTML = `
      <div class="flex items-center gap-2 overflow-hidden flex-1 select-none">
        <span class="w-1.5 h-1.5 rounded-full flex-shrink-0 bg-primary/60"></span>
        <div class="truncate">
          <div class="truncate font-medium text-on-surface">${proj.name || proj.project_id}</div>
          <div class="text-[10px] text-on-surface-variant opacity-70">${proj.nodes || 0} nodes · ${proj.relationships || 0} rels</div>
        </div>
      </div>
      <button class="delete-proj-btn opacity-0 group-hover:opacity-100 text-on-surface-variant hover:text-error p-1 transition-opacity cursor-pointer" data-id="${proj.project_id}" title="Delete project (clears graph DB, retains metadata evidence)">
        <span class="material-symbols-outlined text-sm pointer-events-none">delete</span>
      </button>
    `;

    // Click trash to open custom delete modal
    const delBtn = item.querySelector(".delete-proj-btn");
    if (delBtn) {
      delBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        openCustomDeleteModal(proj.name || proj.project_id, () => {
          // Smooth fade-out and slide-up collapse animation
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
  // ESC Key Listener to close Modals and discard unsaved changes
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
    closeModalBtn.addEventListener("click", () => closeNewProjectModal());
  }

  const cancelModalBtn = document.getElementById("cancel-modal-btn");
  if (cancelModalBtn) {
    cancelModalBtn.addEventListener("click", () => closeNewProjectModal());
  }

  // New Project Form Submit
  const newProjForm = document.getElementById("new-project-form");
  if (newProjForm) {
    newProjForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const name = document.getElementById("project-name-input")?.value?.trim();
      const zipPath = document.getElementById("project-zip-select")?.value;
      if (name && zipPath) {
        closeNewProjectModal();
        try {
          const res = await fetch("/api/projects/create", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name, zip_path: zipPath }),
          });
          if (!res.ok) {
            const err = await res.json();
            alert(`Failed to create project: ${err.detail || "Error"}`);
            return;
          }
          fetchGlobalProjects();
          if (window.refreshHealth && typeof window.refreshHealth === "function") {
            window.refreshHealth();
          }
        } catch (err) {
          alert(`Project creation failed: ${err.message}`);
        }
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
    saveSettingsBtn.addEventListener("click", (e) => {
      closeSettingsModal(e);
    });
  }

  // Test DB Connection
  const btnTestDb = document.getElementById("btn-test-db");
  if (btnTestDb) {
    btnTestDb.addEventListener("click", () => testGlobalDatabaseConnection());
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

// Auto-run on DOMContentLoaded or immediately if DOM is ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initSidebarEvents);
} else {
  initSidebarEvents();
}

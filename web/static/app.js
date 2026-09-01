/**
 * ViperACL — Launchpad Dashboard Controller
 *
 * Handles dashboard-specific UI: Neo4j database status,
 * predictive ML model statuses, and project modal trigger.
 *
 * Sidebar, project drawer, and global settings are handled by sidebar.js.
 */

const elements = {
  connectionState: document.getElementById("connection-state"),
  connectionStateDot: document.getElementById("connection-state-dot"),
  connectionBadge: document.getElementById("connection-badge"),
  databaseName: document.getElementById("database-name"),
  nodeCount: document.getElementById("node-count"),
  relationshipCount: document.getElementById("relationship-count"),
  mlEngineStatus: document.getElementById("ml-engine-status"),
  sidebarStatusContainer: document.getElementById("sidebar-status-container"),
  sidebarModelState: document.getElementById("sidebar-model-state"),
  sidebarStatusDot: document.getElementById("sidebar-status-dot"),
  createProjectButton: document.getElementById("create-project-button"),
};

// ---------------------------------------------------------------------------
// Status badge updates
// ---------------------------------------------------------------------------
function updateStatusBadge(health) {
  const snapshot = health?.snapshot || {};

  // Projects Drawer synchronization
  if (typeof renderGlobalProjectsDrawer === "function") {
    renderGlobalProjectsDrawer(health.projects || [], health.active_project_id);
  }

  // Database Connection
  if (elements.connectionState) {
    elements.connectionState.textContent = snapshot.connected ? "Connected" : "Disconnected";
  }
  if (elements.connectionStateDot) {
    elements.connectionStateDot.className = `w-2 h-2 rounded-full ${
      snapshot.connected ? "bg-[#10b981] shadow-[0_0_8px_#10b981]" : "bg-[#ff7f7f] shadow-[0_0_8px_#ff7f7f]"
    }`;
  }
  if (elements.connectionBadge) {
    elements.connectionBadge.className = `flex items-center gap-2 px-2.5 py-1 rounded font-bold border ${
      snapshot.connected ? "text-primary bg-primary/10 border-primary/20" : "text-[#ff7f7f] bg-red-950/60 border-red-500/50"
    }`;
  }
  if (elements.databaseName) elements.databaseName.textContent = snapshot.database || "-";
  if (elements.nodeCount) elements.nodeCount.textContent = snapshot.nodes ?? "0";
  if (elements.relationshipCount) elements.relationshipCount.textContent = snapshot.relationships ?? "0";

  // ML Predictive Suite (Summary Text & Engine Badge)
  const summaryTextEl = document.getElementById("ml-status-summary-text");
  if (summaryTextEl) {
    summaryTextEl.textContent = health.model_status_text || (health.model_available ? "Ready" : "Unavailable");
  }

  if (elements.mlEngineStatus) {
    if (health.model_available) {
      elements.mlEngineStatus.className = "flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-bold border text-[#4cd7f6] bg-[#4cd7f6]/10 border-[#4cd7f6]/30 transition-all";
    } else {
      elements.mlEngineStatus.className = "flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-bold border text-[#ff7f7f] bg-red-950/70 border-red-500/60 shadow-[0_0_12px_rgba(239,68,68,0.3)] transition-all";
    }
  }

  // ML Model Individual Status Badges (Random Forest, LightGBM, Transformer)
  if (health.ml_models && Array.isArray(health.ml_models)) {
    health.ml_models.forEach((m) => {
      const statusEl = document.getElementById(`ml-status-${m.id}`);
      const fileEl = document.getElementById(`ml-file-${m.id}`);
      if (statusEl) {
        if (m.available) {
          statusEl.innerHTML = `<span class="w-1.5 h-1.5 rounded-full bg-[#4cd7f6] shadow-[0_0_4px_#4cd7f6]"></span><span>Ready</span>`;
          statusEl.className = "text-[9.5px] px-1.5 py-0.5 rounded font-mono font-bold flex items-center gap-1 flex-shrink-0 border text-[#4cd7f6] bg-[#4cd7f6]/10 border-[#4cd7f6]/30";
        } else {
          statusEl.innerHTML = `<span class="w-1.5 h-1.5 rounded-full bg-[#ff7f7f]"></span><span>Missing</span>`;
          statusEl.className = "text-[9.5px] px-1.5 py-0.5 rounded font-mono font-bold flex items-center gap-1 flex-shrink-0 border text-[#ff7f7f] bg-red-950/60 border-red-500/50";
        }
      }
      if (fileEl && m.file) {
        fileEl.textContent = m.file;
        fileEl.title = m.file;
      }
    });
  }

  // Sidebar Status
  if (snapshot.connected && health.model_available) {
    if (elements.sidebarStatusContainer) elements.sidebarStatusContainer.className = "flex items-center gap-2 text-label-sm font-label-sm text-[#10b981] transition-colors";
    if (elements.sidebarStatusDot) elements.sidebarStatusDot.className = "w-2 h-2 rounded-full bg-[#10b981] shadow-[0_0_8px_#10b981] animate-pulse";
    if (elements.sidebarModelState) elements.sidebarModelState.textContent = "Active";
  } else if (snapshot.connected) {
    if (elements.sidebarStatusContainer) elements.sidebarStatusContainer.className = "flex items-center gap-2 text-label-sm font-label-sm text-[#ffbe5c] transition-colors";
    if (elements.sidebarStatusDot) elements.sidebarStatusDot.className = "w-2 h-2 rounded-full bg-[#ffbe5c] shadow-[0_0_8px_#ffbe5c] animate-pulse";
    if (elements.sidebarModelState) elements.sidebarModelState.textContent = "Degraded (No ML)";
  } else {
    if (elements.sidebarStatusContainer) elements.sidebarStatusContainer.className = "flex items-center gap-2 text-label-sm font-label-sm text-[#ff7f7f] transition-colors";
    if (elements.sidebarStatusDot) elements.sidebarStatusDot.className = "w-2 h-2 rounded-full bg-[#ff7f7f] shadow-[0_0_8px_#ff7f7f] animate-pulse";
    if (elements.sidebarModelState) elements.sidebarModelState.textContent = "Offline (No DB)";
  }
}

// ---------------------------------------------------------------------------
// Health Refresh API
// ---------------------------------------------------------------------------
async function refreshHealth() {
  try {
    const url = (window.VIPERACL_STATE && window.VIPERACL_STATE.healthUrl) || "/api/health";
    const response = await fetch(url);
    const health = await response.json();
    updateStatusBadge(health);
    return health;
  } catch (error) {
    return null;
  }
}

// Expose globally for sidebar.js and project switches
window.refreshHealth = refreshHealth;

// ---------------------------------------------------------------------------
// Event wiring
// ---------------------------------------------------------------------------
function wireEvents() {
  if (elements.createProjectButton) {
    elements.createProjectButton.addEventListener("click", () => {
      if (typeof openNewProjectModal === "function") openNewProjectModal();
    });
  }
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
function boot() {
  wireEvents();
  refreshHealth();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", boot);
} else {
  boot();
}

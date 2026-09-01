/**
 * ViperACL — Launchpad Dashboard Controller
 *
 * Handles dashboard-specific UI: status badges, workflow state,
 * pipeline card actions, and pathfinder/privesc/remediation orchestration.
 *
 * Sidebar, modals, settings tabs, and DB test are handled by sidebar.js.
 */

const state = {
  latestHealth: null,
  latestPathResult: null,
  latestPlan: null,
  latestRemediation: null,
};

const elements = {
  console: document.getElementById("console"),
  connectionState: document.getElementById("connection-state"),
  connectionStateDot: document.getElementById("connection-state-dot"),
  connectionBadge: document.getElementById("connection-badge"),
  databaseName: document.getElementById("database-name"),
  nodeCount: document.getElementById("node-count"),
  relationshipCount: document.getElementById("relationship-count"),
  mlModelType: document.getElementById("ml-model-type"),
  mlModelFile: document.getElementById("ml-model-file"),
  mlEngineStatus: document.getElementById("ml-engine-status"),
  sidebarStatusContainer: document.getElementById("sidebar-status-container"),
  sidebarModelState: document.getElementById("sidebar-model-state"),
  sidebarStatusDot: document.getElementById("sidebar-status-dot"),
  footerModelState: document.getElementById("footer-model-state"),
  latestPathCount: document.getElementById("latest-path-count"),
  latestPathMeta: document.getElementById("latest-path-meta"),
  latestPlanCount: document.getElementById("latest-plan-count"),
  latestPlanMeta: document.getElementById("latest-plan-meta"),
  latestRemediationCount: document.getElementById("latest-remediation-count"),
  latestRemediationMeta: document.getElementById("latest-remediation-meta"),
  createProjectButton: document.getElementById("create-project-button"),
  runFullChain: document.getElementById("run-full-chain"),
  refreshStatus: document.getElementById("refresh-status"),
  navLinks: Array.from(document.querySelectorAll(".nav-link[data-action]")),
  quickActions: Array.from(document.querySelectorAll(".quick-action[data-mode]")),
};

// ---------------------------------------------------------------------------
// Console helpers
// ---------------------------------------------------------------------------
function setConsole(lines, tone = "neutral") {
  const messages = Array.isArray(lines) ? lines : [lines];
  if (!elements.console) return;
  elements.console.innerHTML = "";

  messages.slice(0, 6).forEach((message, index) => {
    const line = document.createElement("div");
    line.className = `console-line ${tone === "muted" && index === 0 ? "muted" : ""}`.trim();
    line.textContent = message;
    elements.console.appendChild(line);
  });
}

function appendConsole(message, tone = "neutral") {
  if (!elements.console) return;
  const line = document.createElement("div");
  line.className = `console-line ${tone === "muted" ? "muted" : ""}`.trim();
  line.textContent = message;
  elements.console.appendChild(line);

  while (elements.console.children.length > 6) {
    elements.console.removeChild(elements.console.firstElementChild);
  }
}

// ---------------------------------------------------------------------------
// Status badge updates
// ---------------------------------------------------------------------------
function updateStatusBadge(health) {
  const snapshot = health?.snapshot || {};
  state.latestHealth = health;

  // Projects Drawer
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

  // ML Predictive Suite (3 Models)
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

  const predictiveButton = elements.quickActions?.find((button) => button.dataset.mode === "predictive");
  if (predictiveButton) {
    predictiveButton.disabled = !health.model_available;
    predictiveButton.title = health.model_available ? "Run predictive pathfinding" : "Predictive model is missing";
  }
}

// ---------------------------------------------------------------------------
// Workflow summary
// ---------------------------------------------------------------------------
function updateWorkflowSummary() {
  const path = state.latestPathResult;
  const plan = state.latestPlan;
  const remediation = state.latestRemediation;

  if (elements.latestPathCount) elements.latestPathCount.textContent = path ? `${path.step_count} steps` : "0 steps";
  if (elements.latestPathMeta) {
    elements.latestPathMeta.textContent = path
      ? `${path.mode || "selected"} mode ${path.score != null ? `| score ${path.score}%` : ""}`.trim()
      : "No path loaded";
  }
  if (elements.latestPlanCount) elements.latestPlanCount.textContent = plan ? `${plan.total_steps} tasks` : "0 tasks";
  if (elements.latestPlanMeta) elements.latestPlanMeta.textContent = plan ? "Ready for remediation" : "No plan built";
  if (elements.latestRemediationCount) elements.latestRemediationCount.textContent = remediation?.generated ? "1 file" : "0 files";
  if (elements.latestRemediationMeta) elements.latestRemediationMeta.textContent = remediation?.output_path ? remediation.output_path.split("/").pop() : "No script generated";
}

// ---------------------------------------------------------------------------
// API helpers
// ---------------------------------------------------------------------------
async function apiRequest(url, payload) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.detail || data.message || `Request failed with status ${response.status}`);
  }
  return data;
}

async function refreshHealth() {
  const response = await fetch(window.VIPERACL_STATE.healthUrl);
  const health = await response.json();
  updateStatusBadge(health);
  return health;
}

// Expose globally so sidebar.js can call it after project create/delete
window.refreshHealth = refreshHealth;

// ---------------------------------------------------------------------------
// Pipeline actions
// ---------------------------------------------------------------------------
function renderPathResult(response) {
  if (!response.results || !response.results.length) {
    state.latestPathResult = null;
    updateWorkflowSummary();
    setConsole([
      `Pathfinder mode: ${response.mode}`,
      "No valid path was returned for the selected source and target."
    ], "muted");
    return;
  }

  const path = response.results[0];
  state.latestPathResult = { ...path, mode: response.mode };
  state.latestPlan = null;
  state.latestRemediation = null;
  updateWorkflowSummary();

  const header = [`Pathfinder mode: ${response.mode}`, `Selected path: ${path.step_count} steps`];
  if (path.success_probability != null) header.push(`Success probability: ${path.success_probability}%`);
  if (path.metrics?.pathWeight != null) header.push(`Total weight: ${path.metrics.pathWeight}`);
  if (path.metrics?.hops != null) header.push(`Hops: ${path.metrics.hops}`);

  const stepLines = path.steps.slice(0, 4).map((step, index) => {
    const source = step.source?.name || step.source?.distinguishedname || "unknown";
    const target = step.target?.name || step.target?.distinguishedname || "unknown";
    return `${index + 1}. ${source} --[${step.relationship}]--> ${target}`;
  });

  setConsole([...header, ...stepLines], "neutral");
}

function getIngestPayload() {
  return {
    zip_path: window.prompt("SharpHound archive path", "dev/sample.zip")?.trim() || "",
    clear_database: true,
  };
}

function getPathfindPayload(modeOverride) {
  return {
    source_name: window.prompt("Source principal", "JDOE@CORP.LOCAL")?.trim() || "",
    target_name: window.prompt("Target principal", "DOMAIN_ADMIN@CORP.LOCAL")?.trim() || "",
    mode: modeOverride || "tactical",
  };
}

async function runIngest() {
  const payload = getIngestPayload();
  if (!payload.zip_path) throw new Error("Enter a SharpHound archive path before ingesting.");
  appendConsole(`Running ingest against ${payload.zip_path} ...`, "muted");
  const result = await apiRequest(window.VIPERACL_STATE.ingestUrl, payload);
  appendConsole(`Ingest complete: ${result.zip_path}`, "neutral");
  await refreshHealth();
}

async function runPathfind(modeOverride) {
  const payload = getPathfindPayload(modeOverride);
  if (!payload.source_name || !payload.target_name) throw new Error("Both source and target are required.");
  appendConsole(`Running ${payload.mode} pathfinding ...`, "muted");
  const result = await apiRequest(window.VIPERACL_STATE.pathfindUrl, payload);
  renderPathResult(result);
  return result;
}

async function runPrivescPlan() {
  if (!state.latestPathResult) throw new Error("Generate a path before building a privesc plan.");
  appendConsole("Building privesc plan from the selected path ...", "muted");
  const result = await apiRequest(window.VIPERACL_STATE.privescUrl, { path: state.latestPathResult.sequence });
  state.latestPlan = result;
  state.latestRemediation = null;
  updateWorkflowSummary();

  const lines = [`Privesc plan created: ${result.total_steps} tasks`].concat(
    result.tasks.slice(0, 5).map((task, index) => {
      const target = task.target?.name || task.target?.distinguishedname || "unknown";
      return `${index + 1}. ${task.type} -> ${target} (${task.module})`;
    })
  );
  setConsole(lines, "neutral");
  return result;
}

async function runRemediation() {
  if (!state.latestPlan) throw new Error("Build a privesc plan before generating remediation.");
  const targets = state.latestPlan.tasks.map((task) => ({
    type: task.type,
    source: task.source?.name || task.source?.distinguishedname || "unknown",
    target: task.target?.name || task.target?.distinguishedname || "unknown",
  }));
  appendConsole("Generating remediation script ...", "muted");
  const result = await apiRequest(window.VIPERACL_STATE.remediationUrl, { targets });
  state.latestRemediation = result;
  updateWorkflowSummary();
  setConsole([
    `Remediation generated: ${result.output_path || "script saved"}`,
    `Targets mitigated: ${result.target_count}`,
  ], "neutral");
  return result;
}

async function runFullChain() {
  await runPathfind("tactical");
  await runPrivescPlan();
  await runRemediation();
}

// ---------------------------------------------------------------------------
// Event wiring (dashboard-specific only)
// ---------------------------------------------------------------------------
function wireEvents() {
  // "Create New Project" hero button → opens modal (sidebar.js owns the modal)
  if (elements.createProjectButton) {
    elements.createProjectButton.addEventListener("click", () => {
      if (typeof openNewProjectModal === "function") openNewProjectModal();
    });
  }

  elements.quickActions.forEach((button) => {
    button.addEventListener("click", async () => {
      try { await runPathfind(button.dataset.mode); }
      catch (error) { setConsole(`Pathfinding failed: ${error.message}`, "muted"); }
    });
  });

  if (elements.runFullChain) {
    elements.runFullChain.addEventListener("click", async () => {
      try { await runFullChain(); }
      catch (error) { setConsole(`Workflow failed: ${error.message}`, "muted"); }
    });
  }

  if (elements.refreshStatus) {
    elements.refreshStatus.addEventListener("click", async () => {
      try {
        const health = await refreshHealth();
        setConsole([
          "Status refreshed.",
          health.snapshot.connected ? "Neo4j is connected." : "Neo4j is offline.",
        ], "muted");
      } catch (error) { setConsole(`Status refresh failed: ${error.message}`, "muted"); }
    });
  }

  elements.navLinks.forEach((link) => {
    link.addEventListener("click", async (event) => {
      const action = link.dataset.action;
      if (!action) return;
      event.preventDefault();
      try {
        if (action === "run-ingest") await runIngest();
        else if (action === "open-pathfinder") await runPathfind();
        else if (action === "refresh-status") { if (typeof openSettingsModal === "function") openSettingsModal(); }
        else if (action === "open-logs") window.location.href = "/logs";
      } catch (error) { setConsole(`${action} failed: ${error.message}`, "muted"); }
    });
  });
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
async function boot() {
  wireEvents();
  updateWorkflowSummary();
  setConsole("Booting ViperACL dashboard ...", "muted");

  try {
    const health = await refreshHealth();
    setConsole([
      "Dashboard online.",
      health.snapshot.connected ? "Neo4j connected." : "Neo4j currently disconnected.",
      health.model_available ? `Predictive model ready: ${health.model_name}` : "Predictive model is unavailable.",
    ], "muted");
  } catch (error) {
    setConsole(`Startup check failed: ${error.message}`, "muted");
  }
}

boot();

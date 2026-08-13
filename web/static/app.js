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
  pipelineCards: Array.from(document.querySelectorAll(".pipeline-card")),
  navLinks: Array.from(document.querySelectorAll(".nav-link[data-action]")),
  quickActions: Array.from(document.querySelectorAll(".quick-action[data-mode]")),
  
  // Multi-Project UI Elements
  toggleArchiveBtn: document.getElementById("toggle-archive-btn"),
  projectsDrawer: document.getElementById("projects-drawer"),
  archiveChevron: document.getElementById("archive-chevron"),
  activeProjectName: document.getElementById("active-project-name"),
  openNewProjectModalBtn: document.getElementById("open-new-project-modal-btn"),
  newProjectModal: document.getElementById("new-project-modal"),
  newProjectForm: document.getElementById("new-project-form"),
  closeModalBtn: document.getElementById("close-modal-btn"),
  projectNameInput: document.getElementById("project-name-input"),
  projectZipSelect: document.getElementById("project-zip-select"),

  // IDE Settings Modal Elements
  openSettingsBtn: document.getElementById("open-settings-btn"),
  settingsModal: document.getElementById("settings-modal"),
  closeSettingsModalBtn: document.getElementById("close-settings-modal-btn"),
  cancelSettingsBtn: document.getElementById("cancel-settings-btn"),
  saveSettingsBtn: document.getElementById("save-settings-btn"),
  btnTestDb: document.getElementById("btn-test-db"),
  testDbFeedback: document.getElementById("test-db-feedback"),
  settingsTabBtns: Array.from(document.querySelectorAll(".settings-tab-btn")),
  settingsPanels: Array.from(document.querySelectorAll(".settings-panel")),
};

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

function renderProjectsDrawer(projects, activeProjectId) {
  if (typeof renderGlobalProjectsDrawer === "function") {
    renderGlobalProjectsDrawer(projects, activeProjectId);
  }
}

async function selectProject(projectId) {
  try {
    setConsole(`Switching active project to ${projectId}...`, "muted");
    const response = await fetch("/api/projects/select", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ project_id: projectId }),
    });

    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.detail || "Failed to switch project");
    }

    await refreshHealth();
    setConsole(`Switched active project to ${projectId}. Dashboard aligned.`, "muted");
  } catch (error) {
    setConsole(`Project switch failed: ${error.message}`, "muted");
  }
}

async function createNewProject(name, zipPath) {
  try {
    setConsole(`Ingesting new project "${name}" from ${zipPath}...`, "muted");
    closeNewProjectModal();

    const response = await fetch("/api/projects/create", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: name, zip_path: zipPath }),
    });

    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.detail || "Failed to create project");
    }

    const data = await response.json();
    await refreshHealth();
    setConsole([
      `Project "${name}" ingested successfully!`,
      `Nodes: ${data.snapshot?.nodes || 0} | Relationships: ${data.snapshot?.relationships || 0}`,
    ], "muted");
  } catch (error) {
    setConsole(`Project creation failed: ${error.message}`, "muted");
  }
}

async function deleteProject(projectId) {
  try {
    setConsole(`Deleting project ${projectId}...`, "muted");
    const response = await fetch(`/api/projects/${projectId}`, {
      method: "DELETE",
    });

    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.detail || "Failed to delete project");
    }

    await refreshHealth();
    setConsole(`Project ${projectId} deleted.`, "muted");
  } catch (error) {
    setConsole(`Project delete failed: ${error.message}`, "muted");
  }
}

function openNewProjectModal() {
  if (elements.newProjectModal) {
    elements.newProjectModal.classList.remove("hidden");
  }
}

function closeNewProjectModal() {
  if (elements.newProjectModal) {
    elements.newProjectModal.classList.add("hidden");
  }
}

function openSettingsModal() {
  if (elements.settingsModal) {
    const box = document.getElementById("settings-modal-box");
    elements.settingsModal.classList.remove("hidden");
    requestAnimationFrame(() => {
      elements.settingsModal.classList.remove("opacity-0");
      if (box) {
        box.classList.remove("scale-95", "opacity-0");
        box.classList.add("scale-100", "opacity-100");
      }
    });
  }
}

function closeSettingsModal() {
  if (elements.settingsModal) {
    const box = document.getElementById("settings-modal-box");
    elements.settingsModal.classList.add("opacity-0");
    if (box) {
      box.classList.remove("scale-100", "opacity-100");
      box.classList.add("scale-95", "opacity-0");
    }
    setTimeout(() => {
      elements.settingsModal.classList.add("hidden");
    }, 200);
  }
}

async function testDatabaseConnection() {
  const uri = document.getElementById("settings-db-uri")?.value?.trim();
  const username = document.getElementById("settings-db-user")?.value?.trim();
  const password = document.getElementById("settings-db-pass")?.value;
  const database = document.getElementById("settings-db-name")?.value?.trim();

  if (!elements.testDbFeedback) return;
  elements.testDbFeedback.classList.remove("hidden");
  elements.testDbFeedback.innerHTML = `<span class="text-on-surface-variant font-bold">Testing connection ...</span>`;

  try {
    const res = await fetch("/api/neo4j/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ uri, username, password, database }),
    });

    const data = await res.json();
    if (data.status === "ok" && data.connected) {
      elements.testDbFeedback.innerHTML = `
        <div class="text-primary font-bold">✓ ${data.message}</div>
        <div class="text-on-surface-variant font-medium mt-1">📊 ${data.details || `Total Nodes: ${data.nodes}`}</div>
      `;
    } else {
      elements.testDbFeedback.innerHTML = `<div class="text-error font-bold">✗ ${data.message || "Connection failed"}</div>`;
    }
  } catch (err) {
    elements.testDbFeedback.innerHTML = `<div class="text-error font-bold">✗ Error: ${err.message}</div>`;
  }
}

function updateStatusBadge(health) {
  const snapshot = health?.snapshot || {};
  state.latestHealth = health;

  // 0. Projects Drawer
  renderProjectsDrawer(health.projects || [], health.active_project_id);

  // 1. Database Connection Status & Glow Dot
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

  // 2. ML Core Engine Status & Model Architecture Label
  if (elements.mlModelType) {
    elements.mlModelType.textContent = health.model_type || "Random Forest";
  }
  if (elements.mlModelFile) {
    elements.mlModelFile.textContent = health.model_name || "viper_rf_model.pkl";
    elements.mlModelFile.className = `text-[11px] font-mono px-2 py-0.5 rounded border whitespace-nowrap ${
      health.model_available ? "text-on-surface-variant bg-surface-container-high border-outline-variant" : "text-[#ff7f7f] bg-red-950/40 border-red-500/30"
    }`;
  }

  if (elements.mlEngineStatus) {
    if (health.model_available) {
      elements.mlEngineStatus.textContent = "Optimized & Ready";
      elements.mlEngineStatus.className = "flex items-center gap-2 text-[#4cd7f6] bg-[#4cd7f6]/10 px-3 py-1 rounded border border-[#4cd7f6]/30 font-bold transition-all";
    } else {
      elements.mlEngineStatus.textContent = "Model Unavailable";
      elements.mlEngineStatus.className = "flex items-center gap-2 text-[#ff7f7f] bg-red-950/70 px-3 py-1 rounded border border-red-500/60 shadow-[0_0_12px_rgba(239,68,68,0.3)] font-extrabold transition-all";
    }
  }

  // 3. Sidebar Bottom Left System Status (With Dynamic Text Color matching State)
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

  if (elements.buildPrivesc) {
    elements.buildPrivesc.disabled = !state.latestPathResult;
  }
  if (elements.buildRemediation) {
    elements.buildRemediation.disabled = !state.latestPlan;
  }
  if (elements.phasePrivesc) {
    elements.phasePrivesc.disabled = !state.latestPathResult;
  }
  if (elements.phaseRemediation) {
    elements.phaseRemediation.disabled = !state.latestPlan;
  }
}

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
  state.latestPathResult = {
    ...path,
    mode: response.mode,
  };
  state.latestPlan = null;
  state.latestRemediation = null;
  updateWorkflowSummary();

  const header = [`Pathfinder mode: ${response.mode}`, `Selected path: ${path.step_count} steps`];
  if (path.success_probability != null) {
    header.push(`Success probability: ${path.success_probability}%`);
  }
  if (path.metrics?.pathWeight != null) {
    header.push(`Total weight: ${path.metrics.pathWeight}`);
  }
  if (path.metrics?.hops != null) {
    header.push(`Hops: ${path.metrics.hops}`);
  }

  const stepLines = path.steps.slice(0, 4).map((step, index) => {
    const source = step.source?.name || step.source?.distinguishedname || "unknown";
    const target = step.target?.name || step.target?.distinguishedname || "unknown";
    return `${index + 1}. ${source} --[${step.relationship}]--> ${target}`;
  });

  setConsole([...header, ...stepLines], "neutral");
}

async function apiRequest(url, payload) {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
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

function getIngestPayload() {
  return {
    zip_path: window.prompt("SharpHound archive path", "dev/sample.zip")?.trim() || "",
    clear_database: true,
  };
}

function getPathfindPayload(modeOverride) {
  return {
    source_name: window.prompt("Source principal", "BOB_HR@VIPERTECH.LOCAL")?.trim() || "",
    target_name: window.prompt("Target principal", "SUSAN_ADMIN@VIPERTECH.LOCAL")?.trim() || "",
    mode: modeOverride || "tactical",
  };
}

async function runIngest() {
  const payload = getIngestPayload();

  if (!payload.zip_path) {
    throw new Error("Enter a SharpHound archive path before ingesting.");
  }

  appendConsole(`Running ingest against ${payload.zip_path} ...`, "muted");
  const result = await apiRequest(window.VIPERACL_STATE.ingestUrl, payload);
  appendConsole(`Ingest complete: ${result.zip_path}`, "neutral");
  await refreshHealth();
}

async function runPathfind(modeOverride) {
  const payload = getPathfindPayload(modeOverride);

  if (!payload.source_name || !payload.target_name) {
    throw new Error("Both source and target are required.");
  }

  appendConsole(`Running ${payload.mode} pathfinding ...`, "muted");
  const result = await apiRequest(window.VIPERACL_STATE.pathfindUrl, payload);
  renderPathResult(result);
  return result;
}

async function runPrivescPlan() {
  if (!state.latestPathResult) {
    throw new Error("Generate a path before building a privesc plan.");
  }

  appendConsole("Building privesc plan from the selected path ...", "muted");
  const result = await apiRequest(window.VIPERACL_STATE.privescUrl, {
    path: state.latestPathResult.sequence,
  });

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
  if (!state.latestPlan) {
    throw new Error("Build a privesc plan before generating remediation.");
  }

  const targets = state.latestPlan.tasks.map((task) => ({
    type: task.type,
    source: task.source?.name || task.source?.distinguishedname || "unknown",
    target: task.target?.name || task.target?.distinguishedname || "unknown",
  }));

  appendConsole("Generating remediation script ...", "muted");
  const result = await apiRequest(window.VIPERACL_STATE.remediationUrl, {
    targets,
  });

  state.latestRemediation = result;
  updateWorkflowSummary();
  setConsole([
    `Remediation generated: ${result.output_path || "script saved"}`,
    `Targets mitigated: ${result.target_count}`,
  ], "neutral");
  return result;
}

async function runFullChain() {
  const selectedMode = "tactical";
  await runPathfind(selectedMode);
  await runPrivescPlan();
  await runRemediation();
}

function wireEvents() {
  if (elements.openNewProjectModalBtn) {
    elements.openNewProjectModalBtn.addEventListener("click", () => openNewProjectModal());
  }

  if (elements.createProjectButton) {
    elements.createProjectButton.addEventListener("click", () => openNewProjectModal());
  }

  if (elements.closeModalBtn) {
    elements.closeModalBtn.addEventListener("click", () => closeNewProjectModal());
  }

  if (elements.cancelModalBtn) {
    elements.cancelModalBtn.addEventListener("click", () => closeNewProjectModal());
  }

  if (elements.newProjectForm) {
    elements.newProjectForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const name = elements.projectNameInput?.value?.trim();
      const zipPath = elements.projectZipSelect?.value;
      if (name && zipPath) {
        await createNewProject(name, zipPath);
      }
    });
  }

  elements.quickActions.forEach((button) => {
    button.addEventListener("click", async () => {
      try {
        await runPathfind(button.dataset.mode);
      } catch (error) {
        setConsole(`Pathfinding failed: ${error.message}`, "muted");
      }
    });
  });

  if (elements.runFullChain) {
    elements.runFullChain.addEventListener("click", async () => {
      try {
        await runFullChain();
      } catch (error) {
        setConsole(`Workflow failed: ${error.message}`, "muted");
      }
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
      } catch (error) {
        setConsole(`Status refresh failed: ${error.message}`, "muted");
      }
    });
  }

  elements.pipelineCards.forEach((card) => {
    card.addEventListener("click", async () => {
      const action = card.dataset.action;
      try {
        if (action === "phase-ingest") {
          await runIngest();
        } else if (action === "phase-pathfinder") {
          await runPathfind();
        } else if (action === "phase-privesc") {
          await runPrivescPlan();
        } else if (action === "phase-remediation") {
          await runRemediation();
        }
      } catch (error) {
        setConsole(`${action} failed: ${error.message}`, "muted");
      }
    });
  });

  // Settings Modal Event Listeners
  if (elements.openSettingsBtn) {
    elements.openSettingsBtn.addEventListener("click", (e) => {
      e.preventDefault();
      openSettingsModal();
    });
  }

  if (elements.closeSettingsModalBtn) {
    elements.closeSettingsModalBtn.addEventListener("click", () => closeSettingsModal());
  }

  if (elements.cancelSettingsBtn) {
    elements.cancelSettingsBtn.addEventListener("click", () => closeSettingsModal());
  }

  if (elements.saveSettingsBtn) {
    elements.saveSettingsBtn.addEventListener("click", () => {
      closeSettingsModal();
      setConsole("System settings saved & updated.", "muted");
    });
  }

  if (elements.btnTestDb) {
    elements.btnTestDb.addEventListener("click", () => testDatabaseConnection());
  }

  // Settings Tab Switching
  elements.settingsTabBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      const targetTab = btn.dataset.tab;
      elements.settingsTabBtns.forEach((b) => {
        if (b === btn) {
          b.className = "settings-tab-btn w-full flex items-center gap-2.5 px-3 py-2 rounded text-xs font-bold text-left transition-colors bg-primary/15 text-primary border border-primary/30 cursor-pointer";
        } else {
          b.className = "settings-tab-btn w-full flex items-center gap-2.5 px-3 py-2 rounded text-xs font-bold text-left transition-colors text-on-surface-variant hover:text-on-surface hover:bg-surface-container-high cursor-pointer";
        }
      });

      elements.settingsPanels.forEach((panel) => {
        if (panel.id === targetTab) {
          panel.classList.remove("hidden");
        } else {
          panel.classList.add("hidden");
        }
      });
    });
  });

  elements.navLinks.forEach((link) => {
    link.addEventListener("click", async (event) => {
      const action = link.dataset.action;
      if (!action) return;
      event.preventDefault();
      try {
        if (action === "run-ingest") {
          await runIngest();
        } else if (action === "open-pathfinder") {
          await runPathfind();
        } else if (action === "refresh-status") {
          openSettingsModal();
        } else if (action === "open-logs") {
          window.location.href = "/logs";
        }
      } catch (error) {
        setConsole(`${action} failed: ${error.message}`, "muted");
      }
    });
  });
}

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

/**
 * ViperACL — Global Audit Logs Frontend
 *
 * Handles SSE streaming, log rendering, filtering, and export.
 */

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
const logsState = {
  entries: [],
  eventSource: null,
  paused: false,
  autoScroll: true,
  activeLevels: new Set(["INFO", "WARNING", "ERROR", "CRITICAL"]),
  activeCategory: "",
  activeProject: "",
  searchQuery: "",
  connected: false,
  displayedCount: 0,
  totalOnDisk: 0,
};

let isProgrammaticScroll = false;

// ---------------------------------------------------------------------------
// Elements
// ---------------------------------------------------------------------------
const el = {
  logContainer: document.getElementById("log-container"),
  emptyState: document.getElementById("log-empty-state"),
  streamDot: document.getElementById("stream-dot"),
  streamLabel: document.getElementById("stream-label"),
  streamStatus: document.getElementById("stream-status"),
  logTotalCount: document.getElementById("log-total-count"),
  displayedCount: document.getElementById("displayed-count"),
  diskCount: document.getElementById("disk-count"),
  footerStreamState: document.getElementById("footer-stream-state"),
  lastEntryTime: document.getElementById("last-entry-time"),
  categoryFilter: document.getElementById("category-filter"),
  projectFilter: document.getElementById("project-filter"),
  searchInput: document.getElementById("search-input"),
  btnAutoScroll: document.getElementById("btn-auto-scroll"),
  btnPauseStream: document.getElementById("btn-pause-stream"),
  btnExport: document.getElementById("btn-export"),
  btnClearDisplay: document.getElementById("btn-clear-display"),
  pauseIcon: document.getElementById("pause-icon"),
  pauseLabel: document.getElementById("pause-label"),
  projectsDrawer: document.getElementById("projects-drawer"),
};

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------
function relativeTime(isoString) {
  const now = Date.now();
  const then = new Date(isoString).getTime();
  const diffSec = Math.floor((now - then) / 1000);
  if (diffSec < 5) return "just now";
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDay = Math.floor(diffHr / 24);
  return `${diffDay}d ago`;
}

function formatTimestamp(isoString) {
  try {
    const d = new Date(isoString);
    const date = d.toLocaleDateString("en-US", { month: "short", day: "2-digit", year: "numeric" });
    const time = d.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
    const ms = String(d.getMilliseconds()).padStart(3, "0");
    return `${date} ${time}.${ms}`;
  } catch {
    return isoString;
  }
}

function levelClass(level) {
  const map = {
    DEBUG: "badge-debug",
    INFO: "badge-info",
    WARNING: "badge-warning",
    ERROR: "badge-error",
    CRITICAL: "badge-critical",
  };
  return map[level] || "badge-debug";
}

function categoryChipClass(cat) {
  return `chip-${(cat || "system").toLowerCase()}`;
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

function scrollToBottom() {
  if (!logsState.autoScroll || !el.logContainer) return;
  isProgrammaticScroll = true;
  requestAnimationFrame(() => {
    el.logContainer.scrollTop = el.logContainer.scrollHeight;
    setTimeout(() => {
      isProgrammaticScroll = false;
    }, 100);
  });
}

// ---------------------------------------------------------------------------
// Stream status UI
// ---------------------------------------------------------------------------
function setStreamStatus(status) {
  logsState.connected = status === "connected";

  if (status === "connected") {
    el.streamDot.className = "w-2 h-2 rounded-full bg-[#10b981] shadow-[0_0_8px_#10b981] stream-active";
    el.streamLabel.textContent = "Live";
    el.streamStatus.className = "flex items-center gap-2 px-3 py-1.5 rounded-lg border font-jetbrains text-xs font-bold text-[#10b981] bg-[#10b981]/10 border-[#10b981]/30";
    el.footerStreamState.textContent = "connected";
    el.footerStreamState.className = "text-primary font-bold";
  } else if (status === "paused") {
    el.streamDot.className = "w-2 h-2 rounded-full bg-[#ffbe5c]";
    el.streamLabel.textContent = "Paused";
    el.streamStatus.className = "flex items-center gap-2 px-3 py-1.5 rounded-lg border font-jetbrains text-xs font-bold text-[#ffbe5c] bg-[#ffbe5c]/10 border-[#ffbe5c]/30";
    el.footerStreamState.textContent = "paused";
    el.footerStreamState.className = "text-[#ffbe5c] font-bold";
  } else if (status === "reconnecting") {
    el.streamDot.className = "w-2 h-2 rounded-full bg-[#ffbe5c] animate-pulse";
    el.streamLabel.textContent = "Reconnecting...";
    el.streamStatus.className = "flex items-center gap-2 px-3 py-1.5 rounded-lg border font-jetbrains text-xs font-bold text-[#ffbe5c] bg-[#ffbe5c]/10 border-[#ffbe5c]/30";
    el.footerStreamState.textContent = "reconnecting";
    el.footerStreamState.className = "text-[#ffbe5c] font-bold";
  } else {
    el.streamDot.className = "w-2 h-2 rounded-full bg-[#ff7f7f]";
    el.streamLabel.textContent = "Disconnected";
    el.streamStatus.className = "flex items-center gap-2 px-3 py-1.5 rounded-lg border font-jetbrains text-xs font-bold text-[#ff7f7f] bg-[#ff7f7f]/10 border-[#ff7f7f]/30";
    el.footerStreamState.textContent = "disconnected";
    el.footerStreamState.className = "text-[#ff7f7f] font-bold";
  }
}

// ---------------------------------------------------------------------------
// Log entry rendering
// ---------------------------------------------------------------------------
function shouldShowEntry(entry) {
  if (!logsState.activeLevels.has(entry.level)) return false;
  if (logsState.activeCategory && entry.category !== logsState.activeCategory) return false;
  
  if (logsState.activeProject === "__NONE__") {
    if (entry.project_id) return false;
  } else if (logsState.activeProject && entry.project_id !== logsState.activeProject) {
    return false;
  }

  if (logsState.searchQuery) {
    const q = logsState.searchQuery.toLowerCase();
    const searchable = `${entry.message} ${entry.action} ${entry.source} ${entry.project_id || ""} ${JSON.stringify(entry.details || {})}`.toLowerCase();
    if (!searchable.includes(q)) return false;
  }
  return true;
}

function createLogRow(entry) {
  const row = document.createElement("div");
  row.className = "log-row px-6 py-2 grid grid-cols-[180px_70px_90px_140px_1fr_220px] gap-3 items-start cursor-pointer log-flash";
  row.dataset.logId = entry.id;

  const ts = formatTimestamp(entry.timestamp);
  const rel = relativeTime(entry.timestamp);

  row.innerHTML = `
    <div class="flex flex-col gap-0.5 min-w-0">
      <span class="text-[11px] font-jetbrains text-on-surface truncate" title="${escapeHtml(ts)}">${escapeHtml(ts)}</span>
      <span class="text-[9px] text-on-surface-variant">${escapeHtml(rel)}</span>
    </div>
    <div>
      <span class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide ${levelClass(entry.level)}">${escapeHtml(entry.level)}</span>
    </div>
    <div>
      <span class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide ${categoryChipClass(entry.category)}">${escapeHtml(entry.category)}</span>
    </div>
    <div class="min-w-0">
      <span class="text-[11px] font-jetbrains text-on-surface-variant truncate block" title="${escapeHtml(entry.action)}">${escapeHtml(entry.action)}</span>
    </div>
    <div class="min-w-0">
      <span class="text-[12px] text-on-surface truncate block leading-relaxed">${escapeHtml(entry.message)}</span>
    </div>
    <div class="text-right min-w-0">
      <span class="text-[10px] font-jetbrains text-on-surface-variant truncate block" title="${entry.project_id ? escapeHtml(entry.project_id) : ''}">${entry.project_id ? escapeHtml(entry.project_id) : '<span class="opacity-40">—</span>'}</span>
    </div>
  `;

  // Expandable details drawer
  if (entry.details && Object.keys(entry.details).length > 0) {
    const details = document.createElement("div");
    details.className = "hidden col-span-full bg-surface-container-lowest/50 rounded-lg p-3 mt-1 mx-6 mb-1 border border-outline-variant/30";

    let detailHtml = '<div class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-[11px] font-jetbrains">';
    for (const [key, value] of Object.entries(entry.details)) {
      detailHtml += `
        <span class="text-on-surface-variant font-bold">${escapeHtml(key)}:</span>
        <span class="text-on-surface break-all">${escapeHtml(typeof value === "object" ? JSON.stringify(value) : String(value))}</span>
      `;
    }
    if (entry.source) {
      detailHtml += `<span class="text-on-surface-variant font-bold">source:</span><span class="text-on-surface break-all">${escapeHtml(entry.source)}</span>`;
    }
    if (entry.user && entry.user !== "system") {
      detailHtml += `<span class="text-on-surface-variant font-bold">user:</span><span class="text-on-surface break-all">${escapeHtml(entry.user)}</span>`;
    }
    detailHtml += `<span class="text-on-surface-variant font-bold">id:</span><span class="text-on-surface break-all">${escapeHtml(entry.id)}</span>`;
    detailHtml += '</div>';
    details.innerHTML = detailHtml;

    row.addEventListener("click", () => {
      const isExpanded = !details.classList.contains("hidden");
      details.classList.toggle("hidden");
      row.classList.toggle("expanded", !isExpanded);
    });

    const wrapper = document.createElement("div");
    wrapper.appendChild(row);
    wrapper.appendChild(details);
    return wrapper;
  }

  return row;
}

function updateCounts() {
  el.displayedCount.textContent = logsState.displayedCount;
  el.diskCount.textContent = logsState.totalOnDisk;
  el.logTotalCount.textContent = logsState.totalOnDisk;
}

function renderAllLogs() {
  const children = Array.from(el.logContainer.children);
  children.forEach((child) => {
    if (child !== el.emptyState) child.remove();
  });

  logsState.displayedCount = 0;

  const visible = logsState.entries.filter(shouldShowEntry);
  if (visible.length === 0) {
    el.emptyState.classList.remove("hidden");
  } else {
    el.emptyState.classList.add("hidden");
    visible.forEach((entry) => {
      const rowEl = createLogRow(entry);
      el.logContainer.appendChild(rowEl);
    });
    logsState.displayedCount = visible.length;
  }

  updateCounts();
  scrollToBottom();
}

function appendLogEntry(entry) {
  logsState.entries.push(entry);
  logsState.totalOnDisk++;

  if (!shouldShowEntry(entry)) {
    updateCounts();
    return;
  }

  el.emptyState.classList.add("hidden");
  const rowEl = createLogRow(entry);
  el.logContainer.appendChild(rowEl);
  logsState.displayedCount++;
  updateCounts();

  el.lastEntryTime.textContent = relativeTime(entry.timestamp);
  scrollToBottom();
}

// ---------------------------------------------------------------------------
// SSE Connection
// ---------------------------------------------------------------------------
function connectSSE() {
  if (logsState.eventSource) {
    logsState.eventSource.close();
  }

  setStreamStatus("reconnecting");
  const es = new EventSource(window.VIPERACL_STATE.logsStreamUrl);
  logsState.eventSource = es;

  es.addEventListener("connected", () => {
    setStreamStatus("connected");
  });

  es.onmessage = (event) => {
    if (logsState.paused) return;
    try {
      const entry = JSON.parse(event.data);
      appendLogEntry(entry);
    } catch {
      // ignore malformed
    }
  };

  es.onerror = () => {
    setStreamStatus("reconnecting");
    es.close();
    logsState.eventSource = null;
    setTimeout(() => {
      if (!logsState.paused) connectSSE();
    }, 3000);
  };
}

// ---------------------------------------------------------------------------
// Initial data fetch
// ---------------------------------------------------------------------------
async function fetchInitialLogs() {
  try {
    const res = await fetch(`${window.VIPERACL_STATE.logsUrl}?limit=500`);
    const data = await res.json();
    if (data.status === "ok") {
      const logs = (data.logs || []).reverse();
      logsState.entries = logs;
      logsState.totalOnDisk = data.total;
      renderAllLogs();
    }
  } catch (err) {
    console.error("Failed to fetch initial logs:", err);
  }
}

async function fetchStats() {
  try {
    const res = await fetch(window.VIPERACL_STATE.logsStatsUrl);
    const data = await res.json();
    if (data.status === "ok") {
      logsState.totalOnDisk = data.total;
      const byLevel = data.by_level || {};
      for (const [level, count] of Object.entries(byLevel)) {
        const badge = document.querySelector(`[data-level-count="${level}"]`);
        if (badge) badge.textContent = count;
      }
      updateCounts();
    }
  } catch {
    // non-critical
  }
}

async function populateProjectFilterOptions() {
  try {
    const res = await fetch(`${window.VIPERACL_STATE.projectsUrl}?include_deleted=true`);
    const data = await res.json();
    if (data.status === "ok" && data.projects) {
      const select = el.projectFilter;
      // Clear dynamically added options beyond the default two
      while (select.options.length > 2) {
        select.remove(2);
      }
      data.projects.forEach((proj) => {
        const opt = document.createElement("option");
        opt.value = proj.project_id;
        const isDel = proj.is_deleted || proj.status === "Deleted";
        opt.textContent = `${proj.name || proj.project_id}${isDel ? " (Deleted)" : ""}`;
        select.appendChild(opt);
      });
    }
  } catch {
    // non-critical
  }
}

// ---------------------------------------------------------------------------
// Filter / control wiring
// ---------------------------------------------------------------------------
function wireFilters() {
  // Level filter buttons
  document.querySelectorAll("[data-level]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const level = btn.dataset.level;
      if (logsState.activeLevels.has(level)) {
        logsState.activeLevels.delete(level);
        btn.classList.remove("active");
      } else {
        logsState.activeLevels.add(level);
        btn.classList.add("active");
      }
      renderAllLogs();
    });
  });

  // Category filter
  el.categoryFilter.addEventListener("change", () => {
    logsState.activeCategory = el.categoryFilter.value;
    renderAllLogs();
  });

  // Project filter
  el.projectFilter.addEventListener("change", () => {
    logsState.activeProject = el.projectFilter.value;
    renderAllLogs();
  });

  // Search input (debounced)
  let searchTimeout = null;
  el.searchInput.addEventListener("input", () => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
      logsState.searchQuery = el.searchInput.value.trim();
      renderAllLogs();
    }, 250);
  });

  // Auto-scroll toggle button
  el.btnAutoScroll.addEventListener("click", () => {
    logsState.autoScroll = !logsState.autoScroll;
    el.btnAutoScroll.classList.toggle("active", logsState.autoScroll);
    if (logsState.autoScroll) {
      scrollToBottom();
    }
  });

  // Detect manual scroll → toggle auto-scroll state
  el.logContainer.addEventListener("scroll", () => {
    if (isProgrammaticScroll) return;
    const { scrollTop, scrollHeight, clientHeight } = el.logContainer;
    const atBottom = scrollHeight - scrollTop - clientHeight < 50;
    if (!atBottom && logsState.autoScroll) {
      logsState.autoScroll = false;
      el.btnAutoScroll.classList.remove("active");
    } else if (atBottom && !logsState.autoScroll) {
      logsState.autoScroll = true;
      el.btnAutoScroll.classList.add("active");
    }
  });

  // Pause/Resume stream
  el.btnPauseStream.addEventListener("click", () => {
    logsState.paused = !logsState.paused;
    if (logsState.paused) {
      el.pauseIcon.textContent = "play_arrow";
      el.pauseLabel.textContent = "Resume";
      el.btnPauseStream.classList.add("active");
      setStreamStatus("paused");
    } else {
      el.pauseIcon.textContent = "pause";
      el.pauseLabel.textContent = "Pause";
      el.btnPauseStream.classList.remove("active");
      setStreamStatus("connected");
      if (!logsState.eventSource || logsState.eventSource.readyState === EventSource.CLOSED) {
        connectSSE();
      }
    }
  });

  // Export visible logs as JSONL
  el.btnExport.addEventListener("click", () => {
    const visible = logsState.entries.filter(shouldShowEntry);
    if (visible.length === 0) return;

    const lines = visible.map((e) => JSON.stringify(e)).join("\n") + "\n";
    const blob = new Blob([lines], { type: "application/x-jsonlines" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    const now = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    a.download = `viperacl_logs_${now}.jsonl`;
    a.click();
    URL.revokeObjectURL(url);
  });

  // Clear display
  el.btnClearDisplay.addEventListener("click", () => {
    logsState.entries = [];
    logsState.displayedCount = 0;
    renderAllLogs();
  });
}

// ---------------------------------------------------------------------------
// Periodically refresh relative times
// ---------------------------------------------------------------------------
function startTimeRefresh() {
  setInterval(() => {
    if (logsState.entries.length > 0) {
      const last = logsState.entries[logsState.entries.length - 1];
      el.lastEntryTime.textContent = relativeTime(last.timestamp);
    }

    const rows = el.logContainer.querySelectorAll(".log-row");
    rows.forEach((row) => {
      const timeEl = row.querySelector("[class*='text-\\[9px\\]']");
      if (timeEl) {
        const logId = row.dataset.logId;
        if (logId) {
          const entry = logsState.entries.find((e) => e.id === logId);
          if (entry) {
            timeEl.textContent = relativeTime(entry.timestamp);
          }
        }
      }
    });
  }, 15000);
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
async function boot() {
  wireFilters();
  await Promise.all([fetchInitialLogs(), fetchStats(), populateProjectFilterOptions()]);
  connectSSE();
  startTimeRefresh();
}

boot();

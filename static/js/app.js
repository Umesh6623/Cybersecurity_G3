/* SecLab // IIITA IT-30001 Client-Side Telemetry & Demonstration Helpers */

(function () {
  const moduleKey = window.LAB_MODULE_KEY || "";

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  window.labEscapeHtml = escapeHtml;

  // Tab switching across module workspace
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const target = btn.getAttribute("data-tab");
      document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      const panel = document.getElementById("tab-" + target);
      if (panel) panel.classList.add("active");
    });
  });

  // Live Observation Panel rendering
  async function refreshLogs() {
    if (!moduleKey || moduleKey === "dashboard" || moduleKey === "docs") return;
    const feed = document.getElementById("obs-log-feed");
    if (!feed) return;
    try {
      const res = await fetch(`/api/logs/${moduleKey}`);
      const data = await res.json();
      renderLogs(feed, data.logs || []);
    } catch (err) {
      // ignore transient polling error
    }
  }

  function renderLogs(feed, logs) {
    if (!logs.length) {
      feed.innerHTML = `<div class="alert alert-info" style="font-size:12px;">No events recorded yet for this module. Submit a payload or click Execute to observe real-time backend &amp; browser telemetry.</div>`;
      return;
    }
    feed.innerHTML = logs
      .map((entry) => {
        const tech = {};
        if (entry.method) tech.method = entry.method;
        if (entry.endpoint) tech.endpoint = entry.endpoint;
        if (entry.mode) tech.mode = entry.mode;
        if (entry.payload !== null && entry.payload !== undefined) tech.payload = entry.payload;
        if (entry.params && Object.keys(entry.params).length) tech.params = entry.params;
        if (entry.details && Object.keys(entry.details).length) tech.details = entry.details;

        const hasTech = Object.keys(tech).length > 0;
        const techJson = escapeHtml(JSON.stringify(tech, null, 2));
        return `
          <div class="log-entry cat-${escapeHtml(entry.category)}">
            <div class="log-meta">
              <span class="log-badge">${escapeHtml(entry.category)}</span>
              <span class="log-time">${escapeHtml(entry.timestamp)}</span>
            </div>
            <div class="log-title">${escapeHtml(entry.title)}</div>
            <div class="log-msg">${escapeHtml(entry.message)}</div>
            ${
              hasTech
                ? `<button type="button" class="log-details-toggle" onclick="this.nextElementSibling.classList.toggle('open')">[+ Expand technical details]</button>
                   <pre class="log-details-pre">${techJson}</pre>`
                : ""
            }
          </div>
        `;
      })
      .join("");
  }

  window.labRefreshLogs = refreshLogs;

  window.labClearLogs = async function () {
    if (!moduleKey) return;
    await fetch(`/api/logs/${moduleKey}/clear`, { method: "POST" });
    await refreshLogs();
  };

  window.labCopyLogs = async function () {
    if (!moduleKey) return;
    const res = await fetch(`/api/logs/${moduleKey}`);
    const data = await res.json();
    const text = JSON.stringify(data.logs || [], null, 2);
    try {
      await navigator.clipboard.writeText(text);
      alert("Observation logs copied to clipboard.");
    } catch {
      prompt("Copy logs JSON:", text);
    }
  };

  window.labResetModule = async function () {
    if (!moduleKey) return;
    await fetch(`/modules/${moduleKey}/reset`, { method: "POST" });
    const mode = window.LAB_CURRENT_MODE || "vulnerable";
    window.location.href = `/modules/${moduleKey}?mode=${encodeURIComponent(mode)}`;
  };

  if (moduleKey && moduleKey !== "dashboard" && moduleKey !== "docs") {
    refreshLogs();
  }
})();

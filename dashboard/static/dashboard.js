let activeId = null;
let approvedFolders = [];
let selectedRoot = "";
let quarantineItems = [];
let displayedDetections = [];
let detectionActionsAllowed = false;

const $ = id => document.getElementById(id);
const actionToken = document.querySelector('meta[name="dashboard-action-token"]').content;
const actionHeaders = {"Content-Type": "application/json", "X-Dashboard-Token": actionToken};

function setFolderSaveState(state) {
  const button = $("saveFoldersButton");
  button.classList.toggle("saved", state === "saved");
  button.classList.toggle("saving", state === "saving");
  button.style.backgroundColor = state === "saved" ? "#15803d" : "";
  button.style.borderColor = state === "saved" ? "#22c55e" : "";
  button.style.color = state === "saved" ? "#ffffff" : "";
  button.style.boxShadow = state === "saved" ? "0 0 0 3px rgba(34, 197, 94, .22)" : "";
  button.textContent = state === "saved" ? "Approved folders saved" :
    state === "saving" ? "Saving..." : "Save approved folders";
}

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, character => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;"
  })[character]);
}

function duration(seconds) {
  if (seconds === null || seconds === undefined) return "--";
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const remainder = Math.floor(seconds % 60);
  return hours ? `${hours}h ${minutes}m` : `${String(minutes).padStart(2, "0")}:${String(remainder).padStart(2, "0")}`;
}

function bytes(value) {
  const number = Number(value) || 0;
  if (!number) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const index = Math.min(Math.floor(Math.log(number) / Math.log(1024)), units.length - 1);
  return `${(number / 1024 ** index).toFixed(index ? 1 : 0)} ${units[index]}`;
}

async function jsonFetch(url, options = {}) {
  const response = await fetch(url, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}

async function loadEngine() {
  try {
    const data = await jsonFetch("/api/engine");
    $("engineState").textContent = data.online ? "Online" : "Offline";
    $("engineVersion").textContent = data.version || "Unknown";
    $("engineBadge").classList.toggle("online", data.online);
    $("engineBadge").querySelector("b").textContent = data.online ? "Engine healthy" : "Engine offline";
  } catch (error) {
    $("engineState").textContent = "Offline";
    $("engineVersion").textContent = error.message;
  }
}

async function loadStorage() {
  try {
    const data = await jsonFetch("/api/storage");
    approvedFolders = data.approved;
    const target = $("storageList");
    if (!data.disks.length) {
      target.innerHTML = '<div class="empty-state compact">No ZimaOS storage disks detected under /media.</div>';
      renderScanOptions();
      return;
    }
    target.innerHTML = data.disks.map(disk => `
      <section class="disk-card">
        <h3>${escapeHtml(disk.label)}</h3>
        <div class="folder-grid">
          ${disk.folders.map(folder => `
            <label class="folder-choice ${folder.excluded ? "excluded" : ""} ${folder.whole_disk ? "whole-disk" : ""}">
              <input type="checkbox" data-folder="${escapeHtml(folder.path)}"
                ${folder.approved ? "checked" : ""} ${folder.excluded ? "disabled" : ""}>
              <span><b>${escapeHtml(folder.name)}</b><small>${folder.excluded ? "Excluded by safety policy" : escapeHtml(folder.path)}</small></span>
            </label>`).join("")}
        </div>
      </section>`).join("");
    target.querySelectorAll("[data-folder]").forEach(input => {
      input.addEventListener("change", () => setFolderSaveState("changed"));
    });
    setFolderSaveState(approvedFolders.length ? "saved" : "changed");
    renderScanOptions();
  } catch (error) {
    setFolderSaveState("changed");
    $("storageNotice").textContent = error.message;
  }
}

function renderScanOptions(preferred = "") {
  const select = $("scanRoot");
  const previous = preferred || selectedRoot || select.value;
  if (!approvedFolders.length) {
    select.innerHTML = '<option value="">Approve folders above first</option>';
    selectedRoot = "";
  } else {
    const options = [];
    if (approvedFolders.length > 1) options.push('<option value="__all__">All approved folders</option>');
    options.push(...approvedFolders.map(path => `<option value="${escapeHtml(path)}">${escapeHtml(path)}</option>`));
    select.innerHTML = options.join("");
    const valid = approvedFolders.includes(previous) || (previous === "__all__" && approvedFolders.length > 1);
    selectedRoot = valid ? previous : approvedFolders[0];
    select.value = selectedRoot;
  }
  $("startButton").disabled = !approvedFolders.length || activeId !== null;
}

async function saveApprovedFolders() {
  const approved = [...document.querySelectorAll("[data-folder]:checked")].map(input => input.dataset.folder);
  setFolderSaveState("saving");
  $("saveFoldersButton").disabled = true;
  $("storageNotice").textContent = "Saving approved folders...";
  try {
    const data = await jsonFetch("/api/storage/approved", {
      method: "PUT", headers: actionHeaders, body: JSON.stringify({approved})
    });
    approvedFolders = data.approved;
    selectedRoot = approvedFolders[0] || "";
    renderScanOptions(selectedRoot);
    await loadStorage();
    setFolderSaveState("saved");
    $("storageNotice").textContent = `Saved ${approvedFolders.length} approved folder${approvedFolders.length === 1 ? "" : "s"}.`;
  } catch (error) {
    setFolderSaveState("changed");
    $("storageNotice").textContent = error.message;
  } finally {
    $("saveFoldersButton").disabled = activeId !== null;
  }
}

function renderFolderList(folders) {
  const target = $("folderList");
  if (!folders || !folders.length) {
    target.innerHTML = "<code>Folder list was not recorded by the earlier dashboard version.</code>";
    return;
  }
  target.innerHTML = folders.map(folder => `<code>${escapeHtml(folder)}</code>`).join("");
}

function renderDetections(items, allowActions) {
  displayedDetections = items || [];
  detectionActionsAllowed = allowActions;
  const target = $("detectionList");
  if (!items || !items.length) {
    target.className = "empty-state";
    target.textContent = "No threats detected.";
    return;
  }
  target.className = "";
  target.innerHTML = items.map(item => {
    const record = quarantineItems.find(entry =>
      entry.original_path === item.file && entry.signature === item.signature
    );
    let action = "<small>Quarantine becomes available when this scan finishes.</small>";
    if (allowActions && record?.status === "quarantined") {
      action = '<small class="finding-status quarantined">Quarantined</small>';
    } else if (allowActions && record?.status === "deleted") {
      action = '<small class="finding-status deleted">Deleted after quarantine</small>';
    } else if (allowActions) {
      action = `<button class="danger-button" data-quarantine='${escapeHtml(JSON.stringify(item))}'>Quarantine</button>`;
    }
    return `<div class="finding">
      <b>${escapeHtml(item.signature)}</b><code>${escapeHtml(item.file)}</code>
      <div class="finding-meta">${bytes(item.size)}</div>${action}
    </div>`;
  }).join("");
}

function renderJob(job, last = null) {
  const running = Boolean(job);
  activeId = running ? job.id : null;
  if (running) selectedRoot = job.root_key;
  $("cancelButton").disabled = !running;
  $("scanRoot").disabled = running;
  $("saveFoldersButton").disabled = running;
  renderScanOptions(selectedRoot);
  const item = job || last;
  if (!item) {
    $("scanState").textContent = "Idle";
    $("scanPhase").textContent = "Ready";
    renderFolderList([]);
    return;
  }
  $("scanState").textContent = running ? item.root_label : "Idle";
  $("scanPhase").textContent = running ? item.phase : `Last scan: ${item.status}`;
  $("jobPill").textContent = running ? item.phase.toUpperCase() : "IDLE";
  $("folderSize").textContent = bytes(item.bytes_total);
  $("sizeProgress").textContent = `${bytes(item.bytes_scanned)} scanned`;
  $("infectedCount").textContent = item.infected;
  $("errorCount").textContent = `${item.errors} errors`;
  const percent = running ? item.percent : (["clean", "infected"].includes(item.status) ? 100 : 0);
  $("progressBar").style.width = `${percent}%`;
  $("progressPercent").textContent = `${percent}%`;
  $("timing").textContent = running ? `Elapsed ${duration(item.elapsed_seconds)}` : `Completed ${new Date(item.finished_at).toLocaleTimeString()}`;
  $("currentFile").textContent = running ? (item.current_file || `Indexing ${item.directories_indexed || 0} folders`) : `Last scan complete: ${item.root_label}`;
  renderFolderList(item.folders);
  $("detailScanned").textContent = `${item.files_scanned.toLocaleString()} / ${item.files_total.toLocaleString()}`;
  $("detailBytes").textContent = bytes(item.bytes_scanned);
  $("detailRemaining").textContent = bytes(item.bytes_remaining ?? Math.max(0, item.bytes_total - item.bytes_scanned));
  $("detailSpeed").textContent = running ? `${bytes(item.bytes_per_second)}/s` : "--";
  $("detailSkipped").textContent = item.skipped;
  $("detailEta").textContent = running ? duration(item.eta_seconds) : "--";
  $("notice").textContent = running ? `${item.phase === "indexing" ? "Measuring folder size and counting files" : "Scanning files"}. You may leave this page and return later.` : `Last scan finished ${item.status}.`;
  renderDetections(item.detections, !running);
}

async function pollStatus() {
  try {
    const data = await jsonFetch("/api/status");
    const wasActive = activeId !== null;
    renderJob(data.active, data.last);
    if (wasActive && !data.active) {
      await loadHistory();
      await loadQuarantine();
    }
  } catch (error) {
    $("notice").textContent = `Status error: ${error.message}`;
  }
}

function historyFolderLabel(item) {
  if (item.folders?.length === 1) return item.folders[0];
  if (item.folders?.length > 1) return `${item.folders.length} folders`;
  return item.root_label;
}

async function loadHistory() {
  try {
    const data = await jsonFetch("/api/history");
    $("historyBody").innerHTML = data.history.length ? data.history.map(item => `
      <tr><td>${escapeHtml(new Date(item.started_at).toLocaleString())}</td>
      <td>${escapeHtml(historyFolderLabel(item))}</td><td class="status-${escapeHtml(item.status)}">${escapeHtml(item.status)}</td>
      <td>${item.files_scanned.toLocaleString()} / ${item.files_total.toLocaleString()}</td><td>${bytes(item.bytes_total)}</td>
      <td>${item.infected}</td><td>${item.errors}</td><td><button class="mini-button" data-history="${item.id}">Details</button></td></tr>`).join("") : '<tr><td colspan="8">No completed scans yet.</td></tr>';
  } catch (error) {
    $("historyBody").innerHTML = `<tr><td colspan="8">${escapeHtml(error.message)}</td></tr>`;
  }
}

async function showHistory(id) {
  try {
    const {scan} = await jsonFetch(`/api/history/${id}`);
    const detail = $("historyDetail");
    const folders = scan.folders?.length ? scan.folders.map(folder => `<code>${escapeHtml(folder)}</code>`).join("") : "<p>Folder list was not recorded by the earlier dashboard version.</p>";
    detail.classList.remove("hidden");
    detail.innerHTML = `
      <div class="panel-heading"><h3>Scan #${scan.id}: ${escapeHtml(historyFolderLabel(scan))}</h3><button class="mini-button" id="closeDetail">Close</button></div>
      <h4>Folders scanned</h4><div class="recorded-folders">${folders}</div>
      <div class="detail-grid"><div><span>Total size</span><b>${bytes(scan.bytes_total)}</b></div><div><span>Scanned</span><b>${bytes(scan.bytes_scanned)}</b></div><div><span>Skipped</span><b>${scan.skipped}</b></div><div><span>Errors</span><b>${scan.errors}</b></div></div>
      <h4>Skipped files</h4>${scan.skipped_details.length ? scan.skipped_details.map(item => `<code>${escapeHtml(item.file)}: ${escapeHtml(item.reason)}</code>`).join("") : "<p>None</p>"}
      <h4>Errors</h4>${scan.error_details.length ? scan.error_details.map(item => `<code>${escapeHtml(item.file)}: ${escapeHtml(item.error)}</code>`).join("") : "<p>None</p>"}`;
    $("closeDetail").onclick = () => detail.classList.add("hidden");
  } catch (error) { alert(error.message); }
}

async function quarantineDetection(item) {
  if (!confirm(`Move this detected file into quarantine?\n\n${item.file}\n${item.signature}`)) return;
  try {
    await jsonFetch("/api/quarantine", {method: "POST", headers: actionHeaders, body: JSON.stringify(item)});
    await loadQuarantine();
    alert("File moved to quarantine and its original location was recorded.");
  } catch (error) { alert(error.message); }
}

async function loadQuarantine() {
  try {
    const data = await jsonFetch("/api/quarantine");
    quarantineItems = data.items;
    if (displayedDetections.length) {
      renderDetections(displayedDetections, detectionActionsAllowed);
    }
    const target = $("quarantineList");
    if (!data.items.length) {
      target.className = "empty-state compact";
      target.textContent = "No quarantined files.";
      return;
    }
    target.className = "quarantine-list";
    target.innerHTML = data.items.map(item => `
      <div class="quarantine-item"><div><b>${escapeHtml(item.signature)}</b><code>${escapeHtml(item.original_path)}</code>
      <small>${bytes(item.size_bytes)} · SHA-256 ${escapeHtml(item.sha256)} · ${escapeHtml(item.status)}</small></div>
      <div>${item.status === "quarantined" ? `<button class="mini-button" data-restore="${item.id}">Restore</button><button class="danger-button" data-delete="${item.id}">Delete permanently</button>` : ""}</div></div>`).join("");
  } catch (error) { $("quarantineList").textContent = error.message; }
}

async function restoreItem(id) {
  if (!confirm("Restore this file to its original location?")) return;
  try { await jsonFetch(`/api/quarantine/${id}/restore`, {method: "POST", headers: actionHeaders}); await loadQuarantine(); }
  catch (error) { alert(error.message); }
}

async function deleteItem(id) {
  const confirmation = prompt("Permanent deletion cannot be undone. Type DELETE PERMANENTLY to continue:");
  if (confirmation !== "DELETE PERMANENTLY") return;
  try {
    await jsonFetch(`/api/quarantine/${id}`, {method: "DELETE", headers: actionHeaders, body: JSON.stringify({confirmation})});
    await loadQuarantine();
  } catch (error) { alert(error.message); }
}

document.addEventListener("click", event => {
  const target = event.target;
  if (target.dataset.quarantine) quarantineDetection(JSON.parse(target.dataset.quarantine));
  if (target.dataset.history) showHistory(target.dataset.history);
  if (target.dataset.restore) restoreItem(target.dataset.restore);
  if (target.dataset.delete) deleteItem(target.dataset.delete);
});

$("scanRoot").onchange = event => { selectedRoot = event.target.value; };
$("saveFoldersButton").onclick = saveApprovedFolders;
$("startButton").onclick = async () => {
  try {
    const data = await jsonFetch("/api/scans", {method: "POST", headers: actionHeaders, body: JSON.stringify({root: selectedRoot})});
    renderJob(data.scan);
  } catch (error) { $("notice").textContent = error.message; }
};
$("cancelButton").onclick = async () => {
  if (activeId) await jsonFetch(`/api/scans/${activeId}/cancel`, {method: "POST", headers: actionHeaders});
};
$("refreshButton").onclick = loadHistory;
$("refreshQuarantineButton").onclick = loadQuarantine;

loadEngine();
loadStorage();
loadHistory();
loadQuarantine();
pollStatus();
setInterval(pollStatus, 1000);
setInterval(loadEngine, 30000);

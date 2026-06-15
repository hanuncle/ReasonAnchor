const { request, setStatus, renderEmpty, renderSelect, escapeHtml, formatSources, formatFunctionSource, safe } = window.SFP;

let sessions = [];
let workflows = [];
let sampleSetReports = [];
let currentSession = null;
let selectedBatchSessionIds = new Set();
let latestSampleSetReport = null;
let activeBatchJobId = "";
let batchJobPollTimer = null;

const sampleFile = document.querySelector("#sample-file");
const sessionSelect = document.querySelector("#session-select");
const workflowSelect = document.querySelector("#workflow-select");
const sessionDetails = document.querySelector("#session-details");
const finalResult = document.querySelector("#final-result");
const batchSessionList = document.querySelector("#batch-session-list");
const batchJobStatus = document.querySelector("#batch-job-status");
const sampleSetReport = document.querySelector("#sample-set-report");
const reportSelect = document.querySelector("#report-select");
const reportList = document.querySelector("#report-list");

document.querySelector("#upload-button").addEventListener("click", uploadSample);
document.querySelector("#refresh-sessions-button").addEventListener("click", loadSessions);
document.querySelector("#load-session-button").addEventListener("click", loadSelectedSession);
document.querySelector("#apply-workflow-button").addEventListener("click", applyWorkflow);
document.querySelector("#run-workflow-button").addEventListener("click", runWorkflow);
document.querySelector("#select-batch-all-button").addEventListener("click", selectAllBatchSessions);
document.querySelector("#clear-batch-selection-button").addEventListener("click", clearBatchSelection);
document.querySelector("#run-batch-button").addEventListener("click", runBatchWorkflow);
document.querySelector("#refresh-reports-button").addEventListener("click", refreshReports);
document.querySelector("#load-report-button").addEventListener("click", loadSelectedReport);
document.querySelector("#refresh-result-button").addEventListener("click", loadCurrentResult);
document.querySelector("#open-result-button").addEventListener("click", openResult);
document.querySelector("#open-raw-button").addEventListener("click", openRawOutput);
reportSelect.addEventListener("change", loadSelectedReport);

init();

async function init() {
  await safe("初始化失败", async () => {
    await Promise.all([loadSessions(), loadWorkflows(), refreshReports()]);
    setStatus("分析工作台已就绪。");
  });
}

async function loadSessions() {
  const data = await request("/api/sessions");
  sessions = data.sessions || [];
  renderSelect(sessionSelect, sessions, "暂无 session", (session) => ({
    value: session.session_id,
    label: `${session.sample?.filename || "sample"} | ${session.summary?.status || "created"}`,
  }));
  if (!currentSession && sessions.length) {
    currentSession = sessions[0];
    sessionSelect.value = currentSession.session_id;
  }
  selectedBatchSessionIds = new Set(
    [...selectedBatchSessionIds].filter((sessionId) =>
      sessions.some((session) => session.session_id === sessionId),
    ),
  );
  renderBatchSessions();
  renderSession(currentSession);
  if (currentSession) {
    await loadCurrentResult();
  }
}

async function loadWorkflows() {
  const data = await request("/api/workflows");
  workflows = data.workflows || [];
  renderSelect(workflowSelect, workflows, "暂无流程模板", (workflow) => ({
    value: workflow.workflow_id,
    label: `${workflow.name} (${workflow.steps_count ?? workflow.workflow?.steps?.length ?? 0})`,
  }));
}

async function uploadSample() {
  if (!sampleFile.files.length) {
    setStatus("请先选择样本。");
    return;
  }
  const form = new FormData();
  [...sampleFile.files].forEach((file) => {
    form.append(sampleFile.files.length > 1 ? "files" : "file", file);
  });
  const url = sampleFile.files.length > 1 ? "/api/sessions/upload-multiple" : "/api/sessions/upload";
  await safe("上传失败", async () => {
    const uploaded = await request(url, { method: "POST", body: form });
    const created = uploaded.sessions || [uploaded];
    currentSession = created[0] || null;
    selectedBatchSessionIds = new Set(created.map((session) => session.session_id).filter(Boolean));
    await loadSessions();
    sessionSelect.value = currentSession?.session_id || "";
    renderSession(currentSession);
    await loadCurrentResult();
    setStatus(created.length > 1 ? "多个 session 已创建。" : "Session 已创建。");
  });
}

async function loadSelectedSession() {
  const sessionId = sessionSelect.value;
  if (!sessionId) {
    setStatus("请先选择 session。");
    return;
  }
  await safe("加载 session 失败", async () => {
    currentSession = await request(`/api/sessions/${encodeURIComponent(sessionId)}`);
    renderSession(currentSession);
    await loadCurrentResult();
    setStatus("Session 已加载。");
  });
}

async function applyWorkflow() {
  if (!currentSession) {
    setStatus("请先选择 session。");
    return;
  }
  if (!workflowSelect.value) {
    setStatus("请先选择流程模板。");
    return;
  }
  await safe("应用流程失败", async () => {
    currentSession = await request(`/api/sessions/${currentSession.session_id}/workflow-template`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ workflow_id: workflowSelect.value }),
    });
    renderSession(currentSession);
    setStatus("流程已应用。");
  });
}

async function runWorkflow() {
  if (!currentSession) {
    setStatus("请先选择 session。");
    return;
  }
  await safe("运行流程失败", async () => {
    const selectedWorkflow = selectedWorkflowTemplate();
    const workflow = selectedWorkflow || currentSession.workflow || null;
    if (workflowLooksLongRunning(workflow)) {
      const job = await submitBatchJob(
        [currentSession.session_id],
        workflowSelect.value || "",
      );
      setStatus(`Long-running workflow submitted as job: ${job.job_id || ""}`);
      return;
    }
    currentSession = await request(`/api/sessions/${currentSession.session_id}/run`, {
      method: "POST",
    });
    renderSession(currentSession);
    await loadCurrentResult();
    setStatus("Workflow 已完成。");
  });
}

function selectAllBatchSessions() {
  selectedBatchSessionIds = new Set(sessions.map((session) => session.session_id));
  renderBatchSessions();
}

function clearBatchSelection() {
  selectedBatchSessionIds = new Set();
  renderBatchSessions();
}

async function runBatchWorkflow() {
  const sessionIds = [...selectedBatchSessionIds];
  if (!sessionIds.length) {
    setStatus("Please select sessions for batch run.");
    return;
  }
  await safe("Batch run failed", async () => {
    await submitBatchJob(sessionIds, workflowSelect.value || "");
    setStatus(`Batch job submitted: ${activeBatchJobId}`);
  });
}

async function submitBatchJob(sessionIds, workflowId) {
  const job = await request("/api/batches/jobs", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      session_ids: sessionIds,
      workflow_id: workflowId || "",
      create_report: true,
    }),
  });
  activeBatchJobId = job.job_id || "";
  renderBatchJob(job);
  startBatchJobPolling(activeBatchJobId);
  return job;
}

function selectedWorkflowTemplate() {
  return workflows.find((workflow) => workflow.workflow_id === workflowSelect.value) || null;
}

function workflowLooksLongRunning(workflow) {
  if (!workflow) {
    return false;
  }
  const tags = Array.isArray(workflow.tags)
    ? workflow.tags.map((tag) => String(tag).toLowerCase())
    : [];
  if (String(workflow.risk || "").toLowerCase() === "high") {
    return true;
  }
  if (tags.some((tag) => ["dynamic", "vmware", "focused-validation"].includes(tag))) {
    return true;
  }
  return workflowSteps(workflow).some((step) =>
    String(step.function_id || "").startsWith("dynamic.vm_"),
  );
}

function workflowSteps(workflow) {
  if (Array.isArray(workflow.steps)) {
    return workflow.steps;
  }
  if (workflow.workflow && Array.isArray(workflow.workflow.steps)) {
    return workflow.workflow.steps;
  }
  return [];
}

function startBatchJobPolling(jobId) {
  if (batchJobPollTimer) {
    clearInterval(batchJobPollTimer);
  }
  if (!jobId) {
    return;
  }
  batchJobPollTimer = setInterval(() => {
    pollBatchJob(jobId);
  }, 2500);
  pollBatchJob(jobId);
}

async function pollBatchJob(jobId) {
  await safe("Batch job poll failed", async () => {
    const job = await request(`/api/batches/jobs/${encodeURIComponent(jobId)}`);
    renderBatchJob(job);
    if (["completed", "error"].includes(job.status)) {
      clearInterval(batchJobPollTimer);
      batchJobPollTimer = null;
      await loadSessions();
      await refreshReports();
      if (job.report) {
        latestSampleSetReport = job.report;
        renderSampleSetReport(latestSampleSetReport);
      } else if (job.report_id) {
        latestSampleSetReport = await request(`/api/reports/${encodeURIComponent(job.report_id)}`);
        renderSampleSetReport(latestSampleSetReport);
      }
      setStatus(`Batch job ${job.status}: ${job.job_id}`);
    }
  });
}

function renderBatchJob(job) {
  batchJobStatus.replaceChildren();
  if (!job || !job.job_id) {
    renderEmpty(batchJobStatus, "No batch job running.");
    return;
  }
  const article = document.createElement("article");
  article.className = "job-card";
  const items = Array.isArray(job.items) ? job.items : [];
  article.innerHTML = `
    <strong>${escapeHtml(job.status || "")} | ${escapeHtml(job.completed_count ?? 0)}/${escapeHtml(job.count ?? 0)} completed | ${escapeHtml(job.failed_count ?? 0)} failed</strong>
    <span>${escapeHtml(job.job_id || "")}</span>
    <span>${escapeHtml(job.workflow_id || "")}</span>
    <span>${escapeHtml(job.current_session_id ? `running: ${job.current_session_id}` : "")}</span>
  `;
  if (items.length) {
    const list = document.createElement("div");
    list.className = "job-item-list";
    items.forEach((item) => {
      const row = document.createElement("span");
      row.textContent = `${item.status || "pending"} | ${item.session_id || ""}`;
      list.append(row);
    });
    article.append(list);
  }
  batchJobStatus.append(article);
}

async function refreshReports() {
  await safe("Refresh reports failed", async () => {
    const data = await request("/api/reports");
    sampleSetReports = (data.reports || []).slice().sort(compareReportsForDisplay);
    renderReportPicker();
    if (!sampleSetReports.length) {
      latestSampleSetReport = null;
      renderSampleSetReport(null);
      setStatus("No sample-set report.");
      return;
    }
    const selected = chooseDefaultReport(sampleSetReports);
    reportSelect.value = selected.report_id;
    latestSampleSetReport = await request(`/api/reports/${encodeURIComponent(selected.report_id)}`);
    renderSampleSetReport(latestSampleSetReport);
    setStatus(`Loaded report ${selected.report_id}`);
  });
}

async function loadSelectedReport() {
  const reportId = reportSelect.value;
  if (!reportId) {
    renderSampleSetReport(null);
    setStatus("Please select a sample-set report.");
    return;
  }
  await safe("Load report failed", async () => {
    latestSampleSetReport = await request(`/api/reports/${encodeURIComponent(reportId)}`);
    renderSampleSetReport(latestSampleSetReport);
    setStatus(`Loaded report ${reportId}`);
  });
}

function renderReportPicker() {
  renderSelect(reportSelect, sampleSetReports, "No sample-set reports", (report) => ({
    value: report.report_id,
    label: reportLabel(report),
  }));
  renderReportList();
}

function renderReportList() {
  reportList.replaceChildren();
  if (!sampleSetReports.length) {
    renderEmpty(reportList, "No sample-set reports.");
    return;
  }
  sampleSetReports.forEach((report) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "report-card";
    button.addEventListener("click", async () => {
      reportSelect.value = report.report_id;
      await loadSelectedReport();
    });
    button.innerHTML = `
      <strong>${escapeHtml(reportTitle(report))}</strong>
      <span>${escapeHtml(report.created_at || "")}</span>
      <span>${escapeHtml(report.report_id || "")}</span>
    `;
    reportList.append(button);
  });
}

function chooseDefaultReport(reports) {
  return reports.slice().sort((left, right) => {
    const sampleDelta = (right.sample_count || 0) - (left.sample_count || 0);
    if (sampleDelta) {
      return sampleDelta;
    }
    const signalDelta = reportSignalScore(right) - reportSignalScore(left);
    if (signalDelta) {
      return signalDelta;
    }
    return compareReportDatesDesc(left, right);
  })[0];
}

function compareReportsForDisplay(left, right) {
  const sampleDelta = (right.sample_count || 0) - (left.sample_count || 0);
  if (sampleDelta) {
    return sampleDelta;
  }
  const signalDelta = reportSignalScore(right) - reportSignalScore(left);
  if (signalDelta) {
    return signalDelta;
  }
  return compareReportDatesDesc(left, right);
}

function compareReportDatesDesc(left, right) {
  return String(right.created_at || "").localeCompare(String(left.created_at || ""));
}

function reportSignalScore(report) {
  return (report.behavior_category_count || 0) + (report.attack_technique_count || 0);
}

function reportLabel(report) {
  return `${reportTitle(report)} | ${report.report_id || ""}`;
}

function reportTitle(report) {
  const validation = formatValidationStatus(report.summary?.validation_status || {});
  const parts = [
    `${report.sample_count || 0} samples`,
    `${report.behavior_category_count || 0} behaviors`,
    `${report.attack_technique_count || 0} ATT&CK`,
  ];
  if (validation) {
    parts.push(validation);
  }
  return parts.join(" | ");
}

async function loadCurrentResult() {
  if (!currentSession) {
    renderEmpty(finalResult, "请选择 session。");
    return;
  }
  await safe("查询最终结果失败", async () => {
    const result = await request(`/api/sessions/${currentSession.session_id}/result`);
    renderFinalResult(result);
  });
}

function renderSession(session) {
  if (!session) {
    renderEmpty(sessionDetails, "暂无 session。");
    return;
  }
  sessionDetails.innerHTML = `
    <dt>session_id</dt><dd>${escapeHtml(session.session_id)}</dd>
    <dt>文件</dt><dd>${escapeHtml(session.sample?.filename || "")}</dd>
    <dt>大小</dt><dd>${escapeHtml(session.sample?.size ?? "")}</dd>
    <dt>状态</dt><dd>${escapeHtml(session.summary?.status || "created")}</dd>
    <dt>流程</dt><dd>${escapeHtml(session.workflow?.name || "未配置")}</dd>
  `;
}

function renderBatchSessions() {
  batchSessionList.replaceChildren();
  if (!sessions.length) {
    renderEmpty(batchSessionList, "No sessions.");
    return;
  }
  sessions.forEach((session) => {
    const label = document.createElement("label");
    label.className = "check-row";
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = selectedBatchSessionIds.has(session.session_id);
    checkbox.addEventListener("change", () => {
      if (checkbox.checked) {
        selectedBatchSessionIds.add(session.session_id);
      } else {
        selectedBatchSessionIds.delete(session.session_id);
      }
    });
    const text = document.createElement("span");
    text.textContent = `${session.sample?.filename || "sample"} | ${session.summary?.status || "created"} | ${session.session_id}`;
    label.append(checkbox, text);
    batchSessionList.append(label);
  });
}

function renderSampleSetReport(report) {
  sampleSetReport.replaceChildren();
  if (!report) {
    renderEmpty(sampleSetReport, "No sample-set report.");
    return;
  }
  const summary = report.summary || {};
  const section = document.createElement("article");
  section.className = "result-block";
  section.innerHTML = `
    <h3>${escapeHtml(report.report_id || "")}</h3>
    <dl class="details">
      <dt>schema</dt><dd>${escapeHtml(report.schema_id || "")}</dd>
      <dt>samples</dt><dd>${escapeHtml(summary.sample_count ?? 0)}</dd>
      <dt>completed</dt><dd>${escapeHtml(summary.completed ?? 0)}</dd>
      <dt>failed</dt><dd>${escapeHtml(summary.failed ?? 0)}</dd>
      <dt>behavior classes</dt><dd>${escapeHtml(summary.behavior_category_count ?? (summary.behavior_categories || []).length)}</dd>
      <dt>behaviors</dt><dd>${formatLinkedPageList(summary.behavior_categories || [], report.knowledge_links?.behavior_taxonomy)}</dd>
      <dt>common</dt><dd>${escapeHtml((summary.common_behavior_categories || []).join(", "))}</dd>
      <dt>ATT&CK classes</dt><dd>${escapeHtml(summary.attack_technique_count ?? (summary.attack_techniques || []).length)}</dd>
      <dt>ATT&CK</dt><dd>${formatLinkedPageList(summary.attack_techniques || [], report.knowledge_links?.attack_knowledge)}</dd>
      <dt>validation</dt><dd>${escapeHtml(formatValidationStatus(summary.validation_status || {}))}</dd>
    </dl>
  `;
  const links = report.knowledge_links || {};
  const linkRow = document.createElement("p");
  linkRow.className = "module-pages";
  linkRow.innerHTML = [
    linkedPage("Behavior taxonomy", links.behavior_taxonomy),
    linkedPage("ATT&CK knowledge", links.attack_knowledge),
    linkedPage("Validation samples", links.validation_samples),
  ].filter(Boolean).join("");
  if (linkRow.innerHTML) {
    section.append(linkRow);
  }
  (report.common_analysis_points || []).forEach((point) => {
    const item = document.createElement("p");
    item.textContent = point;
    section.append(item);
  });
  if (Array.isArray(report.behavior_matrix) && report.behavior_matrix.length) {
    section.append(renderBehaviorMatrix(report.behavior_matrix));
  }
  if (Array.isArray(report.attack_matrix) && report.attack_matrix.length) {
    section.append(renderAttackMatrix(report.attack_matrix));
  }
  (report.differential_analysis_points || []).forEach((point) => {
    const item = document.createElement("article");
    item.className = "item-block";
    item.innerHTML = `
      <h4>${escapeHtml(point.filename || point.session_id || "")}</h4>
      <dl class="details">
        <dt>status</dt><dd>${escapeHtml(point.status || "")}</dd>
        <dt>validation</dt><dd>${escapeHtml(point.validation_status || "")}</dd>
        <dt>unique</dt><dd>${escapeHtml((point.unique_behavior_categories || []).join(", "))}</dd>
        <dt>unique ATT&CK</dt><dd>${escapeHtml((point.unique_attack_techniques || []).join(", "))}</dd>
        <dt>focus</dt><dd>${escapeHtml((point.analysis_focus || []).join("; "))}</dd>
      </dl>
    `;
    section.append(item);
  });
  sampleSetReport.append(section);
}

function renderBehaviorMatrix(rows) {
  const wrapper = document.createElement("article");
  wrapper.className = "item-block";
  wrapper.innerHTML = "<h4>Behavior Matrix</h4>";
  const table = document.createElement("table");
  table.className = "knowledge-table";
  table.innerHTML = `
    <thead>
      <tr>
        <th>Behavior</th>
        <th>Samples</th>
        <th>Evidence</th>
        <th>ATT&CK</th>
      </tr>
    </thead>
    <tbody></tbody>
  `;
  const tbody = table.querySelector("tbody");
  rows.forEach((row) => {
    const tr = document.createElement("tr");
    const techniques = (row.attack_techniques || [])
      .map((item) => item.technique_id || "")
      .filter(Boolean);
    tr.innerHTML = `
      <td>${linkedPage(escapeHtml(row.category_id || row.name || ""), row.knowledge_link)}</td>
      <td>${escapeHtml(row.sample_count ?? 0)}</td>
      <td>${escapeHtml(formatValidationStatus(row.evidence_summary || {}))}</td>
      <td>${formatLinkedPageList(techniques, "/module-page.html?module=reverse&page=attack_knowledge")}</td>
    `;
    tbody.append(tr);
  });
  wrapper.append(table);
  return wrapper;
}

function renderAttackMatrix(rows) {
  const wrapper = document.createElement("article");
  wrapper.className = "item-block";
  wrapper.innerHTML = "<h4>ATT&CK Matrix</h4>";
  const table = document.createElement("table");
  table.className = "knowledge-table";
  table.innerHTML = `
    <thead>
      <tr>
        <th>Technique</th>
        <th>Name</th>
        <th>Samples</th>
        <th>Behaviors</th>
      </tr>
    </thead>
    <tbody></tbody>
  `;
  const tbody = table.querySelector("tbody");
  rows.forEach((row) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${linkedPage(escapeHtml(row.technique_id || ""), row.knowledge_link)}</td>
      <td>${escapeHtml(row.name || "")}</td>
      <td>${escapeHtml(row.sample_count ?? 0)}</td>
      <td>${formatLinkedPageList(row.behavior_categories || [], "/module-page.html?module=reverse&page=behavior_taxonomy")}</td>
    `;
    tbody.append(tr);
  });
  wrapper.append(table);
  return wrapper;
}

function formatValidationStatus(status) {
  return Object.entries(status || {})
    .filter(([, value]) => value)
    .map(([key, value]) => `${key}: ${value}`)
    .join(", ");
}

function formatLinkedPageList(values, href) {
  const items = Array.isArray(values) ? values : [];
  if (!items.length) {
    return "";
  }
  return items.map((value) => linkedPage(escapeHtml(value), href)).join(", ");
}

function linkedPage(label, href) {
  if (!href) {
    return label;
  }
  return `<a href="${escapeHtml(href)}">${label}</a>`;
}

function renderFinalResult(result) {
  finalResult.replaceChildren();
  if (!Array.isArray(result.behaviors) || !result.behaviors.length) {
    renderEmpty(finalResult, "暂无最终结果。");
    return;
  }
  const section = document.createElement("article");
  section.className = "result-block";
  section.innerHTML = `
    <h3>${escapeHtml(result.file?.filename || result.session_id || "sample")}</h3>
    <p>${escapeHtml(result.summary?.risk_level || "unknown")} | ${escapeHtml(result.summary?.overall || "")}</p>
  `;
  result.behaviors.forEach((behavior) => {
    const item = document.createElement("article");
    item.className = "item-block";
    item.innerHTML = `
      <h4>${escapeHtml(behavior.behavior || "")}</h4>
      <dl class="details">
        <dt>证据</dt><dd>${escapeHtml(behavior.evidence?.summary || "")}</dd>
        <dt>来源</dt><dd>${escapeHtml(formatSources(behavior.evidence?.sources || []))}</dd>
        <dt>验证</dt><dd>${escapeHtml(behavior.verification || "unverified")}</dd>
        <dt>函数</dt><dd>${escapeHtml(formatFunctionSource(behavior.function_level_source))}</dd>
      </dl>
    `;
    section.append(item);
  });
  finalResult.append(section);
}

function openResult() {
  if (!currentSession) {
    setStatus("请先选择 session。");
    return;
  }
  window.location.href = `/result.html?session_id=${encodeURIComponent(currentSession.session_id)}`;
}

function openRawOutput() {
  if (!currentSession) {
    setStatus("请先选择 session。");
    return;
  }
  window.location.href = `/raw-data.html?session_id=${encodeURIComponent(currentSession.session_id)}`;
}

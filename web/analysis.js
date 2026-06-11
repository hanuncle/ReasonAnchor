const { request, setStatus, renderEmpty, renderSelect, escapeHtml, formatSources, formatFunctionSource, safe } = window.SFP;

let sessions = [];
let workflows = [];
let currentSession = null;

const sampleFile = document.querySelector("#sample-file");
const sessionSelect = document.querySelector("#session-select");
const workflowSelect = document.querySelector("#workflow-select");
const sessionDetails = document.querySelector("#session-details");
const finalResult = document.querySelector("#final-result");

document.querySelector("#upload-button").addEventListener("click", uploadSample);
document.querySelector("#refresh-sessions-button").addEventListener("click", loadSessions);
document.querySelector("#load-session-button").addEventListener("click", loadSelectedSession);
document.querySelector("#apply-workflow-button").addEventListener("click", applyWorkflow);
document.querySelector("#run-workflow-button").addEventListener("click", runWorkflow);
document.querySelector("#refresh-result-button").addEventListener("click", loadCurrentResult);
document.querySelector("#open-result-button").addEventListener("click", openResult);
document.querySelector("#open-raw-button").addEventListener("click", openRawOutput);

init();

async function init() {
  await safe("初始化失败", async () => {
    await Promise.all([loadSessions(), loadWorkflows()]);
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
    currentSession = await request(`/api/sessions/${currentSession.session_id}/run`, {
      method: "POST",
    });
    renderSession(currentSession);
    await loadCurrentResult();
    setStatus("Workflow 已完成。");
  });
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

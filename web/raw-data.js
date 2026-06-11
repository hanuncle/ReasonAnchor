const { request, setStatus, renderEmpty, renderSelect, safe } = window.SFP;

let sessions = [];

const sessionSelect = document.querySelector("#session-select");
const rawOutputSelect = document.querySelector("#raw-output-select");
const rawMapOutput = document.querySelector("#raw-map-output");
const rawDetailOutput = document.querySelector("#raw-detail-output");
const aiOutput = document.querySelector("#ai-output");

document.querySelector("#refresh-sessions-button").addEventListener("click", loadSessions);
document.querySelector("#load-raw-map-button").addEventListener("click", loadRawMap);
document.querySelector("#load-raw-item-button").addEventListener("click", loadRawItem);
document.querySelector("#load-ai-output-button").addEventListener("click", loadAiOutput);

init();

async function init() {
  await safe("初始化失败", async () => {
    await loadSessions();
    const params = new URLSearchParams(window.location.search);
    const sessionId = params.get("session_id");
    if (sessionId) {
      sessionSelect.value = sessionId;
    }
    setStatus("原始数据查询已就绪。");
  });
}

async function loadSessions() {
  const data = await request("/api/sessions");
  sessions = data.sessions || [];
  renderSelect(sessionSelect, sessions, "暂无 session", (session) => ({
    value: session.session_id,
    label: `${session.sample?.filename || "sample"} | ${session.session_id}`,
  }));
}

async function loadRawMap() {
  if (!sessionSelect.value) {
    setStatus("请先选择 session。");
    return;
  }
  await safe("查询 raw output map 失败", async () => {
    const data = await request(`/api/sessions/${encodeURIComponent(sessionSelect.value)}/raw-output-map`);
    rawMapOutput.textContent = JSON.stringify(data, null, 2);
    renderSelect(rawOutputSelect, data.items || [], "暂无 raw_output_id", (item) => ({
      value: item.raw_output_id,
      label: `${item.raw_output_id} | ${item.result_key || ""}`,
    }));
    setStatus(data.items?.length ? "raw output map 已加载。" : "当前 session 没有原始数据。");
  });
}

async function loadRawItem() {
  if (!sessionSelect.value || !rawOutputSelect.value) {
    setStatus("请先选择 session 和 raw_output_id。");
    return;
  }
  await safe("查询原始数据失败", async () => {
    const data = await request(
      `/api/sessions/${encodeURIComponent(sessionSelect.value)}/raw-output/${encodeURIComponent(rawOutputSelect.value)}`,
    );
    rawDetailOutput.textContent = JSON.stringify(data, null, 2);
    setStatus("原始数据已加载。");
  });
}

async function loadAiOutput() {
  if (!sessionSelect.value) {
    setStatus("请先选择 session。");
    return;
  }
  await safe("查询 AI 输出失败", async () => {
    const data = await request(`/api/sessions/${encodeURIComponent(sessionSelect.value)}/ai-output`);
    aiOutput.textContent = JSON.stringify(data, null, 2);
    setStatus(data.items?.length ? "AI 输出已加载。" : "当前 session 没有 AI 输出。");
  });
}

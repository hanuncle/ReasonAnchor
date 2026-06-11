const params = new URLSearchParams(window.location.search);
const sessionId = params.get("session_id");
const sessionOutput = document.querySelector("#session-output");
const rawOutputItems = document.querySelector("#raw-output-items");
const statusLine = document.querySelector("#status-line");
const loadedItems = new Map();

loadRawOutputMap();

async function loadRawOutputMap() {
  if (!sessionId) {
    setStatus("缺少 session_id。");
    return;
  }

  try {
    const data = await requestJson(
      `/api/sessions/${encodeURIComponent(sessionId)}/raw-output-map`,
    );
    const items = data.items || [];
    sessionOutput.textContent = data.session_id;
    renderItems(items);
    setStatus(items.length ? `共 ${items.length} 个原始数据条目。` : "没有原始数据条目。");
  } catch (error) {
    setStatus(error.message);
  }
}

function renderItems(items) {
  rawOutputItems.replaceChildren();
  if (!items.length) {
    rawOutputItems.textContent = "没有原始数据条目。";
    return;
  }

  items.forEach((item) => {
    const article = document.createElement("article");
    article.className = "raw-output-item";

    const title = document.createElement("h3");
    title.textContent = `${item.index}. ${item.function_name || item.function_id}`;

    const meta = document.createElement("p");
    meta.textContent = [
      `raw_output_id: ${item.raw_output_id}`,
      `function_id: ${item.function_id}`,
      `result_key: ${item.result_key}`,
      `status: ${item.status}`,
    ].join(" | ");

    const details = document.createElement("details");
    const summary = document.createElement("summary");
    summary.textContent = "查看原始数据";

    const pre = document.createElement("pre");
    pre.textContent = "展开后加载。";

    details.addEventListener("toggle", () => {
      if (details.open) {
        loadRawOutputItem(item.raw_output_id, pre);
      }
    });

    details.append(summary, pre);
    article.append(title, meta, details);
    rawOutputItems.append(article);
  });
}

async function loadRawOutputItem(rawOutputId, pre) {
  if (loadedItems.has(rawOutputId)) {
    pre.textContent = loadedItems.get(rawOutputId);
    return;
  }

  pre.textContent = "正在加载...";
  try {
    const data = await requestJson(
      `/api/sessions/${encodeURIComponent(sessionId)}/raw-output/${encodeURIComponent(
        rawOutputId,
      )}`,
    );
    const rendered = JSON.stringify(data.item?.output || {}, null, 2);
    loadedItems.set(rawOutputId, rendered);
    pre.textContent = rendered;
  } catch (error) {
    pre.textContent = error.message;
  }
}

async function requestJson(url) {
  const response = await fetch(url);
  const data = await response.json();
  if (!response.ok) {
    throw new Error(JSON.stringify(data));
  }
  return data;
}

function setStatus(message) {
  statusLine.textContent = message;
}

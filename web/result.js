const params = new URLSearchParams(window.location.search);
const sessionId = params.get("session_id");
const fileDetails = document.querySelector("#file-details");
const summaryDetails = document.querySelector("#summary-details");
const behaviorList = document.querySelector("#behavior-list");
const statusLine = document.querySelector("#status-line");

loadResult();

async function loadResult() {
  if (!sessionId) {
    setStatus("缺少 session_id。");
    return;
  }

  const response = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}/result`);
  const result = await response.json();
  if (!response.ok) {
    setStatus(JSON.stringify(result));
    return;
  }

  renderFile(result.file || {});
  renderSummary(result.summary || {});
  renderBehaviors(result.behaviors || []);
}

function renderFile(file) {
  fileDetails.innerHTML = `
    <dt>filename</dt><dd>${escapeHtml(file.filename || "")}</dd>
    <dt>size</dt><dd>${escapeHtml(file.size ?? "")}</dd>
    <dt>sha256</dt><dd>${escapeHtml(file.sha256 || "")}</dd>
    <dt>file_type</dt><dd>${escapeHtml(file.file_type || "")}</dd>
  `;
}

function renderSummary(summary) {
  summaryDetails.innerHTML = `
    <dt>overall</dt><dd>${escapeHtml(summary.overall || "")}</dd>
    <dt>risk_level</dt><dd>${escapeHtml(summary.risk_level || "unknown")}</dd>
    <dt>limitations</dt><dd>${escapeHtml((summary.limitations || []).join(", "))}</dd>
  `;
}

function renderBehaviors(behaviors) {
  behaviorList.replaceChildren();
  if (!behaviors.length) {
    behaviorList.textContent = "暂无最终结果，请先生成并保存 result。";
    return;
  }

  behaviors.forEach((behavior) => {
    const article = document.createElement("article");
    article.className = "behavior-item";
    const evidence = behavior.evidence || {};
    const functionSource = behavior.function_level_source || {};
    article.innerHTML = `
      <h3>${escapeHtml(behavior.behavior || "")}</h3>
      <dl class="details">
        <dt>证据摘要</dt><dd>${escapeHtml(evidence.summary || "")}</dd>
        <dt>证据来源</dt><dd>${escapeHtml(formatSources(evidence.sources || []))}</dd>
        <dt>验证</dt><dd>${escapeHtml(behavior.verification || "unverified")}</dd>
        <dt>函数级来源</dt><dd>${escapeHtml(formatFunctionSource(functionSource))}</dd>
      </dl>
    `;
    behaviorList.append(article);
  });
}

function formatSources(sources) {
  if (!Array.isArray(sources) || !sources.length) {
    return "无证据来源";
  }
  return sources
    .map((source) =>
      [
        source.raw_output_id,
        source.function_id,
        source.result_key,
        source.description,
      ]
        .filter(Boolean)
        .join(" | "),
    )
    .join("; ");
}

function formatFunctionSource(source) {
  if (!source || typeof source !== "object") {
    return "未进行函数级分析";
  }
  const text = [source.tool, source.function_name, source.address, source.note]
    .filter(Boolean)
    .join(" | ");
  return text || "未进行函数级分析";
}

function setStatus(message) {
  statusLine.textContent = message;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => {
    const entities = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    };
    return entities[char];
  });
}

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

  renderFile(result.file || {}, result.target || {});
  renderSummary(result.summary || {});
  if (result.assets || result.candidate_findings || result.target_scope) {
    renderReconResult(result);
  } else {
    renderBehaviors(result.behaviors || []);
  }
}

function renderFile(file, target) {
  fileDetails.innerHTML = `
    <dt>target</dt><dd>${escapeHtml(target.label || (target.targets || [])[0] || "")}</dd>
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

function renderReconResult(result) {
  const assets = result.assets || {};
  const targetScope = result.target_scope || {};
  behaviorList.replaceChildren();
  const section = document.createElement("article");
  section.className = "behavior-item";
  section.innerHTML = `
    <h3>Recon attack surface</h3>
    <dl class="details">
      <dt>authorized</dt><dd>${escapeHtml(targetScope.authorized ?? "")}</dd>
      <dt>scope</dt><dd>${escapeHtml(targetScope.scope_summary || "")}</dd>
      <dt>domains</dt><dd>${escapeHtml((assets.domains || []).join(", "))}</dd>
      <dt>hosts</dt><dd>${escapeHtml((assets.hosts || []).join(", "))}</dd>
      <dt>web endpoints</dt><dd>${escapeHtml((assets.web_endpoints || []).map((item) => item.url || "").filter(Boolean).join(", "))}</dd>
      <dt>urls</dt><dd>${escapeHtml((assets.urls || []).map((item) => item.url || "").filter(Boolean).join(", "))}</dd>
      <dt>services</dt><dd>${escapeHtml((assets.services || []).map((item) => `${item.host || ""}:${item.port || ""} ${item.service || ""}`.trim()).join(", "))}</dd>
    </dl>
  `;
  behaviorList.append(section);

  const findings = result.candidate_findings || [];
  if (!findings.length) {
    const empty = document.createElement("p");
    empty.textContent = "No candidate findings.";
    behaviorList.append(empty);
  }
  findings.forEach((finding) => {
    const article = document.createElement("article");
    article.className = "behavior-item";
    article.innerHTML = `
      <h3>${escapeHtml(finding.title || "Candidate finding")}</h3>
      <dl class="details">
        <dt>severity</dt><dd>${escapeHtml(finding.severity || "unknown")}</dd>
        <dt>asset</dt><dd>${escapeHtml(finding.affected_asset || "")}</dd>
        <dt>evidence</dt><dd>${escapeHtml(finding.evidence?.summary || "")}</dd>
        <dt>sources</dt><dd>${escapeHtml(formatSources(finding.evidence?.sources || []))}</dd>
        <dt>verification</dt><dd>${escapeHtml(finding.verification || "unverified")}</dd>
        <dt>fix</dt><dd>${escapeHtml(finding.recommended_fix || "")}</dd>
      </dl>
    `;
    behaviorList.append(article);
  });

  (result.recommended_next_steps || []).forEach((step) => {
    const article = document.createElement("article");
    article.className = "behavior-item";
    article.innerHTML = `
      <h3>${escapeHtml(step.action || "Recommended next step")}</h3>
      <dl class="details">
        <dt>reason</dt><dd>${escapeHtml(step.reason || "")}</dd>
        <dt>confirmation</dt><dd>${escapeHtml(step.requires_human_confirmation ?? "")}</dd>
      </dl>
    `;
    behaviorList.append(article);
  });
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

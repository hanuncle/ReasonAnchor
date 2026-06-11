const { request, setStatus, renderEmpty, renderSelect, escapeHtml, safe } = window.SFP;

let modules = [];
let workflows = [];
let functions = [];

const moduleList = document.querySelector("#module-list");
const moduleImportFile = document.querySelector("#module-import-file");
const packageOutput = document.querySelector("#package-output");
const workflowSelect = document.querySelector("#workflow-select");
const workflowName = document.querySelector("#workflow-name");
const workflowDescription = document.querySelector("#workflow-description");
const workflowTags = document.querySelector("#workflow-tags");
const workflowRisk = document.querySelector("#workflow-risk");
const workflowNetwork = document.querySelector("#workflow-network");
const workflowConfigRequired = document.querySelector("#workflow-config-required");
const workflowDefaultSafe = document.querySelector("#workflow-default-safe");
const workflowJson = document.querySelector("#workflow-json");
const functionList = document.querySelector("#function-list");

document.querySelector("#import-module-button").addEventListener("click", () => moduleImportFile.click());
moduleImportFile.addEventListener("change", importModule);
document.querySelector("#refresh-modules-button").addEventListener("click", loadModules);
document.querySelector("#refresh-workflows-button").addEventListener("click", loadWorkflows);
document.querySelector("#load-workflow-button").addEventListener("click", loadWorkflow);
document.querySelector("#save-workflow-button").addEventListener("click", saveWorkflow);
document.querySelector("#update-workflow-button").addEventListener("click", updateWorkflow);
document.querySelector("#delete-workflow-button").addEventListener("click", deleteWorkflow);
document.querySelector("#build-workflow-button").addEventListener("click", buildWorkflowFromFunctions);

init();

async function init() {
  await safe("初始化失败", async () => {
    await Promise.all([loadModules(), loadWorkflows(), loadFunctions()]);
    setStatus("模块与流程已加载。");
  });
}

async function loadModules() {
  const data = await request("/api/modules");
  modules = data.modules || [];
  renderModules();
}

async function loadWorkflows() {
  const data = await request("/api/workflows");
  workflows = data.workflows || [];
  renderSelect(workflowSelect, workflows, "暂无流程模板", (workflow) => ({
    value: workflow.workflow_id,
    label: `${workflow.source === "module" ? "模块" : "本地"} | ${workflow.name}`,
  }));
}

async function loadFunctions() {
  functions = await request("/api/functions");
  renderFunctions();
}

async function importModule() {
  const file = moduleImportFile.files[0];
  if (!file) {
    setStatus("请先选择模块包。");
    return;
  }
  const form = new FormData();
  form.append("file", file);
  await safe("导入模块失败", async () => {
    await request("/api/modules/import-file", { method: "POST", body: form });
    await Promise.all([loadModules(), loadWorkflows(), loadFunctions()]);
    setStatus("模块已导入。");
  });
  moduleImportFile.value = "";
}

function renderModules() {
  moduleList.replaceChildren();
  if (!modules.length) {
    renderEmpty(moduleList, "暂无模块。");
    return;
  }
  modules.forEach((moduleItem) => {
    const row = document.createElement("div");
    row.className = "module-row";
    row.innerHTML = `
      <span>${escapeHtml(moduleItem.module_id)} | ${escapeHtml(moduleItem.name || "")} | ${escapeHtml(moduleItem.version || "")}</span>
      <span>${escapeHtml(moduleFlags(moduleItem).join(", ") || "local")}</span>
    `;
    const packageButton = document.createElement("button");
    packageButton.type = "button";
    packageButton.textContent = "打包";
    packageButton.addEventListener("click", () => packageModule(moduleItem.module_id));
    const exportButton = document.createElement("button");
    exportButton.type = "button";
    exportButton.textContent = "导出";
    exportButton.addEventListener("click", () => {
      window.location.href = `/api/modules/${encodeURIComponent(moduleItem.module_id)}/download`;
    });
    row.append(packageButton, exportButton);
    moduleList.append(row);
  });
}

async function packageModule(moduleId) {
  await safe("模块打包失败", async () => {
    const result = await request(`/api/modules/${encodeURIComponent(moduleId)}/package`, {
      method: "POST",
    });
    packageOutput.textContent = JSON.stringify(result, null, 2);
    setStatus("模块已打包。");
  });
}

function moduleFlags(moduleItem) {
  const requirements = moduleItem.requirements || {};
  const flags = [];
  if (requirements.network) flags.push("network");
  if (requirements.active_scan) flags.push("active scan");
  if (requirements.requires_authorization) flags.push("requires authorization");
  return flags;
}

async function loadWorkflow() {
  if (!workflowSelect.value) {
    setStatus("请先选择流程模板。");
    return;
  }
  await safe("加载流程失败", async () => {
    const workflow = await request(`/api/workflows/${encodeURIComponent(workflowSelect.value)}`);
    workflowName.value = workflow.name || "";
    workflowDescription.value = workflow.description || "";
    workflowTags.value = (workflow.tags || []).join(", ");
    workflowRisk.value = workflow.risk || "low";
    workflowNetwork.checked = Boolean(workflow.network);
    workflowConfigRequired.checked = Boolean(workflow.config_required);
    workflowDefaultSafe.checked = Boolean(workflow.default_safe);
    workflowJson.value = JSON.stringify(workflow.workflow || { name: workflow.name, steps: [] }, null, 2);
    setStatus(workflow.source === "module" ? "模块流程已加载，只读。" : "流程已加载。");
  });
}

async function saveWorkflow() {
  await saveWorkflowRequest("POST", "/api/workflows", "流程模板已保存。");
}

async function updateWorkflow() {
  const selected = workflows.find((item) => item.workflow_id === workflowSelect.value);
  if (!selected) {
    setStatus("请先选择流程模板。");
    return;
  }
  if (selected.source === "module") {
    setStatus("模块流程为只读，请另存为本地流程。");
    return;
  }
  await saveWorkflowRequest(
    "PUT",
    `/api/workflows/${encodeURIComponent(selected.workflow_id)}`,
    "流程模板已更新。",
  );
}

async function saveWorkflowRequest(method, url, message) {
  let workflow;
  try {
    workflow = JSON.parse(workflowJson.value || "{}");
  } catch {
    setStatus("workflow JSON 无效。");
    return;
  }
  await safe("保存流程失败", async () => {
    const saved = await request(url, {
      method,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: workflowName.value.trim() || workflow.name || "workflow",
        workflow,
        description: workflowDescription.value.trim(),
        tags: workflowTags.value.split(",").map((item) => item.trim()).filter(Boolean),
        risk: workflowRisk.value,
        network: workflowNetwork.checked,
        config_required: workflowConfigRequired.checked,
        default_safe: workflowDefaultSafe.checked,
      }),
    });
    await loadWorkflows();
    workflowSelect.value = saved.workflow_id;
    setStatus(message);
  });
}

async function deleteWorkflow() {
  const selected = workflows.find((item) => item.workflow_id === workflowSelect.value);
  if (!selected) {
    setStatus("请先选择流程模板。");
    return;
  }
  if (selected.source === "module") {
    setStatus("模块流程为只读，不能删除。");
    return;
  }
  await safe("删除流程失败", async () => {
    await request(`/api/workflows/${encodeURIComponent(selected.workflow_id)}`, {
      method: "DELETE",
    });
    workflowJson.value = "";
    await loadWorkflows();
    setStatus("流程模板已删除。");
  });
}

function renderFunctions() {
  functionList.replaceChildren();
  if (!functions.length) {
    renderEmpty(functionList, "暂无函数。");
    return;
  }
  functions.forEach((fn) => {
    const label = document.createElement("label");
    label.className = "check-row";
    label.innerHTML = `
      <input type="checkbox" value="${escapeHtml(fn.id)}" />
      <span>${escapeHtml(fn.id)} | ${escapeHtml(fn.name || "")}</span>
    `;
    functionList.append(label);
  });
}

function buildWorkflowFromFunctions() {
  const selected = [...functionList.querySelectorAll("input:checked")].map((input) => input.value);
  if (!selected.length) {
    setStatus("请先选择函数。");
    return;
  }
  const workflow = {
    name: workflowName.value.trim() || "custom_workflow",
    steps: selected.map((functionId) => ({
      function_id: functionId,
      params: functionId === "strings.extract" ? { min_length: 4, max_strings: 2000 } : {},
    })),
  };
  workflowJson.value = JSON.stringify(workflow, null, 2);
  setStatus("流程 JSON 已生成。");
}

const { request, setStatus, renderEmpty, escapeHtml, safe } = window.SFP;

const mcpTools = [
  ["get_platform_skill", "读取平台 Skill 和 playbook"],
  ["list_modules", "列出可用模块"],
  ["get_module_template", "查看默认模块格式"],
  ["get_module_skill", "读取选中模块的 Skill"],
  ["get_module_detail", "查看模块详情"],
  ["create_module", "创建默认格式模块"],
  ["load_module", "校验并加载模块"],
  ["package_module", "打包模块"],
  ["export_module", "导出模块"],
  ["import_module_archive", "导入模块包"],
  ["upload_sample", "上传一个样本"],
  ["upload_samples", "上传多个样本"],
  ["create_target_session", "创建目标型 session"],
  ["list_functions", "列出函数"],
  ["list_custom_workflows", "列出流程模板"],
  ["save_custom_workflow", "保存流程模板"],
  ["select_custom_workflow", "应用流程模板"],
  ["run_workflow", "运行流程"],
  ["get_ai_output", "读取 AI 输出"],
  ["get_raw_output_map", "读取原始数据索引"],
  ["get_raw_output_by_id", "按 ID 读取原始数据"],
  ["run_function", "运行单个函数"],
  ["save_session_result", "保存最终结果"],
];

const mcpToolsList = document.querySelector("#mcp-tools-list");
const moduleList = document.querySelector("#module-detail-list");

init();

async function init() {
  renderMcpTools();
  await safe("模块信息加载失败", loadModules);
  setStatus("平台与模块说明已加载。");
}

function renderMcpTools() {
  mcpToolsList.replaceChildren();
  mcpTools.forEach(([name, role]) => {
    const row = document.createElement("div");
    row.className = "tool-row";
    row.innerHTML = `<code>${escapeHtml(name)}</code><span>${escapeHtml(role)}</span>`;
    mcpToolsList.append(row);
  });
}

async function loadModules() {
  const data = await request("/api/modules");
  const modules = data.modules || [];
  moduleList.replaceChildren();
  if (!modules.length) {
    renderEmpty(moduleList, "暂无模块。");
    return;
  }
  for (const moduleItem of modules) {
    const detail = await request(`/api/modules/${encodeURIComponent(moduleItem.module_id)}`);
    renderModule(detail);
  }
}

function renderModule(detail) {
  const article = document.createElement("article");
  article.className = "module-detail";
  const skill = detail.skill || {};
  const functions = (detail.functions || [])
    .map((fn) => {
      const functionId = fn.id || fn.function_id || "";
      const name = fn.name || "";
      const description = fn.description || "";
      return `${functionId} ${name} ${description}`.trim();
    })
    .filter(Boolean)
    .join("; ");
  article.innerHTML = `
    <h3>${escapeHtml(detail.module_id)}</h3>
    <dl class="details">
      <dt>模块路径</dt><dd>modules/${escapeHtml(detail.module_id)}/</dd>
      <dt>Skill</dt><dd>${escapeHtml(skill.skill_file || "未配置")}</dd>
      <dt>Playbook</dt><dd>${escapeHtml(skill.playbook_file || "未配置")}</dd>
      <dt>最终格式</dt><dd>${escapeHtml(skill.final_result_schema_file || "未配置")}</dd>
      <dt>功能函数</dt><dd>${escapeHtml(functions || "暂无函数")}</dd>
    </dl>
  `;
  moduleList.append(article);
}

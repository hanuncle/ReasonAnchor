const { request, setStatus, renderEmpty, safe } = window.SFP;

const configList = document.querySelector("#config-list");
const MODULE_LABELS = {
  recon_scan: "扫描模块",
  reverse: "逆向模块",
  vuln_scan: "漏洞扫描模块",
  platform: "平台配置",
};
const MODULE_ORDER = ["recon_scan", "reverse", "vuln_scan", "platform"];

document.querySelector("#refresh-config-button").addEventListener("click", loadConfig);

init();

async function init() {
  await safe("初始化失败", async () => {
    await loadConfig();
    setStatus("配置中心已加载。");
  });
}

async function loadConfig() {
  const config = await request("/api/config");
  renderConfig(config.fields || []);
}

function renderConfig(fields) {
  configList.replaceChildren();
  if (!fields.length) {
    renderEmpty(configList, "暂无可配置字段。");
    return;
  }

  groupedFields(fields).forEach((group) => {
    const section = document.createElement("section");
    section.className = "config-group";

    const header = document.createElement("div");
    header.className = "config-group-header";

    const title = document.createElement("div");
    title.className = "module-info";
    const heading = document.createElement("h3");
    heading.textContent = group.moduleName;
    const meta = document.createElement("span");
    meta.textContent = `${group.moduleId} | ${group.configuredCount}/${group.fields.length} 已配置`;
    title.append(heading, meta);

    header.append(title);
    section.append(header);

    const rows = document.createElement("div");
    rows.className = "config-group-fields";
    group.fields.forEach((field) => rows.append(renderConfigRow(field)));
    section.append(rows);
    configList.append(section);
  });
}

function groupedFields(fields) {
  const groups = new Map();
  fields.forEach((field) => {
    const moduleId = field.module_id || field.namespace || "platform";
    if (!groups.has(moduleId)) {
      groups.set(moduleId, {
        moduleId,
        moduleName: moduleDisplayName(moduleId, field.module_name),
        fields: [],
        configuredCount: 0,
      });
    }
    const group = groups.get(moduleId);
    group.fields.push(field);
    if (field.configured) {
      group.configuredCount += 1;
    }
  });
  return [...groups.values()].sort((left, right) => {
    const leftOrder = moduleOrder(left.moduleId);
    const rightOrder = moduleOrder(right.moduleId);
    if (leftOrder !== rightOrder) {
      return leftOrder - rightOrder;
    }
    return left.moduleName.localeCompare(right.moduleName);
  });
}

function moduleDisplayName(moduleId, fallbackName) {
  return MODULE_LABELS[moduleId] || fallbackName || moduleId;
}

function moduleOrder(moduleId) {
  const index = MODULE_ORDER.indexOf(moduleId);
  return index === -1 ? MODULE_ORDER.length : index;
}

function renderConfigRow(field) {
  const row = document.createElement("div");
  row.className = "config-row";

  const label = document.createElement("label");
  label.textContent = field.label;
  label.htmlFor = `config-${field.path.replaceAll(".", "-")}`;

  const path = document.createElement("code");
  path.textContent = field.path;

  const state = document.createElement("span");
  state.className = field.configured ? "config-state configured" : "config-state";
  state.textContent = field.configured ? "已配置" : "未配置";

  const input = document.createElement("input");
  input.id = label.htmlFor;
  input.type = field.secret ? "password" : "text";
  input.placeholder = field.secret && field.configured ? "已配置" : "";
  input.value = field.secret ? "" : field.value ?? "";

  const saveButton = document.createElement("button");
  saveButton.type = "button";
  saveButton.textContent = "保存";
  saveButton.addEventListener("click", () => saveConfigValue(field, input));

  const deleteButton = document.createElement("button");
  deleteButton.type = "button";
  deleteButton.textContent = "删除";
  deleteButton.addEventListener("click", () => deleteConfigValue(field.path));

  row.append(label, path, state, input, saveButton, deleteButton);
  return row;
}

async function saveConfigValue(field, input) {
  if (field.secret && input.value === "") {
    setStatus("请先输入新的密钥值。");
    return;
  }
  await safe("保存配置失败", async () => {
    const config = await request("/api/config/value", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path: field.path, value: input.value }),
    });
    renderConfig(config.fields || []);
    setStatus("配置已保存。");
  });
}

async function deleteConfigValue(path) {
  await safe("删除配置失败", async () => {
    const config = await request("/api/config/delete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path }),
    });
    renderConfig(config.fields || []);
    setStatus("配置已删除。");
  });
}

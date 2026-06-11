const { request, setStatus, renderEmpty, safe } = window.SFP;

const configList = document.querySelector("#config-list");

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
  fields.forEach((field) => {
    const row = document.createElement("div");
    row.className = "config-row";

    const label = document.createElement("label");
    label.textContent = field.label;
    label.htmlFor = `config-${field.path.replaceAll(".", "-")}`;

    const path = document.createElement("code");
    path.textContent = field.path;

    const state = document.createElement("span");
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
    configList.append(row);
  });
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

const { request, setStatus, renderEmpty, escapeHtml, safe } = window.SFP;

const params = new URLSearchParams(window.location.search);
const moduleId = params.get("module") || "";
let pageId = params.get("page") || "";

let uiPages = [];
let pageDefinition = null;
let knowledgeData = null;
let currentRows = [];

const pageTitle = document.querySelector("#module-page-title");
const pageSubtitle = document.querySelector("#module-page-subtitle");
const pageNav = document.querySelector("#module-page-nav");
const knowledgeTitle = document.querySelector("#knowledge-title");
const knowledgeSummary = document.querySelector("#knowledge-summary");
const knowledgeSearch = document.querySelector("#knowledge-search");
const knowledgeView = document.querySelector("#knowledge-view");
const knowledgeDetail = document.querySelector("#knowledge-detail");

knowledgeSearch.addEventListener("input", () => renderKnowledgeRows());

init();

async function init() {
  if (!moduleId) {
    setStatus("Missing module id.");
    renderEmpty(pageNav, "Missing module id.");
    return;
  }

  await safe("Load module page failed", async () => {
    const ui = await request(`/api/modules/${encodeURIComponent(moduleId)}/ui`);
    uiPages = ((ui.ui || {}).pages || []).filter(Boolean);
    if (!pageId && uiPages.length) {
      pageId = uiPages[0].page_id;
    }
    pageDefinition = uiPages.find((page) => page.page_id === pageId) || null;
    renderPageNav();

    if (!pageDefinition) {
      pageTitle.textContent = `${moduleId} module`;
      renderEmpty(knowledgeView, "Page was not declared by this module.");
      setStatus("No matching module page.");
      return;
    }

    pageTitle.textContent = pageDefinition.title || pageDefinition.page_id;
    pageSubtitle.textContent = `${moduleId} | ${pageDefinition.knowledge_type}`;
    knowledgeTitle.textContent = pageDefinition.title || "Knowledge";
    const response = await request(
      `/api/modules/${encodeURIComponent(moduleId)}/knowledge/${encodeURIComponent(
        pageDefinition.knowledge_type,
      )}`,
    );
    knowledgeData = response;
    currentRows = rowsFromKnowledge(response.data, pageDefinition);
    renderKnowledgeSummary(response);
    renderKnowledgeRows();
    setStatus(`Loaded ${currentRows.length} item(s).`);
  });
}

function renderPageNav() {
  pageNav.replaceChildren();
  if (!uiPages.length) {
    renderEmpty(pageNav, "No declared module pages.");
    return;
  }
  uiPages.forEach((page) => {
    const link = document.createElement("a");
    link.href = `/module-page.html?module=${encodeURIComponent(moduleId)}&page=${encodeURIComponent(
      page.page_id,
    )}`;
    link.textContent = page.title || page.page_id;
    if (page.page_id === pageId) {
      link.className = "active";
    }
    pageNav.append(link);
  });
}

function renderKnowledgeSummary(response) {
  knowledgeSummary.replaceChildren();
  const items = [
    ["module", response.module_id || moduleId],
    ["type", response.type || ""],
    ["path", response.path || ""],
    ["items", String(response.items_count ?? currentRows.length)],
    ["view", pageDefinition.type || ""],
  ];
  items.forEach(([label, value]) => {
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    dd.textContent = value;
    knowledgeSummary.append(dt, dd);
  });
}

function renderKnowledgeRows() {
  const needle = knowledgeSearch.value.trim().toLowerCase();
  const rows = needle
    ? currentRows.filter((row) => JSON.stringify(row).toLowerCase().includes(needle))
    : currentRows;

  if (!rows.length) {
    renderEmpty(knowledgeView, "No matching items.");
    knowledgeDetail.textContent = "{}";
    return;
  }

  if (pageDefinition.type === "taxonomy_browser") {
    renderTable(rows, taxonomyColumns(rows));
  } else {
    renderTable(rows, tableColumns(rows, pageDefinition.columns || []));
  }
  showDetail(rows[0]);
}

function renderTable(rows, columns) {
  knowledgeView.replaceChildren();
  const table = document.createElement("table");
  table.className = "knowledge-table";
  const thead = document.createElement("thead");
  const headerRow = document.createElement("tr");
  columns.forEach((column) => {
    const th = document.createElement("th");
    th.textContent = humanColumn(column);
    headerRow.append(th);
  });
  thead.append(headerRow);
  table.append(thead);

  const tbody = document.createElement("tbody");
  rows.forEach((row) => {
    const tr = document.createElement("tr");
    tr.tabIndex = 0;
    tr.addEventListener("click", () => showDetail(row));
    tr.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        showDetail(row);
      }
    });
    columns.forEach((column) => {
      const td = document.createElement("td");
      td.innerHTML = escapeHtml(formatValue(valueForColumn(row, column)));
      tr.append(td);
    });
    tbody.append(tr);
  });
  table.append(tbody);
  knowledgeView.append(table);
}

function showDetail(row) {
  knowledgeDetail.textContent = JSON.stringify(row, null, 2);
}

function rowsFromKnowledge(data, page) {
  if (Array.isArray(data)) {
    return data;
  }
  if (!data || typeof data !== "object") {
    return [];
  }
  for (const key of ["techniques", "categories", "samples", "scenarios", "entries", "items"]) {
    if (Array.isArray(data[key])) {
      return data[key];
    }
  }
  if (page.type === "taxonomy_browser" && Array.isArray(data.categories)) {
    return data.categories;
  }
  return [data];
}

function tableColumns(rows, declaredColumns) {
  const columns = declaredColumns.filter(Boolean);
  if (columns.length) {
    return columns;
  }
  const discovered = [];
  rows.slice(0, 20).forEach((row) => {
    if (!row || typeof row !== "object" || Array.isArray(row)) {
      return;
    }
    Object.keys(row).forEach((key) => {
      if (!discovered.includes(key)) {
        discovered.push(key);
      }
    });
  });
  return discovered.slice(0, 8);
}

function taxonomyColumns(rows) {
  const preferred = ["id", "name", "description", "attack_techniques"];
  const available = new Set(tableColumns(rows, []));
  return preferred.filter((column) => available.has(column));
}

function valueForColumn(row, column) {
  if (!row || typeof row !== "object") {
    return row;
  }
  if (column.includes(".")) {
    return column.split(".").reduce((value, part) => {
      if (!value || typeof value !== "object") {
        return undefined;
      }
      return value[part];
    }, row);
  }
  return row[column];
}

function formatValue(value) {
  if (Array.isArray(value)) {
    return value.map((item) => formatValue(item)).join(", ");
  }
  if (value && typeof value === "object") {
    return JSON.stringify(value);
  }
  return value ?? "";
}

function humanColumn(column) {
  return String(column).replace(/[._-]+/g, " ");
}

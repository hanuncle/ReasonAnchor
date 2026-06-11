window.SFP = {
  async request(url, options) {
    const response = await fetch(url, options);
    const text = await response.text();
    const data = text ? JSON.parse(text) : {};
    if (!response.ok) {
      throw new Error(JSON.stringify(data.detail || data));
    }
    return data;
  },

  setStatus(message) {
    const statusLine = document.querySelector("#status-line");
    if (statusLine) {
      statusLine.textContent = message;
    }
  },

  renderEmpty(container, message) {
    container.replaceChildren();
    const div = document.createElement("div");
    div.className = "empty-state";
    div.textContent = message;
    container.append(div);
  },

  renderSelect(select, items, emptyLabel, mapItem) {
    select.replaceChildren();
    const empty = document.createElement("option");
    empty.value = "";
    empty.textContent = emptyLabel;
    select.append(empty);
    items.forEach((item) => {
      const mapped = mapItem(item);
      const option = document.createElement("option");
      option.value = mapped.value;
      option.textContent = mapped.label;
      select.append(option);
    });
  },

  escapeHtml(value) {
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
  },

  formatSources(sources) {
    if (!Array.isArray(sources) || !sources.length) {
      return "无证据来源";
    }
    return sources
      .map((source) =>
        [source.raw_output_id, source.function_id, source.result_key, source.description]
          .filter(Boolean)
          .join(" | "),
      )
      .join("; ");
  },

  formatFunctionSource(source) {
    if (!source || typeof source !== "object") {
      return "未进行函数级分析";
    }
    const text = [source.tool, source.function_name, source.address, source.note]
      .filter(Boolean)
      .join(" | ");
    return text || "未进行函数级分析";
  },

  async safe(prefix, fn) {
    try {
      await fn();
    } catch (error) {
      window.SFP.setStatus(`${prefix}: ${error.message}`);
    }
  },
};

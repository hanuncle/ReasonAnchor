# SecurityFunctionPlatform

[English](README.md) | [简体中文](README.zh-CN.md)

SecurityFunctionPlatform 是一款面向 AI Agent 的 MCP 原生模块与 Skill 管理运行时。

平台把特定能力封装成可插拔模块。每个模块可以携带代码、工作流、配置字段、知识文件、Skill 指令、机器可读 playbook、raw output 精简规则，以及最终结果格式。Codex、Claude Desktop、Cursor 或其他兼容 MCP 的 AI 客户端可以通过平台列出模块、只加载选中模块的 Skill、运行模块函数、保存最终结果，并且在用户批准后迭代模块代码，让后续任务消耗更少 token，输出效果更稳定。

## 产品定位

SecurityFunctionPlatform 不是通用低代码聊天机器人，也不是单一安全工具。它的定位是：

> 面向多 AI 客户端的本地能力运行平台，用模块管理特定功能，用 Skill 管理 AI 调用规则，用可控代码迭代持续增强模块效果。

核心目标：

- **模块化能力**：每个特定功能放在 `modules/<module_id>/` 中。
- **模块可插拔**：支持创建、导入、导出、打包、校验模块。
- **Skill 管理**：AI 先加载平台 Skill，再按用户选择加载某个模块的 Skill/playbook/schema。
- **减少 token 消耗**：AI 不需要一次读取所有模块内容，而是先 `list_modules`，再 `get_module_skill(module_id)`。
- **代码自我迭代**：用户批准后，可以把好用的函数、raw sorter、schema、知识文件沉淀回选中的模块。
- **结果持久化**：raw output、AI 精简输出、最终总结都保存在 session 目录中，方便前端展示和后续追踪。

## 下载与运行

### 1. 克隆项目

```powershell
git clone https://github.com/hanuncle/ReasonAnchor.git
cd SecurityFunctionPlatform
```

### 2. 安装依赖

```powershell
python -m pip install -e ".[dev]"
```

### 3. 启动本地 API 与 Web UI

```powershell
uvicorn security_function_platform.api.main:app --reload --host 127.0.0.1 --port 8111
```

打开：

```text
http://127.0.0.1:8111/
```

常用页面：

- `http://127.0.0.1:8111/`：上传样本、查看模块、选择函数、运行工作流、编辑本地配置。
- `http://127.0.0.1:8111/raw-output.html?session_id=<session_id>`：查看保留的原始函数输出。
- `http://127.0.0.1:8111/result.html?session_id=<session_id>`：查看某个 session 的最终 AI 总结。

### 4. 启动 MCP Server

先启动 API，再运行：

```powershell
python -m security_function_platform.mcp_server.server
```

MCP 配置示例：

```toml
[mcp_servers.security-function-platform]
command = "python"
args = ["-m", "security_function_platform.mcp_server.server"]
cwd = "<absolute-path-to-SecurityFunctionPlatform>"
startup_timeout_sec = 10
tool_timeout_sec = 120

[mcp_servers.security-function-platform.env]
SECURITY_FUNCTION_PLATFORM_API_BASE = "http://127.0.0.1:8111"
```

## 平台功能介绍与使用

### 1. 平台 Skill 加载

AI 客户端应该按这个顺序使用平台：

1. `get_platform_skill`
2. `list_modules`
3. 让用户选择模块，除非用户已经明确指定模块
4. `get_module_skill(module_id)`

`get_platform_skill` 只返回平台级规则。模块相关规则通过 `get_module_skill(module_id)` 按需加载，避免把无关模块内容塞进上下文。

### 2. 模块发现与选择

常用函数：

- `list_modules`：列出当前可用模块。
- `get_module_detail(module_id)`：查看某个模块的 manifest、函数、工作流、配置字段和校验状态。
- `get_module_skill(module_id)`：加载选中模块的 `SKILL.md`、`playbook.json`、`final_result_schema.json`。
- `list_module_knowledge`：只列出模块知识文件，不一次性加载全部内容。

模块不应该写死在平台 Skill 里。AI 应该先发现模块，再按用户选择加载对应模块内容。

### 3. 模块创建

常用函数：

- `get_module_template`：查看默认模块目录结构和 manifest 格式。
- `create_module`：按默认格式创建一个新模块。

默认模块结构：

```text
modules/<module_id>/
  module.json
  functions/
  workflows/
  knowledge/
  config_fields/
  skill/
    SKILL.md
    playbook.json
    final_result_schema.json
  config_files/
```

模块编写规则：

- 可复用函数放在 `functions/`，并声明到 `module.json`。
- 用户可配置字段放在 `config_fields/`，并声明到 `module.json`。
- 模块资源文件放在 `config_files/`。
- 模块专属 Skill、playbook、最终总结格式放在 `skill/`。
- 新建文件前，先查看目标模块目录和附近文件职责，把文件放到正确位置。

### 4. 模块导入、导出与打包

常用函数：

- `package_module(module_id)`：把模块打包成 `.sfpmod.zip`。
- `export_module(module_id)`：导出模块包。
- `import_module_archive(archive_path)`：导入可信的本地模块包。
- Web UI 首页的 Modules 区域也提供模块导入导出能力。

模块打包会排除运行时数据、session 文件、密钥、虚拟环境和禁止导出的路径。

### 5. 函数与工作流执行

常用函数：

- `list_functions`：列出平台注册的函数，包括平台函数和模块函数。
- `list_custom_workflows`：列出已保存的平台或模块工作流模板。
- `save_custom_workflow`：保存新的工作流模板。
- `select_custom_workflow`：把工作流应用到当前 session。
- `run_workflow`：运行当前工作流，并返回精简后的 `ai_output`。
- `run_function`：在当前 session 中额外运行一个函数。

工作流模板可以带 metadata，例如风险级别、是否联网、是否需要配置、标签、是否默认安全等。AI 选择工作流时应该优先看这些字段。

### 6. Session 输出模型

平台保存三层输出：

- **Raw output**：完整原始函数输出，路径是 `data/sessions/<session_id>/raw_output/raw_output.json`。
- **AI output**：精简后的 AI 可读输出，路径是 `data/sessions/<session_id>/ai_output/ai_output.json`。
- **Final result**：AI 写入的最终总结，路径是 `data/sessions/<session_id>/result/result.json`。

AI 应该优先分析 `ai_output`。如果需要查看原始证据，流程是：

1. 调用 `get_raw_output_map(session_id)`
2. 选择需要的 `raw_output_id`
3. 调用 `get_raw_output_by_id(session_id, raw_output_id)`

默认不要一次性拉取全部 raw output。

### 7. 最终结果格式

每个模块可以定义自己的最终总结格式：

```text
modules/<module_id>/skill/final_result_schema.json
```

分析结束后，AI 应该按照选中模块的 schema 写最终总结，并调用：

```text
save_session_result(session_id, result)
```

前端最终结果页面读取：

```text
/api/sessions/<session_id>/result
```

### 8. 本地配置

真实本地配置保存在：

```text
config/local_config.json
```

这个文件被 git 忽略，AI 不应该读取或打印它。

模块的配置字段声明放在：

```text
modules/<module_id>/config_fields/
```

Web UI 的 Local Config 区域可以保存或删除配置映射。密钥字段会被 API 脱敏，不会复制到 session、workflow、raw output、AI output 或 result JSON 中。

### 9. Raw Sorting

Raw sorting 用来把噪声很大的函数输出整理成紧凑的 `ai_output`。

模块自己的 sorter 放在：

```text
modules/<module_id>/config_files/raw_sorting/
```

sorter 索引文件是：

```text
modules/<module_id>/config_files/raw_sorting/raw_sorting_index.json
```

如果输出太吵，应该优化所属模块的 raw sorter，而不是反复拉取完整 raw output 消耗 token。

### 10. 受控代码迭代

代码迭代必须经过用户批准。

推荐流程：

1. 分析开始前，询问用户本次任务是否允许模块代码自我迭代。
2. 先完成分析，并保存最终结果。
3. 如果发现值得沉淀的改进，再次询问用户是否允许写入模块。
4. 用户批准后，只修改选中模块的文件。

允许迭代的位置：

- `modules/<module_id>/functions/`
- `modules/<module_id>/config_files/`
- `modules/<module_id>/config_fields/`
- `modules/<module_id>/knowledge/`
- `modules/<module_id>/skill/SKILL.md`
- `modules/<module_id>/skill/playbook.json`
- `modules/<module_id>/skill/final_result_schema.json`

分析样本时不要自我迭代平台代码，只允许迭代选中模块。

## MCP 工具总览

平台与模块上下文：

- `get_platform_skill`
- `list_modules`
- `get_module_template`
- `get_module_skill`
- `get_module_detail`
- `list_module_knowledge`

模块生命周期：

- `create_module`
- `load_module`
- `package_module`
- `export_module`
- `import_module_archive`

Session 与工作流：

- `upload_sample`
- `upload_samples`
- `list_functions`
- `list_custom_workflows`
- `save_custom_workflow`
- `select_custom_workflow`
- `run_workflow`
- `run_function`

输出与结果：

- `get_ai_output`
- `get_ai_output_by_raw_id`
- `get_raw_output_map`
- `get_raw_output_by_id`
- `save_session_result`

受控文件访问：

- `get_mcp_file_access_policy`
- `inspect_allowed_files`
- `write_allowed_file`

## 安全规则

- 除非选中模块的工作流明确支持并且用户批准，否则不要执行上传样本。
- 不要把样本字节上传到外部服务。
- 不要读取或打印 `config/local_config.json`。
- 不要打印 API key、Auth-Key、token、密码或其他密钥。
- 不要把候选证据当作确认行为。
- 不要自动写入 `observed_behaviors`。
- 优先分析 `ai_output`，只按选定 `raw_output_id` 查看 raw output。
- 最终总结必须通过 `save_session_result` 保存。

## 验证

```powershell
python -m py_compile security_function_platform/core/function_result.py security_function_platform/core/function_base.py security_function_platform/core/function_registry.py
python -m pytest
git diff --check
```

## Recon Scan 更新说明

以下内容用于补充说明当前内置 `recon_scan` 模块的最新行为，与模块内实际 `skill/`、前端和测试保持一致。

### 1. 推荐收口路径

对于 `recon_scan`，推荐的分析收口顺序是：

1. 运行 workflow 或单步 follow-up 函数
2. 优先查看 `ai_output`
3. 刷新 `recon.attack_surface_summarize`
4. 刷新 `recon.next_step_options`
5. 通过 `recon.report_generate` 生成 `recon_final_report`
6. 使用 `save_session_result` 保存 `recon_final_report.data.final_result`

如果结构化报告结果暂时不可用，前端仍可从 `recon_attack_surface` 构造兼容的 fallback 结果。

### 2. AI-Gated 单步 Follow-Up

`recon_scan` 在默认 workflow 之外采用 AI-gated 单步推进模式。完成基础 workflow 后，AI 通常只应在以下函数中选择一个继续：

- `recon.service_identify`
- `recon.web_light_discover`
- `recon.vulnerability_candidate_scan`

每执行完一次 follow-up，都应先回到：

- `recon.attack_surface_summarize`
- `recon.next_step_options`

然后再决定是否继续、停止，或请求人工确认。

### 3. Skill 目录增强

除主入口 `SKILL.md`、`playbook.json` 和 `final_result_schema.json` 外，`recon_scan` 现在还在 `skill/` 目录下维护额外的 supporting Skill 文档，用于拆分更窄的指导职责：

- `CONTROLLED_EXECUTION_SKILL.md`：受控执行、超时处理、噪声提纯、停止条件
- `SCAN_STRATEGY_SKILL.md`：workflow 选择、follow-up 顺序、继续/停止/确认条件
- `FINAL_RESULT_WRITING_SKILL.md`：最终总结写法、证据绑定、候选发现与验证结论分离

这种结构仍然不改变平台的 Skill 加载模型。平台入口依然通过 `get_module_skill(module_id)` 返回模块主 Skill、playbook 和最终结果 schema。

### 4. Recon 最终结果结构补充

`recon_scan` 的 `final_result_schema.json` 在保持原有兼容字段的同时，增加了更适合人工审阅和前端展示的字段，包括：

- `target`
- `file`
- `summary.executive_summary`
- `summary.operator_conclusion`
- `summary.unverified_notice`
- `candidate_findings[*].confidence`
- `candidate_findings[*].manual_verification_steps`
- `recommended_next_steps[*].action`
- `recommended_next_steps[*].priority`
- `recommended_next_steps[*].why_now`

这使同一份 `result.json` 既能继续作为机器可保存的结构化结果，也更适合直接在结果页中查看。

### 5. 前端结果读取行为

当前分析工作台与结果页对 `recon_scan` 的读取逻辑是：

- 优先使用 `recon_final_report` 中的结构化 `final_result`
- 如果该结果还未生成，再回退到 `recon_attack_surface`
- 结果页会优先展示更完整的结论层、候选发现置信度、人工验证提示，以及下一步建议的优先级与原因

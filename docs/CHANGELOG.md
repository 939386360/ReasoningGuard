# Changelog

## 2026-06-24

- 明确 agent 响应协议：保留 `REASONING`、`INTENT`、`TOOL_CALL` 三段格式，为正常工具调用增加完整 JSON 示例，并规定拒绝或无需调用时输出 `TOOL_CALL: None`。
- 增强 agent response parser：支持标准/编号/Markdown 标题、同行内容、fenced JSON、全局 tool-call JSON、`arguments`/`parameters` 别名和自然语言拒绝识别，同时要求正式调用具备完整 `server/method/params`。
- 将 live evaluation 改为 `parsed_tool_call`、`explicit_no_tool_call`、`unparseable_output` 三态处理，删除 scenario fallback tool call；拒绝样本进入 ASR/TCR 分母但不运行 defense，invalid 样本不进入指标并设置 `metrics_valid=false`。
- records、audit 和汇总结果新增 agent outcome、parse error、tool-call source、defense invocation、invalid/refusal 计数等字段。
- 精简 `AGENTS.md` 项目概要：只保留项目定位、PTG/RTV 核心机制、三类实验路径区别、正式实验入口和关键工程限制。
- 新增 `docs/tech_notes/project_architecture_and_code_flow.md`：集中记录 benchmark 加载、agent 调用与解析、judge/RTV、PTG、ReasoningGuard、Guardrail、指标、audit、judge 微调和结果生成的文件与关键函数链路。
- 更新 `AGENTS.md` 技术文档索引，加入项目架构与代码链路文档。
- 扩充 `docs/tech_notes/agent_tool_call_outcome_handling.md`：收录 live 实验实际使用的 agent attack/benign、RTV LLM judge、judge 微调和 LlamaGuard 提示词，并标注各自源码与请求结构。
- 梳理提示词导致的实验风险：agent 缺少原始 benign 任务和工具参数 schema、自定义输出协议未定义 no-tool 状态、runtime judge 缺少真实 tool call/provenance、judge 训练与推理模板不一致，以及 MCPTox 原始 system prompt 未进入当前 live 链路。
- 补充提示词改进优先级：统一三态输出协议、采用原生 tool-calling 或 constrained JSON、结构化隔离不可信内容、补齐 judge 输入并禁止低风险静默 fallback。
- 为 RTV LLM judge 增加 `inherit/fallback/raise` 失败策略；允许在 strict runtime 下显式选择 `fallback`，记录失败后使用 `CAI/OAV/IAD=0.1` 继续实验。
- 为每次 judge 调用保存完整 prompt、原始响应、解析状态、分数、fallback 原因、异常和 latency，并通过 `RTVResult` 快照写入逐样本 `defenses` records 与 `judge.call_record` audit。
- 汇总指标新增 `num_judge_failures` 和 `judge_fallback_rate`；fallback 样本继续参与 ASR/TCR，但对应 defense 设置 `metrics_valid=false`。
- 明确历史 `results/quick_eval/table1_gpt4o_qwen_judge_records.json` 不含 RTV judge 结果；新 records 可从 `defenses.RTV-Only.rtv.judge_record` 和 ReasoningGuard 对应路径复核。
- 补齐 quick benchmark 的 proxy agent 响应适配：确认 Proxy 继承共享的新版 prompt/parser，并新增 Chat/Responses content parts、显式 refusal、原生 tool-call arguments 的归一化，避免合法代理响应被误记为空响应或 parser failure。
- 修复真实 agent prompt 格式化：转义 `AGENT_SYSTEM_PROMPT` JSON 示例中的大括号，避免 proxy/default 非 mock 路径在发送请求前因 `str.format()` 抛出 `KeyError: '"server"'`。

## 2026-06-23

- 新增 runtime audit log：quick/live/multimodel evaluation 支持 `--audit_log`、`--no_audit_log` 和 `--strict_runtime`，将 agent、judge、LlamaGuard 和逐 defense verdict 的关键运行事件写入 JSONL。
- 接入关键 fallback/错误记录：agent 调用失败或空响应、fallback tool call 构造、judge 调用失败、judge JSON 解析失败、低风险默认 judge 分数、LlamaGuard 加载失败和 mock fallback 都会写入 audit log。
- 凝练 `docs/tech_notes/defense_implementation_and_experiment_readiness.md`：保留当前真实程度结论、每种 defense 的简要实现说明、audit log 用法、推荐正式命令、运行后检查和剩余工程项。
- 明确 MCPTox 论文主表全量命令：默认 synthetic 200 attack scenarios，不传 `--official`，使用 `--per_category 55 --max_scenarios 200` 覆盖四类 `55/50/55/40` 分布。
- 新增 `docs/tech_notes/agent_tool_call_outcome_handling.md`：明确 `TOOL_CALL: None` 应作为 agent 拒绝工具调用记录，不能 fallback 成 scenario 默认 tool call，并说明其对 ASR/TCR 的处理。
- 更新正式实验 checklist：推荐 `--strict_runtime`，补充 audit log 检查、`Total selected attack scenarios` 样本数检查、`records_output` 只记录第 1 次 run 且不含逐 defense 判定细节的限制。
- 更正 `docs/tech_notes/model_calling_and_judge_deployment.md` 中 vLLM judge 请求说明：当前 `src/judge.py` 会归一化 `/v1` endpoint，但 payload 只发送 `temperature=0.0` 和 `max_tokens=100`，尚未发送 `do_sample=false` 或启用 constrained JSON decoding。

## 2026-06-21

- 将 live/quick/multimodel 评测入口的数据集默认口径改为 synthetic，并仅保留 `--official` 作为 adapted official 对比入口，避免默认读取 1348 条 MCPTox adapted official 数据。
- 新增 LlamaGuard 本地模型路径参数：quick/live evaluation 支持 `--llamaguard_model`、`--llamaguard_device` 和 `--llamaguard_fail_fast`，可直接传 transformers-compatible 本地目录并避免正式实验静默 fallback。
- 细化 `docs/tech_notes/defense_implementation_and_experiment_readiness.md` 中 LlamaGuard 说明：默认 Hugging Face cache 位置、魔塔模型目录使用方式、新增 CLI 参数和正式实验检查项。
- 新增 `docs/tech_notes/defense_implementation_and_experiment_readiness.md`，梳理六种 defense 的当前实现、mock/fallback 风险、真实实验 checklist 和后续工程补齐项。
- 更新 `AGENTS.md` 技术文档索引，加入防御方法实现与真实实验就绪性文档。
- 对齐 quick benchmark 与主表 live evaluation：`experiments/run_quick_benchmark_by_category.py` 现在只负责 benchmark/category 抽样，实际评估复用 `src/evaluation/live_table1.py` 的主表链路和参数。
- 将本地 LLM judge 默认服务更新为已验证的 `http://aias-compute-4:14545/v1/chat/completions`，默认模型名为 `qwen2.5-7B-Instruct`。
- 新增本地 Qwen judge 服务接入：`LLMJudgeInterface` 的 vLLM/OpenAI-compatible 请求支持 `.../v1` 自动补全到 `/v1/chat/completions`，并使用 `temperature=0.0` 发起 deterministic judge 请求。
- 将 live LLM judge 默认模型改为 `qwen2.5-7B-Instruct`，默认 endpoint 改为 `http://aias-compute-4:14545/v1/chat/completions`，用于复用已验证的本地服务。
- 接入 `/home/liuenguang24/deployed_models` 的 Qwen2.5-7B-Instruct 文本服务，项目侧默认使用已验证的 served model `qwen2.5-7B-Instruct`。
- 更新 `docs/tech_notes/model_calling_and_judge_deployment.md`，记录 vLLM 安装不可用时使用本地 Qwen handler 部署 RTV LLM judge 的方式。
- 新增 `experiments/run_quick_benchmark_by_category.py`，支持按 benchmark/category 每类抽少量样本快速评估，并在脚本末尾提供 PowerShell 使用示例。
- 新增 `tests/test_quick_benchmark_by_category.py`，覆盖每类抽样、MCPTox+ flatten 和 mock quick evaluation 输出。
- 调整中转站 agent base model 适配默认值：默认 endpoint 改为 `https://llm-api.net/v1/chat/completions`，默认 API style 改为 Chat Completions，以匹配当前中转站模型支持的请求格式。
- 新增中转站 agent base model 适配：`src/agent_backbone_proxy.py`、`experiments/run_live_table1_proxy.py`、`experiments/run_live_multimodel_proxy.py`，支持将 GPT-4o、Claude-3.5-Sonnet、Gemini-1.5-Pro、Llama-3.1-70B 统一通过 OpenAI-compatible 中转站调用。
- 更新 `docs/tech_notes/model_calling_and_judge_deployment.md`，补充 `https://llm-api.net/v1`、`/v1/chat/completions`、`/v1/responses` 三种中转站地址的用法和模型映射覆盖方式。
- 更新 `docs/tech_notes/model_calling_and_judge_deployment.md`，补充论文中 RTV judge 的设定：fine-tuned `Qwen2.5-7B-Instruct` constrained judge、`CAI/OAV/IAD` 三类异常分数，以及当前代码默认规则化实现与论文设定的差异。
- 新增 `docs/tech_notes/model_calling_and_judge_deployment.md`，整理 agent 基础模型调用、RTV judge 调用链路，以及 `/home/liuenguang24/deployed_models` 部署方式对 judge 调用的兼容性结论。
- 更新 `AGENTS.md` 技术文档索引，加入模型调用与 judge 部署分析文档。
- 新增 `src/benchmarks/adapt_mcptox_benchmark.py`，可将 `third/MCPTox-Benchmark-main/response_all.json` 转换为当前加载器可读取的 `data/mcptox/mcptox_official.json`。
- 更新 `docs/tech_notes/dataset_format.md`，补充本地 MCPTox-Benchmark 原始数据结构、不能直接加载的原因、适配命令和验证方式。
- 补充最终评估数据集三部分构成：MCPTox、AgentPI context-dependent tasks、MCPTox+；明确 MCPTox 应使用官方/适配数据，AgentPI 当前未找到官方下载链接，synthetic 数据只能作为替代流程数据。

## 2026-06-20

- 新增 `docs/tech_notes/dataset_format.md`，整理项目涉及的数据集构成、格式、加载路径和下载后的本地目录要求。

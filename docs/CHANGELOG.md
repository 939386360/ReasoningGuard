# Changelog

## 2026-06-29

- 在实验运行手册中补充 MCPTox-derived curated 200 条正式 Linux 命令：显式使用 `--official --official_variant curated`、四类过滤、`per_category=55`、真实 agent/judge/LlamaGuard、strict runtime 和独立结果目录，并说明三轮聚合、第一轮 records 与全轮 audit 的产物语义。
- 重组技术文档为五份当前权威文档：项目架构与数据链路、核心防御方法、核心评估方法、实验运行手册和数据集构建 SOP；删除旧顶层文档，历史长文和整合决策统一移入 `docs/tech_notes/archive/`。
- 防御文档明确记录 PTG cross-server 检查恒通过、intent 关键词启发式、普通 REQUEST origin 检查范围和 T3 memory provenance 未进入 live 主链路等实现边界；评估文档集中定义 agent outcome、expected-call matcher、指标分母、CI 和 `metrics_valid`。

- 完成 MCPTox-derived 200 条数据的 Codex 逐条语义审查并生成 `mcptox_official_derived_table1_200_curated.json`：74 条直接接受、126 条审计后编辑、60 次候选替换；删除 111 条无效 benign reference 和 22 条无效 malicious reference。
- 最终 curated 分布保持 TDP/RM/PI/CE = 55/55/50/40，`validate-curated` 通过；逐例 rationale、编辑前后 payload、删除引用及 27 个批次审计记录保存在 `data/mcptox/curation/`。
- 新增 `mcptox_dataset_construction_sop.md`，统一记录确定性转换、静态门禁、LLM-assisted 语义审查、GPT/Codex 提示模板、复现元数据和论文中文描述；明确该流程不是人工标注或 MCPTox 官方四类协议。

## 2026-06-27

- 新增 MCPTox-derived Codex 逐条审查工作流：每批四类各 2 条，必须填写六项语义检查、accept/edit/replace 决定和理由；状态绑定父文件 SHA-256，可断点恢复并保留批次与替换历史。
- 新增确定性备用候选池；核心语义错误优先用同类别、未使用且无 query 冲突的候选替换，替换项重新进入 pending，文本编辑仅允许修改 payload。
- 新增 `derived_table1_curated` 文件格式和 curation validator；200 条未全部终审时禁止 finalize，最终文件记录父数据 hash、reviewer type 和逐场景审查 provenance。
- `load_mcptox`、quick 和 live 新增 `official_variant=derived|curated|legacy`；curated 必须显式选择，缺失或校验失败时不回退。
- 新增 `docs/tech_notes/mcptox_manual_curation_workflow.md`，记录逐条判据、命令、issue code、修复边界和正式实验加载方式。
- 将默认 `mcptox_official_derived_table1_200.json` 升级为 `schema_revision=2`：从原始 clean prompt 构建场景级工具目录，保留原始 tool name、params 和 JSON 类型，移除五工具启发式投影。
- 四类攻击增加严格候选条件和每类 query 去重；保存多个 benign/malicious reference，并移除模型可见的攻击标签、可信注册表状态和预期调用桥接文本。
- 新增 MCPTox-derived validator，生成时强制校验数量分布、类别不变量、catalog 可达性、CE attestation 差异、RM 首调用结构和模型可见标签泄漏；loader 拒绝旧 revision。
- live/quick 改为逐场景加载 agent catalog 并替换 PTG registry；CE 仅在 attack catalog 增加 extension capability，RM 仅在首次调用匹配时注入带 server origin 的 response envelope。
- ASR/TCR 支持多参考调用和 schema 可选参数；删除缺失 intent 时使用 `target_action` 的 ground-truth fallback，并在 records 中增加 response injection 状态。
- 重新生成并审计 200 条数据：分布 55/50/55/40、每类重复 query 为 0、模型可见元标签命中为 0；新增 v2、CE/PTG、RM 门控和多参考匹配测试。

## 2026-06-26

- 新增 MCPTox-derived Table 1 数据集适配：`src/benchmarks/adapt_mcptox_benchmark.py --variant derived_table1` 从 `third/MCPTox-Benchmark-main/response_all.json` 过滤 `wrong_data == 0`，解析官方 `Success` / `Failure-Ignored` tool calls，并生成 `data/mcptox/mcptox_official_derived_table1_200.json`，分布为 55/50/55/40。
- `load_mcptox(use_official=True)` 现在优先加载 `mcptox_official_derived_table1_200.json`，缺失时再回退到 legacy `mcptox_official.json`；新增测试覆盖四类派生字段和 loader 优先级。
- 新增 `docs/tech_notes/mcptox_derived_table1_dataset.md`，明确 `response_manipulation` 与 `capability_escalation` 是 MCPTox-derived 而非官方原生分类，并记录生成命令、字段语义、限制和验证方式。
- 整合 `collab_code3` 的可用改动但不整文件覆盖：恢复 `src.agent_backbone` 的 detailed parser、三态 agent outcome、strict runtime 和 audit 语义，同时保留多轮 tool response 注入与 catalog schema 渲染。
- 为 `MCPCapability` 增加可选 `input_schema`，补齐 clean MCP server 参数 schema，并将 synthetic attack template 升级为包含 `user_query`、`benign_call`、`malicious_call`、`poisoned_tool`、`first_call` 和 `malicious_response` 的可判定结构。
- 改造 live Table 1 主链路：attack/benign 使用同一 user query；L4 攻击通过 compromised catalog 交付；L2 攻击通过多轮 malicious tool response 交付；ASR/TCR 改为匹配实际 `MCPMessage` 的 expected call。
- 新增 `docs/tech_notes/collab_code3_integration_decision.md`，记录 `collab_code3` 采纳项、拒绝项、当前数据流和剩余限制；新增测试覆盖 schema、poisoned catalog、query 相同性和 exact harmful matcher。

## 2026-06-25

- 凝练重写 `collab_code/live_table1_code_audit.md` 第 27 节之后的改进方案：将重复的字段解释、攻击示例、构建伪代码、校验和验收标准合并为最小数据结构、三类 L4 攻击构造、统一编译评估流程及关键点总结。
- 细化 `collab_code/live_table1_code_audit.md` 对 synthetic scenario 完整性的判断：区分已有但语义不足、运行时可生成但未显式保存、当前确实缺失三类信息，避免将 `legitimate_*`、投毒描述和 `target_action` 错误概括为全部缺失。
- 记录 seed=42 下 target server 与 template method 的结构性错配：Tool Description 33/55、Parameter Injection 31/50、Response Manipulation 27/55，并说明 `server_type`、`severity` 随机元数据不参与攻击构造。
- 扩充 `collab_code/live_table1_code_audit.md`：依据 MCPTox 和 MCP Tool 规范，在不新增 Scenario 模型的前提下，给出基于现有 `ATTACK_TEMPLATES`、`MCPCapability`、`MCPServer` 和 `MCPMessage` 的最小攻击构建方案。
- 推荐仅为 `MCPCapability` 增加可选 `input_schema`，在现有 template 中加入 `user_query`、`benign_call`、`malicious_call`、`poisoned_tool`；Tool Description/Parameter Injection 通过独立 poisoned server 描述承载，Capability Escalation 继续使用 advertised/trusted catalog 差异。
- 补充三个现有 category 的完整 template、catalog 和 `MCPMessage` 示例，并建议使用 expected call 匹配替代 reasoning 危险关键词计算 ASR/TCR。
- 收缩重写 `collab_code/live_table1_code_audit.md`：只审计 synthetic MCPTox 200 条在候选 `live_table1.py` 中的实验语义，删除导包、部署和 official/adapted 数据讨论，集中分析四类攻击交付、`MCPMessage`/provenance、多轮 outcome、harmful、ASR/TCR 和 records。
- 明确 synthetic 口径下 145 条 L4 中有 83 条 attack 与 benign 完全相同，50 条 parameter injection 未发生；55 条 response manipulation 还受到第一轮任务、user-role 注入和最终调用状态错误影响。
- 重构 `docs/tech_notes/dataset_format.md`：以 `src/evaluation/eval_runner.py` 为起点，区分攻击模板、raw scenario、normalized scenario、agent prompt 和 defense 输入五层对象，并完整说明两条评估链路的数据流。
- 补充六类 `eval_runner` 合成攻击的 template、scenario、attack/benign `MCPMessage` 和 reasoning trace 示例，明确 server/method 不匹配、字符串 params、空攻击参数、伪 response manipulation 和伪 T3 等问题；同时记录不同 defense 会重新生成 scenario/attack 标签，且 ASR 实际只是恶意标签请求的 approval rate。
- 对比 MCPTox、AgentPI、MCPTox+ 三套 synthetic raw schema，记录 AgentPI/MCPTox+ 进入 `normalize_scenario()` 后丢失核心攻击字段的问题，并给出建议的 canonical scenario 格式。
- 完全重写 `collab_code/attack_prompt_evaluation_analysis.md`：仅分析 seed=42 的 200 条 synthetic MCPTox、`build_compromised_servers()` 和候选 agent/evaluation 链路，逐一列出 8 个攻击模板的完整第一轮 prompt、response manipulation 注入后的第二轮 prompt，以及 attack/benign 的实际差异。
- 明确 synthetic 攻击交付结果：145 条 L4 中只有 62 条产生可见 catalog 变化，83 条 attack 与 benign prompt 完全相同；55 条 response manipulation 仅在第一轮产生 tool call 后进入第二轮，并被包装为 `role=user`。
- 补充候选代码的 no-tool 结论：单轮显式拒绝的 ASR/TCR 公式基本正确，但 parser 会混淆拒绝、解析失败和运行失败，多轮第二轮拒绝还会错误保留第一轮 tool call。

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
- 扩充 agent outcome 技术文档：加入填充静态 capability 后的完整 system prompt，以及 tool description poisoning、parameter injection 的实际 attack/benign user message 示例。
- 记录 `results/0624_run2_5case` 诊断：60 个攻击样本中 58 个在 defense 前输出 no-tool，低 ASR 主要来自 prompt 安全暗示、`Untrusted` 标签和缺失真实 benign task，而非六种 defense 的拦截效果。
- 识别 harmful 标注假阳性：安全的 `files/read` 调用因 reasoning 复述 `execute system commands` 被关键词规则计为攻击成功；后续应按实际 method、params 和副作用判定 harmful。
- 根据 MCPTox 论文和本地官方仓库补充正确 attack query 语义：user message 应始终是 benign query `Q`，攻击载荷 `T_p` 应注入注册阶段的 system/tool metadata，attack 与 benign control 只允许 tool catalog 不同。
- 梳理 MCPTox P1/P2/P3 三种攻击范式、官方四类 outcome 和多工具调用成功条件，并给出适配 ReasoningGuard 三段输出协议的中性 system prompt、attack user message 与 benign control 模板。
- 记录本地 MCPTox 数据链路差异：1348 条 raw 中仅 1312 条有效，当前 adapter 未过滤 36 条错误数据，并丢失真实工具 schema、attack paradigm、expected malicious calls 和多步调用语义。
- 重写 MCPTox prompt 示例：按 P1、P2、P3 分别并排展示 clean system、增加 poisoned tool 后的 attack system、完全相同的 benign user query，以及正常调用、攻击成功、ignored、direct execution 和 refused 的判定方式。
- 依据论文 Threat Model、Figure 2 和 Algorithm 1 补充完整攻击—防御流程：从恶意 MCP 输入进入 catalog/response/registry/context/memory，到 agent 形成 reasoning、intent 和 request，再经过 PTG、RTV、执行与 provenance 记录。
- 为六类攻击补充逐阶段具体示例，并明确 T1 tool poisoning、T2 context-dependent 和 T3 memory poisoning 所需的运行时状态与多轮/跨会话行为。
- 明确 query 调整的边界：删除 `Untrusted/unsafe/refuse` 只能降低提示偏置；只要恶意载荷仍在 user message，攻击本质仍是直接 prompt injection，只有把载荷移入各类别对应的 MCP context 才与论文语义一致。

- 修正本地 Qwen2.5-7B-Instruct handler 的生成参数语义：接收 judge 请求中的 `temperature`，在 `temperature=0` 时自动使用 greedy decoding，在正温度且允许采样时传递实际温度。
- Qwen handler 在 greedy 模式显式覆盖模型内置的 `temperature/top_p/top_k` 采样默认值，避免 Transformers 的无效采样参数警告，并拒绝负数、NaN 和 Infinity 温度。
- 更新 judge 部署文档，说明 `temperature` 与 `do_sample` 的关系以及 Qwen2.5-7B-Instruct 对 greedy decoding 和 sampling 的支持；项目 judge 调用代码保持不变。

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

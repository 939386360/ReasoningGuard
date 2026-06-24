# AGENTS.md

## 1. 项目概要

本项目是论文 **ReasoningGuard: Dual-Layer Defense for MCP-Based LLM Agents via Protocol Attestation and Reasoning Trace Verification** 的实验代码，用于评估 MCP Agent 面对工具污染、参数注入、响应操纵、能力提升、上下文劫持和跨会话记忆污染时的安全性。

核心防御由两层组成：

- **PTG（Protocol-Attested Tool Gateway）**：验证 server/method capability、intent、origin tag 和 intent signature，主要防御工具调用层攻击。
- **RTV（Reasoning Trace Verifier）**：通过 heuristic 或 LLM judge 检查 `CAI`、`OAV`、`IAD` 三类 reasoning anomaly。
- **ReasoningGuard**：先运行 PTG；PTG 失败返回 `BLOCK`，通过后再运行 RTV；RTV 异常返回 `ESCALATE`。

实验比较 `No Defense`、`AttestMCP`、`Guardrail`、`PTG-Only`、`RTV-Only` 和 `ReasoningGuard`，主要指标为 ASR、TCR、Latency、L4_ASR 和 L2_ASR。数据来源包括 MCPTox、AgentPI 和 MCPTox+，部分数据当前使用 synthetic 或 adapted official 版本。

仓库中三类评估路径不能混淆：

|路径|说明|
|---|---|
|`experiments/run_all.py`|返回硬编码 mock 论文结果，不调用真实 agent。|
|`src/evaluation/eval_runner.py` 的 non-mock 路径|直接构造 `MCPMessage` 和 `ReasoningTrace` 的合成模拟，不调用真实 agent。|
|`run_quick_benchmark_by_category.py` / `run_live_table1*.py` → `src/evaluation/live_table1.py`|当前真实 agent/defense 实验主链路。|

正式实验应使用 quick/live 主链路，不启用 agent 或 LlamaGuard mock；需要真实 judge 时显式使用 `--judge_mode llm`，并启用 `--strict_runtime` 和 audit log。

当前项目仍是研究原型：MCP capability 来自静态配置，agent 使用自定义文本 tool-call 协议，base Qwen judge 不等于论文 fine-tuned verifier，T3 memory provenance 和真实 MCP schema 尚未完整接入。详细目录职责、函数调用链和数据流见 `docs/tech_notes/project_architecture_and_code_flow.md`。

## 2. 项目文档设置

1. 技术文档目录：`docs/tech_notes/`
2. 项目更新日志：`docs/CHANGELOG.md`
3. `docs/references/`：原始参考资料：PDF、外部代码仓库等

以上资料都要在真正有需求时才去查看。  
应优先查看本项目已经整理过的相关文档，最后才是原始参考资料。

### 技术文档索引

每次和用户对话讨论复杂的技术点后（比如很复杂的数据格式及数据处理），应该询问用户是否要沉淀一份单独的技术文档到`docs/tech_notes/` 中。  
`AGENTS.md` 只记录目前有哪些技术文档，以及什么时候需要查看。

|技术文档|内容|什么时候查看|
|---|---|---|
|`docs/tech_notes/project_architecture_and_code_flow.md`|项目组件、实验入口、关键文件与函数调用链、数据和输出流|理解整体架构、选择实验入口、排查跨模块调用或新增链路时|
|`docs/tech_notes/dataset_format.md`|数据集格式说明|处理数据读取、样本结构、标注格式时|
|`docs/tech_notes/model_calling_and_judge_deployment.md`|agent 基础模型、RTV judge 调用链路与本地部署兼容性分析|排查真实模型调用、接入 vLLM/OpenAI-compatible endpoint、部署 judge 模型时|
|`docs/tech_notes/defense_implementation_and_experiment_readiness.md`|防御方法实现、mock 风险与真实实验就绪性梳理|梳理 No Defense、AttestMCP、Guardrail、PTG、RTV、ReasoningGuard 是否真实运行及正式实验前检查项时|
|`docs/tech_notes/agent_tool_call_outcome_handling.md`|agent 工具调用结果语义：`TOOL_CALL: None`、解析失败、fallback tool call、提示词与 ASR/TCR 处理|排查 agent response parsing、工具调用拒绝、提示词或 fallback 污染正式实验结果时|

## 3. 相关资料位置

|路径|内容|
|---|---|
|`docs/tech_notes/`|技术文档：如复杂数据格式、训练流程等|
|`docs/CHANGELOG.md`|项目更新日志，每次有重要更新时应该更新该文档|
|`docs/references/`|原始参考资料，如 PDF、MD、外部代码仓库等|

## 4. 经验沉淀

每次踩坑或发现可复用经验时，Agent 应建议写入 `AGENTS.md`。

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

当前项目仍是研究原型：MCP capability 来自静态配置，agent 使用自定义文本 tool-call 协议，base Qwen judge 不等于论文 fine-tuned verifier，T3 memory provenance 和真实 MCP schema 尚未完整接入。详细目录职责、函数调用链和数据流见 `docs/tech_notes/project_architecture_and_data_flow.md`。

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
|`docs/tech_notes/project_architecture_and_data_flow.md`|项目目标、攻击位置、三类评估路径、代码组件、核心数据对象及完整生命周期|第一次理解项目，或定位数据从 benchmark 到 results/audit 的流向时|
|`docs/tech_notes/defense_method.md`|PTG、RTV、ReasoningGuard、六种 defense 的真实判定逻辑、结果对象和论文/代码边界|解释 `BLOCK/ESCALATE/APPROVE`、设计消融或核对防御实现时|
|`docs/tech_notes/evaluation_method.md`|抽样、攻击投递、agent outcome、expected-call matcher、ASR/TCR/Latency、CI 和有效性规则|解释实验设计、指标分母、records 或论文 Evaluation 口径时|
|`docs/tech_notes/experiment_runbook.md`|实验入口、模型与 judge 配置、smoke/formal 命令、CLI 参数、输出检查和故障排查|实际启动 quick/live 实验、部署 endpoint 或检查正式结果时|
|`docs/tech_notes/dataset_construction_sop.md`|MCPTox-derived 的确定性转换、结构校验、逐条语义审查、curated 发布门禁与论文表述|构建、继续审查或复现正式数据集时|
|`docs/tech_notes/table1_effect_ptg_rtv_fix_20260703.md`|effect-based ASR、PTG 三阶段语义检查、RTVContext、校准和正式运行门禁|修改或复核当前 quick/live Table 1 成功判定与防御输入时|
|`docs/tech_notes/table1_0629_run1_5case_analysis.md`|0629 三轮主表结果的 ASR/TCR 分层诊断、原始 MCPTox 对比边界、PTG/RTV 失效原因和修复优先级|解释该次结果、设计后续消融或重跑正式主表时|

`docs/tech_notes/archive/` 保存重组前历史长文和设计决策，不属于当前默认阅读路径。

## 3. 相关资料位置

|路径|内容|
|---|---|
|`docs/tech_notes/`|技术文档：如复杂数据格式、训练流程等|
|`docs/CHANGELOG.md`|项目更新日志，每次有重要更新时应该更新该文档|
|`docs/references/`|原始参考资料，如 PDF、MD、外部代码仓库等|

## 4. 经验沉淀

每次踩坑或发现可复用经验时，Agent 应建议写入 `AGENTS.md`。

- 整合 `collab_code*` 候选代码时不要整文件覆盖；先做 import smoke，核对当前主链路依赖的 parser/outcome/audit 字段，再按功能 cherry-pick。
- 仓库当前跟踪部分 `__pycache__/*.pyc`；只读检查和测试使用 `python -B`，不要运行会重写已跟踪字节码的 `py_compile/compileall`。
- 仓库当前跟踪了部分 `__pycache__/*.pyc`；只读统计脚本应使用 `python -B`，避免导入模块时产生无关字节码改动。

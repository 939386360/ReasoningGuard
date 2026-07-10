# 项目架构与数据链路

|项目|说明|
|---|---|
|职责|建立项目全局认知，说明组件、入口、核心数据对象及其生命周期|
|适合何时阅读|第一次接触项目，或需要定位一条数据在代码中的流向时|
|继续阅读|防御判定见 [defense_method.md](defense_method.md)；实验口径见 [evaluation_method.md](evaluation_method.md)；运行命令见 [experiment_runbook.md](experiment_runbook.md)|
|代码真源|`src/mcp_client.py`、`src/agent_backbone.py`、`src/evaluation/live_table1.py`|
|最近核验|2026-06-29|

## 1. 项目要解决什么问题

ReasoningGuard 研究使用 MCP 工具的 LLM agent 在不可信工具描述、参数、工具响应和记忆影响下，是否会调用攻击者期望的工具，以及如何在调用执行前阻止或升级可疑行为。

系统包含两层防御：

- **PTG（Protocol-Attested Tool Gateway）**：在工具调用层验证 server、method、intent 和 origin 信息。
- **RTV（Reasoning Trace Verifier）**：检查推理轨迹中的 `CAI`、`OAV`、`IAD` 异常。
- **ReasoningGuard**：先运行 PTG；PTG 通过后才运行 RTV。

项目比较 `No Defense`、`AttestMCP`、`Guardrail`、`PTG-Only`、`RTV-Only` 和 `ReasoningGuard`。详细算法和当前实现边界见 [defense_method.md](defense_method.md)。

## 2. 攻击发生在哪里

|攻击类别|主要载体|层级|当前主要数据来源|
|---|---|---|---|
|`tool_description_poisoning`|MCP catalog 中的恶意工具描述|L4|MCPTox-derived|
|`parameter_injection`|工具描述诱导同一 method 使用恶意参数|L4|MCPTox-derived|
|`response_manipulation`|第一次工具调用返回的恶意 server response|L2|MCPTox-derived|
|`capability_escalation`|catalog 中伪造或扩展的 capability|L4|MCPTox-derived|
|`context_dependent_hijacking`|依赖会话上下文的指令劫持|按场景定义|AgentPI、MCPTox+|
|`cross_session_memory_poisoning`|跨会话记忆及其 provenance|T3|MCPTox+|

前四类构成当前 MCPTox-derived 主表数据。后两类已有数据和模拟结构，但真实持久化 memory provenance 尚未完整接入 quick/live 主链路。

## 3. 三条评估路径

仓库中有三条名称相近但语义不同的路径，结果不能混用。

|路径|入口|是否调用真实 agent|用途|
|---|---|---:|---|
|硬编码 mock|`experiments/run_all.py`|否|生成预置论文表格和图，不是实测结果|
|合成 simulation|`src/evaluation/eval_runner.py` 的 `mock_mode=False`|否|直接构造 `MCPMessage` 和 `ReasoningTrace`，测试防御组件|
|quick/live|`run_quick_benchmark_by_category.py`、`run_live_table1*.py`|是，除非显式 `--agent_mock`|当前正式 agent/defense 实验主链路|

正式实验的核心执行函数是 [src/evaluation/live_table1.py](../../src/evaluation/live_table1.py) 中的 `run_live_table1_scenarios_once()`。`config.yaml` 描述研究配置，但 quick/live CLI 不会统一读取该文件；实际运行值以 CLI 默认值和显式参数为准。

## 4. 主链路组件

```text
benchmark JSON
  -> benchmark loader
  -> scenario normalization
  -> clean MCP catalog + attack carrier
  -> agent prompt/model call
  -> AgentParseResult
  -> MCPMessage + ReasoningTrace
  -> six defenses
  -> per-defense rows + detailed record + audit events
  -> metrics JSON + LaTeX table
```

|阶段|主要代码|职责|
|---|---|---|
|数据加载|`src/benchmarks/load_*.py`|读取 MCPTox、AgentPI、MCPTox+|
|抽样|`experiments/run_quick_benchmark_by_category.py`|按 benchmark/category 分组并按 seed 抽样|
|归一化|`normalize_scenario()`|把不同来源映射为运行时 scenario|
|攻击投递|`_invoke_attack_scenario()`|修改 catalog 或注入 tool response|
|Agent|`agent_backbone*.py`|构造模型请求并解析文本 tool call|
|防御|`ptg.py`、`rtv.py`、`reasoning_guard.py`|产生 `APPROVE/BLOCK/ESCALATE`|
|评估|`_evaluate_all_defenses()`|匹配期望调用并生成逐 defense row|
|汇总|`compute_live_metrics()`|计算 ASR、TCR、Latency 等指标|
|审计|`runtime_audit.py`|写入模型、judge、防御和 fallback 事件|

## 5. 数据模型

### 5.1 原始 benchmark scenario

不同 benchmark 可以有额外字段，但 quick/live 期望以下公共语义：

```json
{
  "scenario_id": "...",
  "category": "tool_description_poisoning",
  "attack_layer": "L4",
  "target_server": "slack",
  "method": "slack_post_message",
  "poisoned_content": "...",
  "legitimate_content": "...",
  "template": {
    "user_query": "...",
    "clean_servers": [],
    "benign_calls": [],
    "malicious_calls": []
  }
}
```

`template.clean_servers` 是每个场景的可信 catalog；`benign_calls` 和 `malicious_calls` 是评估标签，不应直接暴露给 agent。数据生产和审查规则见 [dataset_construction_sop.md](dataset_construction_sop.md)。

### 5.2 Normalized scenario

`normalize_scenario()` 产生统一运行时对象：

|字段|含义|
|---|---|
|`scenario_id`|稳定样本标识|
|`category`|攻击类别|
|`attack_layer`|通常为 L4 或 L2|
|`target_server`、`method`|攻击相关 server/method|
|`target_action`|恶意目标的可读描述|
|`malicious_content`|投递给 catalog、response 或 legacy prompt 的恶意内容|
|`legitimate_content`|benign 对照任务内容|
|`user_query`|原始用户请求，可能为空|
|`raw`|完整原始 scenario，供后续读取 template 和标签|

如果原始字段缺失，归一化函数会按 `template` 字段和类别默认值回退。因此“能够归一化”不等于“科研语义正确”，正式数据仍必须先通过 SOP 校验。

### 5.3 MCP 与 reasoning 对象

|对象|关键字段|用途|
|---|---|---|
|`MCPCapability`|`name/description/methods/permissions/input_schema`|描述可信工具能力|
|`MCPServer`|`server_id/name/capabilities/is_compromised`|构造 clean 或 compromised catalog|
|`MCPMessage`|`sender/recipient/method/params/origin/provenance_tags/intent_summary`|PTG 和 Guardrail 的直接输入|
|`ReasoningStep`|`observation/inference/decision/evidence_citations/origin_awareness`|RTV 检查的最小推理单元|
|`ReasoningTrace`|`steps/session_id/timestamp`|RTV 的主要输入|
|`MemoryEntry`|`origin/session_id/intent_hash/is_flagged/dependencies`|T3 provenance 图节点，目前未完整进入 live 数据流|

### 5.4 Agent parse result

Agent 使用项目自定义文本协议返回 `REASONING`、`INTENT` 和 `TOOL_CALL`。解析后得到：

|字段|含义|
|---|---|
|`trace`|解析出的 `ReasoningTrace`|
|`intent_summary`|模型声明的用户意图|
|`tool_call`|合法时包含 `server/method/params`|
|`agent_outcome`|`parsed_tool_call`、`explicit_no_tool_call` 或 `unparseable_output`|
|`tool_call_source`|tool call 的解析来源|
|`parse_error`|失败原因|

系统不会再用 scenario 默认值伪造 fallback tool call。只有 `parsed_tool_call` 会进入六种 defense；另外两种状态的评估处理见 [evaluation_method.md](evaluation_method.md)。

## 6. 一个 case 如何流转

以下使用“用户要求回复 Slack thread，但 poisoned description 诱导先发布另一条消息”的语义作为代表：

|阶段|数据变化|
|---|---|
|源数据|保存 benign `slack_reply_to_thread` 和 malicious `slack_post_message` 标签|
|归一化|提取 category、server、method、恶意描述和原始 template|
|catalog 构造|由 `clean_servers` 建立可信 catalog，再为 attack agent 构造 poisoned catalog|
|模型输入|用户 query 保持 benign；攻击内容通过 tool description 到达 agent|
|模型输出|parser 将文本转换为 intent、trace 和可选 `MCPMessage`|
|标签匹配|若 message 的 server/method/params 匹配 `malicious_calls`，`harmful=True`|
|防御|同一 message 分别送入六种 defense，得到独立 verdict|
|逐条记录|保存原始响应、解析状态、标签匹配和各 defense 详情|
|汇总|每个 defense 独立计算 ASR/TCR/Latency|

关键点是：攻击样本的用户 query 应保持正常任务语义。攻击载体与用户任务混在同一字符串中只属于缺少结构化 template 时的 `legacy_prompt` 回退，不是优先实验形态。

## 7. 输出层级

|输出|粒度|回答的问题|
|---|---|---|
|detailed records JSON|每个 scenario 的 attack/benign agent 调用|模型实际输出了什么、匹配了什么、各防御为何判定|
|results JSON|每个 defense 的聚合指标|论文表格所需的 ASR/TCR/Latency 等|
|audit JSONL|每次运行中的事件|是否发生模型失败、解析失败、judge fallback 或 LlamaGuard fallback|
|LaTeX|聚合指标|主表展示|

字段和指标的权威定义见 [evaluation_method.md](evaluation_method.md)。

## 8. 当前工程边界

- MCP capability 来自 dataset/static configuration，不是实时 MCP server schema discovery。
- Agent 使用自定义文本 tool-call 协议，不是 provider 原生 function calling。
- PTG 的若干论文机制目前是启发式或占位实现，详见 [defense_method.md](defense_method.md)。
- `judge_mode=heuristic` 不是论文中的 fine-tuned Qwen verifier；`judge_mode=llm` 也只有在加载对应训练产物时才可这样表述。
- T3 的 `MemoryProvenanceGraph` 已存在，但 quick/live 不会自动建立跨会话持久 provenance。
- `run_all.py`、旧图表脚本的预置结果不能作为真实运行证据。


# 项目架构与代码链路

更新日期：2026-06-24

本文档梳理 ReasoningGuard 项目的组件职责、实验入口、关键函数调用链、数据流、模型调用、防御判定、指标与输出。处理整体架构、跨模块调用、实验入口选择或新增评估链路时，应先查看本文档。

## 1. 项目定位

本项目是 ReasoningGuard 论文的实验原型，不是完整的生产级 MCP runtime。它由以下部分组成：

- 静态 MCP server/capability 和 provenance 数据结构；
- 可调用 OpenAI、Anthropic、vLLM 或 OpenAI-compatible relay 的 agent backbone；
- PTG 与 RTV 双层防御；
- No Defense、AttestMCP、Guardrail、PTG-Only、RTV-Only 等 baseline；
- MCPTox、AgentPI、MCPTox+ loader 或 synthetic generator；
- live evaluation、旧版 simulation、硬编码 mock 结果；
- RTV judge 调用、训练数据生成、LoRA 微调与阈值校准；
- runtime audit、结果汇总、LaTeX 表格和图片生成。

`README.md` 主要反映早期结构，未完整覆盖 proxy agent、quick/live 主链路、runtime audit 和本地 LLM judge。当前行为应以源码和 `docs/tech_notes/` 为准。

## 2. 核心对象与防御机制

### 2.1 MCP 与 reasoning 数据对象

基础对象定义在 `src/mcp_client.py`：

|对象|作用|
|---|---|
|`MCPCapability`|capability 名称、说明、允许的方法和权限。|
|`MCPServer`|server ID、名称、capability 列表和 compromised 标记。|
|`MCPMessage`|MCP request/response/sampling message，包含 method、params、intent 和 provenance。|
|`MCPClient`|注册 server、创建 invocation/sampling message 并记录消息。|
|`ReasoningStep`|一条 observation → inference → decision 推理步骤。|
|`ReasoningTrace`|多条 reasoning step 及 session/timestamp。|
|`ProvenanceLedger`|保存 request、intent signature、trace 和时间。|
|`MemoryEntry`|跨会话记忆的来源、依赖和风险标记。|

### 2.2 PTG

`src/ptg.py::ProtocolAttestedToolGateway.verify_invocation()` 的调用顺序：

```text
verify_invocation()
  → _verify_attestation()
  → _verify_intent_entailment()
  → _verify_cross_server()
  → _verify_origin_tags()
  → _compute_intent_signature()
  → ProvenanceLedger.record()
```

主要行为：

- 检查 message recipient 是否注册，以及 method 是否属于该 server capability。
- 用 intent 与 capability description 的关键词重叠做启发式 entailment。
- 检查 cross-server consent；当前 `_verify_cross_server()` 基本恒定通过。
- 对 sampling message 检查 server origin tag；普通 request 当前基本通过。
- 用 HMAC-SHA256 对 intent、server、method、params 和 timestamp 计算 signature。
- PTG 通过且传入 trace 时，将结果写入 provenance ledger。

### 2.3 RTV

`src/rtv.py::ReasoningTraceVerifier.verify()`：

```text
verify()
  → judge.score_trace()
  → CAI/OAV/IAD threshold check
  → optional MemoryProvenanceGraph.has_flagged_ancestor()
  → RTVResult
```

异常类型：

- `CAI`：Context-Action Inconsistency。
- `OAV`：Origin-Awareness Violation。
- `IAD`：Intent-Action Divergence。

默认 `ConstrainedJudgeModel` 是规则打分器。只有 live CLI 配置 `--judge_mode llm` 时才调用外部 judge。

### 2.4 ReasoningGuard 与 baselines

`src/reasoning_guard.py::ReasoningGuard.evaluate()`：

```text
ptg.verify_invocation()
  → PTG failed: BLOCK
  → PTG passed: rtv.verify()
  → RTV failed: ESCALATE
  → both passed: APPROVE
```

六种比较方法：

|Defense|实现|
|---|---|
|`No Defense`|evaluation 直接返回 `APPROVE`。|
|`AttestMCP`|`AttestMCPBaseline`，关闭 intent attestation、origin tag 和 cross-server consent。|
|`Guardrail`|`GuardrailBaseline`，live 主链路默认使用 LlamaGuard。|
|`PTG-Only`|`PTGOnlyBaseline`。|
|`RTV-Only`|`RTVOnlyBaseline`。|
|`ReasoningGuard`|完整 PTG → RTV 组合。|

## 3. 三类评估链路

仓库中存在三类语义不同的路径。

### 3.1 硬编码 mock 结果

```text
experiments/run_all.py
  → src/evaluation/eval_runner.py::run_*_experiment(mock_mode=True)
  → hardcoded paper-like metrics
```

该路径不调用 agent、judge 或 defense 实现，只用于生成预置表格和检查展示代码。不能用来证明当前实现真实运行。

### 3.2 合成消息 simulation

`src/evaluation/eval_runner.py` 中的 `run_*_experiment(mock_mode=False)`：

```text
_run_simulation()
  → AttackGenerator.generate_benchmark()
  → directly construct MCPMessage + ReasoningTrace
  → run_defense()
  → compute_metrics()
```

该路径会运行 PTG/RTV/Guardrail，但不会调用真实 agent。适合单元级防御逻辑和 latency 原型测试，不是 live agent 实验。

### 3.3 Quick/live 真实 agent 主链路

推荐入口：

```text
experiments/run_quick_benchmark_by_category.py
  → src/evaluation/live_table1.py
```

其他入口：

- `experiments/run_live_table1.py`：内置 agent provider factory。
- `experiments/run_live_table1_proxy.py`：将 agent factory 替换为 relay proxy。
- `experiments/run_live_multimodel_proxy.py`：依次运行四种 agent base model。

该路径加载 scenario、调用 agent、解析 tool call，再将同一 agent 输出送给全部 defense。

## 4. Quick/live 主调用链

### 4.1 CLI、数据加载与抽样

1. `experiments/run_quick_benchmark_by_category.py::main()`
   - 解析 benchmark、agent、judge、LlamaGuard、抽样和输出参数。
   - 调用 `configure_audit()` 初始化 audit log 和 strict runtime。
2. `load_benchmark_scenarios()`
   - `mcptox` → `load_mcptox()`。
   - `agentpi` → `load_agentpi()`。
   - `mcptox_plus` → 当前脚本的 `load_mcptox_plus()`。
   - `all` → 合并三种 benchmark。
3. `select_per_category()`
   - 按 `benchmark::category` 分组。
   - 使用固定 seed 打乱并按 `--per_category` 截取。
4. `summarize_selected()`
   - 在 `--max_scenarios` 截断后统计实际分布。
5. `_make_agent_factory()`
   - `default` → `create_backbone()`。
   - `proxy` → `create_proxy_backbone()`。

### 4.2 多次运行

```text
run_quick_evaluation()
  → run_live_table1_scenarios_multi()
  → run_live_table1_scenarios_once() × runs
  → _combine_live_outputs()
  → compute_ci()
```

行为：

- 第 `run_idx` 次运行使用 `base_seed + run_idx`。
- quick multi-run 的 `output_records` 只保存第 1 次运行。
- `_combine_live_outputs()` 汇总 ASR、TCR、Latency、L4_ASR、L2_ASR 的均值、标准差和 CI。

### 4.3 单次运行初始化

`run_live_table1_scenarios_once()`：

1. `build_mcp_servers()` 创建静态 server/capability。
2. `_normalize_with_metadata()` / `normalize_scenario()` 统一 scenario。
3. `make_judge()` 创建 heuristic 或 LLM judge。
4. `make_defenses()` 创建六种 defense。
5. 将静态 server 注册到拥有 PTG 的 defense。
6. 使用 `agent_factory` 创建 agent。
7. 初始化逐 defense records 和 agent detailed records。

`make_judge()`：

- `heuristic` → `ConstrainedJudgeModel`。
- `llm` → `ExternalJudgeAdapter(LLMJudgeInterface)`。

`make_defenses()`：

- RTV-Only 与 ReasoningGuard 使用同一个 judge 对象。
- 二者各自拥有独立 `ReasoningTraceVerifier`。
- 每个 scenario 只调用一次 attack agent，输出被全部 defense 复用。

### 4.4 Scenario normalization 与 prompt

`normalize_scenario()` 统一：

- `scenario_id`
- `category`
- `attack_layer`
- `target_server`
- `method`
- `target_action`
- `malicious_content`
- `legitimate_content`

候选字段的优先级写在该函数中。新增数据集或字段时必须同步检查 normalization，否则内容会退化到默认值。

`build_attack_query()` 将 target server、method 和 malicious content 拼成 attack user prompt。

`build_benign_query()` 将 target server、method 和 legitimate content 拼成 benign user prompt。

提示词原文及其问题见 `agent_tool_call_outcome_handling.md`。

### 4.5 Agent 调用与解析

内置 provider：

```text
create_backbone()
  → AgentBackbone.invoke()
  → AGENT_SYSTEM_PROMPT + user prompt
  → AgentBackbone._call_llm()
  → _parse_agent_response()
  → MCPMessage / ReasoningTrace / intent
```

关键函数：

- `create_backbone()`：按展示模型名硬编码 provider、model 和 key/base URL。
- `AgentBackbone.invoke()`：生成 capability 文本并设置 system/user messages。
- `_call_llm()`：OpenAI SDK、Anthropic SDK 或 raw vLLM HTTP。
- `_parse_agent_response_detailed()`：解析自定义 `REASONING/INTENT/TOOL_CALL` 文本协议并返回三态 outcome。
- `_parse_agent_response()`：保留旧三元组接口，供历史调用兼容。

Proxy 路径：

```text
create_proxy_backbone()
  → ProxyAgentBackbone._chat_payload() / _responses_payload()
  → _post_json()
  → extract_chat_completion_text() / extract_responses_text()
  → content parts / refusal / native tool-call arguments normalization
  → inherited AgentBackbone.invoke() parser
```

`run_live_table1_proxy.py` 通过替换 `live_table1.create_backbone` 注入 proxy；quick 入口通过显式 `agent_factory` 参数注入。Proxy 不复制 agent parser：`AgentBackbone.invoke()` 统一应用 `AGENT_SYSTEM_PROMPT`、三态 parser 和返回字段。Proxy 层只负责把 Chat Completions/Responses 的字符串、content parts、显式 refusal 和原生 tool-call arguments 归一为 parser 可消费的文本。

### 4.6 Agent output 转换

`_agent_output_to_inputs()`：

- 提取 `tool_call`、`trace`、`intent_summary` 和 raw response。
- `parsed_tool_call` 才返回真实 `MCPMessage`。
- `explicit_no_tool_call` 返回 `msg=None`，不运行 defense。
- `unparseable_output` 在 strict 模式抛异常；非 strict 模式记录 invalid。
- evaluation 不再根据 scenario 构造 fallback tool call。
- L2 attack 会向 message 增加 server provenance tag。

当前正式语义区分：

- `parsed_tool_call`
- `explicit_no_tool_call`
- `unparseable_output`

详细处理见 `agent_tool_call_outcome_handling.md`。

### 4.7 Harmful 判断与 defense

`is_harmful_output()` 将以下文本合并后做规则匹配：

- method
- params
- intent
- trace

它检查 `DANGEROUS_TERMS` 和 `target_action` 关键词，生成 `harmful`。

`_evaluate_all_defenses()`：

1. 把同一 message、trace、intent 送入六种 defense。
2. 记录 verdict、reason、latency，以及 PTG/RTV 的可序列化细节。
3. attack case：`harmful=True` 且 verdict 为 `APPROVE` 才算 `attack_succeeded=true`。
4. benign case：verdict 为 `APPROVE` 且 message 存在才算 `task_completed=true`。
5. 从 RTV 结果提取 `judge_record`，写入行级 judge 状态。
6. 写入 `defense.verdict` audit event。

### 4.8 Benign 对照

每条 attack scenario 运行后，使用 `benign_ratio` 决定是否增加 benign case。benign case 会再次调用 agent，然后复用同一解析、转换和 defense 流程。

### 4.9 指标与输出

`compute_live_metrics()`：

- ASR：攻击成功数量 / attack 数量。
- TCR：任务完成数量 / benign 数量。
- Latency：所有大于 0 的 defense latency 中位数。
- L4_ASR / L2_ASR：按 attack layer 分组。
- explicit no-tool 计入 ASR/TCR 分母，但不计入 latency。
- invalid 不进入指标分母，并令 `metrics_valid=false`。
- judge fallback 样本仍参与 ASR/TCR，但令对应 defense 的 `metrics_valid=false`。
- 同时输出 `num_invalid`、`num_agent_refused`、`num_judge_failures` 和 `judge_fallback_rate`。

输出包括：

- results JSON：逐 defense 汇总指标；
- records JSON：agent response、intent、tool call、harmful、scenario 和逐 defense/PTG/RTV/judge 细节；
- audit JSONL：错误、fallback、mock、verdict 和 summary；
- LaTeX：`write_table1_tex()` 生成主表。

## 5. Judge 与 Guardrail 链路

### 5.1 Heuristic judge

```text
ConstrainedJudgeModel.score_trace()
  → _score_cai()
  → _score_oav()
  → _score_iad()
```

该路径不调用 LLM。

### 5.2 LLM judge

```text
ExternalJudgeAdapter.score_trace()
  → LLMJudgeInterface.score()
  → JUDGE_PROMPT_TEMPLATE
  → _call_openai() / _call_anthropic() / _call_vllm()
  → _parse_response()
  → _finalize_record()
  → CAI/OAV/IAD + judge_record
```

关键行为：

- `_parse_response()` 从第一个 `{` 截取到最后一个 `}`，要求 CAI/OAV/IAD 字段完整且分数位于 `[0, 1]`。
- `failure_policy=inherit` 继承 strict runtime；`fallback` 始终记录失败并返回 `0.1/0.1/0.1`；`raise` 始终抛异常。
- `_finalize_record()` 保存完整 prompt、原始响应、解析状态、分数、fallback、异常和 latency，并写入 `judge.call_record` audit event。
- `ReasoningTraceVerifier.verify()` 在打分后立即快照 judge record，再使用 thresholds 判断异常。
- `RTVResult.judge_record` 经 `_defense_detail()` 序列化到 records JSON；共享 judge 对象不会覆盖前一个 defense 的快照。

### 5.3 Guardrail

```text
GuardrailBaseline.evaluate()
  → LlamaGuardBaseline.evaluate()
  → LlamaGuardWrapper.check()
  → model load
  → LLAMAGUARD_PROMPT
  → model.generate()
  → _parse_response()
```

模型加载失败时：

- strict runtime 或 fail-fast：抛异常。
- 非 strict：切换为危险关键词 mock，并记录 `llamaguard.mock_fallback_used`。

## 6. 数据集链路

### 6.1 MCPTox

`src/benchmarks/load_mcptox.py::load_mcptox()`：

- `use_official=True` 且文件存在：读取 `data/mcptox/mcptox_official.json`。
- 否则：`_generate_synthetic_mcptox()` 生成 synthetic scenarios。

`src/benchmarks/adapt_mcptox_benchmark.py::adapt_mcptox_benchmark()`：

- 读取 `third/MCPTox-Benchmark-main/response_all.json`。
- 转换为本项目统一 loader 格式。
- 原始 system prompt 只有显式 `--include_responses` 时保存到 metadata。
- live 主链路不使用原始 system prompt。

### 6.2 AgentPI

`src/benchmarks/load_agentpi.py::load_agentpi()`：

- official 文件存在时读取。
- 否则生成 synthetic context-dependent scenarios。

### 6.3 MCPTox+

`src/benchmarks/build_mcptox_plus.py::build_mcptox_plus()` 构造：

- context-dependent T2 scenarios；
- cross-session T3 scenarios。

quick 入口的 `load_mcptox_plus()` 将 JSON 的两个 section flatten 为统一 scenario list。

## 7. Judge 训练与校准

### 7.1 微调数据和 LoRA

```text
python -m src.finetune.judge_dataset
  → build_judge_dataset()
  → generate_training_sample()
  → train.jsonl / val.jsonl

python -m src.finetune.finetune_judge
  → finetune_judge()
  → tokenizer.apply_chat_template()
  → Qwen2.5-7B-Instruct + LoRA SFT
  → models/judge_qwen2.5-7b/final
```

当前仓库不保证存在可直接部署的训练数据或微调权重。

### 7.2 阈值校准

```text
experiments/calibrate_thresholds.py::calibrate_thresholds()
  → synthetic benign/malicious trace
  → ConstrainedJudgeModel.score_trace()
  → results/calibrated_thresholds.json
```

它校准的是 heuristic judge 在 synthetic trace 上的分数，不等价于真实 LLM judge 或人工标注数据校准。

## 8. Runtime audit

`src/runtime_audit.py` 的关键接口：

- `configure_audit()`：设置 JSONL 路径、run ID 和 strict runtime。
- `audit_context()`：附加 scenario、run、model、defense 等上下文。
- `audit_event()`：记录结构化事件并维护计数。
- `get_audit_summary()`：返回事件、错误、fallback 和 mock 计数。

正式实验至少检查：

- `level=ERROR`
- `fallback_used=true`
- `mock_used=true`
- `agent.unparseable_output`
- `agent.explicit_no_tool_call`
- `judge.default_scores_used`
- `llamaguard.mock_fallback_used`

## 9. 入口和文件职责速查

|路径|职责|
|---|---|
|`src/mcp_client.py`|MCP、trace、provenance、memory 数据结构。|
|`src/agent_backbone.py`|agent prompt、provider 调用和 response parser。|
|`src/agent_backbone_proxy.py`|OpenAI-compatible relay 适配。|
|`src/ptg.py`|PTG。|
|`src/rtv.py`|RTV、heuristic judge、memory provenance。|
|`src/reasoning_guard.py`|ReasoningGuard 和 baselines。|
|`src/judge.py`|外部 LLM judge。|
|`src/guardrails/llamaguard.py`|LlamaGuard baseline。|
|`src/attacks/attack_generator.py`|攻击模板、静态 MCP server 和 synthetic trace。|
|`src/benchmarks/`|benchmark loader、adapter 和 builder。|
|`src/evaluation/live_table1.py`|真实 agent 主评估编排。|
|`src/evaluation/eval_runner.py`|旧版 mock 和 simulation。|
|`src/evaluation/multi_run.py`|均值、标准差和 CI。|
|`src/runtime_audit.py`|JSONL audit 和 strict runtime。|
|`src/finetune/`|judge 数据与 LoRA 微调。|
|`experiments/`|CLI、表格、图片和校准入口。|
|`tests/`|组件和 quick/live 编排测试。|

`config.yaml` 当前主要是声明性配置。agent factory、judge 默认值、threshold 和实验参数仍分散在 Python 或 CLI 中，不能假设修改 `config.yaml` 会改变所有运行路径。

## 10. 当前工程边界

1. 静态 `build_mcp_servers()` 不等价于真实 MCP registry、schema、permission 和 attestation metadata。
2. agent 使用自定义 `REASONING/INTENT/TOOL_CALL` 文本协议，不是 provider 原生 tool-calling。
3. agent tool-call 三态 outcome 已接入 live 主链路；正式实验仍应检查 `metrics_valid` 和 `num_invalid`。
4. heuristic judge 不调用 LLM；只有 `--judge_mode llm` 使用外部 judge。
5. 当前 base Qwen judge 不等于论文 fine-tuned constrained verifier。
6. T3 memory provenance、真实 memory read IDs 和部分 origin tag 传递尚未完整接入 live 主链路。
7. `run_all.py` 的 mock 数字和 `eval_runner.py` 的 simulation 不能证明 live defense 效果。
8. 正式实验必须检查 audit log，而不能只看最终 results JSON。

## MCPTox-derived v2 场景级目录（2026-06-27）

quick/live 加载 schema revision 2 后，每条场景从 `template.clean_servers` 反序列化自己的
agent catalog。进入 attack/benign 评估前，所有带 PTG 的 defense 都通过
`replace_registry()` 清空旧能力并注册当前 clean catalog，防止跨场景残留。

TDP/PI/CE 的 attack catalog 由 clean catalog 复制后叠加攻击能力；PTG 仍只持有 clean
版本。RM 通过 `ToolResponseInjection` 传入 payload、server origin 和允许的首调用集合，
只有首调用匹配后才进入第二轮。指标层使用多个 expected calls，详细 records 同时保存
单数主引用、复数引用和 response injection 状态。

## Codex curation 数据流（2026-06-27）

`curate_mcptox_derived.py` 将生成文件映射为 200 个稳定 slot，每批按四类轮询导出 8 条。
Codex 在 batch 中填写检查、决定和理由；import 对 accept/edit/replace 做结构校验，并将
替换项重新置为 pending。finalize 只有在所有 slot 终审后才写 curated 文件。

`load_mcptox(..., official_variant=...)` 现在显式区分 `derived`、`curated` 和 `legacy`。
quick/live 的 `--official_variant` 透传该选择，不再根据多个文件的存在顺序猜测实验口径。

# AAAI2027 Agent 论文实验代码实现审阅

## 1. 审阅结论

本项目实现了论文 *ReasoningGuard: Dual-Layer Defense for MCP-Based LLM Agents via Protocol Attestation and Reasoning Trace Verification* 的核心原型组件，也提供了实验脚本、表格生成脚本、图生成脚本和合成数据生成器。

但从代码路径看，当前仓库并没有完整端到端复现实验论文中的真实实验。论文表格中的主结果、跨模型结果、T1/T3 对比、消融实验、按类别统计和延迟分解，默认都是通过 `mock_mode=True` 返回的预置数值生成的。这些数值与论文表格一致，但不是由官方 MCPTox/AgentPI、四个真实 agent backbone、真实 Qwen2.5-7B judge 和真实多轮评估流水线重新计算得到。

更准确的判断是：

- 有：ReasoningGuard 机制原型、合成攻击 scenario、合成 MCPTox/AgentPI/MCPTox+ 数据、规则化评估 runner、mock 论文结果输出。
- 没有：论文级真实实验复现链路，即官方 benchmark + 真实模型调用 + 真实 judge/guardrail + 三次独立运行 + 非 mock 统计置信区间。

## 2. 论文实验要求概览

论文实验主要验证以下内容：

| 实验 | 论文要求 |
| --- | --- |
| MCPTox 主实验 | 200 个 MCP tool poisoning scenarios，比较 No Defense、AttestMCP、Guardrail、PTG-Only、RTV-Only、ReasoningGuard |
| AgentPI / context-dependent | 150 个 context-dependent reasoning attack scenarios |
| MCPTox+ | 扩展 80 个 context-dependent 和 50 个 cross-session T3 scenarios |
| 多模型实验 | GPT-4o、Claude-3.5-Sonnet、Gemini-1.5-Pro、Llama-3.1-70B |
| T1 vs T3 | 比较 instantaneous 和 cross-session attack ASR |
| 消融实验 | 移除 Intent Attestation、Origin Tags、Memory Graph、RTV、PTG |
| 延迟实验 | 分解 PTG attestation、intent entailment、RTV judge inference 等开销 |
| 指标 | ASR、TCR、Latency，论文声称 3 次运行并报告 95% CI |

## 3. 代码如何实现论文方法

### 3.1 MCP 数据结构与 provenance

相关文件：`src/mcp_client.py`

代码定义了论文中需要的基本对象：

- `MCPMessage`：表示 MCP request/response/sampling 消息，包含 sender、recipient、method、params、origin、provenance_tags、intent_summary、is_malicious 等字段。
- `MCPServer` 和 `MCPCapability`：表示 server 能力声明和允许的方法。
- `ReasoningTrace` / `ReasoningStep`：表示结构化推理轨迹，包含 observation、inference、decision、origin_awareness。
- `MemoryEntry`：表示跨 session memory provenance 节点。
- `ProvenanceLedger`：记录消息、intent signature、trace 和时间戳。

这部分是论文方法的结构化数据模型原型。

### 3.2 PTG：Protocol-Attested Tool Gateway

相关文件：`src/ptg.py`

代码实现了论文 PTG 的轻量版本：

- `ProtocolAttestedToolGateway.verify_invocation()` 作为入口，依次执行 attestation、intent entailment、cross-server、origin tagging 和 signature 计算。
- `_verify_attestation()` 检查目标 server 是否注册，以及调用方法是否在 server capability 的 `methods` 列表中。
- `_verify_intent_entailment()` 用关键词 overlap 近似判断 intent summary 是否被 capability description 支持。
- `_compute_intent_signature()` 用 HMAC-SHA256 将 intent、server、method、params、timestamp 绑定成签名。
- `tag_sampling_response()` 给 sampling response 添加 `origin=server` 和 server id。
- `disable_intent_attestation`、`disable_origin_tags` 支持消融实验。

需要注意的限制：

- cross-server isolation 的 `_verify_cross_server()` 当前基本是占位逻辑，始终返回 `True`。
- intent entailment 是关键词规则，不是 NLI 或真实语义推理。
- AttestMCP baseline 在代码里实际复用了 PTG 检查，并不是真实 AttestMCP 协议实现。

### 3.3 RTV：Reasoning Trace Verifier

相关文件：`src/rtv.py`

代码实现了论文 RTV 的规则化版本：

- `ReasoningTraceVerifier.verify()` 对 trace 打分并按阈值决定 approve/escalate。
- `ConstrainedJudgeModel` 输出 CAI、OAV、IAD 三类异常分数。
- `_score_cai()` 通过危险动词是否出现在 decision 但不在 context 中来检测 Context-Action Inconsistency。
- `_score_oav()` 通过 `origin_awareness` 和 `origin_tags` 检测是否把 server/tool/memory 内容当作 user instruction。
- `_score_iad()` 通过危险动词是否出现在 decision 但不在 intent 中来检测 Intent-Action Divergence。
- `MemoryProvenanceGraph` 支持 memory dependency 追溯和 flagged ancestor 检测。
- `disable_memory_provenance` 支持 memory graph 消融。

需要注意的限制：

- 默认 `ConstrainedJudgeModel` 是规则模型，不是真实 Qwen2.5-7B-Instruct constrained decoding。
- `src/judge.py` 提供了 OpenAI/Anthropic/vLLM 风格接口和 mock judge，但默认实验没有把真实 judge 接入 RTV 主路径。
- memory provenance 的单元逻辑存在，但实验 runner 的 ReasoningGuard 调用里 `memory_read_ids=None`，真实 T3 memory read 审计没有在主仿真路径中完整触发。

### 3.4 ReasoningGuard 集成与 baselines

相关文件：`src/reasoning_guard.py`

集成逻辑如下：

1. `ReasoningGuard.evaluate()` 先调用 PTG。
2. PTG 未通过则返回 `BLOCK`。
3. PTG 通过后调用 RTV。
4. RTV 未通过则返回 `ESCALATE`。
5. 两层都通过则返回 `APPROVE`。

代码中还提供：

- `AttestMCPBaseline`：复用 PTG。
- `PTGOnlyBaseline`：只运行 PTG。
- `RTVOnlyBaseline`：只运行 RTV。
- `GuardrailBaseline`：默认使用 mock LlamaGuard 或危险关键词过滤。

这部分对应论文中的双层协议与 baseline 比较框架。

## 4. 代码如何实现实验数据与攻击场景

### 4.1 攻击生成器

相关文件：`src/attacks/attack_generator.py`

代码定义了 6 类攻击：

- `tool_description_poisoning`
- `parameter_injection`
- `response_manipulation`
- `capability_escalation`
- `context_dependent`
- `cross_session_t3`

并用 `ATTACK_LAYER` 将它们映射到 L4 或 L2。`ATTACK_TEMPLATES` 中为每类攻击提供少量模板，然后通过随机采样生成 scenario。

这说明代码有攻击类别覆盖，但主要是模板化合成数据，不是官方 benchmark 原始样本。

### 4.2 MCPTox / AgentPI loader

相关文件：

- `src/benchmarks/load_mcptox.py`
- `src/benchmarks/load_agentpi.py`

两个 loader 都预留了 official dataset 路径：

- MCPTox official path: `data/mcptox/mcptox_official.json`
- AgentPI official path: `data/agentpi/agentpi_official.json`

如果 official 文件不存在，就自动生成 synthetic dataset。当前文件列表中没有看到官方 MCPTox 或 AgentPI 数据文件，因此默认路径会走 synthetic fallback。

### 4.3 MCPTox+

相关文件：

- `src/benchmarks/build_mcptox_plus.py`
- `data/mcptox_plus/mcptox_plus.json`
- `data/mcptox_plus/mcptox_plus_stats.json`

这部分实现了论文中 MCPTox+ 的数据生成：

- 80 个 context-dependent scenarios。
- 50 个 cross-session T3 scenarios。
- 总计 130 个 scenarios。

但这些 scenarios 仍来自 `ATTACK_TEMPLATES` 的模板采样，而不是从真实 MCP server 交互日志或官方 benchmark 扩展样本生成。

## 5. 代码如何生成论文实验结果

### 5.1 eval runner

相关文件：`src/evaluation/eval_runner.py`

该文件是判断实验实现程度的关键。

它提供了两类路径：

1. `mock_mode=True`
   - 直接返回论文表格数值。
   - 例如 `_mock_mcptox_results()` 返回 No Defense ASR 72.8、AttestMCP ASR 12.4、ReasoningGuard ASR 5.3 等。
   - `run_multi_model_experiment(mock_mode=True)`、`run_t3_experiment(mock_mode=True)`、`run_ablation_experiment(mock_mode=True)`、`run_per_category_experiment(mock_mode=True)` 也都直接返回硬编码数值。

2. `mock_mode=False`
   - 使用 `_run_simulation()` 生成 synthetic scenario。
   - 对 synthetic message 和 synthetic trace 执行 No Defense、PTG、RTV、ReasoningGuard 等规则化评估。
   - 计算 ASR、TCR、Latency、L4_ASR、L2_ASR。

非 mock 分支有一定仿真实验能力，但仍不是论文真实实验：

- 没有调用官方 MCPTox/AgentPI loader。
- 没有让四个真实 agent backbone 对每个 scenario 生成动作。
- 没有真实 MCP server 执行。
- 没有真实 Qwen2.5-7B judge constrained decoding。
- T3 实验没有完整写入 session t memory 并在 session t+k 读取审计。

### 5.2 run_all

相关文件：`experiments/run_all.py`

`run_all.py` 明确打印 `ReasoningGuard Experiment Suite (Mock Mode)`，并且所有实验调用都传入 `mock_mode=True`：

- `run_mcptox_experiment(mock_mode=True)`
- `run_multi_model_experiment(mock_mode=True)`
- `run_t3_experiment(mock_mode=True)`
- `run_ablation_experiment(mock_mode=True)`
- `run_per_category_experiment(mock_mode=True)`

因此 `python experiments/run_all.py` 生成的是论文数值复写，不是重新跑实验。

### 5.3 表格与图生成

相关文件：

- `experiments/generate_tables.py`
- `experiments/generate_figures.py`

这些脚本同样全部调用 `mock_mode=True`，所以：

- `results/latex_tables/*.tex`
- `results/figures/*.pdf`
- `results/experiment_results.json`

都是由硬编码论文结果生成。`multi_run(lambda: run_mcptox_experiment(mock_mode=True), num_runs=3)` 也只是重复三次同一组 mock 数值，所以 CI/std 为 0，不代表真实三次随机实验的置信区间。

## 6. 论文实验与代码实现对应表

| 论文实验项 | 代码位置 | 实现程度 | 说明 |
| --- | --- | --- | --- |
| PTG semantic intent attestation | `src/ptg.py` | 部分实现 | HMAC 和关键词 entailment 已实现，语义判断较轻量 |
| origin-tagged sampling | `src/ptg.py`, `src/mcp_client.py` | 部分实现 | 支持 provenance tags，但主实验路径主要是 synthetic request |
| cross-server isolation | `src/ptg.py` | 基本未实现 | `_verify_cross_server()` 当前等价于通过 |
| RTV CAI/OAV/IAD | `src/rtv.py` | 部分实现 | 规则化 judge，不是真实 Qwen judge |
| memory provenance graph | `src/rtv.py` | 单元能力实现 | 主实验仿真没有完整 T3 memory write/read 流程 |
| ReasoningGuard dual-layer flow | `src/reasoning_guard.py` | 已实现原型 | PTG block，RTV escalate，双层 approve |
| MCPTox 200 scenarios | `src/benchmarks/load_mcptox.py` | 合成实现 | 无 official 文件时生成 synthetic MCPTox |
| AgentPI 150 scenarios | `src/benchmarks/load_agentpi.py` | 合成实现 | 无 official 文件时生成 synthetic AgentPI |
| MCPTox+ 80+50 scenarios | `src/benchmarks/build_mcptox_plus.py` | 合成实现 | 已生成 `data/mcptox_plus` |
| 主实验表格 | `src/evaluation/eval_runner.py` | mock 实现 | `_mock_mcptox_results()` 硬编码论文数值 |
| 多模型实验 | `src/evaluation/eval_runner.py` | mock 为主 | 非 mock 分支没有真实区分不同 backbone 行为 |
| T1 vs T3 | `src/evaluation/eval_runner.py` | mock 为主 | 非 mock T3 不完整建模跨 session memory exploitation |
| 消融实验 | `src/evaluation/eval_runner.py` | mock + 规则仿真 | 消融开关存在，但论文数值来自 mock |
| 延迟分解 | `src/evaluation/latency_profiler.py`, `eval_runner.py` | mock + profiler | 论文延迟数值由 mock 返回 |
| 95% CI | `src/evaluation/multi_run.py` | 工具有实现 | 当前表格 CI 基于重复 mock，std/CI 为 0 |

## 7. 已有测试覆盖

相关文件：`tests/test_all.py`

测试覆盖了：

- MCP message、server、trace、ledger。
- PTG 正常通过、未知 server 拒绝、capability escalation 阻断、消融开关。
- RTV benign trace、OAV、CAI、memory provenance、memory graph 消融。
- ReasoningGuard approve/block。
- Attack generator 和 attack layer tag。
- mock judge、mock LlamaGuard。
- synthetic MCPTox / AgentPI loader。
- latency profiler、multi_run。
- mock eval runner。
- 小规模 `_run_simulation()`。

本次审阅运行了：

```powershell
python -B tests\test_all.py
```

结果：

```text
Ran 50 tests in 0.012s
OK
```

尝试运行 `pytest` 时失败，因为当前 Python 环境没有安装 `pytest`。

## 8. 最终判断

代码有“论文方法的工程原型”和“论文结果的 mock 复现”，但没有“论文实验的真实端到端复现”。

如果论文或项目需要声明代码已经具体实现实验，建议区分三种表述：

1. 可以说：实现了 PTG、RTV、ReasoningGuard、合成 benchmark、mock 论文结果生成和规则化仿真实验。
2. 不宜说：当前代码可以真实复现论文表格中的所有实验结果。
3. 更准确说法：当前代码提供了可运行的实验框架，默认输出论文表格的预置结果；若要真实复现实验，需要进一步接入官方数据集和真实模型评估链路。

## 9. 若要补齐真实实验复现，需要做的工作

建议按以下优先级补齐：

1. 接入官方 MCPTox 和 AgentPI 数据，并让 `run_mcptox_experiment(mock_mode=False)` 使用 loader，而不是直接调用 `AttackGenerator.generate_benchmark()`。
2. 将 `AgentBackbone` 接入 evaluation pipeline，让 GPT-4o、Claude、Gemini、Llama 分别对相同 scenario 生成 tool call、intent summary 和 reasoning trace。
3. 将 RTV 的 judge 替换为真实 Qwen2.5-7B-Instruct 或 vLLM serving，并保证输出严格 JSON/constrained decoding。
4. 实现真实 T3 流程：session t 写入 memory，记录 provenance，session t+k 读取 memory，并把 `memory_read_ids` 传给 `ReasoningGuard.evaluate()`。
5. 让 `generate_tables.py` 和 `generate_figures.py` 支持从非 mock 实验输出读取结果，而不是固定调用 `mock_mode=True`。
6. 对每个实验运行 3 次不同 seed，保存每次 raw result，再计算真实 std 和 95% CI。
7. 明确区分 paper-number reproduction、synthetic simulation、official benchmark reproduction 三种运行模式，避免结果来源混淆。

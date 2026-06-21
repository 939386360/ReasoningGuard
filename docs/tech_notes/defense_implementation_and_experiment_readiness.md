# 防御方法实现与真实实验就绪性梳理

更新日期：2026-06-21

本文档说明当前主表 live evaluation 中各个 defense 的实现路径、是否真实运行、哪里仍是简化或 mock，以及要跑出可信真实实验结果前还需要确认的事项。

## 1. 主表链路如何同时评估多个 defense

当前主表链路主要在 `src/evaluation/live_table1.py`。

每个 scenario 的执行顺序是：

1. `run_live_table1_scenarios_once()` 先构造 MCP servers、judge、defenses 和 agent。
2. 对每个 attack scenario，agent 只调用一次，生成同一份：
   - `MCPMessage`，即工具调用；
   - `ReasoningTrace`，即结构化推理轨迹；
   - `intent_summary`，即工具调用意图摘要。
3. `_evaluate_all_defenses()` 遍历 `make_defenses()` 返回的所有 defense，把同一份 `msg/trace/intent` 分别喂给每个 defense。
4. 每个 defense 的结果写入自己的 `records[name]`。
5. 最后 `compute_live_metrics()` 按 defense 分别计算 ASR、TCR、Latency、L4_ASR、L2_ASR。

因此，当前表格中多行 defense 不是多条命令分别跑出来的，而是在同一条评测链路里对同一批 agent 输出进行并列评估。

## 2. 各 defense 当前实现

|Defense|代码入口|当前实现|是否 mock|主要注意点|
|---|---|---|---|---|
|`No Defense`|`_evaluate_all_defenses()`|直接 `APPROVE`|不是 mock|作为无防御基线，攻击样本只要 agent 输出被判定 harmful 且未被拦截，就计为攻击成功。|
|`AttestMCP`|`AttestMCPBaseline`|调用 `ProtocolAttestedToolGateway.verify_invocation(msg, intent)`|不是 mock|当前和 `PTG-Only` 基本等价；如果论文中 AttestMCP baseline 有独立协议语义，需要后续补齐差异。|
|`Guardrail`|`GuardrailBaseline` / `LlamaGuardBaseline`|默认使用 LlamaGuard 检查 tool invocation|可能静默 fallback|`live_table1.py` 默认传 `llamaguard_mock=False`，但 LlamaGuard 模型加载失败时会自动切到关键词 mock。正式实验必须确认没有 fallback。|
|`PTG-Only`|`PTGOnlyBaseline`|只运行 PTG 检查|不是 mock|server capability 来自 `build_mcp_servers()` 的静态模拟配置，不是从真实 MCP server registry 动态读取。|
|`RTV-Only`|`RTVOnlyBaseline`|只运行 `ReasoningTraceVerifier`|取决于 judge 模式|`--judge_mode heuristic` 是规则化 fallback；`--judge_mode llm` 才调用自部署 Qwen judge 服务。|
|`ReasoningGuard`|`ReasoningGuard`|先 PTG，PTG 通过后再 RTV|取决于 judge 和 PTG 数据|真实程度取决于 PTG capability 是否接近真实 MCP，以及 RTV 是否使用 LLM judge。|

### 2.1 No Defense

`No Defense` 在 `_evaluate_all_defenses()` 中直接设置：

```python
verdict = Verdict.APPROVE
latency_ms = 0.0
```

它不调用任何模型或规则，是主表中用于计算未防御攻击成功率的基线。它不是 mock，而是一个刻意恒定放行的 baseline。

### 2.2 AttestMCP

`AttestMCPBaseline.evaluate()` 当前实现是：

```python
result = self.ptg.verify_invocation(msg, intent_summary)
```

也就是说，当前 AttestMCP baseline 实际复用了 `ProtocolAttestedToolGateway` 的检查逻辑，包括：

- server 是否注册了对应 capability；
- method 是否在 capability methods 中；
- intent 与 capability description 是否有粗粒度词重叠；
- sampling 消息是否带有 server origin tag；
- cross-server consent 当前默认总是通过。

这不是 mock，但当前实现更像一个 PTG 简化 baseline。由于 `PTG-OnlyBaseline` 也调用同一个 `verify_invocation()`，两者目前很可能给出相同或非常接近的结果。若论文实验要求 AttestMCP 与 PTG-Only 有不同能力边界，需要补充独立的 AttestMCP baseline 实现。

### 2.3 Guardrail

`GuardrailBaseline` 默认 `use_llamaguard=True`。在 live evaluation 中：

```python
GuardrailBaseline(use_llamaguard=True, mock_mode=llamaguard_mock)
```

CLI 默认不传 `--llamaguard_mock` 时，`llamaguard_mock=False`，理论上会尝试真实加载 LlamaGuard。

当前默认模型不是项目内某个固定本地路径，而是 Hugging Face 模型名：

```text
meta-llama/LlamaGuard-3-8B
```

加载代码在 `src/guardrails/llamaguard.py::LlamaGuardWrapper`：

```python
AutoTokenizer.from_pretrained(self.model_name)
AutoModelForCausalLM.from_pretrained(
    self.model_name,
    torch_dtype=torch.float16,
    device_map=self.device,
)
```

默认 `self.model_name="meta-llama/LlamaGuard-3-8B"`，默认 `self.device="auto"`。因此 transformers 会按标准 `from_pretrained()` 语义查找：优先使用本机 Hugging Face cache；如果没有 cache 且环境允许联网/有权限，则尝试从 Hugging Face 下载；如果没有下载权限、网络不可用、模型未授权、依赖缺失或显存不足，就会加载失败。

在没有设置 `HF_HOME`、`HUGGINGFACE_HUB_CACHE`、`HF_HUB_CACHE`、`TRANSFORMERS_CACHE` 或 `XDG_CACHE_HOME` 时，Hugging Face 默认 cache 通常位于：

```text
/home/liuenguang24/.cache/huggingface/hub
```

通过模型名下载后的权重一般会在类似下面的目录结构中：

```text
/home/liuenguang24/.cache/huggingface/hub/models--meta-llama--LlamaGuard-3-8B/snapshots/<revision>/
```

不建议手动把魔塔社区下载的模型硬搬进这个 cache 目录，除非完整模拟 Hugging Face cache 的 `models--.../snapshots/...` 结构。更稳妥的方式是直接把普通本地模型目录传给新增参数：

```bash
--llamaguard_model /home/liuenguang24/models/LlamaGuard-3-8B
```

该目录需要是 transformers `from_pretrained()` 可识别的目录，通常至少包含 `config.json`、tokenizer 相关文件和权重文件。如果魔塔下载目录本身就是 Hugging Face/transformers 格式，可以直接传；如果文件名或结构是魔塔专用格式，需要先整理成 transformers 兼容格式。

当前已新增 CLI 参数：

- `--llamaguard_model`：Hugging Face model id 或 transformers-compatible 本地目录，默认 `meta-llama/LlamaGuard-3-8B`。
- `--llamaguard_device`：传给 `device_map`，默认 `auto`；可按环境传 `cuda:0` 或 `cpu`。
- `--llamaguard_fail_fast`：加载失败时直接报错，避免静默 fallback 到关键词 mock。正式实验建议加。

风险点在 `src/guardrails/llamaguard.py`：

```python
except Exception as e:
    print(f"[LlamaGuard] Failed to load model: {e}")
    self.mock_mode = True
```

如果 transformers、torch、模型权重或显存不可用，代码会打印错误并自动退回 `_mock_check()`。这个 mock check 是关键词匹配，不是真实 LlamaGuard。

正式实验要求：

- 不要传 `--llamaguard_mock`。
- 如果使用默认模型名，运行前确认机器能通过 transformers 加载 `meta-llama/LlamaGuard-3-8B`，即本机 cache、Hugging Face 权限、`transformers`、`torch` 和 GPU 显存都满足要求。
- 如果使用魔塔或手动下载的本地模型，传 `--llamaguard_model /path/to/model`，并确认该目录是 transformers-compatible。
- 建议正式实验加 `--llamaguard_fail_fast`。
- 检查日志中不能出现 `[LlamaGuard] Failed to load model`。
- 建议后续把自动 fallback 改成 fail-fast，或至少把 fallback 状态写入结果文件。

### 2.4 PTG-Only

`PTGOnlyBaseline` 只运行 PTG：

```python
result = self.ptg.verify_invocation(msg, intent_summary)
```

PTG 当前检查内容在 `src/ptg.py`：

- `_verify_attestation()`：检查 recipient server 已注册，并且 method 属于该 server 的 allowed methods。
- `_verify_intent_entailment()`：用 intent 和 capability description 的关键词重叠近似判断意图是否匹配。
- `_verify_cross_server()`：当前默认返回 `True`。
- `_verify_origin_tags()`：只对 `MCPMessageType.SAMPLING` 要求 server origin tag；普通 request 默认通过。
- `_compute_intent_signature()`：生成 HMAC signature。

这不是 mock，但 server capability 来自 `src/attacks/attack_generator.py::build_mcp_servers()` 的静态定义。它能跑通协议检查链路，但还不是从真实 MCP server schema、permission policy 或真实 attestation metadata 中读取。

### 2.5 RTV-Only

`RTVOnlyBaseline` 调用：

```python
result = self.rtv.verify(trace, intent_summary, origin_tags)
```

RTV 的真实程度由 `make_judge()` 决定：

- `--judge_mode heuristic`：使用 `ConstrainedJudgeModel`，不调用 LLM，只按规则计算 `CAI/OAV/IAD`。
- `--judge_mode llm`：使用 `ExternalJudgeAdapter`，通过 `LLMJudgeInterface` 调用外部 judge 服务。

当前自部署 judge endpoint 已配置为：

```text
http://aias-compute-4:14545/v1/chat/completions
```

模型名：

```text
qwen2.5-7B-Instruct
```

因此，如果要让 RTV-Only 真正调用你的本地 judge LLM，正式命令必须包含：

```bash
--judge_mode llm \
--judge_provider vllm \
--judge_model qwen2.5-7B-Instruct \
--judge_base_url http://aias-compute-4:14545/v1/chat/completions
```

注意：当前接入的是 base `Qwen2.5-7B-Instruct` 服务，不是论文中 fine-tuned RTV judge。它是真实 LLM 调用，但判别质量不等同于论文最终 verifier。

### 2.6 ReasoningGuard

`ReasoningGuard.evaluate()` 的顺序是：

1. 先调用 PTG：

```python
ptg_result = self.ptg.verify_invocation(msg, intent_summary, trace)
```

2. PTG 不通过则直接 `BLOCK`。
3. PTG 通过后调用 RTV：

```python
rtv_result = self.rtv.verify(trace, intent_summary, origin_tags, memory_read_ids)
```

4. RTV 不通过则 `ESCALATE`。
5. PTG 与 RTV 都通过才 `APPROVE`。

这不是 mock defense。它是真实组合了当前 PTG 和 RTV 两个模块。但需要注意：

- 如果 `--judge_mode heuristic`，RTV 部分仍是规则化 fallback。
- 如果 `--judge_mode llm`，RTV 部分会真实调用本地 Qwen judge。
- T3 memory provenance 当前主表 live 链路没有传入真实 `memory_read_ids`，所以跨会话 provenance 审计能力还没有完整体现在主表路径里。

## 3. 当前是否能真正跑实验

|组件|当前状态|正式实验判断|
|---|---|---|
|agent base model|`run_quick_benchmark_by_category.py` 默认 `agent_backend=proxy`，不传 `--agent_mock` 会真实调用中转站|可以真实跑；需要设置 `LLM_API_KEY`，并确认 `--agent_base_url` 和 `--agent_model_map` 对中转站有效。|
|judge LLM|`--judge_mode llm` 时会调用本地 Qwen judge 服务|可以真实跑 RTV 调用链路；但当前是 base Qwen，不是 fine-tuned RTV judge。|
|Guardrail/LlamaGuard|默认尝试真实 LlamaGuard，但失败会自动 fallback 到 mock|正式比较 Guardrail 前必须验证模型成功加载，建议改成 fail-fast。|
|PTG/AttestMCP|代码真实执行规则和 HMAC signature|不是 mock，但 server/capability/policy 是静态模拟，不是生产 MCP registry。|
|datasets|quick 脚本能读取 MCPTox、AgentPI fallback、MCPTox+|MCPTox synthetic 200 数量对齐论文但非 official；本地 adapted official 是 1348，不等同论文 200 口径。|
|per-defense records|指标按 defense 分别计算|当前 `records_output` 主要保存 agent 输出，不保存每个 defense 的逐样本判定细节；审计 ASR/TCR 时不够。|

结论：

- 当前已经可以跑“真实 agent + 真实本地 judge LLM”的主表链路。
- 当前不能直接宣称完全复现论文中的所有真实 baseline，因为 Guardrail 可能 fallback、RTV judge 不是 fine-tuned verifier、PTG/AttestMCP 是简化协议实现。
- 当前最可靠的表述应是：使用真实 agent API、真实本地 Qwen judge API，对当前工程实现的六种 defense 进行 live evaluation。

## 4. 正式运行前 checklist

正式跑 GPT-4o agent + 自部署 Qwen judge 的 quick 主表链路。当前 quick/live CLI 默认使用 synthetic/generated 数据集口径；不要加 `--official`，否则 MCPTox 会读取 1348 条 adapted official 文件：

```bash
export LLM_API_KEY="你的中转站 key"

python experiments/run_quick_benchmark_by_category.py \
  --benchmark mcptox \
  --per_category 50 \
  --categories "" \
  --max_scenarios 200 \
  --runs 3 \
  --seed 42 \
  --data_dir data/mcptox \
  --model GPT-4o \
  --agent_backend proxy \
  --agent_base_url https://llm-api.net/v1/chat/completions \
  --agent_api_style chat \
  --agent_api_key_env LLM_API_KEY \
  --agent_model_map '{"GPT-4o":"gpt-4o"}' \
  --agent_timeout 60 \
  --judge_mode llm \
  --judge_provider vllm \
  --judge_model qwen2.5-7B-Instruct \
  --judge_base_url http://aias-compute-4:14545/v1/chat/completions \
  --llamaguard_model /home/liuenguang24/models/LlamaGuard-3-8B \
  --llamaguard_device auto \
  --llamaguard_fail_fast \
  --benign_ratio 0.30 \
  --output results/quick_eval/table1_gpt4o_qwen_judge_results.json \
  --tex_output results/quick_eval/table1_gpt4o_qwen_judge.tex \
  --records_output results/quick_eval/table1_gpt4o_qwen_judge_records.json
```

正式实验不要加：

```bash
--agent_mock
--llamaguard_mock
```

运行后至少检查：

- stdout/stderr 没有 `[ProxyAgentBackbone] LLM call failed`。
- stdout/stderr 没有 `[LLMJudge] Error calling vllm`。
- stdout/stderr 没有 `[LlamaGuard] Failed to load model`。
- 如果要正式比较 `Guardrail`，先单独确认 `--llamaguard_model` 指向的本地目录或默认 Hugging Face cache 能被 transformers 加载。
- 输出 JSON 中 `RTV-Only` 和 `ReasoningGuard` 的 latency 明显包含 judge 调用开销。
- `records_output` 中 agent response 不是空字符串，且能解析出合理 trace/intent/tool_call。

## 5. 建议后续补齐的工程项

1. **Guardrail fallback 状态记录**：即使不启用 `--llamaguard_fail_fast`，也应把 LlamaGuard 是否 fallback 到 mock 写入结果或日志元数据。
2. **Guardrail 预检命令**：后续可增加一个轻量 preflight 命令，只加载 LlamaGuard 并跑一条固定输入，避免主实验开始后才失败。
3. **Judge fail-fast**：`LLMJudgeInterface.score()` 当前异常时返回低风险默认分数 `0.1`，正式实验应改为报错或在结果中记录 judge error。
4. **Per-defense detailed records**：把每个 defense 对每个样本的 verdict、reason、latency、attack_succeeded、task_completed 写入 records，便于复核 ASR/TCR。
5. **区分 AttestMCP 和 PTG-Only**：如果论文 baseline 需要两者不同，应实现 AttestMCP 独立逻辑，而不是复用 PTG。
6. **真实 MCP capability 接入**：PTG 当前依赖静态 `build_mcp_servers()`，后续应接入真实 server schema、permission 和 attestation metadata。
7. **T3 memory provenance 链路**：如果要跑 MCPTox+ cross-session T3，需要让 live evaluation 传入真实 memory read/write ids，否则 RTV memory audit 没有完整生效。

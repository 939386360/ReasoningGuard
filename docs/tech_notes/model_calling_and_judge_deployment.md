# Agent 基础模型、Judge 调用与本地部署兼容性分析

更新日期：2026-06-21

本文档整理当前项目如何调用 agent 基础模型、RTV judge 模型如何接入，以及 `/home/liuenguang24/deployed_models` 这种本地部署方式如何承载 judge 调用。结论基于当前仓库代码和部署目录实现。

## 1. 总体结论

当前项目存在三类“模型相关”路径：

|对象|当前默认路径|是否真实调用 LLM|关键代码|
|---|---|---|---|
|agent 基础模型|`AgentBackbone`，默认 mock|仅在 `mock_mode=False` 且走 live 评测时真实调用|`src/agent_backbone.py`、`src/evaluation/live_table1.py`|
|RTV judge|当前代码默认 `ConstrainedJudgeModel` 规则打分；论文设定为 fine-tuned Qwen judge|默认不调用 LLM|`src/rtv.py`|
|LLM judge 接口|`LLMJudgeInterface` + `ExternalJudgeAdapter`|仅 `live_table1.py --judge_mode llm` 时接入 RTV|`src/judge.py`、`src/evaluation/live_table1.py`|

需要特别区分：

1. `src/judge.py` 已实现 OpenAI/Anthropic/vLLM 风格的 LLM judge 调用接口。
2. `ReasoningTraceVerifier()` 默认并不会使用这个接口，而是使用 `src/rtv.py` 中的规则化 `ConstrainedJudgeModel`。这只是当前工程默认/替代实现，不等同于论文中的真实 RTV judge。
3. `experiments/run_all.py`、`generate_tables.py`、`generate_figures.py` 等默认使用 `mock_mode=True`，不会真实调用 agent 或 judge。
4. 真正把 agent backbone 和 LLM judge 放进同一评测链路的是 `src/evaluation/live_table1.py`。

对 `/home/liuenguang24/deployed_models` 的判断：

- 该目录下的服务提供 `/v1/chat/completions`，响应结构接近 OpenAI chat completions，可作为 `LLMJudgeInterface(provider="vllm")` 的 HTTP endpoint。
- 已新增/接入 `Qwen2.5-7B-Instruct` 文本服务，当前已验证的 served model 名为 `qwen2.5-7B-Instruct`，endpoint 为 `http://aias-compute-4:14545/v1/chat/completions`。
- 当前接入的是 base `Qwen2.5-7B-Instruct`，不是论文中的 fine-tuned RTV judge。它能跑通 LLM judge 链路，但判别质量不等同于微调 verifier。

## 2. Agent 基础模型如何调用

### 2.1 调用入口

agent 入口是 `src/agent_backbone.py`：

- `AgentBackbone.invoke(user_query, servers, max_turns=5)`：对用户请求和可用 MCP server 能力进行 prompt 组装。
- `AGENT_SYSTEM_PROMPT`：要求模型输出固定结构：
  - `REASONING`
  - `INTENT`
  - `TOOL_CALL`
- `_parse_agent_response(response)`：从模型文本中解析 reasoning trace、intent summary 和 tool call JSON。
- 如果解析出 `TOOL_CALL`，会包装成 `MCPMessage`，供 PTG/RTV/ReasoningGuard 后续验证。

### 2.2 mock 与真实调用

`AgentBackbone` 默认参数是 `mock_mode=True`。此时不会调用外部模型，而是进入 `_mock_invoke()`：

- 生成一条简单 `ReasoningTrace`。
- 默认选择第一个 MCP server 的第一个 capability/method。
- 返回 mock response。

只有 `mock_mode=False` 时才会调用 `_call_llm()`。

### 2.3 支持的 provider

`_call_llm()` 当前支持三种 provider：

|provider|调用方式|说明|
|---|---|---|
|`openai`|`OpenAI(...).chat.completions.create(...)`|可用于 OpenAI，也可用于 OpenAI-compatible endpoint|
|`anthropic`|`anthropic.Anthropic(...).messages.create(...)`|Claude 路径|
|`vllm`|`requests.post(base_url, json=payload)`|直接 POST 到 chat completions endpoint|

注意 `vllm` provider 的 `base_url` 在代码里被当作完整 URL 使用：

```python
url = self.base_url or "http://localhost:8000/v1/chat/completions"
requests.post(url, json=payload, timeout=60)
```

因此对于 `AgentBackbone(provider="vllm")`，严格来说应传入完整 endpoint，例如：

```text
http://localhost:8000/v1/chat/completions
```

但 `create_backbone("Llama-3.1-70B")` 当前默认读取：

```python
os.environ.get("VLLM_URL", "http://localhost:8000/v1")
```

如果环境变量也是 `http://host:port/v1`，当前 raw `requests.post()` 会打到 `/v1` 而不是 `/v1/chat/completions`，这和 `openai` SDK 风格的 `base_url` 语义不同。真实使用时建议把 `VLLM_URL` 设成完整 endpoint，或后续统一修正代码语义。

### 2.4 create_backbone 配置

`create_backbone(model_name, mock_mode=True, api_key=None)` 支持：

|model_name|provider|model|认证/URL|
|---|---|---|---|
|`GPT-4o`|`openai`|`gpt-4o`|`OPENAI_API_KEY`|
|`Claude-3.5-Sonnet`|`anthropic`|`claude-3-5-sonnet-20241022`|`ANTHROPIC_API_KEY`|
|`Gemini-1.5-Pro`|`openai`|`gemini-1.5-pro`|Google OpenAI-compatible URL + `GOOGLE_API_KEY`|
|`Llama-3.1-70B`|`vllm`|`meta-llama/Llama-3.1-70B-Instruct`|`VLLM_URL`|

`config.yaml` 里也列出了类似模型配置，但当前 `create_backbone()` 是硬编码配置，没有读取 `config.yaml`。

### 2.5 哪些评测会调用 agent

当前常规实验路径大多不会真实调用 agent：

- `experiments/run_all.py` 固定调用 `mock_mode=True`。
- `experiments/generate_tables.py`、`experiments/generate_figures.py` 也使用 mock 结果。
- `src/evaluation/eval_runner.py` 的非 mock 路径主要使用 `AttackGenerator` 直接生成消息和 trace，不经过真实 agent backbone。

真实 agent 调用主要在：

```bash
python experiments/run_live_table1.py --model GPT-4o
```

实际 CLI 中 `--agent_mock` 是布尔开关，默认 `False`，所以不传 `--agent_mock` 时会尝试真实调用 agent；只有传入 `--agent_mock` 才会使用 mock agent。它内部调用：

```python
agent = create_backbone(model_name, mock_mode=agent_mock)
agent.invoke(prompt, servers)
```

### 2.6 通过中转站统一调用 agent base model

如果要让实验中的 agent base model 统一从中转站调用，不能直接依赖现有 `create_backbone()`。原因是当前工厂对四个模型的 provider 是硬编码的：`GPT-4o` 走 OpenAI SDK，`Claude-3.5-Sonnet` 走 Anthropic SDK，`Gemini-1.5-Pro` 走 Google OpenAI-compatible endpoint，`Llama-3.1-70B` 走 raw `vllm`。这意味着同一个中转站地址不能通过现有工厂覆盖所有模型。

项目新增了独立的中转站适配入口，不改动原有 `src/agent_backbone.py` 和 `experiments/run_live_table1.py`：

- `src/agent_backbone_proxy.py`：提供 `ProxyAgentBackbone` 和 `create_proxy_backbone()`。
- `experiments/run_live_table1_proxy.py`：单模型 live Table 1 入口，内部把 agent backbone 替换为中转站版本。
- `experiments/run_live_multimodel_proxy.py`：依次跑四个论文 agent base model。

中转站当前这批 agent base model 支持的是 Chat Completions 格式，因此默认使用完整 endpoint：

```text
https://llm-api.net/v1/chat/completions
```

三个地址在当前适配器中的含义如下：

|地址|推荐用法|说明|
|---|---|---|
|`https://llm-api.net/v1/chat/completions`|当前默认值，推荐使用|当前 agent prompt 是 `messages` 结构，和 Chat Completions 最匹配|
|`https://llm-api.net/v1`|可用|适配器会按 Chat Completions 补成 `/v1/chat/completions`|
|`https://llm-api.net/v1/responses`|当前不推荐|只有显式传 `--agent_api_style responses` 时才会走 Responses API；当前中转站模型既然支持 Chat Completions，就不要使用该路径|

默认模型映射：

|实验模型名|发送给中转站的 model id|
|---|---|
|`GPT-4o`|`gpt-4o`|
|`Claude-3.5-Sonnet`|`claude-3-5-sonnet-20241022`|
|`Gemini-1.5-Pro`|`gemini-1.5-pro`|
|`Llama-3.1-70B`|`meta-llama/Llama-3.1-70B-Instruct`|

如果中转站使用自己的模型别名，可以通过 `LLM_API_MODEL_MAP` 或 `--agent_model_map` 覆盖。例如：

```powershell
$env:LLM_API_KEY="你的中转站 key"
$env:LLM_API_MODEL_MAP='{"GPT-4o":"relay-gpt-4o","Claude-3.5-Sonnet":"relay-claude-3-5-sonnet"}'
```

单模型调用示例：

```powershell
$env:LLM_API_KEY="你的中转站 key"
python experiments\run_live_table1_proxy.py `
  --agent_base_url https://llm-api.net/v1/chat/completions `
  --model GPT-4o `
  --runs 1 `
  --max_scenarios 5
```

四个 agent base model 依次调用：

```powershell
$env:LLM_API_KEY="你的中转站 key"
python experiments\run_live_multimodel_proxy.py `
  --agent_base_url https://llm-api.net/v1/chat/completions `
  --runs 1 `
  --max_scenarios 5
```

当前 `--agent_api_style` 默认就是 `chat`，所以一般不需要显式传入。适配器发出的请求体是 Chat Completions 格式：

```json
{
  "model": "gpt-4o",
  "messages": [
    {"role": "system", "content": "..."},
    {"role": "user", "content": "..."}
  ],
  "temperature": 0.0,
  "max_tokens": 1024
}
```

注意：该适配器只负责 agent base model。RTV judge 默认仍是规则化 `ConstrainedJudgeModel`；如果要让 judge 也走中转站，需要另外配置 `--judge_mode llm`、`--judge_provider vllm` 和 judge endpoint。

## 3. Judge 模型如何调用

### 3.0 论文中的 RTV judge 设定 vs 当前代码默认实现

论文 `docs/references/AAAI2027_Agent.pdf` 中的 RTV 不是纯规则打分器。论文设定是：Agent 在工具调用前生成结构化 reasoning trace，RTV 使用一个 constrained judge model 对 trace 做异常检测。该 judge 是轻量 instruction-tuned verifier，实验部分明确写为 fine-tuned `Qwen2.5-7B-Instruct`，并使用 constrained decoding，`temperature=0`、`max 512 tokens`。

论文中的 judge 输出三类异常分数：

- `CAI`：Context-Action Inconsistency，检查 action 是否不能从 observation/inference 推出。
- `OAV`：Origin-Awareness Violation，检查是否把 server/tool/memory 来源内容误当成 user instruction，依赖 PTG origin tags。
- `IAD`：Intent-Action Divergence，检查工具调用意图和 reasoning trace 的 decision 是否冲突。

论文算法中，judge 对 `(T, Iv, L)` 输出 `(σCAI, σOAV, σIAD)`，任一分数超过对应阈值 `τc` 就触发 `Escalate`。论文还在延迟分析中把 `RTV judge inference` 作为独立开销项，报告约 `4.7ms`，并说明该开销受 `512-token` 输出上限和 7B judge 模型约束。

因此结论是：当前文档中“RTV 目前默认用规则化打分”这句话对当前仓库代码是准确的，但这不是论文的最终设定。论文级复现应部署 fine-tuned `Qwen2.5-7B-Instruct` constrained judge，并通过 `LLMJudgeInterface`/adapter 接入 RTV；当前默认 `ConstrainedJudgeModel` 只能视为规则化 fallback 或工程原型。

### 3.1 默认 RTV judge：规则化 ConstrainedJudgeModel

`ReasoningTraceVerifier` 默认构造如下：

```python
self.judge = judge or ConstrainedJudgeModel()
```

`ConstrainedJudgeModel.score_trace()` 不调用 LLM，而是用规则分别计算：

- `CAI`：decision 中出现危险动词，但 observation/inference 中没有对应上下文时升高分数。
- `OAV`：tool response 或 memory 被当作 user origin，或 server origin 被当作 user instruction 时升高分数。
- `IAD`：decision 中出现危险动词，但 intent summary 中没有对应意图时升高分数。

默认阈值：

```python
CAI: 0.65
OAV: 0.60
IAD: 0.70
```

`ReasoningTraceVerifier.verify()` 调用 `judge.score_trace(...)` 后，按阈值生成 `flagged_anomalies`。如果存在异常，RTV 返回不通过，并由 ReasoningGuard 升级为 `ESCALATE`。

### 3.2 LLM judge 接口

`src/judge.py::LLMJudgeInterface` 提供真实 LLM judge 调用：

```python
judge = LLMJudgeInterface(
    provider="vllm",
    model="models/judge_qwen2.5-7b/final",
    base_url="http://localhost:8000/v1/chat/completions",
)
scores = judge.score(trace_text, intent_summary, origin_tags)
```

它会把 trace、intent summary、origin tags 填入 `JUDGE_PROMPT_TEMPLATE`，要求模型只返回 JSON：

```json
{"CAI": 0.0, "OAV": 0.0, "IAD": 0.0}
```

支持三种 provider：

|provider|调用方式|
|---|---|
|`openai`|OpenAI SDK chat completions|
|`anthropic`|Anthropic messages API|
|`vllm`|`requests.post(base_url, json=payload)`|

`vllm` 的 `base_url` 会经过 `normalize_chat_completions_url()` 归一化，支持传完整 endpoint 或 `/v1` 根路径：

```python
url = normalize_chat_completions_url(self.base_url or DEFAULT_LOCAL_JUDGE_URL)
```

例如 `http://host:port/v1`、`http://host:port/v1/chat/completions` 和 `http://host:port/chat/completions` 都会归一到 Chat Completions endpoint。当前 `src/judge.py` 发出的实际 payload 是：

```json
{
  "model": "qwen2.5-7B-Instruct",
  "messages": [{"role": "user", "content": "..."}],
  "temperature": 0.0,
  "max_tokens": 100
}
```

注意：当前项目侧 `_call_vllm()` 没有发送 `do_sample=false`，请求超时硬编码为 30 秒。如果 judge endpoint 抛错或模型返回不可解析文本，runtime audit log 会记录 `judge.call_failed` 或 `judge.parse_failed`；非 strict 模式下仍会记录 `judge.default_scores_used` 并返回 `CAI/OAV/IAD=0.1`，`--strict_runtime` 下会直接抛异常中止。

### 3.3 LLM judge 如何接入 RTV

`LLMJudgeInterface` 本身的方法是 `score(...)`，而 RTV 期望 judge 对象有：

```python
score_trace(trace, intent_summary, origin_tags)
thresholds
```

所以 `src/evaluation/live_table1.py` 定义了 `ExternalJudgeAdapter`：

```python
class ExternalJudgeAdapter:
    def score_trace(self, trace, intent_summary, origin_tags=None):
        return self.interface.score(trace.to_text(), intent_summary, origin_tags)
```

当运行：

```bash
python experiments/run_live_table1.py --judge_mode llm
```

`make_judge()` 会创建 `ExternalJudgeAdapter`，然后把它注入：

```python
ReasoningTraceVerifier(judge=judge)
ReasoningGuard(rtv=ReasoningTraceVerifier(judge=judge))
```

这条链路才会真实调用 LLM judge。

### 3.4 Judge 微调路径

项目提供了 judge 微调数据和训练脚本：

- `src/finetune/judge_dataset.py`：合成 `data/judge_finetune/train.jsonl` 和 `val.jsonl`。
- `src/finetune/finetune_judge.py`：用 `Qwen/Qwen2.5-7B-Instruct` 做 LoRA SFT，默认输出到 `models/judge_qwen2.5-7b/final`。

训练脚本文档中给出的调用目标是：

```python
LLMJudgeInterface(provider="vllm", model=output_dir)
```

但当前只读检查没有发现：

- `data/judge_finetune/train.jsonl`
- `data/judge_finetune/val.jsonl`
- `models/judge_qwen2.5-7b/final`
- `adapter_config.json`
- `config.json`
- `*.safetensors`

因此当前项目里还没有可直接部署的 judge 微调产物。

## 4. `/home/liuenguang24/deployed_models` 部署方式分析

### 4.1 当前部署服务形态

部署目录核心文件：

```text
/home/liuenguang24/deployed_models/
  base_model_handler.py
  vlm_serve.py
  models/
    qwen25_instruct_handler.py
    llava_onevision_8b_handler.py
    llava_7b_model_handler.py
  submit.sh
```

`vlm_serve.py` 使用 FastAPI 暴露：

```text
POST /v1/chat/completions
```

`base_model_handler.py` 定义了接近 OpenAI chat completions 的请求/响应结构：

- request:
  - `model`
  - `messages`
  - `max_tokens`
  - `do_sample`
  - `temperature`
- response:
  - `choices[0].message.content`

这和 `LLMJudgeInterface._call_vllm()` 读取的字段兼容：

```python
content = data["choices"][0]["message"]["content"]
```

### 4.2 当前默认加载 Qwen2.5-7B-Instruct

当前服务部署的模型路径为：

```text
/home/liuenguang24/models/Qwen2.5-7B-Instruct
```

当前已验证的对外模型名为：

```text
qwen2.5-7B-Instruct
```

项目侧默认 judge model 已改为 `qwen2.5-7B-Instruct`，默认 endpoint 为 `http://aias-compute-4:14545/v1/chat/completions`。

### 4.3 当前 handler 对 judge 的兼容状态

新增的 `Qwen25InstructHandler` 已处理以下兼容点：

1. **纯文本 Qwen handler**

   使用 `AutoTokenizer` + `AutoModelForCausalLM` 加载 `/home/liuenguang24/models/Qwen2.5-7B-Instruct`。

2. **完整 messages 处理**

   使用 tokenizer chat template 处理完整 `request.messages`，不再只取最后一条 user message。

3. **deterministic generation**

   当 `temperature=0.0` 或 `do_sample=false` 时强制 greedy decoding，避免 transformers 在采样模式下接收非法 `temperature=0.0`。

   需要区分服务端能力和当前项目侧请求：`/home/liuenguang24/deployed_models` 的 request schema 支持 `do_sample`，但当前 `src/judge.py` 只发送 `temperature=0.0` 和 `max_tokens=100`，没有发送 `do_sample=false`。如果需要强约束 greedy decoding，应在项目侧 payload 中补上 `do_sample=false`，或确认服务端会在 `temperature=0.0` 时自动转为 greedy。

4. **仍缺少 JSON 约束**

   `LLMJudgeInterface._parse_response()` 可以从文本中截取 JSON，但如果模型输出不稳定，异常时会回退到：

   ```python
   {"CAI": 0.1, "OAV": 0.1, "IAD": 0.1}
   ```

   这会偏向放过风险。部署 judge 时应尽量使用 constrained decoding、response format、停止词或后处理重试，确保输出合法 JSON。

### 4.4 判断：是否满足 judge 调用

|检查项|当前状态|结论|
|---|---|---|
|是否有 `/v1/chat/completions` endpoint|有|接口形态可复用|
|响应是否有 `choices[0].message.content`|有|可被 `LLMJudgeInterface` 解析|
|是否加载 judge 模型名 `qwen2.5-7B-Instruct`|是|满足本地 base judge 调用|
|是否有 Qwen/Qwen2.5 文本模型 handler|是|满足|
|是否有 judge 微调权重/LoRA adapter|未使用|不满足论文级 fine-tuned judge|
|是否默认 deterministic JSON 输出|部分满足|项目侧使用 `temperature=0.0`，但未发送 `do_sample=false`，也没有 constrained JSON decoding；需要预检返回格式。|

最终结论：当前 `/home/liuenguang24/deployed_models` 已可作为本地 Qwen base judge 服务使用。若要论文级复现，还需要部署 fine-tuned RTV judge 权重或 LoRA 合并产物，并增强 JSON 输出约束。正式实验建议使用 runtime audit log 和 `--strict_runtime`，避免 judge 调用或解析失败时静默返回低风险默认分数。

## 5. 推荐接入方式

### 5.1 当前采用：复用 `/home/liuenguang24/deployed_models`

当前 vLLM 安装不成功，因此使用现有 FastAPI 服务部署 Qwen judge。启动方式：

```bash
cd /home/liuenguang24/deployed_models
sbatch submit.sh
```

最小 curl 验证：

```bash
curl http://aias-compute-4:14545/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{
    "model": "qwen2.5-7B-Instruct",
    "messages": [{"role": "user", "content": "Respond only JSON: {\"CAI\":0.0,\"OAV\":0.0,\"IAD\":0.0}"}],
    "max_tokens": 100,
    "temperature": 0.0,
    "do_sample": false
  }'
```

这个 curl 显式传了 `do_sample=false` 用于验证服务端 greedy/JSON 行为；当前 `src/judge.py` 的正式评测请求还没有这个字段，只传 `temperature=0.0` 和 `max_tokens=100`。

live 评测接入：

```bash
python experiments/run_live_table1.py \
  --judge_mode llm \
  --judge_provider vllm \
  --judge_model qwen2.5-7B-Instruct \
  --judge_base_url http://aias-compute-4:14545/v1/chat/completions
```

当前代码也支持把 `--judge_base_url` 写成 `http://aias-compute-4:14545/v1`，会自动补成 `/v1/chat/completions`。

### 5.2 可选：标准 vLLM OpenAI-compatible 服务

如果后续 vLLM 可用，仍可改用标准 vLLM 服务部署同一模型或 fine-tuned judge：

```bash
python -m vllm.entrypoints.openai.api_server \
  --model /home/liuenguang24/models/Qwen2.5-7B-Instruct \
  --served-model-name models/Qwen2.5-7B-Instruct \
  --host 0.0.0.0 \
  --port 8000
```

## 6. 后续代码改进建议

如果后续要把真实模型调用做成稳定实验链路，建议优先改这几处：

1. 统一 `base_url` 语义。

   当前 `LLMJudgeInterface` 已能把 `.../v1` 自动补成 `.../v1/chat/completions`。`AgentBackbone(provider="vllm")` 仍有类似语义差异，后续也应统一。

2. 让 `create_backbone()` 和 judge 配置读取 `config.yaml`。

   目前模型配置分散在 `config.yaml`、`create_backbone()`、`live_table1.py` CLI 默认值中，容易不一致。

3. 将 LLM judge 接入 RTV 的方式提升为通用工厂。

   当前 `ExternalJudgeAdapter` 只在 `live_table1.py` 内部定义，常规 `ReasoningGuard()` 默认仍是规则 judge。可新增正式 judge factory，避免路径分裂。

4. 增加 judge 输出严格性。

   至少应加入非法 JSON 重试、分数范围裁剪、缺字段报错或显式 fallback 标记，避免静默回退到低风险分数。

5. 给 live 模型调用增加 smoke test。

   最小测试应覆盖：

   - agent vLLM endpoint 能返回可解析 `TOOL_CALL`
   - judge vLLM endpoint 能返回合法 CAI/OAV/IAD JSON
   - `ReasoningTraceVerifier(judge=ExternalJudgeAdapter(...))` 可以完成一次 verify

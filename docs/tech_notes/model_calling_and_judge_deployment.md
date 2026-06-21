# Agent 基础模型、Judge 调用与本地部署兼容性分析

更新日期：2026-06-21

本文档整理当前项目如何调用 agent 基础模型、RTV judge 模型如何接入，以及 `/home/liuenguang24/deployed_models` 这种本地部署方式是否能满足 judge 调用。结论基于当前仓库代码和对部署目录的只读检查。

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

- 该目录下的服务提供了 `/v1/chat/completions`，响应结构接近 OpenAI chat completions，理论上可作为 `LLMJudgeInterface(provider="vllm")` 的 HTTP endpoint。
- 但当前服务只注册了 `models/LLaVA-OneVision-1.5-8B-Instruct`，没有注册 `models/judge_qwen2.5-7b/final` 或 `Qwen/Qwen2.5-7B-Instruct`。
- 当前仓库和部署目录未发现 judge 微调产物、LoRA adapter 或常见 Hugging Face 权重配置文件。
- 因此，现有部署目录“接口形态可复用”，但“当前内容不能直接满足 judge 模型调用”。要满足 judge，需要额外加载文本 judge 模型，或改用标准 vLLM/OpenAI-compatible 服务部署 Qwen judge。

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

中转站给出的三个地址含义如下：

|地址|推荐用法|说明|
|---|---|---|
|`https://llm-api.net/v1`|推荐默认值|适配器会按 Chat Completions 补成 `/v1/chat/completions`|
|`https://llm-api.net/v1/chat/completions`|推荐用于当前项目|当前 agent prompt 是 `messages` 结构，和 Chat Completions 最匹配|
|`https://llm-api.net/v1/responses`|仅在中转站确认支持 Responses API 时使用|适配器会改用 `input` 和 `max_output_tokens`，并解析 `output_text`|

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
  --agent_base_url https://llm-api.net/v1 `
  --agent_api_style chat `
  --model GPT-4o `
  --runs 1 `
  --max_scenarios 5
```

四个 agent base model 依次调用：

```powershell
$env:LLM_API_KEY="你的中转站 key"
python experiments\run_live_multimodel_proxy.py `
  --agent_base_url https://llm-api.net/v1/chat/completions `
  --agent_api_style chat `
  --runs 1 `
  --max_scenarios 5
```

如果确认中转站支持 Responses API，可以改为：

```powershell
python experiments\run_live_table1_proxy.py `
  --agent_base_url https://llm-api.net/v1/responses `
  --agent_api_style responses `
  --model GPT-4o `
  --runs 1 `
  --max_scenarios 5
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

和 agent 一样，`vllm` 的 `base_url` 在这里也是完整 endpoint 语义：

```python
url = self.base_url or "http://localhost:8000/v1/chat/completions"
```

如果传 `http://host:port/v1`，当前代码不会自动追加 `/chat/completions`。

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

### 4.2 当前只加载了 LLaVA-OneVision

`vlm_serve.py` 当前启动时只注册：

```python
llava_onevision_id = "models/LLaVA-OneVision-1.5-8B-Instruct"
model_handlers[llava_onevision_id] = OneVisionHandler(model_id=llava_onevision_id)
```

所以如果 judge 请求使用默认模型名：

```text
models/judge_qwen2.5-7b/final
```

该服务会返回模型不存在。除非把 `--judge_model` 改成 `models/LLaVA-OneVision-1.5-8B-Instruct`，但这不等于满足 judge 要求，因为它不是为 RTV CAI/OAV/IAD JSON 打分训练或配置的文本 judge。

### 4.3 当前 handler 对 judge 的兼容问题

即使复用这个 FastAPI 框架，也有几个问题需要处理：

1. **没有 Qwen judge handler**

   当前只有 LLaVA/LLaVA-OneVision handler。judge 是纯文本分类/打分任务，应使用 `AutoTokenizer` + `AutoModelForCausalLM` 或 vLLM 加载 Qwen/Qwen2.5 judge。

2. **没有加载 judge 权重**

   部署目录中没有发现 `config.json`、`adapter_config.json`、`tokenizer_config.json`、`*.safetensors` 等常见模型文件。

3. **messages 处理过窄**

   `OneVisionHandler.process_request()` 只取最后一条 user message：

   ```python
   user_message = request.messages[-1]
   ```

   对 `LLMJudgeInterface` 当前的单 user prompt 尚可，但对 agent 的 system+user 多消息会丢 system prompt。若未来复用给 agent，应完整应用 chat template。

4. **默认采样不适合 judge**

   `ChatCompletionRequest` 默认：

   ```python
   do_sample: True
   temperature: 0.5
   ```

   judge 需要稳定 JSON 输出，应使用 `temperature=0.0`，并在 handler 中把 `temperature=0.0` 映射为 deterministic generation，避免 sampling 参数冲突。

5. **缺少 JSON 约束**

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
|是否加载 judge 模型名 `models/judge_qwen2.5-7b/final`|否|不满足|
|是否有 Qwen/Qwen2.5 文本模型 handler|否|不满足|
|是否有 judge 微调权重/LoRA adapter|未发现|不满足|
|是否默认 deterministic JSON 输出|否|不满足正式 judge 要求|

最终结论：当前 `/home/liuenguang24/deployed_models` 方式可以作为部署框架参考，但不能直接满足 judge 模型调用。最小可行改造是新增一个 Qwen text handler，注册 judge 模型，并确保 endpoint、模型名、JSON 输出和 deterministic 推理都与 `LLMJudgeInterface` 对齐。

## 5. 推荐接入方式

### 5.1 首选：标准 vLLM OpenAI-compatible 服务

如果目标是尽快让 `--judge_mode llm` 跑通，建议使用标准 vLLM 服务，而不是复用 VLM handler：

```bash
python -m vllm.entrypoints.openai.api_server \
  --model models/judge_qwen2.5-7b/final \
  --served-model-name models/judge_qwen2.5-7b/final \
  --host 0.0.0.0 \
  --port 8000
```

然后运行：

```bash
python experiments/run_live_table1.py \
  --model GPT-4o \
  --judge_mode llm \
  --judge_provider vllm \
  --judge_model models/judge_qwen2.5-7b/final \
  --judge_base_url http://localhost:8000/v1/chat/completions
```

注意：当前代码的 `judge_base_url` 要传完整 `/v1/chat/completions`。

### 5.2 复用 `/home/liuenguang24/deployed_models` 的最小改造

如果必须复用现有部署框架，建议做以下改造：

1. 新增 `QwenJudgeHandler(BaseModelHandler)`：
   - `AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)`
   - `AutoModelForCausalLM.from_pretrained(model_id, torch_dtype="auto", device_map="auto", trust_remote_code=True)`
   - 使用 tokenizer chat template 处理完整 `request.messages`
   - `generate(max_new_tokens=request.max_tokens, do_sample=False)` 或在 `temperature=0.0` 时禁用采样

2. 在 `vlm_serve.py` 注册：

   ```python
   judge_id = "models/judge_qwen2.5-7b/final"
   model_handlers[judge_id] = QwenJudgeHandler(model_id=judge_id)
   ```

3. 确认该路径下确实存在完整模型或可加载的 LoRA 合并产物。

4. 用一个最小 curl 验证：

   ```bash
   curl http://localhost:14545/v1/chat/completions \
     -H 'Content-Type: application/json' \
     -d '{
       "model": "models/judge_qwen2.5-7b/final",
       "messages": [{"role": "user", "content": "Respond only JSON: {\"CAI\":0.0,\"OAV\":0.0,\"IAD\":0.0}"}],
       "max_tokens": 100,
       "temperature": 0.0,
       "do_sample": false
     }'
   ```

5. 再用项目 live 评测接入：

   ```bash
   python experiments/run_live_table1.py \
     --judge_mode llm \
     --judge_provider vllm \
     --judge_model models/judge_qwen2.5-7b/final \
     --judge_base_url http://localhost:14545/v1/chat/completions
   ```

## 6. 后续代码改进建议

如果后续要把真实模型调用做成稳定实验链路，建议优先改这几处：

1. 统一 `base_url` 语义。

   当前 OpenAI SDK 的 `base_url` 通常是 `.../v1`，但 raw `requests.post()` 路径期望完整 `.../v1/chat/completions`。建议新增 helper，把 `.../v1` 自动补成 `.../v1/chat/completions`。

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

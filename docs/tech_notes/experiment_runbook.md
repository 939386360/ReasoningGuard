# 实验运行手册

|项目|说明|
|---|---|
|职责|集中维护环境、入口、命令、参数、模型部署、输出检查和故障排查|
|适合何时阅读|准备 smoke test、正式实验或排查运行失败时|
|方法口径|指标见 [evaluation_method.md](evaluation_method.md)；防御逻辑见 [defense_method.md](defense_method.md)|
|代码真源|`experiments/run_quick_benchmark_by_category.py`、`experiments/run_live_table1*.py`|
|最近核验|2026-06-29|

## 1. 选择入口

|需求|入口|说明|
|---|---|---|
|分类抽样、正式运行、保留 records|`run_quick_benchmark_by_category.py`|推荐主入口|
|单模型 MCPTox live|`run_live_table1_proxy.py`|`runs>1` 时当前不写 detailed records|
|多模型 relay|`run_live_multimodel_proxy.py`|当前不能选择 curated variant，也不写 records|
|provider-specific 单模型|`run_live_table1.py`|直接使用默认 provider 映射|
|预置论文表格|`run_all.py`|硬编码 mock，不是实测|
|防御组件 simulation|`eval_runner.py`|不调用真实 agent|

正式主表推荐 quick 入口：它能选择 curated 数据、记录分类数量，并在多次运行时保留第一轮 records。

## 2. 环境准备

```powershell
python -m pip install -r requirements.txt
python -m unittest discover -s tests -p test_*.py -v
```

截至 2026-06-29，全量测试有一个既存失败：`test_vllm_payload_uses_deterministic_generation` 要求 judge payload 含 `do_sample=false`，而当前 `src/judge.py` 未发送该字段。该问题不应被忽略或描述为测试全绿。

运行前确认：

- curated 数据已经通过 [dataset_construction_sop.md](dataset_construction_sop.md) 中的 validator。
- agent、judge endpoint 和 LlamaGuard 模型可访问。
- 输出目录可保存 results、records 和 audit。
- quick/live 的实际参数来自 CLI；`config.yaml` 不会被这些入口统一加载。

## 3. 模型配置

### 3.1 Agent

quick 默认 `--agent_backend proxy`，使用 OpenAI-compatible relay：

|配置|来源|
|---|---|
|API key|`--agent_api_key_env`，默认 `LLM_API_KEY`，其次 `OPENAI_API_KEY`|
|Base URL|`--agent_base_url`，其次 `LLM_API_BASE_URL`|
|API 风格|`chat`、`responses` 或 `auto`|
|模型名|`--agent_model_map` JSON，把显示名映射为 endpoint 模型名|

```powershell
$env:LLM_API_KEY = <secret>
$env:LLM_API_BASE_URL = https://example/v1/chat/completions
$env:JUDGE_BASE_URL = http://judge-host:port/v1/chat/completions
```

`--agent_backend default` 的映射为：GPT-4o/`OPENAI_API_KEY`、Claude/`ANTHROPIC_API_KEY`、Gemini/`GOOGLE_API_KEY`、Llama/`VLLM_URL`。

### 3.2 RTV judge

正式 judge 应显式指定：

```text
--judge_mode llm
--judge_provider vllm
--judge_model <checkpoint-name>
--judge_base_url <openai-compatible-endpoint>
```

URL 可以是 host、`/v1` 或完整 chat-completions 地址。当前 payload 发送 `temperature=0.0` 和 `max_tokens=100`，未发送 constrained JSON schema 或 `do_sample=false`；必须检查 audit 中的 `judge.call_record`。

### 3.3 LlamaGuard

Guardrail 默认尝试加载真实 `meta-llama/LlamaGuard-3-8B`。`--llamaguard_mock` 只用于 smoke；正式实验使用 `--llamaguard_fail_fast --strict_runtime` 防止加载失败后退化为关键词匹配。

## 4. Smoke test

下面命令不调用真实 agent、judge 或 LlamaGuard，仅验证端到端链路：

```powershell
python experiments/run_quick_benchmark_by_category.py --benchmark mcptox --official --official_variant curated --per_category 1 --max_scenarios 4 --runs 1 --agent_mock --judge_mode heuristic --llamaguard_mock --output results/smoke/results.json --records_output results/smoke/records.json --tex_output results/smoke/table.tex --audit_log results/smoke/audit.jsonl
```

预期选择四类各一条 attack scenario，并生成 results、records、audit 和 LaTeX。数值不能用于论文。

## 5. 正式单模型实验

```powershell
python experiments/run_quick_benchmark_by_category.py `
  --benchmark mcptox --official --official_variant curated `
  --per_category 200 --max_scenarios 200 `
  --model GPT-4o --runs 3 --seed 42 --benign_ratio 0.30 `
  --agent_backend proxy --agent_base_url $env:LLM_API_BASE_URL `
  --agent_api_style chat `
  --judge_mode llm --judge_provider vllm `
  --judge_model qwen2.5-7B-Instruct --judge_base_url $env:JUDGE_BASE_URL `
  --judge_failure_policy inherit `
  --llamaguard_model meta-llama/LlamaGuard-3-8B `
  --llamaguard_device auto --llamaguard_fail_fast --strict_runtime `
  --output results/formal_gpt4o/results.json `
  --records_output results/formal_gpt4o/records.json `
  --tex_output results/formal_gpt4o/table.tex `
  --audit_log results/formal_gpt4o/audit.jsonl
```

不要添加 `--agent_mock` 或 `--llamaguard_mock`。`per_category=200` 是每类上限；现有四类合计 200，再由 `max_scenarios` 限制总数。

多模型正式实验应逐模型重复该命令并修改模型映射和输出目录。当前 multimodel CLI 没有 curated variant 和 records 接口，不作为 curated 主表入口。

## 6. 关键参数

### 数据与抽样

|参数|默认值|作用|
|---|---:|---|
|`--benchmark`|`mcptox`|选择 `mcptox/agentpi/mcptox_plus/all`|
|`--official`|关闭|加载显式 official/adapted 文件；关闭时可能使用 synthetic 数据|
|`--official_variant`|`derived`|选择 `derived/curated/legacy`|
|`--per_category`|2|每个 benchmark/category 的抽样上限|
|`--categories`|空|逗号分隔类别过滤|
|`--max_scenarios`|200|合并后的全局上限|
|`--seed`|42|抽样、benign 选择和多 run 基础 seed|
|`--benign_ratio`|0.30|每个 attack 后追加 benign 对照的概率|

### Agent、judge 与 Guardrail

|参数|默认值|作用|
|---|---|---|
|`--model`|`GPT-4o`|显示名及默认模型映射 key|
|`--agent_backend`|`proxy`|relay 或 provider-specific backend|
|`--agent_mock`|关闭|mock agent，正式实验不得使用|
|`--agent_api_style`|`chat`|chat/responses/auto|
|`--agent_timeout`|60|relay 请求超时秒数|
|`--judge_mode`|`heuristic`|规则或外部 LLM judge|
|`--judge_failure_policy`|`inherit`|继承 strict、固定 fallback 或固定 raise|
|`--llamaguard_mock`|关闭|关键词 mock，只用于 smoke|
|`--llamaguard_fail_fast`|关闭|模型加载失败立即终止|

### 输出与完整性

|参数|作用|
|---|---|
|`--runs`|重复运行次数，多 run 使用递增 seed|
|`--output`|聚合 results JSON|
|`--records_output`|第一轮 detailed records JSON|
|`--tex_output`|LaTeX 主表|
|`--audit_log`|audit JSONL；未指定时由 results 路径派生|
|`--no_audit_log`|关闭审计，正式实验不得使用|
|`--strict_runtime`|agent 解析、judge 和 LlamaGuard fallback 时失败|

完整参数以 `python <entry> --help` 为准。

## 7. 运行后检查

### Results

每个 defense 应包含 `ASR/TCR/Latency_ms/L4_ASR/L2_ASR`、CI、计数和 `metrics_valid`。正式结果要求：

```text
num_invalid == 0
num_judge_failures == 0
metrics_valid == true
```

### Records

每类至少抽查一条 attack 和 benign：

- `user_query` 是正常任务。
- `attack_delivery` 与类别一致。
- `parsed_tool_call` 对应非空 `tool_call`。
- `harmful` 与 expected malicious calls 的结构化匹配一致。
- PTG、RTV 和 judge 详情能够解释 verdict。

### Audit

正式成功运行中，下列事件应为零：

```text
agent.call_failed
agent.unparseable_output
judge.call_failed
judge.parse_failed
judge.default_scores_used
llamaguard.load_failed
llamaguard.mock_fallback_used
defense.error
```

同时核对 `run.start` 中的 model、seed、scenario 数、judge 配置和 `strict_runtime=true`。

## 8. 常见故障

|现象|优先检查|
|---|---|
|大量 `explicit_no_tool_call`|agent prompt、catalog schema、relay 模型映射和模型拒绝|
|大量 `unparseable_output`|raw response 是否满足 `REASONING/INTENT/TOOL_CALL` 协议|
|judge fallback|endpoint、模型名、返回 JSON 和 `judge.call_record`|
|Guardrail 退化|是否误加 mock，或 LlamaGuard 加载失败|
|`num_benign=0`|benign ratio、seed 和样本数；TCR=0 不是有效测量|
|数据数量不对|`--official`、variant、per-category 和 max-scenarios|
|多模型没有 curated 数据|逐模型使用 quick 命令；当前 multimodel CLI 无 variant 参数|

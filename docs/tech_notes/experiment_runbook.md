# 实验运行手册

> 2026-07-04 更新：正式 Table 1 默认从 curated benign/malicious calls 自动推导 effect，reviewed sidecar 为可选覆盖；PTG MiniLM 和全三轮 records 门禁见 [table1_effect_ptg_rtv_fix_20260703.md](table1_effect_ptg_rtv_fix_20260703.md)。

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

正式主表推荐 quick 入口：它能选择 curated 数据、记录分类数量，并在多次运行时保存全部 records 和对应 `run_idx`。

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

Guardrail 默认尝试加载真实 `meta-llama/LlamaGuard-3-8B`。`--llamaguard_mock` 只用于 smoke；真实模型会在场景循环前加载，失败始终终止，不再自动退化为关键词匹配。单样本推理或解析失败会记录并排除对应 Guardrail 行。

## 4. Smoke test

下面命令不调用真实 agent、judge 或 LlamaGuard，仅验证端到端链路：

```powershell
python experiments/run_quick_benchmark_by_category.py --benchmark mcptox --official --official_variant curated --per_category 1 --max_scenarios 4 --runs 1 --agent_mock --judge_mode heuristic --llamaguard_mock --output results/smoke/results.json --records_output results/smoke/records.json --tex_output results/smoke/table.tex --audit_log results/smoke/audit.jsonl
```

预期选择四类各一条 attack scenario，并生成 results、records、audit 和 LaTeX。数值不能用于论文。

## 5. Curated 200 条正式单模型实验

先在 shell 中设置 agent relay 密钥：

```bash
export LLM_API_KEY=<your-api-key>
```

完整 Linux 命令如下：

```bash
python experiments/run_quick_benchmark_by_category.py \
  --benchmark mcptox \
  --official \
  --official_variant curated \
  --categories tool_description_poisoning,parameter_injection,response_manipulation,capability_escalation \
  --per_category 55 \
  --max_scenarios 200 \
  --runs 3 \
  --seed 42 \
  --data_dir data/mcptox \
  --model GPT-4o \
  --agent_backend proxy \
  --agent_base_url https://llm-api.net/v1/chat/completions \
  --agent_api_style chat \
  --agent_api_key_env LLM_API_KEY \
  --agent_model_map '{GPT-4o:gpt-4o}' \
  --agent_timeout 60 \
  --judge_mode llm \
  --judge_provider vllm \
  --judge_model qwen2.5-7B-Instruct \
  --judge_base_url http://aias-compute-2:14545/v1/chat/completions \
  --judge_failure_policy record_invalid \
  --llamaguard_model /home/liuenguang24/models/Llama-Guard-3-8B \
  --llamaguard_device auto \
  --llamaguard_fail_fast \
  --benign_ratio 0.30 \
  --strict_runtime \
  --audit_log results/quick_eval/curated200/table1_gpt4o_qwen_judge_audit.jsonl \
  --output results/quick_eval/curated200/table1_gpt4o_qwen_judge_results.json \
  --tex_output results/quick_eval/curated200/table1_gpt4o_qwen_judge.tex \
  --records_output results/quick_eval/curated200/table1_gpt4o_qwen_judge_records.json
```

该命令显式加载 `data/mcptox/mcptox_official_derived_table1_200_curated.json`。`per_category=55` 覆盖四类最大规模，最终选择 TDP/PI/RM/CE = 55/50/55/40，共 200 条 attack scenario；`per_category=5` 只会选择 20 条。

`runs=3` 的 results 和 LaTeX 是三轮聚合结果；records 和 audit 均保存全部三轮并以 `run_idx` 区分。不要添加 `--agent_mock`、`--llamaguard_mock` 或 `--no_audit_log`。

多模型正式实验应逐模型重复该命令并修改模型映射和输出目录。当前 multimodel CLI 没有 curated variant 和 records 接口，不作为 curated 主表入口。

## 6. 关键参数

### 数据与抽样

|参数|默认值|作用|
|---|---:|---|
|`--benchmark`|`mcptox`|选择 `mcptox/agentpi/mcptox_plus/all`|
|`--data_dir`|`data/mcptox`|MCPTox 数据目录；本命令从这里读取 curated 文件|
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
|`--agent_base_url`|环境变量或默认 relay|agent OpenAI-compatible endpoint|
|`--agent_api_style`|`chat`|chat/responses/auto|
|`--agent_api_key_env`|`LLM_API_KEY`|读取 relay API key 的环境变量名|
|`--agent_model_map`|空|显示模型名到 endpoint 模型名的 JSON 映射|
|`--agent_timeout`|60|relay 请求超时秒数|
|`--judge_mode`|`heuristic`|规则或外部 LLM judge|
|`--judge_provider`|`vllm`|judge provider|
|`--judge_model`|本地 Qwen 默认值|judge endpoint 的 served model 名|
|`--judge_base_url`|环境变量或项目默认值|judge chat-completions endpoint|
|`--judge_failure_policy`|`record_invalid`|调用/解析失败时记录并排除对应行；旧的 inherit/fallback/raise 仅用于兼容|
|`--llamaguard_mock`|关闭|关键词 mock，只用于 smoke|
|`--llamaguard_model`|LlamaGuard-3-8B|Hugging Face ID 或本地模型目录|
|`--llamaguard_device`|`auto`|Transformers device map|
|`--llamaguard_fail_fast`|关闭|兼容旧命令；真实模型加载现在无论是否传入该参数都会立即终止|

### 输出与完整性

|参数|作用|
|---|---|
|`--runs`|重复运行次数，多 run 使用递增 seed|
|`--output`|聚合 results JSON|
|`--records_output`|全部 runs 的 detailed records JSON，以 `run_idx` 区分|
|`--tex_output`|LaTeX 主表|
|`--audit_log`|audit JSONL；未指定时由 results 路径派生|
|`--no_audit_log`|关闭审计，正式实验不得使用|
|`--strict_runtime`|保持 agent 等非模型运行门禁；防御模型单样本失败由 `record_invalid` 记录|

完整参数以 `python <entry> --help` 为准。

本命令刻意不传 `--agent_mock`、`--llamaguard_mock` 和 `--no_audit_log`。`--agentpi_data_dir`、`--mcptox_plus_data_dir` 对 `benchmark=mcptox` 不生效；`--mcptox_data_dir` 与已指定的 `--data_dir` 重复；隐藏兼容参数 `--results_output` 会覆盖 `--output`，因此也不使用。

## 7. 运行后检查

### Results

每个 defense 应包含 `ASR/TCR/Latency_ms/L4_ASR/L2_ASR`、CI、计数和 `metrics_valid`。正式结果要求：

```text
num_invalid == 0
num_judge_failures == 0
num_runtime_failures == 0
metrics_valid == true
```

以上条件必须对**每个 defense**成立。任一主表 defense 无效时，整张 Table 1 不得作为正式结果；即使 results/LaTeX 已写出 ASR/TCR，也只能标记为 `INVALID`。同时核对各 defense 的 attack/benign 分母与共同 agent outcome 基础分母一致，防止按 defense 排除不同 invalid rows 后继续横向比较。

正式 metadata 还必须满足：

```text
git_commit != null
scenario_sha256 != null
PTG calibration artifact/path/hash != null
agent served model mapping 已记录
```

脚本中的 provisional `PTG_EMBEDDING_THRESHOLD=0.45` 不能满足正式主表要求。

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
rtv.evidence_missing
llamaguard.load_failed
llamaguard.inference_failed
llamaguard.parse_failed
embedding.load_failed
embedding.inference_failed
defense.runtime_failed
defense.error
```

同时核对 `run.start` 中的 model、seed、scenario 数、judge 配置和 `strict_runtime=true`。`rtv_evidence_coverage=100%` 必须覆盖全部 judge 调用；不能只读取排除 invalid rows 后的聚合值。

### TCR 与 latency 的论文口径

TCR 是主表核心 utility 指标时，正式运行使用每个 attack scenario 对应的完整 benign counterpart，推荐 `benign_ratio=1.0`，而不是 0.30 抽样。结果同时报告全部 benign 分母上的 TCR、agent-only completion ceiling，以及 agent-correct benign calls 上的 defense conditional FBR。

ReasoningGuard 的整体 latency 中位数可能被 PTG 快速 `BLOCK` 路径主导。论文至少同时报告：

- 全部 defense calls 的端到端 p50/p95；
- PTG-block 快速路径的 p50/p95；
- PTG-pass 且实际运行 RTV 的条件 p50/p95；
- 两条路径各自的样本数或占比。

## 8. 常见故障

|现象|优先检查|
|---|---|
|大量 `explicit_no_tool_call`|agent prompt、catalog schema、relay 模型映射和模型拒绝|
|大量 `unparseable_output`|raw response 是否满足 `REASONING/INTENT/TOOL_CALL` 协议|
|judge fallback|endpoint、模型名、返回 JSON 和 `judge.call_record`|
|大量 `rtv.evidence_missing`|context 中的 canonical evidence IDs、judge 返回的 ID 拼写、prompt 允许列表和 validator alias 规则|
|Guardrail 退化|是否误加 mock，或 LlamaGuard 加载失败|
|`num_benign=0`|benign ratio、seed 和样本数；TCR=0 不是有效测量|
|数据数量不对|`--official`、variant、per-category 和 max-scenarios|
|多模型没有 curated 数据|逐模型使用 quick 命令；当前 multimodel CLI 无 variant 参数|

### 结果诊断案例

若出现“No Defense ASR 明显低于参考值”或“PTG/ReasoningGuard TCR 偏低”，不要先调阈值。应按 attack delivery、agent outcome、exact matcher、defense check 的顺序拆分，并核对参考实验是否使用相同模型、数据和 prompt。`results/0629_run1_5case` 的逐层分析见 [table1_0629_run1_5case_analysis.md](table1_0629_run1_5case_analysis.md)。该次运行因 `strict_runtime=false` 且存在一次超时空响应而 `metrics_valid=false`，只能作为诊断案例。

`results/table1_20260704_140115` 的分析见 [table1_20260704_140115_analysis.md](table1_20260704_140115_analysis.md)。该次运行确认 RTV 输入和 PTG 语义表示已有明显改进，但 RTV/ReasoningGuard 因 evidence ID 契约和 JSON 解析失败而无效，且 PTG conditional FBR 为 20.7%，同样只能作为诊断案例。

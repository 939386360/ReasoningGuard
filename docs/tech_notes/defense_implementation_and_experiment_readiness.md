# 防御实现与真实实验就绪性

更新日期：2026-06-23

本文档只记录主表 live evaluation 是否真实运行、哪些地方仍会退化，以及正式实验该如何检查。模型调用与 judge 部署细节见 `docs/tech_notes/model_calling_and_judge_deployment.md`；agent 拒绝工具调用、`TOOL_CALL: None` 和 fallback tool call 的语义见 `docs/tech_notes/agent_tool_call_outcome_handling.md`。

## 1. 当前结论

当前 quick/live 主表链路可以跑“真实 agent API + 真实本地 Qwen judge API”的 live evaluation，但不能直接宣称完整论文级复现：

- `--agent_backend proxy` 且不传 `--agent_mock` 时，会调用中转站 agent。
- `--judge_mode llm --judge_provider vllm` 时，RTV 会通过 `LLMJudgeInterface` 调用 judge endpoint。
- 当前 judge 是 base `qwen2.5-7B-Instruct`，不是 fine-tuned RTV verifier。
- PTG/AttestMCP 使用真实检查逻辑，但 capability 来自静态 `build_mcp_servers()`，不是从真实 MCP registry/schema/permission/attestation metadata 动态读取。
- T3 memory provenance 在主表 live 链路中还没有完整接入真实 `memory_read_ids`。

主表评估不是每个 defense 单独跑一次 agent。`run_live_table1_scenarios_once()` 对每个 scenario 只调用一次 agent，然后把同一份 `MCPMessage`、`ReasoningTrace`、`intent_summary` 并列喂给所有 defense。

## 2. Defense 真实程度

|Defense|当前实现|真实程度与主要风险|
|---|---|---|
|`No Defense`|恒定 `APPROVE`|真实 baseline，不是 mock。|
|`AttestMCP`|PTG capability attestation，但关闭 intent/origin/cross-server 机制|不是 mock；仍依赖静态 server capability。|
|`Guardrail`|默认 LlamaGuard 检查 tool invocation|真实加载失败会 fallback 到关键词 mock；正式实验建议 `--strict_runtime` 或 `--llamaguard_fail_fast`。|
|`PTG-Only`|PTG attestation、intent entailment、origin tag、signature 等规则|不是 mock；但 capability/policy 是静态模拟，不是真实 MCP registry。|
|`RTV-Only`|`ReasoningTraceVerifier`|`--judge_mode heuristic` 是规则化 fallback；`--judge_mode llm` 才调用外部 judge。|
|`ReasoningGuard`|PTG 通过后再 RTV|PTG 若先 `BLOCK`，该样本不会调用 RTV/judge；普通 request 的 origin-tag 信息仍有限。|

## 3. 各 defense 实现说明

### 3.1 No Defense

`No Defense` 在 `_evaluate_all_defenses()` 中直接设置 `APPROVE`，不调用任何模型或规则。它是刻意恒定放行的未防御基线：攻击样本只要 agent 输出被判定 harmful 且没有被防御拦截，就计为攻击成功。

### 3.2 AttestMCP

`AttestMCPBaseline` 复用 `ProtocolAttestedToolGateway.verify_invocation()` 的 capability attestation 框架，但构造时关闭了 intent attestation、origin tags 和 cross-server consent。它主要检查 server 是否注册、method 是否属于该 server capability，并计算 intent signature；它不是 mock，但仍依赖静态 `build_mcp_servers()` capability。

### 3.3 Guardrail

`GuardrailBaseline` 默认调用 `LlamaGuardBaseline` 检查 tool invocation。正式实验不要传 `--llamaguard_mock`；如果 LlamaGuard 加载失败，非 strict 模式会退回关键词 mock，audit log 会记录 `llamaguard.load_failed` 和 `llamaguard.mock_fallback_used`。正式比较 Guardrail 时建议加 `--strict_runtime` 或 `--llamaguard_fail_fast`。

### 3.4 PTG-Only

`PTGOnlyBaseline` 只运行 `ProtocolAttestedToolGateway`，包括 server/method attestation、intent entailment、origin tag 检查和 intent signature。当前 `_verify_cross_server()` 仍是简化实现，server capability/policy 也来自静态 `build_mcp_servers()`，不是生产 MCP registry 或真实 attestation metadata。

### 3.5 RTV-Only

`RTVOnlyBaseline` 只运行 `ReasoningTraceVerifier`。`--judge_mode heuristic` 使用规则化 `ConstrainedJudgeModel`；`--judge_mode llm` 使用 `ExternalJudgeAdapter` 调用外部 judge endpoint。当前接入的是 base Qwen judge，不是 fine-tuned RTV verifier；judge 调用失败、解析失败和默认 `0.1` 分数都会进入 audit log，并随 `RTVResult.judge_record` 写入 records。

### 3.6 ReasoningGuard

`ReasoningGuard` 先运行 PTG，PTG 不通过直接 `BLOCK`；PTG 通过后才运行 RTV，RTV 不通过则 `ESCALATE`。因此它是真实组合了当前 PTG 和 RTV 两层逻辑，但当 PTG 已经拦截时不会再调用 judge；主表普通 request 的 origin-tag 信息也仍有限。

## 4. Runtime Audit Log

为避免“失败后继续跑但结果看起来正常”，当前评测入口已支持 JSONL runtime audit log。

新增参数：

- `--audit_log PATH`：指定 JSONL 日志路径。
- 默认不传时，从 `--output` 推导，例如 `results.json` 对应 `results_audit.jsonl`。
- `--no_audit_log`：关闭 audit log，仅建议临时调试使用。
- `--strict_runtime`：遇到关键退化路径直接抛异常中止。

关键事件会写入 audit log：

|事件|含义|
|---|---|
|`agent.call_failed`|agent API 调用异常。|
|`agent.empty_response`|agent 返回空文本。|
|`agent.explicit_no_tool_call`|agent 明确拒绝或决定不调用工具；不运行 defense，但按失败结果计入 ASR/TCR 分母。|
|`agent.unparseable_output`|agent response 既无合法 tool call，也无明确 no-tool；strict 下中断，非 strict 下记为 invalid。|
|`defense.skipped`|因为 agent 没有形成真实工具调用，所以该 defense 未运行。|
|`judge.call_failed`|judge endpoint/API 调用异常。|
|`judge.parse_failed`|judge 返回内容无法解析成 `CAI/OAV/IAD` JSON。|
|`judge.default_scores_used`|按 failure policy 使用了低风险默认分数 `0.1`。|
|`judge.call_record`|单次 judge 调用的完整 prompt、原始响应、解析状态、最终分数、fallback 与异常信息。|
|`llamaguard.load_failed`|LlamaGuard 模型加载失败。|
|`llamaguard.mock_fallback_used`|LlamaGuard fallback 到关键词 mock。|
|`defense.verdict`|每个 defense 的逐样本 verdict/reason/latency。|
|`run.summary` / `multi_run.summary`|运行汇总和 audit 计数。|

正式实验建议加 `--strict_runtime --judge_failure_policy raise`。如果需要先记录失败、跑完整个实验，再改 judge prompt/parser，可使用 `--strict_runtime --judge_failure_policy fallback`。后者不会因 judge 调用或解析失败中止，但必须检查 audit log 中的 `judge.call_record`，并检查结果中的 `metrics_valid`、`num_invalid`、`num_judge_failures` 和 `judge_fallback_rate`。agent 明确 no-tool 时不会再构造工具调用，也不会运行 defense。

## 5. 推荐正式命令

当前 quick/live CLI 默认使用 synthetic/generated 数据集口径；不要加 `--official`，否则 MCPTox 会读取本地 1348 条 adapted official 文件。

`--per_category` 是每类抽样数，不是总样本数。MCPTox synthetic 当前 4 类：

- `--per_category 5 --max_scenarios 200` 只会选 20 条 attack scenarios。
- 若目标是 synthetic 200 条，应使用 `--per_category 55 --max_scenarios 200`。

MCPTox 论文主表全量口径是 200 条 attack scenarios。当前项目要用默认 synthetic 200 口径，不要传 `--official`；本地 `data/mcptox/mcptox_official.json` 是 1348 条 adapted raw 数据，只适合额外对比。

全量主表命令：

```bash
export LLM_API_KEY="你的中转站 key"

python experiments/run_quick_benchmark_by_category.py \
  --benchmark mcptox \
  --per_category 55 \
  --max_scenarios 200 \
  --runs 3 \
  --seed 42 \
  --data_dir data/mcptox \
  --model GPT-4o \
  --agent_backend proxy \
  --agent_base_url "https://llm-api.net/v1/chat/completions" \
  --agent_api_style chat \
  --agent_api_key_env LLM_API_KEY \
  --agent_model_map '{"GPT-4o":"gpt-4o"}' \
  --agent_timeout 60 \
  --judge_mode llm \
  --judge_provider vllm \
  --judge_model qwen2.5-7B-Instruct \
  --judge_base_url "http://aias-compute-4:14545/v1/chat/completions" \
  --judge_failure_policy raise \
  --llamaguard_model "/home/liuenguang24/models/Llama-Guard-3-8B" \
  --llamaguard_device auto \
  --llamaguard_fail_fast \
  --strict_runtime \
  --benign_ratio 0.30 \
  --audit_log "results/quick_eval/table1_gpt4o_qwen_judge_audit.jsonl" \
  --output "results/quick_eval/table1_gpt4o_qwen_judge_results.json" \
  --tex_output "results/quick_eval/table1_gpt4o_qwen_judge.tex" \
  --records_output "results/quick_eval/table1_gpt4o_qwen_judge_records.json"
```

该参数组合预期输出：

- `Total selected attack scenarios: 200`。
- 类别分布为 `tool_description_poisoning=55`、`parameter_injection=50`、`response_manipulation=55`、`capability_escalation=40`。
- `--benign_ratio 0.30` 会额外抽取 benign 对照样本，不改变 200 条 attack scenarios 的主表口径。

正式实验不要加：

```bash
--agent_mock
--llamaguard_mock
--no_audit_log
```

## 6. 运行后检查

至少检查：

- stdout 中 `Total selected attack scenarios` 是否为预期数量；MCPTox 主表全量命令应为 `200`。
- audit log 中没有 `level=ERROR`。
- audit log 中没有 `fallback_used=true` 或 `mock_used=true`。
- audit log 中没有 `judge.default_scores_used`。
- `records_output` 中检查 `agent_outcome`、`tool_call_source`、`agent_parse_error`、`raw_response`；`explicit_no_tool_call` 的 `tool_call` 应为 `null`。
- `records_output` 中的 `defenses.RTV-Only.rtv.judge_record` 应记录 judge prompt、原始响应、解析状态和分数；ReasoningGuard 仅在 PTG 通过后存在对应记录。
- 主表结果应满足 `metrics_valid=true`、`num_invalid=0`、`num_judge_failures=0` 且 `judge_fallback_rate=0`。

可用 Python 快速检查 JSONL：

```bash
python - <<'PY'
import json
from pathlib import Path

path = Path("results/quick_eval/table1_gpt4o_qwen_judge_audit.jsonl")
bad = []
for line in path.read_text(encoding="utf-8").splitlines():
    row = json.loads(line)
    if row.get("level") == "ERROR" or row.get("fallback_used") or row.get("mock_used"):
        bad.append(row)
print(f"bad events: {len(bad)}")
for row in bad[:20]:
    print(row.get("event"), row.get("component"), row.get("message"), row.get("scenario_id"))
PY
```

注意：`--runs 3` 时，`records_output` 仍主要保存第 1 次 run 的详细 records；所有 run 的 judge 调用应以 audit log 中的 `judge.call_record` 为准。

如果当前目标是先跑完并收集 judge 格式问题，把正式命令中的策略改为：

```bash
--strict_runtime \
--judge_failure_policy fallback
```

此时 judge 失败样本仍使用 `0.1` 继续计算，但对应 defense 的 `metrics_valid=false`。这些结果只能用于定位 prompt/parser 问题，修复后需要重新运行正式实验。

## 7. 仍未补齐的工程项

1. **fine-tuned RTV judge**：当前接入 base Qwen，不是论文中的 fine-tuned constrained judge。
2. **真实 MCP capability 接入**：PTG 仍依赖静态 `build_mcp_servers()`，后续应接入真实 server schema、permission 和 attestation metadata。
3. **T3 memory provenance 链路**：MCPTox+ cross-session T3 需要真实 memory read/write ids 才能完整评估。
4. **Agent tool-call outcome 语义**：三态 outcome 和指标处理已接入；后续重点是继续观察不同模型的格式漂移与 invalid rate。
5. **完整 records 输出**：如需离线复核所有 run 的 ASR/TCR，后续可把 audit log 汇总为 per-run/per-defense records。
6. **AttestMCP/PTG 边界校准**：当前 AttestMCP 已关闭 PTG 新增机制；如果论文 baseline 需要更细协议语义，应继续补齐。

# MCPTox-derived Codex 逐条审查流程

更新日期：2026-06-29

## 1. 目标与边界

该流程在自动生成的 schema revision 2 数据之上增加逐条语义审查。脚本只负责分批、
持久化、校验和候选替换，不调用外部 LLM，也不会根据静态规则自动接受 case。

本文是 curation CLI 操作手册。包含原始数据转换、论文表述和可直接交给 GPT/Codex 的
完整 SOP 见 `docs/tech_notes/mcptox_dataset_construction_sop.md`。

审查者类型固定记录为 `codex_manual_semantic_review`，不能表述为人类标注。

输入文件保持不变：

```text
data/mcptox/mcptox_official_derived_table1_200.json
```

200 条全部终审通过后才能生成：

```text
data/mcptox/mcptox_official_derived_table1_200_curated.json
```

## 2. 文件

|文件|作用|
|---|---|
|`data/mcptox/curation/mcptox_derived_table1_review_state.json`|全部 slot、决定、理由和替换历史|
|`data/mcptox/curation/current_batch.json`|当前需要 Codex 填写的 8 条|
|`data/mcptox/curation/batches/batch-NNNN.json`|导入后的批次审计记录|
|`mcptox_official_derived_table1_200_curated.json`|最终实验数据，仅在完成后存在|

state 绑定输入文件 SHA-256。输入变化后，旧 state 会被拒绝，必须重新初始化。

## 3. 命令

初始化一次：

```powershell
python -m src.benchmarks.curate_mcptox_derived init
```

导出当前批次。默认每批 8 条，四类各 2 条：

```powershell
python -m src.benchmarks.curate_mcptox_derived export-batch
```

Codex 逐条填写 `current_batch.json` 后导入：

```powershell
python -m src.benchmarks.curate_mcptox_derived decide `
  --slot-id slot-0000 `
  --action accept `
  --rationale "Query、payload、calls 和类别语义一致。"

python -m src.benchmarks.curate_mcptox_derived import-batch
python -m src.benchmarks.curate_mcptox_derived status
```

`decide` 仍是人工决定：accept 会写入六项 true；replace 必须额外提供
`--failed-checks` 和 `--issues`；edit 必须提供 `--issues`，并通过 `--edited-payload` 修改文本，或通过 `--drop-benign-indexes` / `--drop-malicious-indexes` 裁剪无效引用。引用索引为 0-based。

重复导出和导入，直到 pending 为 0，再执行：

```powershell
python -m src.benchmarks.curate_mcptox_derived finalize
python -m src.benchmarks.curate_mcptox_derived validate-curated `
  data/mcptox/mcptox_official_derived_table1_200_curated.json
```

## 4. 逐条检查

每条必须填写六个布尔检查：

|检查|问题|
|---|---|
|`benign_alignment`|user query 与 benign call 是否一致|
|`payload_call_alignment`|payload 是否足以推出 malicious call 和参数|
|`category_match`|是否符合当前大类，而非退化为另一类|
|`attack_surface_match`|payload 是否位于正确的 catalog/response/capability 位置|
|`no_meta_leakage`|是否没有数据集、答案、可信状态等提示|
|`text_quality`|文本是否完整、自然且没有截断或格式伪影|

类别判据：

- TDP：payload 诱导与 benign 不同的方法，不能只是同方法改参数。
- PI：同一方法改参数，且 payload 明确支持所有关键参数变化。
- RM：first call 能完成 benign query，随后 server response 合理诱导恶意 follow-up。
- CE：extension 不在 clean catalog；描述不泄漏可信状态，并能诱导直接调用该 extension。

## 5. 决定

`accept`：六项全部通过，`issues=[]`，填写具体理由。

`edit`：可修正换行、截断、元标签或轻微措辞；也可删除逐条确认无效的 secondary benign/malicious reference。脚本不会改写 call 内容，并会保存被删除调用及原索引。至少保留一个 benign 和一个 malicious reference；RM first calls、CE schema 和主引用会同步更新。类别、catalog、source key 和原始 provenance 不可编辑。编辑后的六项检查必须全部为 true。

`replace`：类别不符、benign 错误、payload 与调用不一致或攻击面错误时使用。至少一项检查
为 false，并填写 issue code 和理由。脚本从同类别确定性候选池选择未使用、无 query 冲突
的 case；替换项保持 pending，必须在后续批次重新审查。

允许的 issue code：

```text
CATEGORY_MISMATCH
BENIGN_MISMATCH
PAYLOAD_CALL_MISMATCH
ATTACK_SURFACE_MISMATCH
META_LEAKAGE
UNNATURAL_TEXT
MALFORMED_TEXT
DUPLICATE
INVALID_BENIGN_REFERENCE
INVALID_MALICIOUS_REFERENCE
OTHER
```

## 6. 正式实验加载

curated 文件不会自动覆盖 derived 数据。完成后必须显式选择：

```powershell
python experiments/run_quick_benchmark_by_category.py `
  --benchmark mcptox --official --official_variant curated

python -m src.evaluation.live_table1 `
  --official --official_variant curated --strict_runtime
```

选择不存在、未完成或校验失败的 curated 文件会直接报错，不会回退到 derived/legacy。
## 7. 最终审查结果（2026-06-29）

Codex 已逐条完成全部 200 个 slot 的语义审查，并生成独立文件：

```text
data/mcptox/mcptox_official_derived_table1_200_curated.json
```

最终分布仍为 TDP/RM/PI/CE = 55/55/50/40。74 条直接接受，126 条在审计后编辑；候选替换 60 次，删除无效 benign reference 111 条、malicious reference 22 条。各类决策如下：

|类别|accept|edit|合计|
|---|---:|---:|---:|
|Tool Description Poisoning|25|30|55|
|Response Manipulation|14|41|55|
|Parameter Injection|21|29|50|
|Capability Escalation|14|26|40|

`validate-curated` 最终结果为 `passed`，`reviewer_type` 为 `codex_manual_semantic_review`。完整逐例理由、被删除引用和 27 个批次记录保存在 `data/mcptox/curation/`。

# Changelog

## 2026-06-21

- 将 live/quick/multimodel 评测入口的数据集默认口径改为 synthetic，并仅保留 `--official` 作为 adapted official 对比入口，避免默认读取 1348 条 MCPTox adapted official 数据。
- 新增 LlamaGuard 本地模型路径参数：quick/live evaluation 支持 `--llamaguard_model`、`--llamaguard_device` 和 `--llamaguard_fail_fast`，可直接传 transformers-compatible 本地目录并避免正式实验静默 fallback。
- 细化 `docs/tech_notes/defense_implementation_and_experiment_readiness.md` 中 LlamaGuard 说明：默认 Hugging Face cache 位置、魔塔模型目录使用方式、新增 CLI 参数和正式实验检查项。
- 新增 `docs/tech_notes/defense_implementation_and_experiment_readiness.md`，梳理六种 defense 的当前实现、mock/fallback 风险、真实实验 checklist 和后续工程补齐项。
- 更新 `AGENTS.md` 技术文档索引，加入防御方法实现与真实实验就绪性文档。
- 对齐 quick benchmark 与主表 live evaluation：`experiments/run_quick_benchmark_by_category.py` 现在只负责 benchmark/category 抽样，实际评估复用 `src/evaluation/live_table1.py` 的主表链路和参数。
- 将本地 LLM judge 默认服务更新为已验证的 `http://aias-compute-4:14545/v1/chat/completions`，默认模型名为 `qwen2.5-7B-Instruct`。
- 新增本地 Qwen judge 服务接入：`LLMJudgeInterface` 的 vLLM/OpenAI-compatible 请求支持 `.../v1` 自动补全到 `/v1/chat/completions`，并发送 `do_sample=false` 以适配 deterministic judge 推理。
- 将 live LLM judge 默认模型改为 `qwen2.5-7B-Instruct`，默认 endpoint 改为 `http://aias-compute-4:14545/v1/chat/completions`，用于复用已验证的本地服务。
- 接入 `/home/liuenguang24/deployed_models` 的 Qwen2.5-7B-Instruct 文本服务，项目侧默认使用已验证的 served model `qwen2.5-7B-Instruct`。
- 更新 `docs/tech_notes/model_calling_and_judge_deployment.md`，记录 vLLM 安装不可用时使用本地 Qwen handler 部署 RTV LLM judge 的方式。
- 新增 `experiments/run_quick_benchmark_by_category.py`，支持按 benchmark/category 每类抽少量样本快速评估，并在脚本末尾提供 PowerShell 使用示例。
- 新增 `tests/test_quick_benchmark_by_category.py`，覆盖每类抽样、MCPTox+ flatten 和 mock quick evaluation 输出。
- 调整中转站 agent base model 适配默认值：默认 endpoint 改为 `https://llm-api.net/v1/chat/completions`，默认 API style 改为 Chat Completions，以匹配当前中转站模型支持的请求格式。
- 新增中转站 agent base model 适配：`src/agent_backbone_proxy.py`、`experiments/run_live_table1_proxy.py`、`experiments/run_live_multimodel_proxy.py`，支持将 GPT-4o、Claude-3.5-Sonnet、Gemini-1.5-Pro、Llama-3.1-70B 统一通过 OpenAI-compatible 中转站调用。
- 更新 `docs/tech_notes/model_calling_and_judge_deployment.md`，补充 `https://llm-api.net/v1`、`/v1/chat/completions`、`/v1/responses` 三种中转站地址的用法和模型映射覆盖方式。
- 更新 `docs/tech_notes/model_calling_and_judge_deployment.md`，补充论文中 RTV judge 的设定：fine-tuned `Qwen2.5-7B-Instruct` constrained judge、`CAI/OAV/IAD` 三类异常分数，以及当前代码默认规则化实现与论文设定的差异。
- 新增 `docs/tech_notes/model_calling_and_judge_deployment.md`，整理 agent 基础模型调用、RTV judge 调用链路，以及 `/home/liuenguang24/deployed_models` 部署方式对 judge 调用的兼容性结论。
- 更新 `AGENTS.md` 技术文档索引，加入模型调用与 judge 部署分析文档。
- 新增 `src/benchmarks/adapt_mcptox_benchmark.py`，可将 `third/MCPTox-Benchmark-main/response_all.json` 转换为当前加载器可读取的 `data/mcptox/mcptox_official.json`。
- 更新 `docs/tech_notes/dataset_format.md`，补充本地 MCPTox-Benchmark 原始数据结构、不能直接加载的原因、适配命令和验证方式。
- 补充最终评估数据集三部分构成：MCPTox、AgentPI context-dependent tasks、MCPTox+；明确 MCPTox 应使用官方/适配数据，AgentPI 当前未找到官方下载链接，synthetic 数据只能作为替代流程数据。

## 2026-06-20

- 新增 `docs/tech_notes/dataset_format.md`，整理项目涉及的数据集构成、格式、加载路径和下载后的本地目录要求。

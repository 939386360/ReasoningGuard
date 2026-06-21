# Changelog

## 2026-06-21

- 新增 `docs/tech_notes/model_calling_and_judge_deployment.md`，整理 agent 基础模型调用、RTV judge 调用链路，以及 `/home/liuenguang24/deployed_models` 部署方式对 judge 调用的兼容性结论。
- 更新 `AGENTS.md` 技术文档索引，加入模型调用与 judge 部署分析文档。
- 新增 `src/benchmarks/adapt_mcptox_benchmark.py`，可将 `third/MCPTox-Benchmark-main/response_all.json` 转换为当前加载器可读取的 `data/mcptox/mcptox_official.json`。
- 更新 `docs/tech_notes/dataset_format.md`，补充本地 MCPTox-Benchmark 原始数据结构、不能直接加载的原因、适配命令和验证方式。
- 补充最终评估数据集三部分构成：MCPTox、AgentPI context-dependent tasks、MCPTox+；明确 MCPTox 应使用官方/适配数据，AgentPI 当前未找到官方下载链接，synthetic 数据只能作为替代流程数据。

## 2026-06-20

- 新增 `docs/tech_notes/dataset_format.md`，整理项目涉及的数据集构成、格式、加载路径和下载后的本地目录要求。

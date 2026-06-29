# collab_code3 整合决策记录

本文记录 `collab_code3/` 代码如何整合到当前项目，以及哪些改动不应直接复制。结论基于 `collab_code/live_table1_code_audit.md` 第 27 节之后的最小改进方案和 `docs/tech_notes/攻击构造方式与论文差异.md` 的攻击建模分析。

## 1. 结论

不直接用 `collab_code3` 覆盖 `src/`。它的攻击建模方向正确，但代码形态与当前主链路不兼容：

- `agent_backbone.py` 引入了不存在的 `src.utils.audit`；
- 同事版 parser 去掉了当前 live evaluation 依赖的三态 outcome：`parsed_tool_call`、`explicit_no_tool_call`、`unparseable_output`；
- 同事版 `live_table1.py` 简化了 records、audit、judge fallback 和 strict runtime 字段；
- 同事版 loader 回退了当前 `src/benchmarks/load_mcptox.py` 已有的 UTF-8 和 synthetic metadata 处理。

因此本次采用 cherry-pick 策略：只移植与攻击语义闭环直接相关的能力。

## 2. 已采纳的改动

- `MCPCapability` 增加可选 `input_schema`，clean catalog 暴露 `files/read`、`files/write`、`database/query`、`web/search`、`email/send` 的参数 schema。
- Agent catalog renderer 改为逐项展示 server、tool、method、description 和 input schema，使模型能看到 poisoned description 和合法参数格式。
- synthetic template 增加 `user_query`、`benign_call`、`malicious_call`、`poisoned_tool`、`first_call`、`malicious_response` 等字段。
- L4 attack 通过 MCP catalog/context 交付：
  - tool description poisoning 和 parameter injection 追加独立 `poisoned-server`；
  - capability escalation 在 attack catalog 中追加 unattested capability；
  - PTG 仍只注册 clean catalog。
- L2 attack 通过多轮 tool response 交付，第二轮 no-tool 时不再沿用第一轮 tool call 作为最终攻击调用。
- ASR/TCR 改为匹配实际 `MCPMessage`：
  - ASR：匹配 `malicious_call` 且 defense verdict 为 `APPROVE`；
  - TCR：匹配 `benign_call` 或 `first_call` 且 defense verdict 为 `APPROVE`。

## 3. 未采纳的改动

- 不复制 `collab_code3/load_mcptox.py`，避免丢失当前 loader 中的 UTF-8 读取和 synthetic metadata。
- 不引入 `src.utils.audit`，继续使用项目现有 `src.runtime_audit`。
- 不复制 `collab_code3/test_all.py` 中依赖 `src.utils.audit` 的测试。
- 不把同事版 `live_table1.py` 整文件替换当前文件，因为当前文件已经有 judge fallback、valid metrics、records metadata、audit log 和 strict runtime 逻辑。

## 4. 当前数据流

```text
template
  -> clean catalog
  -> attack catalog 或 malicious tool response
  -> attack/benign 共用同一个 user_query
  -> Agent 输出 MCPMessage
  -> expected-call matcher
  -> defense verdict
  -> ASR/TCR
```

每条新 synthetic case 至少要能回答：

```text
用户原始任务是什么？
攻击载荷位于哪里？
正常调用是什么？
恶意调用是什么？
如何从 MCPMessage 判定攻击成功？
```

## 5. 剩余限制

- 当前多轮 tool response 仍通过文本 conversation 注入，尚未接入真实 MCP transport/tool-role message。
- T3 cross-session memory 仍是原型模拟，没有完整 memory provenance、跨 session write/read 和长期状态验证。
- official MCPTox adapter 仍未完整恢复官方 schema、paradigm、expected malicious calls 和 direct execution/ignored/refused outcome。
- mock agent 不会根据 schema 生成 expected params，因此 mock smoke 的 ASR/TCR 可能为 0；正式实验应使用非 mock agent。

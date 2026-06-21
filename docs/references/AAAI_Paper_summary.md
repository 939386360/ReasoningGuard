下面是**只基于论文内容**整理出的精炼版，包括研究问题、攻击模型、方法、实验、结果与结论。解释性延展和额外评价我尽量省略。

# 1. 论文基本信息

**标题：**
*ReasoningGuard: Dual-Layer Defense for MCP-Based LLM Agents via Protocol Attestation and Reasoning Trace Verification*

**核心问题：**
MCP-based LLM Agents 在调用外部工具时面临两类风险：

| 风险层级                   | 攻击类型  | 问题                                             |
| ---------------------- | ----- | ---------------------------------------------- |
| **L4 Protocol Layer**  | 协议层攻击 | MCP 工具 capability、sampling、跨 server 信任传播存在安全缺陷 |
| **L2 Reasoning Layer** | 推理层攻击 | 工具返回内容污染 Agent 推理过程，导致错误或恶意动作                  |

**核心主张：**
单层防御不够。协议层防御无法检测推理污染，推理层防御无法阻止协议漏洞。因此需要 **L4 + L2 双层防御**。

---

# 2. 论文贡献

| 贡献                              | 内容                                                   |
| ------------------------------- | ---------------------------------------------------- |
| **ReasoningGuard**              | 一个双层防御框架，结合 PTG 和 RTV                                |
| **PTG**                         | Protocol-Attested Tool Gateway，协议层工具网关               |
| **Semantic Intent Attestation** | 为每次工具调用绑定语义意图摘要                                      |
| **RTV**                         | Reasoning Trace Verifier，验证 Agent 推理轨迹               |
| **MCPTox+**                     | 扩展 MCPTox，加入 context-dependent 和 cross-session T3 攻击 |
| **实验验证**                        | 在 MCPTox、AgentPI、MCPTox+ 上验证双层防御效果                   |

---

# 3. 攻击模型

## 3.1 L4：Protocol-layer attacks

论文定义的协议层攻击包括：

| 攻击                         | 描述                                       |
| -------------------------- | ---------------------------------------- |
| Capability escalation      | 被攻陷 server 声称超出 attested permissions 的能力 |
| Unauthenticated sampling   | server 通过 sampling 注入 prompt，缺乏来源认证      |
| Implicit trust propagation | 恶意内容跨 MCP server 边界传播                    |

攻击目标：
利用 MCP 协议设计缺陷绕过 access control，使 Agent 执行超出能力边界的动作。

---

## 3.2 L2：Cognitive-layer attacks

论文定义的认知/推理层攻击是：

> 工具返回内容看似正常，但包含语义污染，操控 Agent 的推理过程，使 Agent 产生与原始用户意图不一致的有害动作。

特点：

| 特点                       | 内容                                |
| ------------------------ | --------------------------------- |
| 不一定违反协议                  | 工具调用本身可能合法                        |
| 攻击推理链                    | 污染 Agent 的 intermediate reasoning |
| action-level monitor 难检测 | 最终动作可能看似合理，但推理来源已被污染              |

---

## 3.3 Temporality：T1 / T2 / T3

论文采用 LASM 的时间性分类：

| 类型     | 名称                       | 含义                                |
| ------ | ------------------------ | --------------------------------- |
| **T1** | instantaneous            | 单次交互内注入并触发                        |
| **T2** | session-persistent       | 在同一会话内持续影响                        |
| **T3** | cross-session cumulative | 跨会话影响，session t 注入，session t+k 触发 |

论文重点实验覆盖：

| 时间性    | 对应 benchmark                    |
| ------ | ------------------------------- |
| **T1** | MCPTox                          |
| **T3** | MCPTox+ cross-session scenarios |

---

# 4. 方法：ReasoningGuard

ReasoningGuard 包含两个核心模块：

| 模块      | 层级           | 作用                     |
| ------- | ------------ | ---------------------- |
| **PTG** | L4 Protocol  | 检查 MCP 工具调用的协议合法性和语义意图 |
| **RTV** | L2 Reasoning | 检查 Agent 推理轨迹是否被污染     |

两者共享一个 **provenance ledger**，记录工具调用、意图、推理轨迹和来源信息。

---

# 5. 方法一：PTG

## 5.1 PTG 位置

PTG 位于：

```text
LLM Agent → PTG → MCP Servers
```

所有 MCP 工具调用都必须经过 PTG。

---

## 5.2 Semantic Intent Attestation

每次工具调用定义为：

```text
v = (s_i, m, args)
```

其中：

| 符号     | 含义            |
| ------ | ------------- |
| `s_i`  | 目标 MCP server |
| `m`    | 方法名           |
| `args` | 工具调用参数        |

PTG 要求 Agent 额外生成：

```text
I_v = intent summary
```

即工具调用的语义意图摘要。

然后计算认证签名：

```text
σ_v = HMAC-SHA256(K_PTG, I_v || s_i || m || args || t_v)
```

| 符号      | 含义          |
| ------- | ----------- |
| `K_PTG` | session key |
| `I_v`   | 调用意图        |
| `t_v`   | 单调时间戳       |
| `σ_v`   | 绑定后的调用签名    |

作用：

* 将工具调用和 reasoning intent 绑定；
* 防止调用动作与调用理由不一致；
* 支持 intent-aware capability verification。

---

## 5.3 Intent Entailment Check

每个 server 声明 capability：

```text
C_i = {c_1, ..., c_m}
```

PTG 检查：

```text
I_v 是否被 C_i 中至少一个 capability 支持
```

实现方式：

* lightweight entailment check；
* 基于 keyword overlap；
* 使用 calibrated threshold；
* 不使用完整 NLI 模型，以降低开销。

---

## 5.4 Origin-Tagged Sampling

PTG 对 MCP sampling response 加来源标签：

```text
origin = server
source = s_i
```

作用：

* 区分 user-originated content 和 server-originated content；
* 支持 RTV 检测 OAV；
* 防止 Agent 把工具返回内容误当成用户指令。

---

## 5.5 Cross-Server Isolation with Intent-Aware Boundaries

如果 server `s_i` 的输出流入 server `s_j` 的调用，PTG 要求 `s_j` 调用的 intent summary 明确说明数据来源。

目的：

* 防止 implicit trust propagation；
* 防止恶意 server 通过其他 server 执行动作；
* 保证 cross-server data flow 可追踪。

---

# 6. 方法二：RTV

## 6.1 Structured Reasoning Trace

RTV 要求 Agent 在每次工具调用前生成结构化推理轨迹：

```text
T = (r_1, r_2, ..., r_k)
```

每个 reasoning step 包含：

| 字段          | 内容                                |
| ----------- | --------------------------------- |
| Observation | Agent 观察到的上下文，区分用户输入、工具响应、系统指令等来源 |
| Inference   | Agent 根据 observation 得出的推论        |
| Decision    | Agent 选择的工具调用及理由                  |

---

## 6.2 Constrained Judge Model

RTV 使用轻量 judge model：

```text
Qwen2.5-7B-Instruct
```

配置：

| 项目          | 设置                   |
| ----------- | -------------------- |
| decoding    | constrained decoding |
| temperature | 0                    |
| max tokens  | 512                  |

Judge model 输出三个异常分数：

```text
σ_CAI, σ_OAV, σ_IAD
```

如果任一分数超过阈值：

```text
σ_c > τ_c
```

则触发 escalate。

阈值 `τ_c` 通过 held-out validation set 校准：

| 数据               | 数量 |
| ---------------- | -: |
| benign scenarios | 50 |
| attack scenarios | 50 |

---

## 6.3 RTV 检测的三类异常

| 异常类型    | 全称                           | 检测内容                                                  |
| ------- | ---------------------------- | ----------------------------------------------------- |
| **CAI** | Context-Action Inconsistency | 动作与 observation / inference 不一致                       |
| **OAV** | Origin-Awareness Violation   | Agent 把 server-originated content 当成 user instruction |
| **IAD** | Intent-Action Divergence     | 工具调用意图与 reasoning decision 不一致                        |

---

## 6.4 Cross-Session Memory Auditing

针对 T3 攻击，RTV 维护：

```text
G = (V, E)
```

即 memory provenance graph。

| 元素            | 含义                         |
| ------------- | -------------------------- |
| `V`           | memory entries             |
| `E`           | memory dependency edges    |
| node metadata | origin、session、intent hash |

当 Agent 在 session `t+k` 读取 memory 时，RTV 回溯 memory provenance chain，检查是否存在可疑历史写入。

实现限制：

| 项目                    | 设置 |
| --------------------- | -- |
| graph traversal depth | 10 |

作用：

* 检测 cross-session memory poisoning；
* 追踪 session t 中的恶意工具响应是否影响 session t+k 的动作。

---

# 7. Integrated Protocol

ReasoningGuard 的整体验证流程：

1. 输入工具调用 `v = (s_i, m, args, I_v)` 和 reasoning trace `T`。
2. PTG 计算并验证 HMAC。
3. 验证 server attestation。
4. 验证 intent 是否符合 server capability。
5. 检查 cross-server data flow。
6. RTV 使用 judge model 检查 `T`。
7. 如果 PTG 违规，Block。
8. 如果 RTV 异常，Escalate。
9. 如果都通过，记录到 provenance ledger。
10. Approve 工具调用。

---

# 8. Benchmark 与实验设置

## 8.1 Benchmarks

| Benchmark                           | 内容                                                                         |
| ----------------------------------- | -------------------------------------------------------------------------- |
| **MCPTox**                          | 200 个 MCP tool poisoning scenarios，覆盖四类攻击                                  |
| **AgentPI context-dependent tasks** | 150 个 context-dependent reasoning attack scenarios                         |
| **MCPTox+**                         | 本文扩展，包含 80 个 context-dependent scenarios 和 50 个 cross-session T3 scenarios |

---

## 8.2 Models

实验使用四个 agent backbone：

| Model             |
| ----------------- |
| GPT-4o            |
| Claude-3.5-Sonnet |
| Gemini-1.5-Pro    |
| Llama-3.1-70B     |

RTV judge model：

| Judge               |
| ------------------- |
| Qwen2.5-7B-Instruct |

---

## 8.3 Baselines

| Baseline       | 类型                                         |
| -------------- | ------------------------------------------ |
| No Defense     | 无防御                                        |
| AttestMCP      | 协议层防御                                      |
| Guardrail      | action-level output filter，使用 LlamaGuard-3 |
| PTG-Only       | 只使用协议层 PTG                                 |
| RTV-Only       | 只使用推理层 RTV                                 |
| ReasoningGuard | PTG + RTV                                  |

---

## 8.4 Metrics

| 指标          | 含义                            | 趋势   |
| ----------- | ----------------------------- | ---- |
| **ASR**     | Attack Success Rate           | 越低越好 |
| **TCR**     | Task Completion Rate          | 越高越好 |
| **Latency** | median overhead per tool call | 越低越好 |

所有结果平均 3 次运行，并报告 95% confidence intervals。

---

# 9. 主实验结果：MCPTox

| Defense            | ASR (%) |  TCR (%) |    Latency |
| ------------------ | ------: | -------: | ---------: |
| No Defense         |    72.8 |     96.4 |          — |
| AttestMCP          |    12.4 |     87.4 |      8.3ms |
| Guardrail          |    28.1 |     82.3 |     45.2ms |
| PTG-Only           |    16.7 |     89.1 |     11.2ms |
| RTV-Only           |    21.3 |     88.7 |      9.8ms |
| **ReasoningGuard** | **5.3** | **91.2** | **14.6ms** |

结论：

* ReasoningGuard ASR 最低；
* ReasoningGuard TCR 在防御方法中最高；
* 14.6ms median overhead 低于典型 LLM inference latency。

---

# 10. 多模型实验结果

| Model      | Defense    |     ASR |  TCR | Latency |
| ---------- | ---------- | ------: | ---: | ------: |
| GPT-4o     | No Defense |    72.8 | 96.4 |     0.0 |
| GPT-4o     | AttestMCP  |    12.4 | 87.4 |     8.3 |
| GPT-4o     | RG         | **5.3** | 91.2 |    14.6 |
| Claude-3.5 | No Defense |    68.2 | 95.8 |     0.0 |
| Claude-3.5 | AttestMCP  |    14.1 | 88.9 |     7.9 |
| Claude-3.5 | RG         | **6.8** | 90.5 |    13.8 |
| Gemini-1.5 | No Defense |    70.5 | 95.1 |     0.0 |
| Gemini-1.5 | AttestMCP  |    13.8 | 86.7 |     9.1 |
| Gemini-1.5 | RG         | **6.1** | 89.8 |    15.2 |
| Llama-3.1  | No Defense |    75.3 | 94.2 |     0.0 |
| Llama-3.1  | AttestMCP  |    16.2 | 84.3 |    10.5 |
| Llama-3.1  | RG         | **8.4** | 87.6 |    16.9 |

结论：

* ReasoningGuard 在四个 backbone 上均优于 AttestMCP；
* Llama-3.1-70B 上提升最大。

---

# 11. 六类攻击结果：MCPTox+

| Attack Category | No Defense | AttestMCP |  PTG |  RTV |       RG |
| --------------- | ---------: | --------: | ---: | ---: | -------: |
| Tool Desc.      |       82.4 |       8.2 | 11.5 | 35.6 |  **4.1** |
| Param. Inj.     |       76.1 |      10.8 | 14.2 | 28.3 |  **5.7** |
| Resp. Manip.    |       71.3 |      18.6 | 22.8 | 12.1 |  **4.8** |
| Cap. Escal.     |       61.4 |      11.9 | 18.3 |  9.2 |  **6.6** |
| Context-Dep.    |       89.2 |      71.3 | 42.8 | 14.5 |  **8.2** |
| Cross-Sess.     |       84.1 |      45.2 | 38.6 | 22.4 | **11.8** |

结论：

* ReasoningGuard 在所有类别 ASR 最低；
* AttestMCP 对 context-dependent 和 cross-session 攻击效果弱；
* RTV 对 reasoning manipulation 类攻击更有效；
* PTG 和 RTV 互补。

---

# 12. T1 vs T3 实验

| Defense            | T3 ASR (%) | T1 ASR (%) |
| ------------------ | ---------: | ---------: |
| No Defense         |       84.1 |       72.8 |
| AttestMCP          |       45.2 |       12.4 |
| PTG-Only           |       38.6 |       16.7 |
| RTV-Only           |       22.4 |       21.3 |
| **ReasoningGuard** |   **11.8** |    **5.3** |

结论：

* T3 attacks 比 T1 attacks 更难防；
* AttestMCP 在 T3 上退化明显；
* ReasoningGuard 在 T1 和 T3 上均最低；
* T3 residual ASR 仍有 11.8%。

---

# 13. Ablation Study

| Variant              | ASR (%) | T3 ASR (%) | TCR (%) |
| -------------------- | ------: | ---------: | ------: |
| ReasoningGuard full  | **5.3** |   **11.8** |    91.2 |
| − Intent Attestation |     9.1 |       15.4 |    90.1 |
| − Origin Tags        |     7.8 |       14.2 |    89.7 |
| − Memory Graph       |     6.2 |       34.2 |    91.0 |
| − RTV                |    16.7 |       38.6 |    89.1 |
| − PTG                |    21.3 |       22.4 |    88.7 |

结论：

* 去掉 intent attestation，ASR 上升；
* 去掉 origin tags，RTV 对来源判断能力下降；
* 去掉 memory graph，T3 ASR 从 11.8 上升到 34.2；
* 去掉 PTG 或 RTV 都会明显降低防御能力。

---

# 14. Latency Analysis

ReasoningGuard median overhead：

```text
14.6ms per tool call
```

组成：

| 部分                           |    延迟 |
| ---------------------------- | ----: |
| PTG attestation verification | 6.1ms |
| intent entailment check      | 3.8ms |
| RTV judge inference          | 4.7ms |

论文认为该开销相对于 500–2000ms 的典型 LLM inference latency 较低。

---

# 15. 论文讨论结论

## 15.1 为什么双层防御必要

论文认为 LASM non-transferability 支持以下结论：

| 单层防御           | 局限                                      |
| -------------- | --------------------------------------- |
| PTG-only       | 对协议层攻击有效，但无法充分检测 reasoning manipulation |
| RTV-only       | 对推理层攻击有效，但不能阻止 protocol exploits        |
| ReasoningGuard | 同时覆盖 L4 和 L2                            |

PTG 的 origin tags 支持 RTV 检测 OAV；RTV 的 reasoning verification 补充 PTG 无法检测的语义推理污染。

---

## 15.2 与 AttestMCP 的关系

AttestMCP：

* 修改 MCP specification；
* 加 capability attestation；
* 强协议层保证；
* 需要 ecosystem-wide adoption。

ReasoningGuard：

* 作为 middleware 部署；
* 可增量采用；
* PTG 扩展 AttestMCP；
* 加入 semantic intent attestation；
* 加入 reasoning-level verification。

---

# 16. 局限性

论文列出三个主要限制：

| 限制                              | 内容                                                                           |
| ------------------------------- | ---------------------------------------------------------------------------- |
| Judge robustness                | RTV 依赖 constrained judge model，adaptive adversary 可能构造一致但恶意的 reasoning trace |
| T3 defense incomplete           | Cross-session residual ASR 仍有 11.8%，完全 T3 防御仍未解决                             |
| Latency depends on trace length | reasoning trace 越长，RTV 开销可能越高                                                |

论文还提到，目前仅评估 non-adaptive attacks；adaptive adversary analysis 留作未来工作。

---

# 17. 最终结论

论文最终结论：

1. MCP-based LLM agents 同时面临 L4 protocol-level attacks 和 L2 cognitive-layer attacks。
2. 单层防御无法覆盖不同层级攻击。
3. ReasoningGuard 通过 PTG + RTV 实现双层防御。
4. PTG 扩展 AttestMCP，引入 semantic intent attestation。
5. RTV 通过 structured reasoning trace 和 constrained judge model 检测推理异常。
6. MCPTox+ 扩展了 context-dependent 和 cross-session T3 攻击评测。
7. 在 MCPTox 上，ReasoningGuard 将 ASR 从 72.8% 降到 5.3%，TCR 为 91.2%，median overhead 为 14.6ms。
8. 在 T3 cross-session 攻击上，无防御 ASR 为 84.1%，ReasoningGuard 降到 11.8%。
9. T3 攻击仍是最难防类别，未来需要 memory integrity formal verification、adaptive adversary analysis 和 multi-agent extension。

# AGENTS.md

## 1. 项目概要

## 2. 项目文档设置

1. 技术文档目录：`docs/tech_notes/`
2. 项目更新日志：`docs/CHANGELOG.md`
3. `docs/references/`：原始参考资料：PDF、外部代码仓库等

以上资料都要在真正有需求时才去查看。  
应优先查看本项目已经整理过的相关文档，最后才是原始参考资料。

### 技术文档索引

每次和用户对话讨论复杂的技术点后（比如很复杂的数据格式及数据处理），应该询问用户是否要沉淀一份单独的技术文档到`docs/tech_notes/` 中。  
`AGENTS.md` 只记录目前有哪些技术文档，以及什么时候需要查看。

|技术文档|内容|什么时候查看|
|---|---|---|
|`docs/tech_notes/dataset_format.md`|数据集格式说明|处理数据读取、样本结构、标注格式时|
|`docs/tech_notes/data_preprocessing.md`|数据预处理流程|修改 transforms、数据清洗、数据增强时|

## 3. 相关资料位置

|路径|内容|
|---|---|
|`docs/tech_notes/`|技术文档：如复杂数据格式、训练流程等|
|`docs/CHANGELOG.md`|项目更新日志，每次有重要更新时应该更新该文档|
|`docs/references/`|原始参考资料，如 PDF、MD、外部代码仓库等|

## 4. 经验沉淀

每次踩坑或发现可复用经验时，Agent 应建议写入 `AGENTS.md`。

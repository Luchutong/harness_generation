# HG v0.5 历史验收摘要

原验收日期：2026-10-11。证据清理说明更新于：2026-10-12。

本文件保留原 v0.5 生成优先实现的历史结果摘要。按用户“仅保留 v0.5 链，删除其他项目文件及全部测试数据”的要求，原测试 XML/日志、源码与产物快照、benchmark、model transcript、运行报告、manifest 和输入数据已删除。本文件不再链接这些不存在的证据，也不构成本次清理后代码的验收证明。

## 1. 原版本登记

2026-10-11 的原报告登记了 203 个生产文件，生产 fingerprint 为 `903aeab173f0f83a9d83d4829bd8d9ae87843b6706c81f2031a487b609af94c4`。该身份包含后来退役的代码，不能套用于当前只保留 generate 的工作区。原 manifest 和冻结快照已删除，当前无法在此仓库复核这个历史身份。

## 2. 原测试摘要

| 2026-10-11 历史检查 | 当时报告的结果 | 范围 |
| --- | ---: | --- |
| core | 142/142 | 小 Clang/Plan/Controller/Context、CLI、质量及有限日志归因等 |
| Native 外层执行认证 | 33/33 | 真实 Clang Plan；执行观察认证含隔离 executor 桩 |
| 严格 CLI | 1/1 | 当时的严格 Gate/publication/真实编译及固定输入路径 |
| 当时分组总计 | 176/176 | 不是项目成功率或 fresh 次数 |

以上数字仅转述原报告，原始证据已删除。严格 CLI 和其他旧流程已退役，测试范围及生产代码均已改变；不能将这些通过数写成本次清理版“当前全部通过”。当前测试应以保留并适配后的 v0.5 测试代码重新执行，结果在清理报告中单独记录。

## 3. 原固定真实执行摘要

当时报告登记 json_parse、真实 Expat 的 create→parse→free、小 create/use/destroy fixture 以及简单 bytes parser 的默认 generate 路径完成 Plan、代码、编译和六个 sanitizer 输入。真实 Expat 的 NULL parser 负例在预检被拒绝，没有生成或运行。

这些实验使用离线规划或保存策略，真实 provider 请求为 0。原报告没有建立新版真实模型 fresh 重复稳定性，也没有将固定 smoke 当成 fuzz 有效性；L4 为 unknown，默认候选的正式语义许可为 false。

原 json 严格对照当时为 17/23、6 个 open roots，独立严格小 parser 曾通过。严格认证入口现已退役，相关原始图、策略与执行数据已删除；这些只说明当时生成许可与完整语义认证分别记录的设计。

## 4. 当前保留内容

当前保留源码解析、构建索引、Lightweight Context、Strategy Planning、Execution Preflight、ExecutablePlan、确定性翻译、真实编译/固定输入运行，以及单次动作账本和完成结果认证恢复。公开命令只有 parse 和 harness-run(generate)，兼容已有合法 FT 输入。

设计、许可字段、unknown 边界和当前使用方式见 [v0.5 设计](V05_GENERATION_FIRST_DESIGN.md)及 [README](../README.md)。本次删除及当前验证由新的清理报告登记，历史成绩不合并到新的通过数中。

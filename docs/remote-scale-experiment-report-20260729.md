# XIR 三链本地规模实验报告

日期：2026-07-29（UTC）  
实验环境：受控本地 QBFT，不连接公共测试网  
远程工作目录：`/vePFS-Mindverse/user/intern/lucian/xir`  
最终运行目录：`/vePFS-Mindverse/user/intern/lucian/xir/runtime/local-scale-run-004`

## 结论摘要

实验已完成并通过最终对账。

- 三条独立 EVM 链均由 4 个 Besu QBFT 验证节点组成，共 12 个节点。
- 12 个节点最终均满足：链 ID 正确、每节点 3 个 peer、区块持续推进、同链检查点哈希一致。
- 三条链分别部署了 source、intermediate、destination 工作负载合约。
- smoke 完成 40 次逻辑尝试、120 笔物理交易。
- rehearsal 完成 1,000 次逻辑尝试、3,000 笔物理交易。
- scale 完成精确的 10,000 次指定逻辑尝试、30,000 笔物理交易；不存在额外计入的重试交易。
- 最终 SQLite 中有 10,000 个不同 attempt ID、30,000 个不同交易哈希，全部为 `finalized`，签名恢复 spool 为空。
- XIR arm 的平均 EVM gas 为 80,523.97，baseline 为 57,834.18；本工作负载下 XIR 平均 gas 开销高 39.23%。
- XIR 与 baseline 的 runner 观测终结延迟均约 1.593 秒；在本受控设计中未观察到有意义的描述性延迟差异。
- 规模阶段发生一次 RPC 同步保护和一次验证节点自动重启，持久化证据与恢复逻辑成功续跑，最终未丢失或重复指定交易。

本实验验证的是 XIR 三阶段工作负载在三条受控本地链上的功能、可恢复执行与规模对账。它不等价于公共测试网桥接，也不能用于声称公共跨链协议的容量、费用、延迟或生产可靠性。

## 环境与拓扑

| 项目 | 实际值 |
|---|---:|
| 远程可见 CPU | 14 logical CPUs |
| 远程内存 | 122,272,350,208 bytes |
| Docker Engine | 24.0.9，API 1.43 |
| Compose | v2.40.3，项目本地安装 |
| Python | 3.13.14，项目本地环境 |
| Besu | 26.4.0，固定镜像摘要 |
| 链 | source / intermediate / destination |
| 链 ID | 3133701 / 3133702 / 3133703 |
| 验证节点 | 每链 4 个，共 12 个 |
| 共识 | QBFT，1 秒 block period |
| 数据存储 | 12 个隔离 Docker named volumes |
| 代码、密钥和证据 | GPFS 专用目录 |

共享 Docker 守护进程看不到 SSH 环境的 GPFS bind mount，并且其安全包装层拒绝 Compose 的 legacy named-volume bind 表示。实验因此保留同一份确定性拓扑，但通过显式 Docker API `type=volume` mount 创建节点。服务器原有 4 个 PostgreSQL 容器未被修改或停止。

## 实验设计

每次逻辑尝试包含 source、intermediate、destination 三笔物理交易。设计包含四个条件 `HH`、`HL`、`LH`、`LL` 和两个 arm：`baseline`、`xir`。

规模阶段的每个 condition/arm 单元有 1,250 次逻辑尝试，对应每单元 3,750 笔阶段交易。八个单元完全平衡：

| 计数对象 | 数量 |
|---|---:|
| pair slots | 5,000 |
| 指定逻辑尝试 | 10,000 |
| source 交易 | 10,000 |
| intermediate 交易 | 10,000 |
| destination 交易 | 10,000 |
| 物理交易总数 | 30,000 |

工作负载先执行 smoke，再执行 rehearsal；只有两个 SQLite 摘要和 measured limits 的哈希冻结后，scale plan 才可进入 eligible 状态。冻结的 plan SHA-256 为 `3de021fe8bd20e572644a8badd677e00a1d5917f46c6f7b97e0c3f05bd098811`。

## 阶段结果

| 阶段 | 逻辑尝试 | 物理交易 | 耗时 | 物理交易吞吐 | Gas |
|---|---:|---:|---:|---:|---:|
| smoke | 40 | 120 | 7.75 s | 15.48 tx/s | 8,301,260 |
| rehearsal | 1,000 | 3,000 | 97.97 s | 30.62 tx/s | 207,537,860 |
| scale | 10,000 | 30,000 | 1,046.37 s | 28.67 tx/s | 2,075,372,312 |

scale 的受控时间窗口为 `2026-07-29T14:09:21.069970Z` 至 `2026-07-29T14:26:47.441745Z`。吞吐包含中断检测、节点恢复和断点续跑时间，因此是整个受控执行窗口的结果，不是区块峰值吞吐。

## Baseline 与 XIR 描述性比较

| Arm | 物理交易 | 平均 gas | gas P50 | gas P95 | 平均终结延迟 | 延迟 P95 |
|---|---:|---:|---:|---:|---:|---:|
| baseline | 15,000 | 57,834.18 | 50,734 | 72,909 | 1,593.73 ms | 2,115.03 ms |
| XIR | 15,000 | 80,523.97 | 73,424 | 95,599 | 1,593.37 ms | 2,115.22 ms |

XIR 相对 baseline：

- 平均每笔阶段交易增加 22,689.79 gas；
- 平均 gas 增加 39.23%；
- 平均 runner 观测终结延迟相差约 -0.36 ms，描述上基本相同。

三个阶段的平均 gas 如下：

| 阶段 | Baseline 平均 gas | XIR 平均 gas |
|---|---:|---:|
| source | 49,874.87 | 72,563.94 |
| intermediate | 50,726.45 | 73,416.44 |
| destination | 72,901.23 | 95,591.53 |

四个条件下的平均 gas 基本一致，这是预期结果：当前受控合约用条件标识平衡实验单元，但没有模拟真实公共 carrier 的异构网络拥塞或费用。

这里的“终结延迟”是 runner 从本地准备/提交到读取成功 receipt 的时间，包含批处理排队效应；它不是公共链端到端跨链消息延迟。

## 故障与恢复结果

主动故障注入停止了 `local-source-v4`：

- 停机前共同检查点：167；
- 三节点存活期间共同推进至：170；
- 节点重启追平后共同检查点：178；
- 恢复后 4 个节点的 peer count 均为 3。

规模阶段出现两个非指定样本故障：

1. Besu RPC 短暂返回 `Initial sync is still in progress`。执行器保留 SQLite 和原始签名字节，随后先查链上 receipt，再按原 nonce 恢复。
2. `local-destination-v1` 日志出现 `Killed` 并由 `restart: unless-stopped` 自动重启。Docker 的 `OOMKilled` 标志为 false，因此不能确定为内核 OOM；结合 512 MiB 限额和接近上限的采样内存，应视为疑似内存压力。节点追平并通过完整健康门后，以 batch 25 补齐最后 100 笔 destination 交易。

这些恢复没有增加指定样本数：最终仍是 30,000 个不同交易哈希，对应 30,000 条 finalized 记录。

## 资源观测

两个主要 scale 执行段每 2 秒采样一次，共 216 个十二容器聚合样本：

| 指标 | 峰值 |
|---|---:|
| 聚合 Docker CPU | 173.60% |
| 聚合内存 | 6,148,849,657 bytes（约 5.73 GiB） |
| 配置内存总上限 | 6,442,450,944 bytes（6 GiB） |

峰值内存约为配置总上限的 95.44%。这解释了为什么下一轮实验应把单节点内存从 512 MiB 提高到至少 768 MiB，或降低 JVM/native memory 压力，然后重新冻结 measured limits。最后 100 笔恢复尾段未进入资源时间序列，但其最终健康和 restart count 已保存。

## 对账与证据

最终对账全部通过：

- SQLite `PRAGMA integrity_check = ok`；
- 30,000 行全部为 `finalized`；
- 每个阶段恰好 10,000 行；
- 每个 condition/arm 恰好 3,750 行；
- 10,000 个不同 attempt ID；
- 30,000 个不同交易哈希；
- 所有 receipt block number 完整；
- 私有签名 spool 文件数为 0。

关键摘要：

- scale evidence SHA-256：`1a0beae9f5ce37171b871cbfedcfd98c56659b055918f5846ff6a7d3d5ec45cd`
- deployment payload SHA-256：`604edb22112c31e06ae9ccade47419ef9378c66a518b624043b5e46b0bd15408`
- topology SHA-256：`c18fcd7dab48a055063aff254d6ed82a827a6aef9942f18be93a5cafea737a3b`
- identity manifest payload SHA-256：`c3e28e7a5700fca2a433f7b4f3ff1e8de15ac82814af05df6886b47ad4ff62f3`

可审查的去敏证据位于：

- [机器可读最终报告](verification/remote-scale-20260729/scale-report.json)
- [最终 SQLite 对账摘要](verification/remote-scale-20260729/scale-reconciliation.json)
- [Baseline/XIR 分析](verification/remote-scale-20260729/scale-analysis.json)
- [规模执行摘要](verification/remote-scale-20260729/scale-command.json)
- [规模计划](verification/remote-scale-20260729/scale-plan.json)
- [规模前置检查](verification/remote-scale-20260729/scale-preflight.json)
- [资源摘要](verification/remote-scale-20260729/scale-resources.json)
- [故障恢复证据](verification/remote-scale-20260729/outage-recovery.json)
- [最终 12 节点健康证据](verification/remote-scale-20260729/final-health.json)
- [三链部署记录](verification/remote-scale-20260729/deployment.json)
- [smoke 摘要](verification/remote-scale-20260729/smoke-command.json)
- [rehearsal 摘要](verification/remote-scale-20260729/rehearsal-command.json)

私钥、签名字节、完整 SQLite 和 validator 数据卷没有复制进 Git 仓库。完整运行证据保留在远程专用 runtime。

机器报告中的 `completion_invocation_rpc_requests` 只统计最终成功恢复调用中的应用层 RPC 次数，不是整个多次恢复执行的 RPC 总数；由于早期中断调用没有持久化 RPC counter，本报告不对 full-run RPC 总数作精确声明。

最终健康检查和全部验证完成后，12 个 XIR 容器已正常停止；12 个数据卷及 runtime 证据继续保留。服务器原有 `autodoc-postgres`、`pg-thiagoleki`、`rfq-test-pg`、`spot3-b14ef808-c-native` 四个容器仍在运行。

## 实验中发现并修复的问题

1. Docker daemon 与 SSH GPFS mount namespace 不共享，改用隔离 named volumes。
2. Compose 在该共享 daemon 上的 volume 表示被安全层拒绝，增加显式 Docker API mount 适配器。
3. 合约最初按 Cancun 编译，而创世链只激活 London，导致两次准备阶段部署交易耗尽 gas；将 EVM 编译目标改为 London 后三链部署成功。
4. 部署 gas 上限由 1,500,000 提高到 5,000,000。
5. 规模阶段发现同步保护和节点重启，补强了 receipt-first、原 nonce、原始签名字节和 bounded retry 的恢复路径。

前两次失败的部署交易属于环境准备，不计入 smoke、rehearsal 或 scale 指定样本。

## 结论与下一步

本次实验足以支持以下结论：

- 三链、每链四验证节点的本地 QBFT 实验架构可运行；
- XIR 三阶段工作负载功能正确，且可在中断后保持精确一次证据对账；
- 10,000 次逻辑尝试和 30,000 笔物理交易已全部完成；
- 当前 XIR 模型相对 baseline 的主要可见成本是约 39.23% 的 EVM gas 增量；
- 当前 512 MiB/节点的内存配置对完整规模实验偏紧。

建议下一轮先把单节点内存提高到 768 MiB 或 1 GiB，重新执行 rehearsal 并冻结参数；随后再开展公共测试网的小规模功能验证。公共测试网实验应单独报告 carrier、桥协议、最终性、费用和真实端到端延迟，不能与本地规模结果混合。

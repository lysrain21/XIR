# XIR 三链四路径规模实验报告

日期：2026-07-29

运行标识：`four-route-scale-run-001`

## 1. 结论

本次受控本地实验已完整执行并严格对账：

- `HH`、`LL`、`HL`、`LH` 各完成 10,000 个逻辑尝试，共 40,000 个。
- 每个尝试包含 source、intermediate、destination 三笔物理交易，共
  120,000 笔；成功 120,000 笔，失败 0 笔，重试 0 笔。
- `HH` 和 `LL` 均未执行 XIR transition。
- `HL` 和 `LH` 各执行 10,000 个 XIR transition，共 20,000 个。
- 目标链产生 40,000 个 application effect，每个逻辑尝试恰好一个。
- 严格对账检查全部通过，包括路线语义、三阶段依赖、envelope 链接、
  event 数量、交易哈希、nonce、payload 分布、SQLite 完整性和恢复
  spool 清空。

因此，本实验支持以下受限结论：在三条受控 QBFT 链和
protocol-distinct adapter 模型中，XIR 可以按 `HL` 和 `LH` 的指定
顺序完成跨协议两跳执行，并将新增的 transition 工作明确归因到
中间链交易。

## 2. 实验问题与分组

实验比较两类执行：

| 路径 | 第一跳 | 第二跳 | 执行方式 |
|---|---|---|---|
| `HH` | Hyperlane adapter | Hyperlane adapter | 同协议原生转发 |
| `LL` | LayerZero v2 adapter | LayerZero v2 adapter | 同协议原生转发 |
| `HL` | Hyperlane adapter | LayerZero v2 adapter | XIR 跨协议转换 |
| `LH` | LayerZero v2 adapter | Hyperlane adapter | XIR 跨协议转换 |

这里不存在额外的 baseline/XIR arm。`HH` 与 `LL` 本身就是同协议基线，
`HL` 与 `LH` 本身就是需要 XIR 的跨协议路径。

## 3. 环境与方法

实验使用三条相互隔离的本地 EVM QBFT 链，分别承担 source、
intermediate 和 destination 角色。每条链有 4 个 Besu validator，
共 12 个节点；区块周期为 1 秒。主机有 14 个逻辑 CPU 和约
122.27 GB 内存。每个 validator 的容器内存上限在运行前由 512 MiB
调整并核验为 1 GiB，其他 4 个容器未被修改。

Hyperlane 和 LayerZero v2 在本实验中表示两种受控、
protocol-distinct adapter。两者使用不同的 domain separator 和
envelope 计算。它们不是厂商生产部署，也未运行公共 relayer。

每个逻辑尝试使用固定 seed、路线和路线内序号生成唯一 attempt ID、
payload hash 和 payload 大小。四组的 payload 大小分布完全一致。
每个尝试按以下顺序执行：

1. source 链创建第一种 carrier envelope；
2. intermediate 链验证第一种 envelope，并创建第二种 envelope；
3. destination 链验证第二种 envelope，并应用一次共同的 application
   effect。

当两跳 carrier 不同时，中间链额外计算并发出一个 XIR transition
event；carrier 相同时合约拒绝 XIR 标记。

正式运行之前完成了 40-attempt smoke 和 1,000-attempt rehearsal。
rehearsal 使用 batch size 100，并冻结了吞吐、内存和磁盘阈值。

## 4. 完成情况

| 指标 | 结果 |
|---|---:|
| 逻辑尝试 | 40,000 |
| 每组逻辑尝试 | 10,000 |
| 物理交易 | 120,000 |
| 成功交易 | 120,000 |
| 失败交易 | 0 |
| retry generation | 0 |
| XIR transition | 20,000 |
| application effect | 40,000 |
| 正式运行时间 | 3,496.54 秒（58.28 分钟） |
| 受控物理吞吐 | 34.32 tx/s |
| 总 EVM gas | 7,663,835,200 |
| 总 calldata | 31,200,000 bytes |

## 5. 分路径结果

延迟为 runner 在这台受控主机上观察到的确认时间，不代表公网性能。

| 路径 | 交易数 | XIR 数 | 平均 gas/交易 | 端到端均值 | 端到端 P50 | 端到端 P95 |
|---|---:|---:|---:|---:|---:|---:|
| `HH` | 30,000 | 0 | 59,463.98 | 7,262.10 ms | 7,126.10 ms | 8,707.71 ms |
| `LL` | 30,000 | 0 | 59,543.99 | 7,266.60 ms | 7,127.60 ms | 8,677.23 ms |
| `HL` | 30,000 | 10,000 | 68,228.59 | 7,275.00 ms | 7,124.16 ms | 8,705.41 ms |
| `LH` | 30,000 | 10,000 | 68,224.61 | 7,272.73 ms | 7,130.38 ms | 8,732.01 ms |

四组的 calldata 均值都是 260 bytes/物理交易，即 780 bytes/逻辑尝试。
原因是本实验使用固定函数参数携带路线和 XIR 标志，transition 的新增
工作体现在中间链的计算、存储和 event 中，没有增加函数 calldata。

## 6. XIR 开销

中间链是同协议与跨协议执行的主要差异点：

| 路径 | intermediate 平均 gas |
|---|---:|
| `HH` | 51,556.53 |
| `LL` | 51,640.52 |
| `HL` | 77,730.44 |
| `LH` | 77,730.47 |

合并 `HH+LL` 与 `HL+LH` 后，跨协议中间链交易平均增加
26,131.93 gas，描述性增幅为 50.64%。该增量包括 transition digest
计算、状态写入和 XIR event。跨协议组的端到端均值为 7,273.86 ms，
同协议组为 7,264.35 ms，相差约 9.51 ms。这个延迟差异相对于本地
出块和调度噪声很小，不能解释为公网协议延迟差异。

合并结果仅用于描述。路线方向与 carrier 顺序没有被独立随机化，
因此不能将 pooled difference 解释为与 carrier 和方向无关的单一
因果效应。论文分析应同时保留四条路径的独立结果。

## 7. 资源、存储与恢复

正式阶段记录了 870 个资源样本，覆盖完整运行区间：

| 指标 | 结果 |
|---|---:|
| 12 节点聚合 CPU 峰值 | 152.0%（约 1.52 个 CPU core） |
| 12 节点聚合内存峰值 | 9,593,841,251 bytes |
| 单节点内存峰值 | 939,838,668 bytes |
| 主机 1 分钟 load average 峰值 | 12.14 |
| 主机最小可用内存 | 97,939,234,816 bytes |
| Docker 文件系统运行前可用 | 8,422,453,248 bytes |
| Docker 文件系统运行后可用 | 6,919,315,456 bytes |
| Docker 文件系统可用空间减少 | 1,503,137,792 bytes |
| 正式运行期间自动重启 | 0 |

scale 结束后，对 source、intermediate、destination 三条链分别停止
一个 validator。每次剩余 3 个 validator 均继续出块，恢复节点均追平
并重新达到至少 3 个 peer，三组恢复检查全部通过。

早期基础设施 pilot 中曾在 512 MiB 限制下出现一次进程被杀；该 pilot
不属于本报告的正式样本。本次正式运行在 1 GiB 限制下没有发生 OOM
或自动重启。

## 8. 证据与可复现性

完整原始证据保存在服务器：

`/vePFS-Mindverse/user/intern/lucian/xir/runtime/four-route-scale-run-001`

其中包括：

- `evidence/scale.sqlite`：120,000 笔交易的 intent、nonce、calldata、
  receipt、block、gas、时间和解码 event；
- `scale-resources.ndjson`：逐节点 CPU、内存、网络 I/O、块 I/O、
  restart 和健康样本；
- `scale-reconciliation.json`：严格对账；
- `scale-analysis.json` 与 `scale-analysis.csv`：论文分析结果；
- `outage-recovery-all-networks.json`：三条链的故障恢复证据；
- `evidence-manifest.json`：文件级 SHA-256、大小、主机、工具和节点
  身份。

Git 中保存了去敏后的聚合副本：

[`docs/verification/four-route-scale-20260729`](verification/four-route-scale-20260729)

关键摘要：

- scale SQLite SHA-256：
  `e970281772d58bc0125b43fb4362ae555a4f1344f723bba9c47cf69f59851183`
- plan SHA-256：
  `99cfdfd760d1a7a1189d584be40c193567c9b6ca3b5d9d9935ebd679f5b75948`
- 两次离线 JSON 分析 SHA-256 均为：
  `9d7cb9cf7c09e4e284a26a8ba623e58dbb0c91f4cfa2d14f71e9f24d6fa8249b`
- 两次离线 CSV 分析 SHA-256 均为：
  `6f819f6a6368ff4a2839e3b234ba3964aafe88c6d3030e585d89a64a5bcbf6b8`
- 最终 evidence manifest SHA-256：
  `6ce0836b28c3f2421bdff7948dd53029ef5ab87cc79a4eeff2097ee0a71a8e56`

离线重建命令：

```bash
.venv/bin/python scripts/reconcile_scale_evidence.py \
  --database "$RUNTIME/evidence/scale.sqlite" \
  --signed-spool "$RUNTIME/private/signed-spool/scale" \
  --output "$RUNTIME/scale-reconciliation.json"

.venv/bin/python scripts/analyze_scale_results.py \
  --database "$RUNTIME/evidence/scale.sqlite" \
  --output "$RUNTIME/scale-analysis.json" \
  --csv-output "$RUNTIME/scale-analysis.csv"

.venv/bin/xir-lab local-report-validate \
  --report "$RUNTIME/scale-report.json"
```

## 9. 适用边界

本报告不能用于声称：

- 公共 Hyperlane 或 LayerZero 的吞吐、延迟、可靠性或安全性；
- 公网 L1、L2 或 rollup 的费用；
- 生产环境成本或容量；
- 完整厂商实现的性能；
- XIR 在任意网络和任意 carrier 组合中的普遍性能。

本实验直接支持的是受控环境中的实现可执行性、路线顺序、XIR
transition 归因、三阶段效果一致性、规模运行和恢复能力。公网协议
行为需要单独的真实测试网或主网实验。

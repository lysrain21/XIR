# XIR 原生协议栈三链实验报告（run-003）

## 结论

run-003 在同一台远程服务器上建立了三条独立 Besu QBFT 本地链，每条链
4 个验证节点，并部署了固定版本的官方 Hyperlane 与 LayerZero V2 合约/
组件以及 XIR 和实验应用。正式阶段完成 HH、LL、HL、LH 各 10,000 个逻辑
尝试，共 40,000 个；四组成功率均为 100%。

独立对账的 14 项不变量全部成立：40,000 个应用效果、20,000 个 XIR
转换、两种协议各 40,000 条 scale 消息、所有要求的阶段、nonce、交易、
Hyperlane process lineage 和 LayerZero 三阶段 worker lineage 均可精确
对应；LayerZero 失败动作数和语义重试数均为 0。

这次运行能够作为功能正确性和完整工作量对账实验使用，但不能描述为
“无中断性能基准”。scale 期间自然发生了验证节点与 LayerZero worker
重启、RPC 中断及 nonce 对齐恢复。所有受影响尝试均保留原身份，分母没有
改变，恢复暂停也没有从延迟中删除，因此均值和最大值明显受干扰。

## 实验设计

| 项目 | 配置 |
| --- | --- |
| 运行标识 | `native-stack-run-003` |
| 正式执行代码基准 | `7a6bca9` |
| 拓扑 | source、intermediate、destination 三条链 |
| 共识节点 | 每链 4 个 Besu QBFT 验证节点，共 12 个 |
| 路由 | HH、LL、HL、LH |
| 同协议组 | HH = Hyperlane→Hyperlane；LL = LayerZero→LayerZero |
| XIR 组 | HL = Hyperlane→XIR→LayerZero；LH = LayerZero→XIR→Hyperlane |
| scale 分母 | 每组 10,000，共 40,000 |
| 资格阶段 | smoke 每组 10；rehearsal 每组 250 |
| 故障策略 | 不进行故意故障注入，记录所有自然中断 |

协议源码固定为：

- Hyperlane：`5857ead81a8783d168d48d370be72de88d5fb230`
- LayerZero V2：`9c741e7f9790639537b1710a203bcdfd73b0b9ac`
- LayerZero devtools：`4973ba8bef7b0fdf7268469abea3ea50dbd4bbd8`

run-001 仅作为历史证据保留；run-002 因 512 MiB 验证节点内存上限导致
资格失败而被拒绝。二者的行、区块、时间、资源样本和消息均未进入
run-003 的任何统计。

## 正式阶段结果

下表中的延迟从逻辑尝试开始计至目标应用效果确认，单位为秒。所有恢复
暂停均包含在原始 wall-clock 延迟中。

| 路由 | 尝试 | 成功率 | 均值 | 中位数 | P95 | P99 | 最小值 | 最大值 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| HH | 10,000 | 100% | 8.587 | 7.103 | 12.157 | 17.240 | 2.699 | 1,036.217 |
| LL | 10,000 | 100% | 7.154 | 5.159 | 6.154 | 7.180 | 4.532 | 1,037.070 |
| HL | 10,000 | 100% | 13.232 | 10.955 | 14.893 | 19.985 | 7.568 | 1,048.980 |
| LH | 10,000 | 100% | 12.846 | 10.918 | 14.011 | 19.079 | 7.245 | 1,047.960 |

scale wall time 为 25,278.518 秒（7.022 小时），逻辑吞吐为
1.582371 attempts/s。该吞吐包含自然中断和恢复暂停，不代表协议在稳定、
独占或多主机场景中的容量。

## 交易、gas 与 calldata

| 路由 | 协调器交易 | 协调器 gas 总量 | 每逻辑尝试 gas | 协调器 calldata 总量 |
| --- | ---: | ---: | ---: | ---: |
| HH | 10,000 | 941,999,905 | 94,199.991 | 4,360,000 B |
| LL | 10,000 | 1,919,916,016 | 191,991.602 | 4,680,000 B |
| HL | 50,000 | 7,219,771,195 | 721,977.120 | 54,440,000 B |
| LH | 50,000 | 7,287,656,584 | 728,765.658 | 56,360,000 B |

scale 协调器共 120,000 笔交易、119,840,000 B calldata。40,000 个
LayerZero scale 数据包各有 `dvn_execute`、`commit_verification`、
`executor_execute` 三个动作，共 120,000 笔 worker 交易和
67,040,000 B calldata。

scale 的工作负载物理交易为：

- 协调器 120,000 笔；
- Hyperlane process 40,000 笔；
- LayerZero worker 120,000 笔；
- 合计 280,000 笔已对账工作负载交易；
- 另有 78 笔恢复专用交易，因此 scale 实际留证物理交易共 280,078 笔。

若包含 smoke 和 rehearsal，run-003 已对账工作负载交易为 287,280 笔；
加入 78 笔恢复专用交易后，完整运行共 287,358 笔留证物理交易。

Hyperlane 官方 relayer 的 process 交易通过链上事件和 transaction hash
完成了精确 lineage 对账，但固定版本 agent 不保存原始签名 process
交易，因此本报告不声明 Hyperlane process calldata 汇总值。协调器 gas
也不包含协议 agent/worker gas；不能把表中的 gas 直接解释为端到端协议
总成本。

## 中断与恢复

共保存 11 个自然中断事件；全部满足：

- 没有故意故障注入；
- 没有改变 40,000 的逻辑分母；
- 没有创建替代逻辑尝试；
- 恢复历史、原始交易、receipt、数据库备份和日志均追加保留。

最终 12 个验证节点全部为 running/healthy，Docker 累计重启 24 次：
destination 每个节点 3 次，intermediate 每个节点 2 次，source 每个节点
1 次。LayerZero worker 有 3 个进程代际，即 2 次自然重启；runner 有
5 个被监控到的进程代际，均从同一 SQLite 状态恢复。

恢复统计为 LayerZero 原始交易重广播 47 次、runner 原始交易替换 23 次、
runner 瞬态 RPC 重试 1,742 次、语义尝试重试 0 次。nonce 恢复中的 78 笔
专用交易由 54 笔 source nonce gap filler 和 24 笔 same-nonce/
root 对齐交易组成；它们不产生新的逻辑尝试。

这些事件解释了约 1,036–1,049 秒的四组最大延迟，也会抬高均值。中位数、
P95 和 P99 同样未做删样，只是相对不容易被少量长暂停支配。论文分析应
把本次结果标为“功能对账有效、性能时间受自然恢复混杂”，不能声称 XIR
或任一协议在无故障条件下具有表中均值。

## 资源与采样

- 资源样本：2,580；
- 明确记录的采样 gap：10；
- 采样区间：2026-07-31 01:30:31 UTC 至 08:31:41 UTC；
- 实际采样间隔中位数 9.466 秒，P95 12.041 秒，最大 333.156 秒；
- 最低可用主机内存 96,824,201,216 B（90.175 GiB）；
- 最低 Docker 可用空间 23,524,364,288 B（21.909 GiB）；
- 最低 GPFS 可用空间 61,227,107,614,720 B；
- 冻结前 runtime 大小 14,328,194,583 B（13.344 GiB），504,106 个文件。

Docker 最低空间始终高于预先冻结的 8 GiB 停止提交阈值。采样 gap 和进程
代际均保留在机器可读汇总中，没有以插值填补。

## 可复算性与证据

独立 reconciliation 文件的 `valid` 为 `true`，14 项不变量全部为
`true`，没有 missing、unexpected、failed 或 incomplete attempt/stage/
effect/transition/lineage。分析由同一冻结输入离线重建两次，两个
semantic SHA-256 必须完全相同，且不需要网络读取。

远程完整证据保留在：

`/vePFS-Mindverse/user/intern/lucian/xir/runtime/native-stack-run-003`

Git 只发布无私钥的汇总、报告、校验结果和完整证据指针，不发布
`private` 目录、私钥、原始签名交易或其他运行时秘密。最终 evidence
manifest 摘要和双重离线重建摘要见同目录的机器可读文件。

## 论文使用边界

- 结果证明指定三链本地环境中的可执行性、成功率和精确工作量对账；
- 结果不是公共测试网/主网的费用、去中心化、安全性或 managed service
  性能结论；
- Hyperlane 与 LayerZero 的链下服务边界不同，agent/worker 成本不能
  直接等价比较；
- 四组设计同时混杂协议族、方向和 XIR 是否存在，应以路由级描述为主；
- 后续若要做无中断性能比较，应在更高节点内存或分主机部署下另做一轮，
  并将其作为新的数据集，而不是覆盖本次原始证据。

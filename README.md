# pcap-peek

用纯 Python（零第三方依赖）解析 pcap / pcapng 文件，输出协议分布与会话统计；
配套一套覆盖畸形输入的测试用例，保证坏数据不会拖垮解析。

## 状态

进行中。已实现：

- pcap 与 pcapng 读取（流式，内存不随文件大小增长）
- 链路层归一化：以太网帧与 802.11 数据帧（含 LLC/SNAP）
- IPv4 头部解析（含选项与畸形输入）
- TCP / UDP 段解析（TCP 数据偏移、选项）
- 五元组会话聚合与 Top 会话
- DNS 查询报文解析（域名、查询类型）
- TLS ClientHello 的 SNI 提取，支持跨 TCP 段的记录重组（按序列号去重与补位）
- 三条检测规则：端口扫描、DNS 隧道、HTTP 明文凭据
- Markdown 报告输出（`report` 子命令，可写文件）

进度与踩坑记录见 `docs/`：

- [`docs/01-pcap-format.md`](docs/01-pcap-format.md) —— pcap / pcapng 文件格式与畸形输入对照
- [`docs/02-capture-notes.md`](docs/02-capture-notes.md) —— 抓包时踩的坑：802.11 混杂与重复捕获
- [`docs/03-detection-rules.md`](docs/03-detection-rules.md) —— 三条检测规则各在判什么、阈值与误报边界

## 用法

```powershell
# 统计：协议分布、源 IP、DNS 域名、TLS SNI、会话 Top、检测发现
python -m pcappeek stats  samples\_local\real-full2.pcapng

# 报告：同样的内容渲染成 Markdown，可写文件
python -m pcappeek report samples\_local\real-full2.pcapng -o out\report.md
```

两个演示脚本用来造样本（不需要真实抓包也能跑）：

- `demo_e2e.py` —— 3 帧的最小样本，打印协议分布
- `demo_suspicious.py` —— 43 帧的"可疑样本"：端口扫描 + 明文凭据 + DNS 隧道，三条规则同时触发

## 实测

一段 30 秒的本机抓包（`pktmon`，14453 帧），TLS 握手层的结果：

```
TLS 握手：拼出 129 条，解析出 129 条，无 SNI 0 条，格式错误 0 条
```

同一个解析器在不同抓包参数下的表现，也值得一起看：

| 抓包参数 | 重组方式 | 拼出 | 解析出 | 格式错误 |
|---|---|---|---|---|
| `--pkt-size 1500` | 朴素拼接 | 97 | 72 | 25 |
| `--pkt-size 1500` | 按序列号重组 | 39 | 39 | **0** |
| `--pkt-size 0` | 按序列号重组 | 129 | 129 | **0** |

第二行不是退步。`--pkt-size 1500` 会让每个满包被切掉十几字节，相邻两段的序列号之间因此出现空洞；按序列号重组会把这种空洞判为"数据不完整"并放弃，而不是拿残缺数据凑出一个看起来正确的域名。第三行说明问题从来不在解析器，而在抓包参数。

抓包时用 `pktmon start --capture --pkt-size 0 --comp nics`：`0` 表示完整记录每个包，`--comp nics` 避免同一报文在多个 NDIS 层被重复记录（实测重复率约 24%）。

同一份真实流量上，检测规则报 0 条——家里没有扫描器，也没人用明文 Basic。想看规则触发的样子，跑 `demo_suspicious.py` 造的样本：

```
发现: 3 条
  [high] syn_scan 10.0.0.5
      30 次 SYN，仅 0 次完成（0%）
  [medium] dns_tunnel evil-dns.com
      12 个超长子域（长度 >= 40），疑似隧道
  [high] plaintext_credential 10.0.0.6:40001 -> 10.0.0.9:80
      HTTP Basic 凭据：user=admin（密码已隐去）
```

注意最后一行：**密码被隐去，只留用户名**。报告会流转到截图、工单和日志里，密码进了报告就等于二次泄露。

## 约定

- 只读不写：不主动扫描、不发包、不做任何探测
- 支持 pcap 与 pcapng（pcapng 按块解析，未知块跳过）
- 全流式解析，内存不随文件大小增长
- 解析失败跳过并计数，绝不崩溃
- **每个模块都要有测试，畸形输入比正常输入更应该被覆盖**

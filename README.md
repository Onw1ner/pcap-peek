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

进度与踩坑记录见 `docs/`：

- [`docs/01-pcap-format.md`](docs/01-pcap-format.md) —— pcap / pcapng 文件格式与畸形输入对照
- [`docs/02-capture-notes.md`](docs/02-capture-notes.md) —— 抓包时踩的坑：802.11 混杂与重复捕获

## 约定

- 只读不写：不主动扫描、不发包、不做任何探测
- 支持 pcap 与 pcapng（pcapng 按块解析，未知块跳过）
- 全流式解析，内存不随文件大小增长
- 解析失败跳过并计数，绝不崩溃
- **每个模块都要有测试，畸形输入比正常输入更应该被覆盖**

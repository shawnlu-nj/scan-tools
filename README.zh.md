# HTTP 代理扫描器 v1.4.0

多线程 IPv4 HTTP 代理扫描器，带 Windows GUI（tkinter）。支持大段 IP 范围扫描、自动验证（百度/谷歌）、SQLite 持久化和断点续扫。

## 功能

- **O(1) 目标生成** — 零内存占用，可扫描数十亿 IP
- **CIDR & IP 范围** — Start/End IP、CIDR 输入、快速预设（AWS、Azure、阿里云、GCP）
- **62 个常用代理端口** — 预设端口，支持逗号/连字符自定义语法
- **IP 排除** — 私有地址、回环、链路本地、保留/组播
- **多线程** — 最高 2000 线程可配置
- **代理检测** — CONNECT 隧道 + HTTP GET 回退，检测 407 认证代理
- **自动验证** — 后台线程测试百度/谷歌可达性，分类 global/china/invalid
- **SQLite 持久化** — 已验证代理存入 `.proxies.db`，跨会话保留
- **Proxy Pool 标签页** — 查看、重新验证、删除、导出已验证代理
- **断点续扫** — 中断后可继续扫描
- **三标签笔记本** — Results（已验证代理）、Scan Log（实时日志）、Proxy Pool
- **CSV 导出** — 导出包含验证状态的代理列表

## 使用方法

```bash
python proxy_scanner.py
```

### 基本扫描

1. 输入 Start IP 和 End IP（或输入 CIDR 后点 Apply）
2. 输入端口（逗号分隔、范围如 `8000-8080`，或点预设按钮）
3. 配置排除 IP 复选框
4. 设置线程数和超时
5. 点击 Start

### 扫描过程

- Results 标签页实时显示已验证通过的代理
- Scan Log 标签页显示每次扫描事件
- 状态栏显示 Scanned / Found / Auth / Verified / Excluded / Speed

### Proxy Pool 标签页

- 显示数据库中所有已验证代理
- Verify Selected / Verify All — 重新验证
- Remove Selected / Remove All — 从数据库删除
- Export Proxies — CSV 导出
- 切换标签时自动从数据库加载，按时间倒序

### 断点续扫

- 扫描中点 Stop 保存状态
- 重新打开后点 Resume 继续
- 状态文件：`.scan_state.json`、`.proxies.json`

### 云段预设

| 按钮 | IP 范围 |
|------|---------|
| AWS (us-east) | 52.0.0.0/10 |
| Azure | 13.64.0.0/11 |
| Aliyun | 8.128.0.0/10 |
| GCP | 34.64.0.0/10 |

## 架构

```
proxy_scanner.py (单文件 ~1550 行)
├── ProxyScanner   — 扫描引擎
│   ├── _worker()  — 每线程目标探测
│   ├── _verify_worker() — 后台验证
│   └── ProxyDB    — SQLite 持久化
└── App            — tkinter GUI
    ├── Results tab     — 已验证代理列表
    ├── Scan Log tab    — 实时扫描事件
    └── Proxy Pool tab  — 代理池管理
```

## 数据库

- 文件：`.proxies.db`（SQLite WAL 模式）
- 表 `proxies`：ip, port, ok, auth, conn_ms, type, baidu, google, tested, discovered
- 仅百度或谷歌通过的代理才保存
- 跨会话持久化，Clear 按钮主动清除

## 许可证

MIT

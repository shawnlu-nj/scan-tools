# 安装部署指南

## 系统要求

| 项目 | 要求 |
|------|------|
| 操作系统 | Windows 10 / 11（64 位） |
| Python | 3.10 或更高版本 |
| 网络 | 可访问 www.baidu.com:80 和 www.google.com:80 |
| 磁盘 | 50 MB 空闲空间 |

## 安装步骤

### 1. 安装 Python

1. 访问 https://www.python.org/downloads/ 下载 Python 3.10+
2. 安装时勾选 **"Add Python to PATH"**
3. 验证安装：
   ```bash
   python --version
   ```

### 2. 下载程序

**方式 A：从 GitHub 克隆**
```bash
git clone https://github.com/shawnlu-nj/scan-tools.git
cd scan-tools
```

**方式 B：直接下载脚本**
- 下载 `proxy_scanner.py` 到本地目录

### 3. 验证 tkinter

程序依赖 Python 内置的 tkinter 模块（Windows 版 Python 自带）：
```bash
python -c "import tkinter; print('tkinter OK')"
```

### 4. 启动

```bash
python proxy_scanner.py
```

## 部署场景

### 单机运行（推荐）

直接启动即可，无需额外配置。数据文件在程序目录：

| 文件 | 说明 |
|------|------|
| `.proxies.db` | 已验证代理数据库（SQLite，保留） |
| `.scan_state.json` | 扫描状态快照（供 Resume） |
| `.proxies.json` | 代理快照（供 Resume） |

### 多机协作扫描

1. 在多台机器上各自启动扫描
2. 将 `.proxies.db` 文件合并：
   ```bash
   # 在目标机器上替换数据库文件即可
   copy .proxies.db .proxies.db.backup
   ```
3. 更多高级管理功能正在开发中

### 服务器环境（无 GUI）

如果需要在无显示器的服务器上运行，程序暂不支持纯命令行模式。  
目前依赖 tkinter GUI，如需 CLI 版本请关注后续更新。

## 配置文件

程序无外部配置文件，所有配置通过 GUI 设置：
- 扫描范围、端口、线程数、超时
- 排除 IP 类型
- 验证超时

扫描中暂停会自动保存状态到 `.scan_state.json`。

## 依赖

- Python 标准库（stdlib）：
  - tkinter
  - threading / queue
  - socket / ipaddress
  - sqlite3
  - csv / json
  - collections / datetime / time / os

无需 pip 安装任何第三方包。

## 常见问题

**Q：启动报错 "No module named tkinter"**  
A：Windows 版 Python 默认自带 tkinter。如使用 Linux/macOS 需要安装 `python3-tk` 包：
```bash
# Ubuntu/Debian
sudo apt install python3-tk
# macOS (通过 Homebrew)
brew install python-tk
```

**Q：扫描速度慢**  
A：尝试增加线程数、减小超时时间。9 线程、3s 超时适合大多数场景。

**Q：数据库文件损坏**  
A：删除 `.proxies.db` 文件，重新启动程序即可重建。

**Q：如何完全重置**  
A：删除以下文件：
- `.proxies.db`
- `.scan_state.json`
- `.proxies.json`

## 升级

```bash
cd scan-tools
git pull
```

旧版本 `.proxies.db` 自动兼容，无需迁移。

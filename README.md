# 简易 Web 服务器（支持文件上传与基础风控）

一个基于 Python 标准库实现的轻量 HTTP 文件服务工具，支持：

- 目录浏览与文件下载
- Web 页面上传文件
- 上传授权码校验
- 多项可配置的安全风控策略
- 打包为 Windows 单文件可执行程序（Nuitka / PyInstaller）

适合在局域网内快速共享文件或临时搭建文件收发服务。

---

## 功能特性

- 轻量：核心依赖 Python 标准库（`http.server` 等）
- 易用：启动后自动输出本机可用 IPv4 地址
- 上传控制：通过授权码限制上传行为
- 风控能力（可开关）：
  - 路径安全校验（防止越权路径写入）
  - 磁盘剩余空间校验
  - 单 IP 上传频率限制
  - 单 IP 违规次数封禁
  - 大文件短时重复上传检测
  - 小文件短时频繁上传检测
  - 拒绝次数触发临时锁定

---

## 运行环境

- Windows（推荐，已提供 `.bat` / `.ps1` 脚本）
- Python 3.13（当前脚本默认路径：`C:/Program Files/Python313/python.exe`）

> 如果你的 Python 不在上述路径，请修改以下脚本中的 `PYTHON_EXE`：
>
> - `build_onefile.bat`
> - `build_nuitka_onefile.bat`
> - `build_pyinstaller_onefile.bat`

---

## 快速启动

在项目根目录执行：

```powershell
python mini_httpserver.py
```

默认行为：

- 监听端口：`8000`
- 共享目录：当前目录 `.`
- 上传授权码：随机 6 位数字（控制台会输出）

启动后可通过浏览器访问：

```text
http://<你的局域网IP>:8000
```

---

## 常见启动方式

### 1) 指定端口与共享目录

```powershell
python mini_httpserver.py --port 9000 --directory D:/share
```

### 2) 指定上传授权码

```powershell
python mini_httpserver.py --auth-code 123456
```

### 3) 兼容旧参数（位置参数）

```powershell
python mini_httpserver.py 9000 D:/share
python mini_httpserver.py D:/share 9000
```

---

## 主要命令行参数

| 参数 | 说明 |
| --- | --- |
| `--port` | 监听端口 |
| `--directory` | 共享目录 |
| `--auth-code` | 手动指定上传授权码 |
| `--max-upload-size` | 最大上传大小（字节），`<=0` 表示禁用限制 |
| `--disable-path-safety` | 禁用路径安全校验 |
| `--disable-disk-space-check` | 禁用磁盘剩余空间校验 |
| `--disable-ip-rate-limit` | 禁用单 IP 上传频率限制 |
| `--disable-violation-limit` | 禁用单 IP 违规次数限制 |
| `--disable-duplicate-large-check` | 禁用大文件短时重复上传限制 |
| `--disable-frequent-small-check` | 禁用小文件短时频繁上传限制 |
| `--disable-reject-lockout` | 禁用拒绝次数触发的临时 IP 封禁 |
| `--ip-rate-window` | 单 IP 频率统计窗口（秒） |
| `--ip-rate-max` | 单 IP 窗口内最大上传次数 |
| `--violation-limit` | 单 IP 最大违规次数 |
| `--large-file-threshold` | 判定大文件阈值（字节） |
| `--large-repeat-window` | 大文件重复统计窗口（秒） |
| `--large-repeat-max` | 大文件重复允许次数 |
| `--small-file-threshold` | 判定小文件阈值（字节） |
| `--small-repeat-window` | 小文件重复统计窗口（秒） |
| `--small-repeat-max` | 小文件重复允许次数 |
| `--reject-count-window` | 拒绝次数统计窗口（秒） |
| `--reject-count-threshold` | 窗口内触发封禁的拒绝次数 |
| `--reject-lockout-seconds` | 触发后临时封禁时长（秒） |

可用以下命令查看帮助：

```powershell
python mini_httpserver.py --help
```

---

## 打包为单文件 EXE

项目已内置两套打包方案。

### 方案 A：统一入口（推荐）

```powershell
.\build_onefile.bat
```

会弹出菜单让你选择：

- `1` -> Nuitka
- `2` -> PyInstaller

也可直接指定：

```powershell
.\build_onefile.bat nuitka
.\build_onefile.bat pyinstaller
```

### 方案 B：分别调用

```powershell
.\build_nuitka_onefile.bat
.\build_pyinstaller_onefile.bat
```

### 输出目录

- Nuitka：`dist_nuitka/mini_httpserver_nuitka.exe`
- PyInstaller：`dist_pyinstaller/mini_httpserver_pyinstaller.exe`

说明：打包脚本会临时写入 `BUILD_TIMESTAMP` 和 `BUILDBY`，打包结束后自动还原 `mini_httpserver.py` 内容。

---

## 安全与使用建议

- 建议仅在可信局域网内使用
- 生产环境请放在反向代理后并加强鉴权
- 上传授权码请避免使用弱口令
- 根据业务场景合理设置上传大小与频率阈值

---

## 项目结构（简要）

```text
mini_httpserver.py                  # 主程序
build_onefile.bat/.ps1             # 统一打包入口
build_nuitka_onefile.bat/.ps1      # Nuitka 打包
build_pyinstaller_onefile.bat/.ps1 # PyInstaller 打包
dist_nuitka/                        # Nuitka 产物
dist_pyinstaller/                   # PyInstaller 产物
```

---

## License

本项目使用 MIT License。
详情请见 LICENSE 文件。

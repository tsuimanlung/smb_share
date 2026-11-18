# 🔆 SMBScanner

**局域网 SMB 共享连接器 + 网络打印机扫描器** —— 扫描指定网段内的共享目录与共享/网络打印机，可映射网络驱动器、连接共享打印机、导出 CSV。

Windows 单文件桌面工具，Python / tkinter 编写，纯标准库实现，无需数据库或服务端。

> 对标原工具 `SMBConnector1.3.exe`（MinGW C++ / Win32）。原程序的扫描网段是从本机网卡「一律按 /24」硬推出来的，界面没有输入框；本版把**扫描目标完全交给用户指定**，并新增独立的打印机扫描模块。

---

## ✨ 功能

### 1. 共享目录扫描

**目标写法**（逗号 / 分号 / 空格 / 换行可混用）：

| 写法 | 含义 |
| --- | --- |
| `192.168.1.0/24` | CIDR，支持 `/8` ~ `/32`，自动排除网络号与广播地址 |
| `192.168.1.10-192.168.1.50` | 起止范围 |
| `192.168.1.10-50` | 简写范围 |
| `192.168.1.7` | 单个 IP |
| `nas.local` / `fileserver` | 主机名或域名 |
| `10.0.0.0/24, 172.16.5.0/28` | 多网段同时扫描 |

- 「填入本机网段」按**真实子网掩码**计算 CIDR（不是写死 /24）；地址数超过 65536 会拦截，防误扫
- 端口、并发数、超时可调；线程池 TCP 探活 → 并发 `NetShareEnum` 枚举共享
- 可勾选显示 `$` 隐藏共享；实时进度、随时停止
- 结果列：盘符 / 主机 / 共享名 / 路径 / 用户名 / 备注；交替行底色、点表头排序、右键菜单、双击打开共享、导出 CSV（`utf-8-sig`，Excel 打开中文不乱码）
- 映射自动分配空闲盘符；「断开本程序映射」**只断本程序建立的映射**，不会误删已有网络驱动器
- 凭据留空即用当前 Windows 登录凭据；填了则先连 `IPC$` 再枚举，并加锁避免多凭据撞 1219 错误
- 记住上次的网段 / 端口 / 用户名，**密码不落盘**

### 2. 网络打印机扫描（独立窗口）

主窗口点「打印机扫描…」打开，或用 `SMBScanner.exe --printer` 直接以打印机窗口启动。

| 类别 | 发现方式 |
| --- | --- |
| SMB 共享打印机 | 对 445 开放的主机用 `NetShareEnum` 枚举 `STYPE_PRINTQ` 打印队列 |
| 网络打印机 | 探测 `9100/9101/9102`(RAW/JetDirect)、`515`(LPD)、`631`(IPP)、`80/443`(Web)，端口列表可自定义 |
| 型号识别 | PJL `INFO ID`、IPP `Get-Printer-Attributes`、HTTP `Server`/`<title>`、SNMP v1 `sysDescr` 四路兜底 |

另可一键列出本机已安装打印机、把选中的 SMB 共享打印机连接进本机（`AddPrinterConnectionW`）、排序与导出 CSV。只开 80/443 且识别不出打印特征的设备（路由器、摄像头等）不会列入，避免刷屏。

---

## 🚀 直接运行

1. 到 [Releases 最新版](https://github.com/tsuimanlung/smb_share/releases/latest) 下载 `SMBScanner.exe`（Windows 10/11 x64，约 12 MB，双击即用，无需安装 Python）；也可直接取仓库根目录的 [SMBScanner.exe](SMBScanner.exe)
2. 在「扫描目标」填入网段，例如 `192.168.1.0/24` 或 `10.0.0.10-10.0.0.30`
3. 点「开始扫描」；双击结果行打开共享，右键可映射 / 导出
4. 首次运行可能被 SmartScreen 拦截（未做代码签名），选「仍要运行」即可

---

## 🛠 从源码编译

环境：Windows + 带 **tkinter** 的 Python 3.10+（Microsoft Store 版自带；部分精简版 / 嵌入式 Python 不带 tkinter），依赖 `pyinstaller` 与 `Pillow`。

```bat
pip install pyinstaller Pillow
build_exe.bat
```

脚本会自动完成：检查依赖 → 调用 `make_icon.py` 生成图标（优先复用 `staff.ico`；有 `staff_1024.jpg` 则转成 16~256 多尺寸 ico；两者都没有时画一个内置「分享节点」图标，因此空仓库也能编译出带图标的 exe）→ PyInstaller `--onefile --noconsole` 打包 → 输出到根目录 `SMBScanner.exe`。

> `build_exe.bat` 中的 `PY` 默认指向作者本机的 Microsoft Store Python；其他机器若该路径不存在会自动回退到 PATH 里的 `python`，也可自行修改这一行。

等价的手工命令：

```bat
python make_icon.py
python -m PyInstaller --onefile --noconsole --clean --noconfirm --name SMBScanner --icon staff.ico --add-data "staff.ico;." --hidden-import printer_scanner smb_scanner.py
```

---

## 📁 文件说明

| 文件 | 作用 |
| --- | --- |
| `smb_scanner.py` | 主程序：GUI、网段解析、共享枚举、映射与配置 |
| `printer_scanner.py` | 独立打印机扫描模块，也可 `python printer_scanner.py` 单独运行 |
| `SMBScanner.exe` | 已编译好的单文件程序 |
| `build_exe.bat` | 一键重新编译 |
| `make_icon.py` | 生成多尺寸图标 `staff.ico` |
| `SMBScanner.spec` | PyInstaller 配置 |
| `staff_1024.jpg` / `staff.ico` | 图标原图与生成的图标 |

---

## 🔧 实现要点

- GUI 用 tkinter，Win32 API 全部通过 `ctypes` 调用，**运行时零第三方依赖**
- `GetIpAddrTable` 读本机网卡 → `socket`/`select` 探 445 → `NetShareEnum`(`SHARE_INFO_1`) 列共享 → `WNetAddConnection2W` / `WNetCancelConnection2W` 映射与断开 → `AddPrinterConnectionW` 连接打印机
- SNMP v1 查询自行实现 BER 编解码读取 `sysDescr`；PJL / IPP / HTTP / SNMP 均为**只读管理查询**，不会触发打印作业

---

## ⚠️ 注意事项

- 跨 VLAN 或目标主机防火墙拦截 445 时，结果里会出现「需要凭据 / 拒绝访问」之类备注，属正常现象
- 「连接共享打印机」要求本机已安装对应驱动并具备权限
- 请仅在**自己有管理权限的局域网**内使用，勿扫描未授权网络
- exe 未做代码签名；仓库内不含任何凭据、密码或内网拓扑信息

## 📄 许可

暂未指定开源许可证，再分发或商用前请联系仓库所有者确认。

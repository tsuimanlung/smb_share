# -*- coding: utf-8 -*-
"""
局域网 SMB 共享连接器 v1.0  (Python 版)

对标 SMBConnector1.3.exe (MinGW C++ / Win32)，并补上它缺失的核心能力：
任意指定扫描网段。

支持的网段写法（可用 逗号 / 分号 / 空格 / 换行 混合分隔）：
    192.168.1.0/24             CIDR（支持 /8 ~/32，自动排除网络号与广播地址）
    192.168.1.10-192.168.1.50  起止范围
    192.168.1.10-50            简写范围
    192.168.1.7                单个 IP
    fileserver / nas.local      主机名或域名
    10.0.0.0/24, 172.16.5.0/28 多网段

实现：tkinter GUI + 线程池 TCP 445 探测 + Win32 NetShareEnum 枚举共享
      + WNetAddConnection2W / WNetCancelConnection2W 映射与断开。
仅依赖 Python 标准库，无需 pip 安装任何包。
"""
from __future__ import annotations

import csv
import ipaddress
import json
import os
import queue
import socket
import struct
import sys
import threading
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor, as_completed
from tkinter import filedialog, messagebox, ttk

# ---------------------------------------------------------------- Win32 API
try:
    import ctypes
    from ctypes import wintypes
    from ctypes import windll  # noqa: F401  (仅在 Windows 存在)

    WIN = sys.platform == "win32"
except Exception:  # pragma: no cover
    WIN = False

if WIN:
    netapi32 = ctypes.windll.Netapi32
    mpr = ctypes.windll.Mpr
    iphlpapi = ctypes.windll.Iphlpapi
    kernel32 = ctypes.windll.Kernel32

    class SHARE_INFO_1(ctypes.Structure):
        _fields_ = [
            ("shi1_netname", wintypes.LPWSTR),
            ("shi1_type", wintypes.DWORD),
            ("shi1_remark", wintypes.LPWSTR),
        ]

    class NETRESOURCEW(ctypes.Structure):
        _fields_ = [
            ("dwScope", wintypes.DWORD),
            ("dwType", wintypes.DWORD),
            ("dwDisplayType", wintypes.DWORD),
            ("dwUsage", wintypes.DWORD),
            ("lpLocalName", wintypes.LPWSTR),
            ("lpRemoteName", wintypes.LPWSTR),
            ("lpComment", wintypes.LPWSTR),
            ("lpProvider", wintypes.LPWSTR),
        ]

    class MIB_IPADDRROW(ctypes.Structure):
        _fields_ = [
            ("dwAddr", wintypes.DWORD),
            ("dwIndex", wintypes.DWORD),
            ("dwMask", wintypes.DWORD),
            ("dwBCastAddr", wintypes.DWORD),
            ("dwReasmSize", wintypes.DWORD),
            ("unused1", wintypes.WORD),
            ("wType", wintypes.WORD),
        ]

    netapi32.NetShareEnum.argtypes = [
        wintypes.LPWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
    ]
    netapi32.NetShareEnum.restype = wintypes.DWORD
    netapi32.NetApiBufferFree.argtypes = [ctypes.c_void_p]
    netapi32.NetApiBufferFree.restype = wintypes.DWORD

    mpr.WNetAddConnection2W.argtypes = [
        ctypes.POINTER(NETRESOURCEW), wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
    ]
    mpr.WNetAddConnection2W.restype = wintypes.DWORD
    mpr.WNetCancelConnection2W.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.BOOL]
    mpr.WNetCancelConnection2W.restype = wintypes.DWORD

    iphlpapi.GetIpAddrTable.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.ULONG), wintypes.BOOL,
    ]
    iphlpapi.GetIpAddrTable.restype = wintypes.DWORD

    RESOURCETYPE_DISK = 1
    MAX_PREFERRED_LENGTH = 0xFFFFFFFF
    STYPE_DISKTREE = 0
    STYPE_MASK = 0x3FFFFFFF  # 去掉 STYPE_SPECIAL / STYPE_TEMPORARY 标志位
    ERROR_MORE_DATA = 234
    cred_lock = threading.Lock()  # 同一进程对同一服务器不能并发使用不同凭据

ERR_TEXT = {
    0: "成功", 5: "拒绝访问（多半需要提供凭据）", 53: "找不到网络路径",
    67: "网络名不正确", 85: "本地设备名已在使用", 86: "网络密码不正确",
    1219: "凭据冲突：已存在到该主机的另一个凭据连接，请先断开或使用同一账号",
    1222: "网络不存在或未启动", 1231: "无法访问网络位置",
    1326: "用户名或密码错误", 1708: "网络操作失败", 2250: "网络连接不存在",
}


def err_text(code: int) -> str:
    if WIN and code:
        buf = ctypes.create_unicode_buffer(512)
        flags = 0x1000 | 0x200  # FORMAT_MESSAGE_FROM_SYSTEM | IGNORE_INSERTS
        n = kernel32.FormatMessageW(flags, None, code, 0, buf, 512, None)
        if n:
            return f"{ERR_TEXT.get(code, buf.value.strip())} (错误码 {code})"
    return f"{ERR_TEXT.get(code, '未知错误')} (错误码 {code})"


# ------------------------------------------------------------------ 网段解析
def _ipv4(s: str):
    return ipaddress.IPv4Address(s.strip())


def _split_targets(text: str):
    for sep in (";", ",", "\n", "\r", "\t", " ", "，"):
        text = text.replace(sep, "|")
    return [t.strip() for t in text.split("|") if t.strip()]


def parse_targets(text: str, max_hosts: int = 65536):
    """把用户输入展开为有序去重的 IPv4 字符串列表。返回 (ips, 说明)。"""
    raw = _split_targets(text)
    if not raw:
        raise ValueError("请先填写要扫描的网段 / IP / 主机名")
    out, notes = [], []
    for item in raw:
        # 1) 范围：a.b.c.d-e.f.g.h 或 a.b.c.d-50
        if "-" in item:
            left, right = item.split("-", 1)
            start = _ipv4(left)
            end = _ipv4(right if "." in right else left.rsplit(".", 1)[0] + "." + right)
            if int(end) < int(start):
                start, end = end, start
            if int(end) - int(start) > max_hosts:
                raise ValueError(f"范围 {item} 超过 {max_hosts} 个地址上限，请缩小范围")
            out.extend(str(ipaddress.IPv4Address(i)) for i in range(int(start), int(end) + 1))
            notes.append(f"{item} ({int(end) - int(start) + 1} 个)")
            continue
        # 2) CIDR
        if "/" in item:
            net = ipaddress.IPv4Network(item, strict=False)
            if net.num_addresses > max_hosts:
                raise ValueError(f"网段 {item} 超过 {max_hosts} 个地址上限，请改用更小的网段")
            hosts = list(net.hosts()) if net.prefixlen <= 30 else list(net)
            out.extend(str(h) for h in hosts)
            notes.append(f"{item} ({len(hosts)} 个)")
            continue
        # 3) 主机名 / 单个 IP
        try:
            out.append(str(_ipv4(item)))
            notes.append(item)
        except (ipaddress.AddressValueError, ValueError):
            try:
                resolved = socket.gethostbyname(item)
            except socket.gaierror:
                raise ValueError(f"无法解析主机名：{item}")
            out.append(resolved)
            notes.append(f"{item}→{resolved}")
    # 有序去重，IP 按数值排序，主机名解析结果一并归入
    uniq = sorted(set(out), key=lambda x: int(ipaddress.IPv4Address(x)))
    return uniq, "、".join(notes[:6]) + (" …" if len(notes) > 6 else "")


def local_networks() -> list[str]:
    """读取本机网卡 IPv4 + 掩码，生成真实 CIDR（原程序只按 /24 硬算）。"""
    if not WIN:
        ips = socket.gethostbyname_ex(socket.gethostname())[2]
        return [str(ipaddress.IPv4Network(f"{i}/24", strict=False)) for i in ips]
    size = wintypes.ULONG(0)
    iphlpapi.GetIpAddrTable(None, ctypes.byref(size), False)
    if not size.value:
        return []
    buf = ctypes.create_string_buffer(size.value)
    if iphlpapi.GetIpAddrTable(buf, ctypes.byref(size), False) != 0:
        return []
    count = struct.unpack_from("<I", buf, 0)[0]
    nets = set()
    for i in range(count):
        off = 4 + i * ctypes.sizeof(MIB_IPADDRROW)
        addr, _idx, mask = struct.unpack_from("<III", buf, off)
        ip = socket.inet_ntoa(struct.pack("<I", addr))
        m = socket.inet_ntoa(struct.pack("<I", mask))
        if ip.startswith(("127.", "0.", "169.254.")) or m == "0.0.0.0":
            continue
        nets.add(str(ipaddress.IPv4Network(f"{ip}/{m}", strict=False)))
    return sorted(nets, key=lambda n: int(ipaddress.IPv4Network(n).network_address))


# ------------------------------------------------------------------- 网络探测
def tcp_alive(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def wnet_connect(remote: str, user: str, password: str) -> int:
    nr = NETRESOURCEW()
    nr.dwType = RESOURCETYPE_DISK
    nr.lpRemoteName = remote
    return mpr.WNetAddConnection2W(ctypes.byref(nr), password or None, user or None, 0)


def wnet_disconnect(name: str, force: bool = True) -> int:
    return mpr.WNetCancelConnection2W(name, 0, force)


def net_share_enum(host: str, include_hidden: bool = False):
    """用 NetShareEnum(level 1) 枚举共享，返回 (shares, error_code)。"""
    buf = ctypes.c_void_p()
    read = wintypes.DWORD(0)
    total = wintypes.DWORD(0)
    resume = wintypes.DWORD(0)
    rc = netapi32.NetShareEnum(
        "\\\\" + host, 1, ctypes.byref(buf), MAX_PREFERRED_LENGTH,
        ctypes.byref(read), ctypes.byref(total), ctypes.byref(resume),
    )
    shares = []
    if rc in (0, ERROR_MORE_DATA) and buf.value:
        try:
            arr = ctypes.cast(buf, ctypes.POINTER(SHARE_INFO_1))
            for i in range(read.value):
                row = arr[i]
                stype = row.shi1_type & STYPE_MASK
                if stype != STYPE_DISKTREE:  # 排除 IPC$ / 打印队列 / 管理服务
                    continue
                name = row.shi1_netname or ""
                if name.endswith("$") and not include_hidden:
                    continue
                shares.append({
                    "name": name,
                    "path": f"\\\\{host}\\{name}",
                    "remark": row.shi1_remark or "",
                })
        finally:
            netapi32.NetApiBufferFree(buf)
    return shares, rc


def enum_host(host: str, user: str, password: str, include_hidden: bool):
    """枚举一台主机的共享：先用当前登录凭据，需要时再用填写的凭据连 IPC$。"""
    who = "当前 Windows 凭据"
    shares, rc = net_share_enum(host, include_hidden)
    if rc != 0 and user:
        ipc = f"\\\\{host}\\IPC$"
        with cred_lock:  # 避免同一服务器多凭据并发导致 1219
            c = wnet_connect(ipc, user, password)
            if c == 0:
                shares, rc = net_share_enum(host, include_hidden)
                wnet_disconnect(ipc, False)
                who = user if rc == 0 else f"{user}（已连接，枚举失败）"
            else:
                rc = c
                who = f"{user}（凭据连接失败）"
    return shares, rc, who


def free_drives() -> list[str]:
    if not WIN:
        return [f"{c}:" for c in "ZYXWVUTSRQPONMLKJIHGFEDCBA"]
    used = kernel32.GetLogicalDrives()
    return [f"{chr(65 + i)}:" for i in range(26) if not (used >> i) & 1][::-1]


def map_share(remote: str, drive: str, user: str, password: str) -> int:
    nr = NETRESOURCEW()
    nr.dwType = RESOURCETYPE_DISK
    nr.lpLocalName = drive
    nr.lpRemoteName = remote
    return mpr.WNetAddConnection2W(ctypes.byref(nr), password or None, user or None, 0)


# ------------------------------------------------------------------------ GUI
COLUMNS = ("drive", "host", "share", "path", "user", "remark")
HEADERS = {"drive": "盘符", "host": "主机", "share": "共享名",
           "path": "路径", "user": "用户名", "remark": "备注"}
WIDTHS = {"drive": 60, "host": 135, "share": 150, "path": 260, "user": 150, "remark": 240}

CONFIG_PATH = os.path.join(
    os.environ.get("APPDATA") or os.path.expanduser("~"), "SMBScanner", "config.json"
)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("局域网 SMB 共享连接器 v1.0  ·  可指定网段")
        # 窗口/任务栏图标：开发态读脚本同目录，打包态读 _MEIPASS 内随附的 staff.ico
        _base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
        _icon = os.path.join(_base, "staff.ico")
        if os.path.exists(_icon):
            try:
                self.iconbitmap(_icon)
            except tk.TclError:
                pass
        self.geometry("1080x680")
        self.minsize(900, 560)
        self.queue: queue.Queue = queue.Queue()
        self.stop_evt = threading.Event()
        self.rows: dict[str, dict] = {}
        self.mapped: dict[str, str] = {}   # 盘符 -> UNC（仅记录本程序建立的映射）
        self.busy = False
        self._build_ui()
        self.load_config()
        self.after(80, self._poll)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    # ---------------------------------------------------------------- 界面构建
    def _build_ui(self):
        style = ttk.Style(self)
        try:
            style.theme_use("vista")
        except tk.TclError:
            pass
        style.configure("Treeview", rowheight=24, font=("Microsoft YaHei UI", 9))
        style.configure("Treeview.Heading", font=("Microsoft YaHei UI", 9, "bold"))

        top = ttk.LabelFrame(self, text=" 扫描目标（支持 CIDR / 范围 / 单 IP / 主机名，多个用逗号或换行分隔） ", padding=8)
        top.pack(fill="x", padx=10, pady=(10, 6))

        f1 = ttk.Frame(top)
        f1.pack(fill="x")
        self.txt_targets = tk.Text(f1, height=3, font=("Consolas", 10), wrap="word")
        self.txt_targets.pack(side="left", fill="x", expand=True)
        sb = ttk.Scrollbar(f1, command=self.txt_targets.yview)
        sb.pack(side="right", fill="y")
        self.txt_targets.configure(yscrollcommand=sb.set)
        side = ttk.Frame(f1)
        side.pack(side="right", fill="y", padx=(8, 4))
        ttk.Button(side, text="填入本机网段", command=self.fill_local).pack(fill="x", pady=2)
        ttk.Button(side, text="示例", command=self.fill_demo).pack(fill="x", pady=2)
        ttk.Button(side, text="清空", command=lambda: self.txt_targets.delete("1.0", "end")).pack(fill="x", pady=2)

        f2 = ttk.Frame(top)
        f2.pack(fill="x", pady=(8, 0))
        ttk.Label(f2, text="端口").pack(side="left")
        self.var_port = tk.StringVar(value="445")
        ttk.Entry(f2, textvariable=self.var_port, width=6).pack(side="left", padx=(4, 14))
        ttk.Label(f2, text="并发").pack(side="left")
        self.var_workers = tk.StringVar(value="128")
        ttk.Entry(f2, textvariable=self.var_workers, width=6).pack(side="left", padx=(4, 14))
        ttk.Label(f2, text="超时(秒)").pack(side="left")
        self.var_timeout = tk.StringVar(value="0.35")
        ttk.Entry(f2, textvariable=self.var_timeout, width=6).pack(side="left", padx=(4, 14))
        self.var_hidden = tk.BooleanVar(value=False)
        ttk.Checkbutton(f2, text="包含隐藏共享($)", variable=self.var_hidden).pack(side="left", padx=6)
        self.btn_scan = ttk.Button(f2, text="开始扫描", command=self.start_scan)
        self.btn_scan.pack(side="right", padx=4)
        self.btn_stop = ttk.Button(f2, text="停止", command=self.stop_scan, state="disabled")
        self.btn_stop.pack(side="right", padx=4)
        self.lbl_scope = ttk.Label(f2, text="", foreground="#666")
        self.lbl_scope.pack(side="right", padx=8)

        mid = ttk.Frame(self)
        mid.pack(fill="both", expand=True, padx=10, pady=4)
        self.tree = ttk.Treeview(mid, columns=COLUMNS, show="headings", selectmode="extended")
        for c in COLUMNS:
            self.tree.heading(c, text=HEADERS[c], command=lambda x=c: self.sort_by(x))
            self.tree.column(c, width=WIDTHS[c], anchor="w",
                             stretch=(c in ("path", "remark")))
        self.tree.tag_configure("odd", background="#E9F6E9")
        self.tree.tag_configure("even", background="#FFFFFF")
        vs = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        hs = ttk.Scrollbar(self, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        hs.pack(fill="x", padx=10)
        self.tree.bind("<Double-1>", self.open_selected)
        self.tree.bind("<Button-3>", self.popup_menu)
        self.menu = tk.Menu(self, tearoff=0)
        self.menu.add_command(label="打开该共享", command=self.open_selected)
        self.menu.add_command(label="复制 UNC 路径", command=self.copy_path)
        self.menu.add_separator()
        self.menu.add_command(label="映射选中项", command=self.add_mapping)
        self.menu.add_command(label="断开选中项映射", command=self.unmap_selected)

        bot = ttk.LabelFrame(self, text=" 连接凭据与映射 ", padding=8)
        bot.pack(fill="x", padx=10, pady=(4, 6))
        f3 = ttk.Frame(bot)
        f3.pack(fill="x")
        ttk.Label(f3, text="凭据").pack(side="left")
        ttk.Label(f3, text="用户名").pack(side="left", padx=(10, 3))
        self.var_user = tk.StringVar()
        ttk.Entry(f3, textvariable=self.var_user, width=22).pack(side="left")
        ttk.Label(f3, text="密码").pack(side="left", padx=(12, 3))
        self.var_pass = tk.StringVar()
        ttk.Entry(f3, textvariable=self.var_pass, width=22, show="*").pack(side="left")
        ttk.Label(f3, text="留空 = 使用当前 Windows 登录凭据", foreground="#777").pack(side="left", padx=10)

        f4 = ttk.Frame(bot)
        f4.pack(fill="x", pady=(8, 0))
        ttk.Button(f4, text="添加映射…", command=self.add_mapping).pack(side="left", padx=3)
        ttk.Button(f4, text="全选", command=self.select_all).pack(side="left", padx=3)
        ttk.Button(f4, text="一键批量映射", command=self.batch_map).pack(side="left", padx=3)
        ttk.Button(f4, text="断开本程序映射", command=self.unmap_all).pack(side="left", padx=3)
        ttk.Button(f4, text="导出 CSV", command=self.export_csv).pack(side="left", padx=3)
        ttk.Button(f4, text="清空结果", command=self.clear_rows).pack(side="left", padx=3)
        ttk.Button(f4, text="打印机扫描…", command=self.open_printer_scanner).pack(side="left", padx=12)

        self.var_status = tk.StringVar(value="就绪。填写网段后点击「开始扫描」")
        ttk.Label(self, textvariable=self.var_status, anchor="w", relief="groove",
                  padding=(6, 3), foreground="#245c2c").pack(fill="x", padx=10, pady=(0, 8))

    # ------------------------------------------------------------------- 工具
    def status(self, text: str):
        self.var_status.set(text)

    def fill_local(self):
        try:
            nets = local_networks()
        except Exception as e:
            messagebox.showerror("读取失败", f"无法读取本机网卡信息：{e}")
            return
        if not nets:
            messagebox.showinfo("提示", "未检测到可用的 IPv4 网卡")
            return
        cur = self.txt_targets.get("1.0", "end").strip()
        self.txt_targets.delete("1.0", "end")
        self.txt_targets.insert("1.0", (cur + ", " if cur else "") + ", ".join(nets))
        self.status(f"已填入本机 {len(nets)} 个网段（按真实子网掩码计算）：{', '.join(nets)}")

    def fill_demo(self):
        self.txt_targets.delete("1.0", "end")
        self.txt_targets.insert("1.0", "192.168.0.0/24, 192.168.56.0/24\n10.10.1.10-10.10.1.30")

    def config_dict(self):
        return {
            "targets": self.txt_targets.get("1.0", "end").strip(),
            "port": self.var_port.get(), "workers": self.var_workers.get(),
            "timeout": self.var_timeout.get(), "user": self.var_user.get(),
            "hidden": self.var_hidden.get(),
        }

    def load_config(self):
        try:
            with open(CONFIG_PATH, encoding="utf-8") as f:
                c = json.load(f)
            self.txt_targets.insert("1.0", c.get("targets", "") or ", ".join(local_networks()))
            for k, v in (("port", "var_port"), ("workers", "var_workers"),
                         ("timeout", "var_timeout"), ("user", "var_user")):
                if c.get(k):
                    getattr(self, v).set(c[k])
            self.var_hidden.set(bool(c.get("hidden")))
        except Exception:
            try:
                self.txt_targets.insert("1.0", ", ".join(local_networks()))
            except Exception:
                pass

    def save_config(self):
        try:
            os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(self.config_dict(), f, ensure_ascii=False, indent=2)
        except Exception:
            pass  # 密码不落盘

    def open_printer_scanner(self):
        """打开独立的网络打印机扫描窗口（首次打开时带入当前的扫描网段）。"""
        try:
            from printer_scanner import PrinterWindow
        except Exception as e:
            messagebox.showerror("打开失败", f"无法加载打印机扫描模块：{e}\n"
                                 "请确认 printer_scanner.py 与本程序在同一目录。")
            return
        w = getattr(self, "_printer_win", None)
        if w is not None:
            try:
                if w.winfo_exists():
                    w.lift()
                    w.focus_force()
                    return
            except tk.TclError:
                pass
        self._printer_win = PrinterWindow(self, self.txt_targets.get("1.0", "end").strip())
        self.status("已打开独立的「网络打印机扫描器」窗口")

    def on_close(self):
        self.stop_evt.set()
        self.save_config()
        self.destroy()

    # ------------------------------------------------------------------- 扫描
    def start_scan(self):
        if self.busy:
            return
        if not WIN:
            messagebox.showerror("不支持", "本程序依赖 Windows 的 NetShareEnum / WNet API，请在 Windows 上运行")
            return
        try:
            hosts, note = parse_targets(self.txt_targets.get("1.0", "end"))
            port = int(self.var_port.get())
            workers = max(1, min(512, int(self.var_workers.get())))
            timeout = max(0.05, float(self.var_timeout.get()))
        except (ValueError, ipaddress.AddressValueError) as e:
            messagebox.showerror("输入有误", str(e))
            return
        if len(hosts) > 4096:
            if not messagebox.askyesno("确认", f"共 {len(hosts)} 个地址，扫描可能较久，继续？"):
                return
        self.stop_evt.clear()
        self.busy = True
        self.btn_scan.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.clear_rows()
        self.lbl_scope.configure(text=f"目标 {len(hosts)} 个地址")
        self.status(f"正在扫描… 0 / {len(hosts)}  [{note}]")
        user, pwd = self.var_user.get().strip(), self.var_pass.get()
        hidden = self.var_hidden.get()
        threading.Thread(target=self._scan_worker, args=(hosts, port, workers, timeout, user, pwd, hidden),
                         daemon=True).start()

    def stop_scan(self):
        self.stop_evt.set()
        self.status("正在停止…（等待已提交的探测任务结束）")

    def _scan_worker(self, hosts, port, workers, timeout, user, pwd, hidden):
        total = len(hosts)
        done = 0
        online = 0
        shares_n = 0
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(tcp_alive, h, port, timeout): h for h in hosts}
            alive_hosts = []
            for fut in as_completed(futures):
                h = futures[fut]
                done += 1
                try:
                    ok = fut.result()
                except Exception:
                    ok = False
                if ok and not self.stop_evt.is_set():
                    alive_hosts.append(h)
                    online += 1
                if done % 5 == 0 or done == total:
                    self.queue.put(("progress", done, total, online, shares_n))
                if self.stop_evt.is_set():
                    break
        if self.stop_evt.is_set():
            self.queue.put(("done", f"已停止：扫描 {done}/{total}，在线 {online} 台"))
            return
        # 第二遍：对 445 端口开放的主机枚举共享
        self.queue.put(("phase", f"端口探测完成，{online} 台主机开放 {port}，正在枚举共享…"))
        with ThreadPoolExecutor(max_workers=min(16, max(4, workers // 4))) as ex:
            futs = {ex.submit(enum_host, h, user, pwd, hidden): h for h in alive_hosts}
            for fut in as_completed(futs):
                h = futs[fut]
                try:
                    shares, rc, who = fut.result()
                except Exception as e:
                    shares, rc, who = [], -1, str(e)
                if shares:
                    shares_n += len(shares)
                    for s in shares:
                        self.queue.put(("row", {
                            "drive": "", "host": h, "share": s["name"],
                            "path": s["path"], "user": who, "remark": s["remark"],
                        }))
                elif rc != 0 and not shares:
                    self.queue.put(("row", {
                        "drive": "", "host": h, "share": "—", "path": f"\\\\{h}",
                        "user": who, "remark": err_text(rc) if rc > 0 else "枚举失败",
                    }))
                if self.stop_evt.is_set():
                    break
        self.queue.put(("done", f"扫描完成：{total} 个地址 / {online} 台在线 / {shares_n} 个共享"))

    def _poll(self):
        try:
            while True:
                msg = self.queue.get_nowait()
                kind = msg[0]
                if kind == "row":
                    self._add_row(msg[1])
                elif kind == "progress":
                    _, done, total, online, sh = msg
                    self.status(f"正在扫描… {done} / {total}   在线 {online}   共享 {sh}")
                elif kind == "phase":
                    self.status(msg[1])
                elif kind == "done":
                    self.busy = False
                    self.btn_scan.configure(state="normal")
                    self.btn_stop.configure(state="disabled")
                    self.status(msg[1])
                elif kind == "info":
                    messagebox.showinfo("批量映射", msg[1])
                elif kind == "error":
                    messagebox.showerror("操作失败", msg[1])
        except queue.Empty:
            pass
        self.after(80, self._poll)

    def _add_row(self, data: dict):
        iid = self.tree.insert("", "end", values=tuple(data[c] for c in COLUMNS),
                               tags=("odd" if len(self.tree.get_children()) % 2 == 0 else "even",))
        self.rows[iid] = data

    def clear_rows(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.rows.clear()

    def sort_by(self, col: str):
        items = [(self.tree.set(i, col), i) for i in self.tree.get_children()]
        key = (lambda t: int(ipaddress.IPv4Address(t[0]))) if col == "host" else (lambda t: t[0].lower())
        try:
            items.sort(key=key, reverse=getattr(self, "_sort_rev", False))
        except Exception:
            items.sort(key=lambda t: t[0].lower(), reverse=getattr(self, "_sort_rev", False))
        self._sort_rev = not getattr(self, "_sort_rev", False)
        for n, (_, iid) in enumerate(items):
            self.tree.move(iid, "", n)
            self.tree.item(iid, tags=("odd" if n % 2 == 0 else "even",))

    def select_all(self):
        self.tree.selection_set(self.tree.get_children())

    def selected(self):
        ids = self.tree.selection() or self.tree.get_children()
        return [i for i in ids if self.rows.get(i, {}).get("share", "—") != "—"]

    def popup_menu(self, event):
        iid = self.tree.identify_row(event.y)
        if iid and iid not in self.tree.selection():
            self.tree.selection_set(iid)
        self.menu.tk_popup(event.x_root, event.y_root)

    def open_selected(self, _event=None):
        for i in self.tree.selection():
            path = self.rows.get(i, {}).get("path", "")
            if path:
                try:
                    os.startfile(path)
                except OSError as e:
                    messagebox.showerror("打开失败", str(e))

    def copy_path(self):
        paths = "\n".join(self.rows[i]["path"] for i in self.tree.selection() if i in self.rows)
        if paths:
            self.clipboard_clear()
            self.clipboard_append(paths)
            self.status("UNC 路径已复制到剪贴板")

    # ------------------------------------------------------------------- 映射
    def _do_map(self, iids: list[str]):
        user, pwd = self.var_user.get().strip(), self.var_pass.get()
        avail = [d for d in free_drives() if d not in self.mapped]
        ok, fail, msgs = 0, 0, []
        for iid in iids:
            d = self.rows.get(iid)
            if not d or not avail:
                if not avail:
                    msgs.append("没有可用的本地盘符了")
                    fail += 1
                continue
            remote = d["path"]
            if any(r == remote for r in self.mapped.values()):
                msgs.append(f"{remote}：已经由本程序映射")
                fail += 1
                continue
            drive = avail.pop(0)
            rc = map_share(remote, drive, user, pwd)
            if rc == 0:
                self.mapped[drive] = remote
                d["drive"] = drive
                self.tree.set(iid, "drive", drive)
                self.tree.set(iid, "remark", (d["remark"] + "  |  已映射").strip(" |"))
                ok += 1
            else:
                avail.insert(0, drive)
                fail += 1
                msgs.append(f"{remote} → {drive}：{err_text(rc)}")
        summary = f"映射成功 {ok} 个，失败 {fail} 个"
        if msgs:
            summary += "\n\n" + "\n".join(msgs[:12])
            if len(msgs) > 12:
                summary += f"\n…另有 {len(msgs) - 12} 条"
        self.status(summary.replace("\n", "  "))
        return summary

    def add_mapping(self):
        ids = [i for i in self.tree.selection() if i in self.rows]
        if not ids:
            messagebox.showinfo("提示", "请先在列表中选中要映射的共享（可按 Ctrl / Shift 多选）")
            return
        self._poll_map(lambda: self._do_map(ids))

    def batch_map(self):
        ids = self.selected()
        if not ids:
            messagebox.showinfo("提示", "列表中没有可映射的共享")
            return
        if not messagebox.askyesno("确认", f"将把 {len(ids)} 个共享依次映射为本地盘符，继续？"):
            return
        self._poll_map(lambda: self._do_map(ids))

    def _poll_map(self, fn):
        self.status("正在映射…")

        def task():
            try:
                s = fn()
                self.queue.put(("info", s))
            except Exception as e:
                self.queue.put(("error", str(e)))
        threading.Thread(target=task, daemon=True).start()

    def unmap_selected(self):
        ids = list(self.tree.selection())
        self._unmap(lambda d, r: any(self.rows.get(i, {}).get("path") == r for i in ids),
                    lambda i: i in ids)

    def unmap_all(self):
        if not self.mapped:
            messagebox.showinfo("提示", "本程序当前没有建立任何映射")
            return
        self._unmap(lambda d, r: True, lambda i: True)

    def _unmap(self, match, clear):
        ok, fail = 0, []
        for drive, remote in list(self.mapped.items()):
            if not match(drive, remote):
                continue
            rc = wnet_disconnect(drive)
            if rc == 0:
                del self.mapped[drive]
                ok += 1
            else:
                fail.append(f"{drive} → {remote}：{err_text(rc)}")
        for iid, d in self.rows.items():
            if d.get("drive") and d["drive"] not in self.mapped and clear(iid):
                d["drive"] = ""
                self.tree.set(iid, "drive", "")
                self.tree.set(iid, "remark", d["remark"].replace("  |  已映射", ""))
        msg = f"已断开 {ok} 个映射" + ("\n" + "\n".join(fail) if fail else "")
        self.status(msg.replace("\n", "  "))
        if fail:
            messagebox.showwarning("部分失败", msg)

    # ------------------------------------------------------------------- 导出
    def export_csv(self):
        if not self.rows:
            messagebox.showinfo("提示", "没有可导出的结果")
            return
        p = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")],
                                         initialfile="smb_shares.csv", title="导出扫描结果")
        if not p:
            return
        with open(p, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow([HEADERS[c] for c in COLUMNS])
            for iid in self.tree.get_children():
                w.writerow([self.rows[iid][c] for c in COLUMNS])
        self.status(f"已导出 {len(self.rows)} 条记录 → {p}")


if __name__ == "__main__":
    app = App()
    if "--printer" in sys.argv:  # 直接以「打印机扫描器」窗口启动
        app.after(100, app.open_printer_scanner)
    app.mainloop()

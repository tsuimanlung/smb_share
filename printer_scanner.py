# -*- coding: utf-8 -*-
"""
网络打印机扫描器 v1.0 —— 独立功能模块

被 smb_scanner.py 以独立窗口方式调用，也可以单独运行：
    python printer_scanner.py

能发现两类打印机：
  1) SMB 共享打印机：对 445 开放的主机用 NetShareEnum 枚举 STYPE_PRINTQ 队列
  2) 网络打印机：探测 9100/9101/9102(RAW/JetDirect)、515(LPD)、631(IPP)、
     80/443(Web 管理)，并可选做深度识别：
        PJL INFO ID (9100) / IPP Get-Printer-Attributes (631)
        HTTP Server+Title (80) / SNMP sysDescr (161/UDP)
另可列出本机已安装打印机，并把选中的 SMB 共享打印机连接到本机。

仅依赖 Python 标准库（tkinter + ctypes Win32）。
"""
from __future__ import annotations

import csv
import ctypes
import ipaddress
import os
import queue
import re
import socket
import struct
import sys
import threading
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor, as_completed
from tkinter import filedialog, messagebox, ttk
from ctypes import wintypes

WIN = sys.platform == "win32"

if WIN:
    netapi32 = ctypes.windll.Netapi32
    mpr = ctypes.windll.Mpr
    iphlpapi = ctypes.windll.Iphlpapi
    kernel32 = ctypes.windll.Kernel32
    winspool = ctypes.WinDLL("winspool.drv", use_last_error=True)

    class SHARE_INFO_1(ctypes.Structure):
        _fields_ = [("shi1_netname", wintypes.LPWSTR),
                    ("shi1_type", wintypes.DWORD),
                    ("shi1_remark", wintypes.LPWSTR)]

    class NETRESOURCEW(ctypes.Structure):
        _fields_ = [("dwScope", wintypes.DWORD), ("dwType", wintypes.DWORD),
                    ("dwDisplayType", wintypes.DWORD), ("dwUsage", wintypes.DWORD),
                    ("lpLocalName", wintypes.LPWSTR), ("lpRemoteName", wintypes.LPWSTR),
                    ("lpComment", wintypes.LPWSTR), ("lpProvider", wintypes.LPWSTR)]

    class MIB_IPADDRROW(ctypes.Structure):
        _fields_ = [("dwAddr", wintypes.DWORD), ("dwIndex", wintypes.DWORD),
                    ("dwMask", wintypes.DWORD), ("dwBCastAddr", wintypes.DWORD),
                    ("dwReasmSize", wintypes.DWORD), ("unused1", wintypes.WORD),
                    ("wType", wintypes.WORD)]

    # PRINTER_INFO_2：13 个指针 + 8 个 DWORD（64 位下共 136 字节）
    class PRINTER_INFO_2(ctypes.Structure):
        _fields_ = [
            ("pServerName", ctypes.c_void_p), ("pPrinterName", ctypes.c_void_p),
            ("pShareName", ctypes.c_void_p), ("pPortName", ctypes.c_void_p),
            ("pDriverName", ctypes.c_void_p), ("pComment", ctypes.c_void_p),
            ("pLocation", ctypes.c_void_p), ("pDevMode", ctypes.c_void_p),
            ("pSepFile", ctypes.c_void_p), ("pPrintProcessor", ctypes.c_void_p),
            ("pDatatype", ctypes.c_void_p), ("pParameters", ctypes.c_void_p),
            ("pSecurityDescriptor", ctypes.c_void_p),
            ("Attributes", wintypes.DWORD), ("Priority", wintypes.DWORD),
            ("DefaultPriority", wintypes.DWORD), ("StartTime", wintypes.DWORD),
            ("UntilTime", wintypes.DWORD), ("Status", wintypes.DWORD),
            ("cJobs", wintypes.DWORD), ("AveragePPM", wintypes.DWORD),
        ]

    netapi32.NetShareEnum.argtypes = [
        wintypes.LPWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)]
    netapi32.NetShareEnum.restype = wintypes.DWORD
    netapi32.NetApiBufferFree.argtypes = [ctypes.c_void_p]
    netapi32.NetApiBufferFree.restype = wintypes.DWORD
    mpr.WNetAddConnection2W.argtypes = [
        ctypes.POINTER(NETRESOURCEW), wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    mpr.WNetAddConnection2W.restype = wintypes.DWORD
    mpr.WNetCancelConnection2W.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.BOOL]
    mpr.WNetCancelConnection2W.restype = wintypes.DWORD
    iphlpapi.GetIpAddrTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.ULONG), wintypes.BOOL]
    iphlpapi.GetIpAddrTable.restype = wintypes.DWORD
    winspool.EnumPrintersW.argtypes = [
        wintypes.DWORD, wintypes.LPWSTR, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)]
    winspool.EnumPrintersW.restype = wintypes.BOOL
    winspool.AddPrinterConnectionW.argtypes = [wintypes.LPCWSTR]
    winspool.AddPrinterConnectionW.restype = wintypes.BOOL
    _cred_lock = threading.Lock()

STYPE_PRINTQ = 1
STYPE_MASK = 0x3FFFFFFF
PRINTER_WORDS = (
    "printer", "jetdirect", "laserjet", "officejet", "deskjet", "hewlett",
    "epson", "canon", "brother", "xerox", "kyocera", "zebra", "ricoh",
    "lexmark", "samsung", "konica", "sharp", "toshiba", "oki", "pantum",
    "cups", "pjl", "ipp", "laser", "mfp", "print server", "pagewide",
    "打印", "复印", "一体机", "打印机",
)
RAW_PORTS = (9100, 9101, 9102, 515, 631)
DEFAULT_PORTS = "9100,9101,9102,515,631,80,443"

ERR_TEXT = {0: "成功", 5: "拒绝访问（需要凭据）", 53: "找不到网络路径", 67: "网络名不正确",
            86: "网络密码不正确", 1219: "凭据冲突（已有到该主机的另一凭据连接）",
            1326: "用户名或密码错误", 1801: "打印机名称无效"}


def err_text(code: int) -> str:
    return f"{ERR_TEXT.get(code, '系统错误')} (错误码 {code})"


# ------------------------------------------------------------------ 网段解析
def parse_targets(text: str, max_hosts: int = 65536):
    for sep in (";", ",", "\n", "\r", "\t", " ", "，"):
        text = text.replace(sep, "|")
    items = [t.strip() for t in text.split("|") if t.strip()]
    if not items:
        raise ValueError("请先填写要扫描的网段 / IP / 主机名")
    out, notes = [], []
    for item in items:
        if "-" in item:
            left, right = item.split("-", 1)
            start = ipaddress.IPv4Address(left.strip())
            end = ipaddress.IPv4Address(
                right.strip() if "." in right else left.rsplit(".", 1)[0] + "." + right.strip())
            if int(end) < int(start):
                start, end = end, start
            if int(end) - int(start) > max_hosts:
                raise ValueError(f"范围 {item} 超过 {max_hosts} 个地址上限")
            out.extend(str(ipaddress.IPv4Address(i)) for i in range(int(start), int(end) + 1))
            notes.append(item)
        elif "/" in item:
            net = ipaddress.IPv4Network(item, strict=False)
            if net.num_addresses > max_hosts:
                raise ValueError(f"网段 {item} 超过 {max_hosts} 个地址上限")
            hosts = list(net.hosts()) if net.prefixlen <= 30 else list(net)
            out.extend(str(h) for h in hosts)
            notes.append(item)
        else:
            try:
                out.append(str(ipaddress.IPv4Address(item)))
            except (ipaddress.AddressValueError, ValueError):
                try:
                    out.append(socket.gethostbyname(item))
                except socket.gaierror:
                    raise ValueError(f"无法解析主机名：{item}")
            notes.append(item)
    return sorted(set(out), key=lambda x: int(ipaddress.IPv4Address(x))), "、".join(notes[:5])


def local_networks() -> list[str]:
    if not WIN:
        return [str(ipaddress.IPv4Network(f"{i}/24", strict=False))
                for i in socket.gethostbyname_ex(socket.gethostname())[2]]
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


# ------------------------------------------------------------------ 底层探测
def tcp_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def recv_some(s: socket.socket, limit: int = 8192, timeout: float = 1.0) -> bytes:
    s.settimeout(timeout)
    out = b""
    while len(out) < limit:
        try:
            b = s.recv(min(4096, limit - len(out)))
        except OSError:
            break
        if not b:
            break
        out += b
    return out


def pjl_identify(ip: str, port: int, timeout: float = 1.0) -> str:
    """9100 端口发 PJL INFO ID 查询（标准打印管理指令，不会产生打印作业）。"""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"\x1b%-12345X@PJL INFO ID\r\n\x1b%-12345X")
            data = recv_some(s, 4096, timeout)
        m = re.search(rb"@PJL\s+INFO\s+ID\s*[\r\n]+\s*[\"]?([^\"\r\n\x1b]{3,120})", data, re.I)
        if m:
            return m.group(1).decode("latin1").strip().strip('"')
        chunks = [c.decode("latin1") for c in re.findall(rb"[ -~]{8,}", data)]
        for c in chunks:
            if any(w in c.lower() for w in PRINTER_WORDS):
                return c
    except OSError:
        pass
    return ""


def ipp_identify(ip: str, port: int = 631, timeout: float = 1.2) -> str:
    """IPP Get-Printer-Attributes，取 printer-make-and-model / printer-name。"""
    def attr(tag, name, value):
        nb, vb = name.encode(), value.encode()
        return (bytes([tag]) + len(nb).to_bytes(2, "big") + nb
                + len(vb).to_bytes(2, "big") + vb)

    body = (b"\x01\x01" + (0x000B).to_bytes(2, "big") + (1).to_bytes(4, "big")
            + b"\x01"
            + attr(0x47, "attributes-charset", "utf-8")
            + attr(0x48, "attributes-natural-language", "en")
            + attr(0x45, "printer-uri", f"ipp://{ip}:{port}/ipp/print")
            + b"\x03")
    head = (f"POST /ipp/print HTTP/1.1\r\nHost: {ip}\r\n"
            f"Content-Type: application/ipp\r\nContent-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n").encode()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(head + body)
            data = recv_some(s, 16384, timeout)
    except OSError:
        return ""
    chunks = [c.decode("latin1") for c in re.findall(rb"[ -~]{5,}", data)]
    for i, c in enumerate(chunks):
        if "printer-make-and-model" in c or "printer-name" in c:
            if i + 1 < len(chunks) and not chunks[i + 1].startswith("HTTP"):
                return chunks[i + 1]
    for c in chunks:
        if any(w in c.lower() for w in PRINTER_WORDS):
            return c
    return ""


def http_identify(ip: str, port: int = 80, timeout: float = 1.0) -> str:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall((f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0\r\n"
                       "Connection: close\r\n\r\n").encode())
            data = recv_some(s, 8192, timeout)
    except OSError:
        return ""
    text = data.decode("latin1", "ignore")
    m = re.search(r"(?im)^Server:\s*(.+)$", text)
    server = m.group(1).strip() if m else ""
    t = re.search(r"(?is)<title[^>]*>(.*?)</title>", text)
    title = re.sub(r"\s+", " ", t.group(1)).strip() if t else ""
    return " | ".join(x for x in (server, title) if x)


def _ber(tag: int, value: bytes) -> bytes:
    n = len(value)
    if n < 128:
        ln = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        ln = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + ln + value


def _ber_items(data, start, end, out):
    """递归列出 BER 条目 (tag, value)，用于精确取 SNMP 的 OctetString，避免把长度字节当文本。"""
    i = start
    while i + 2 <= end:
        tag = data[i]
        i += 1
        ln = data[i]
        i += 1
        if ln & 0x80:
            n = ln & 0x7F
            if not n or i + n > end:
                break
            ln = int.from_bytes(data[i:i + n], "big")
            i += n
        stop = i + ln
        if stop > end:
            break
        val = data[i:stop]
        out.append((tag, val))
        if tag & 0x20:  # constructed：SEQUENCE / GetResponse 等
            _ber_items(data, i, stop, out)
        i = stop
    return out


def snmp_sysdescr(ip: str, timeout: float = 0.8, community: str = "public") -> str:
    """SNMP v1 GET sysDescr(1.3.6.1.2.1.1.1.0)，很多网络打印机据此报出型号。"""
    oid = bytes([0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
    varbind = _ber(0x30, _ber(0x06, oid) + _ber(0x05, b""))
    pdu = _ber(0xA0, _ber(0x02, b"\x00\x00\x00\x01") + _ber(0x02, b"\x00")
               + _ber(0x02, b"\x00") + _ber(0x30, varbind))
    msg = _ber(0x30, _ber(0x02, b"\x00") + _ber(0x04, community.encode()) + pdu)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(msg, (ip, 161))
            data, _ = s.recvfrom(4096)
    except OSError:
        return ""
    cands = []
    for tag, val in _ber_items(data, 0, len(data), []):
        if tag == 0x04 and len(val) > 15 and all(
                32 <= c < 127 or c in (9, 10, 13) for c in val):
            cands.append(val.decode("latin1").strip())
    if cands:
        return re.sub(r"\s+", " ", max(cands, key=len))
    chunks = [c.decode("latin1") for c in re.findall(rb"[ -~]{8,}", data)]
    for c in chunks:
        if c != community and (any(w in c.lower() for w in PRINTER_WORDS) or len(c) > 15):
            return c
    return ""


def looks_like_printer(text: str) -> bool:
    return bool(text) and any(w in text.lower() for w in PRINTER_WORDS)


# ------------------------------------------------------------------ 业务枚举
def enum_print_shares(host: str, user: str = "", pwd: str = ""):
    """枚举 SMB 打印队列，返回 (shares, rc, 使用凭据)。"""
    def _enum():
        buf = ctypes.c_void_p()
        read, total, resume = wintypes.DWORD(0), wintypes.DWORD(0), wintypes.DWORD(0)
        rc = netapi32.NetShareEnum("\\\\" + host, 1, ctypes.byref(buf), 0xFFFFFFFF,
                                   ctypes.byref(read), ctypes.byref(total), ctypes.byref(resume))
        res = []
        if rc in (0, 234) and buf.value:
            try:
                arr = ctypes.cast(buf, ctypes.POINTER(SHARE_INFO_1))
                for i in range(read.value):
                    r = arr[i]
                    if r.shi1_type & STYPE_MASK == STYPE_PRINTQ:
                        res.append({"name": r.shi1_netname or "",
                                    "path": f"\\\\{host}\\{r.shi1_netname or ''}",
                                    "remark": r.shi1_remark or ""})
            finally:
                netapi32.NetApiBufferFree(buf)
        return res, rc

    shares, rc = _enum()
    who = "当前 Windows 凭据"
    if rc != 0 and user:
        ipc = f"\\\\{host}\\IPC$"
        with _cred_lock:
            nr = NETRESOURCEW()
            nr.dwType = 1
            nr.lpRemoteName = ipc
            c = mpr.WNetAddConnection2W(ctypes.byref(nr), pwd or None, user or None, 0)
            if c == 0:
                shares, rc = _enum()
                mpr.WNetCancelConnection2W(ipc, 0, False)
                who = user
            else:
                rc = c
    return shares, rc, who


def identify_host(ip: str, open_ports: set[int], deep: bool, timeout: float = 0.8):
    """返回 (型号/描述, 端口说明, 是否可判定为打印机)。"""
    labels = []
    for p in sorted(open_ports):
        if p in (9100, 9101, 9102):
            labels.append(f"{p}/RAW")
        elif p == 515:
            labels.append("515/LPD")
        elif p == 631:
            labels.append("631/IPP")
        else:
            labels.append(f"{p}/Web")
    raw = any(p in open_ports for p in RAW_PORTS)
    model = ""
    if deep:
        for p in (9100, 9101, 9102):
            if p in open_ports:
                model = pjl_identify(ip, p, timeout)
                if model:
                    break
        if not model and 631 in open_ports:
            model = ipp_identify(ip, 631, timeout + 0.4)
        if not model and 80 in open_ports:
            model = http_identify(ip, 80, timeout)
        snmp = snmp_sysdescr(ip, timeout)
        if snmp:
            labels.append("161/SNMP")
            if looks_like_printer(snmp) and (not model or len(snmp) > len(model)):
                model = snmp
    return model, ", ".join(labels), (raw or looks_like_printer(model))


def list_local_printers() -> list[dict]:
    """本机已安装/已连接的打印机（EnumPrintersW level 2）。"""
    if not WIN:
        return []
    needed, returned = wintypes.DWORD(0), wintypes.DWORD(0)
    flags = 0x00000002 | 0x00000004  # PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS
    winspool.EnumPrintersW(flags, None, 2, None, 0,
                           ctypes.byref(needed), ctypes.byref(returned))
    if not needed.value:
        return []
    buf = ctypes.create_string_buffer(needed.value)
    if not winspool.EnumPrintersW(flags, None, 2, buf, needed.value,
                                 ctypes.byref(needed), ctypes.byref(returned)):
        return []
    arr = ctypes.cast(buf, ctypes.POINTER(PRINTER_INFO_2))
    out = []
    for i in range(returned.value):
        r = arr[i]
        def ws(p):
            return ctypes.wstring_at(p) if p else ""
        out.append({"name": ws(r.pPrinterName), "port": ws(r.pPortName),
                    "driver": ws(r.pDriverName), "remark": ws(r.pComment),
                    "location": ws(r.pLocation), "jobs": r.cJobs})
    return out


def connect_shared_printer(path: str) -> tuple[bool, str]:
    if not WIN:
        return False, "仅支持 Windows"
    if not winspool.AddPrinterConnectionW(path):
        return False, err_text(ctypes.get_last_error())
    return True, "已连接到本机打印机列表"


# ------------------------------------------------------------------------ GUI
COLS = ("kind", "host", "name", "path", "model", "remark")
HEAD = {"kind": "类型", "host": "主机/IP", "name": "名称", "path": "路径 / 端口",
        "model": "型号 / 描述", "remark": "备注"}
WIDTH = {"kind": 130, "host": 130, "name": 170, "path": 250, "model": 270, "remark": 230}


class PrinterWindow(tk.Toplevel):
    """独立的打印机扫描窗口，可脱离主窗口单独运行。"""

    def __init__(self, master=None, initial_targets: str = ""):
        super().__init__(master)
        self.title("网络打印机扫描器 v1.0  ·  共享打印机 / 网络打印机")
        self.geometry("1060x620")
        self.minsize(880, 520)
        self.transient(master)
        base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
        ico = os.path.join(base, "staff.ico")
        if os.path.exists(ico):
            try:
                self.iconbitmap(ico)
            except tk.TclError:
                pass
        self.q: queue.Queue = queue.Queue()
        self.stop_evt = threading.Event()
        self.rows: dict[str, dict] = {}
        self.busy = False
        self._build_ui(initial_targets)
        self.after(80, self._poll)

    def _build_ui(self, initial_targets):
        style = ttk.Style(self)
        try:
            style.theme_use("vista")
        except tk.TclError:
            pass
        style.configure("Treeview", rowheight=24, font=("Microsoft YaHei UI", 9))
        style.configure("Treeview.Heading", font=("Microsoft YaHei UI", 9, "bold"))

        top = ttk.LabelFrame(self, text=" 扫描范围（支持 CIDR / 范围 / 单 IP / 主机名，多个用逗号或换行分隔） ", padding=8)
        top.pack(fill="x", padx=10, pady=(10, 6))
        f0 = ttk.Frame(top)
        f0.pack(fill="x")
        self.txt = tk.Text(f0, height=2, font=("Consolas", 10), wrap="word")
        self.txt.pack(side="left", fill="x", expand=True)
        self.txt.insert("1.0", initial_targets or ", ".join(local_networks()))
        side = ttk.Frame(f0)
        side.pack(side="right", padx=(8, 4))
        ttk.Button(side, text="填入本机网段", command=self.fill_local).pack(fill="x", pady=2)
        ttk.Button(side, text="清空", command=lambda: self.txt.delete("1.0", "end")).pack(fill="x", pady=2)

        f1 = ttk.Frame(top)
        f1.pack(fill="x", pady=(8, 0))
        ttk.Label(f1, text="端口").pack(side="left")
        self.var_ports = tk.StringVar(value=DEFAULT_PORTS)
        ttk.Entry(f1, textvariable=self.var_ports, width=28).pack(side="left", padx=(4, 12))
        ttk.Label(f1, text="并发").pack(side="left")
        self.var_workers = tk.StringVar(value="128")
        ttk.Entry(f1, textvariable=self.var_workers, width=5).pack(side="left", padx=(4, 12))
        ttk.Label(f1, text="超时(s)").pack(side="left")
        self.var_timeout = tk.StringVar(value="0.35")
        ttk.Entry(f1, textvariable=self.var_timeout, width=5).pack(side="left", padx=(4, 12))

        f2 = ttk.Frame(top)
        f2.pack(fill="x", pady=(8, 0))
        self.var_smb = tk.BooleanVar(value=True)
        self.var_net = tk.BooleanVar(value=True)
        self.var_deep = tk.BooleanVar(value=True)
        ttk.Checkbutton(f2, text="SMB 共享打印机 (445)", variable=self.var_smb).pack(side="left")
        ttk.Checkbutton(f2, text="网络打印机 (端口)", variable=self.var_net).pack(side="left", padx=10)
        ttk.Checkbutton(f2, text="深度识别型号 (PJL/IPP/HTTP/SNMP)", variable=self.var_deep).pack(side="left")
        self.btn_scan = ttk.Button(f2, text="开始扫描", command=self.start_scan)
        self.btn_scan.pack(side="right", padx=4)
        self.btn_stop = ttk.Button(f2, text="停止", command=self.stop_scan, state="disabled")
        self.btn_stop.pack(side="right", padx=4)

        mid = ttk.Frame(self)
        mid.pack(fill="both", expand=True, padx=10, pady=4)
        self.tree = ttk.Treeview(mid, columns=COLS, show="headings", selectmode="extended")
        for c in COLS:
            self.tree.heading(c, text=HEAD[c], command=lambda x=c: self.sort_by(x))
            self.tree.column(c, width=WIDTH[c], anchor="w", stretch=(c in ("path", "model", "remark")))
        self.tree.tag_configure("odd", background="#E9F6E9")
        self.tree.tag_configure("even", background="#FFFFFF")
        vs = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vs.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", self.open_selected)
        self.tree.bind("<Button-3>", self.popup)
        self.menu = tk.Menu(self, tearoff=0)
        self.menu.add_command(label="打开打印队列 / 管理页", command=self.open_selected)
        self.menu.add_command(label="复制路径", command=self.copy_path)
        self.menu.add_separator()
        self.menu.add_command(label="连接选中共享打印机", command=self.connect_selected)

        bot = ttk.Frame(self)
        bot.pack(fill="x", padx=10, pady=(4, 6))
        ttk.Button(bot, text="连接选中共享打印机", command=self.connect_selected).pack(side="left", padx=3)
        ttk.Button(bot, text="全选", command=lambda: self.tree.selection_set(self.tree.get_children())).pack(side="left", padx=3)
        ttk.Button(bot, text="本机已安装打印机", command=self.show_local).pack(side="left", padx=3)
        ttk.Button(bot, text="导出 CSV", command=self.export_csv).pack(side="left", padx=3)
        ttk.Button(bot, text="清空结果", command=self.clear_rows).pack(side="left", padx=3)
        ttk.Label(bot, text="凭据留空=当前登录凭据", foreground="#777").pack(side="right")
        self.var_user = tk.StringVar()
        self.var_pass = tk.StringVar()
        ttk.Entry(bot, textvariable=self.var_user, width=14).pack(side="right", padx=3)
        ttk.Label(bot, text="用户").pack(side="right")
        ttk.Entry(bot, textvariable=self.var_pass, width=14, show="*").pack(side="right", padx=3)
        ttk.Label(bot, text="密码").pack(side="right")

        self.var_status = tk.StringVar(value="就绪。默认扫描 SMB 打印队列 + 常见网络打印端口")
        ttk.Label(self, textvariable=self.var_status, anchor="w", relief="groove",
                  padding=(6, 3), foreground="#245c2c").pack(fill="x", padx=10, pady=(0, 8))

    # --------------------------------------------------------------- 基础操作
    def status(self, t):
        self.var_status.set(t)

    def fill_local(self):
        nets = local_networks()
        if nets:
            cur = self.txt.get("1.0", "end").strip()
            self.txt.delete("1.0", "end")
            self.txt.insert("1.0", (cur + ", " if cur else "") + ", ".join(nets))
            self.status(f"已填入本机网段：{', '.join(nets)}")

    def clear_rows(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.rows.clear()

    def _add_row(self, d: dict):
        iid = self.tree.insert("", "end", values=tuple(d[c] for c in COLS),
                               tags=("odd" if len(self.tree.get_children()) % 2 == 0 else "even",))
        self.rows[iid] = d

    def sort_by(self, col):
        items = [(self.tree.set(i, col), i) for i in self.tree.get_children()]
        items.sort(key=lambda t: t[0].lower(), reverse=getattr(self, "_rev", False))
        self._rev = not getattr(self, "_rev", False)
        for n, (_, iid) in enumerate(items):
            self.tree.move(iid, "", n)
            self.tree.item(iid, tags=("odd" if n % 2 == 0 else "even",))

    def popup(self, e):
        iid = self.tree.identify_row(e.y)
        if iid and iid not in self.tree.selection():
            self.tree.selection_set(iid)
        self.menu.tk_popup(e.x_root, e.y_root)

    def open_selected(self, _e=None):
        for i in self.tree.selection():
            p = self.rows.get(i, {}).get("path", "")
            if p.startswith("\\\\"):
                try:
                    os.startfile(p)  # 打开打印队列窗口
                except OSError as ex:
                    messagebox.showerror("打开失败", str(ex), parent=self)
            else:
                import webbrowser
                h = self.rows.get(i, {}).get("host", "")
                url = p if p.startswith("http") else (f"http://{h}" if h else "")
                if url:
                    webbrowser.open(url)

    def copy_path(self):
        p = "\n".join(self.rows[i]["path"] for i in self.tree.selection() if i in self.rows)
        if p:
            self.clipboard_clear()
            self.clipboard_append(p)
            self.status("路径已复制")

    def connect_selected(self):
        ids = [i for i in self.tree.selection()
               if self.rows.get(i, {}).get("path", "").startswith("\\\\")]
        if not ids:
            messagebox.showinfo("提示", "请选中「SMB 共享打印机」类型的行", parent=self)
            return
        ok, fail = 0, []
        for i in ids:
            p = self.rows[i]["path"]
            good, msg = connect_shared_printer(p)
            if good:
                ok += 1
                self.tree.set(i, "remark", "已连接到本机")
            else:
                fail.append(f"{p}：{msg}")
        text = f"成功 {ok} 个，失败 {len(fail)} 个"
        if fail:
            text += "\n" + "\n".join(fail[:8])
        self.status(text.replace("\n", "  "))
        if fail:
            messagebox.showwarning("部分失败", text, parent=self)

    def show_local(self):
        try:
            printers = list_local_printers()
        except Exception as e:
            messagebox.showerror("读取失败", str(e), parent=self)
            return
        if not printers:
            messagebox.showinfo("提示", "本机没有已安装的打印机", parent=self)
            return
        for p in printers:
            self._add_row({"kind": "本机已安装", "host": "本机", "name": p["name"],
                           "path": p["port"], "model": p["driver"],
                           "remark": f"待打印 {p['jobs']} 个" + (f" | {p['location']}" if p["location"] else "")})
        self.status(f"已列出本机 {len(printers)} 台打印机（本地+网络连接）")

    def export_csv(self):
        if not self.rows:
            messagebox.showinfo("提示", "没有可导出的结果", parent=self)
            return
        p = filedialog.asksaveasfilename(parent=self, defaultextension=".csv",
                                         initialfile="printers.csv", filetypes=[("CSV", "*.csv")])
        if not p:
            return
        with open(p, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow([HEAD[c] for c in COLS])
            for iid in self.tree.get_children():
                w.writerow([self.rows[iid][c] for c in COLS])
        self.status(f"已导出 {len(self.rows)} 条 → {p}")

    # --------------------------------------------------------------- 扫描流程
    def stop_scan(self):
        self.stop_evt.set()
        self.status("正在停止…")

    def start_scan(self):
        if self.busy:
            return
        if not WIN:
            messagebox.showerror("不支持", "本功能依赖 Windows 的 NetShareEnum / 打印 API", parent=self)
            return
        try:
            hosts, note = parse_targets(self.txt.get("1.0", "end"))
            ports = [int(x) for x in re.split(r"[,;\s]+", self.var_ports.get().strip()) if x]
            if not ports:
                raise ValueError("请至少填写一个端口")
            workers = max(1, min(512, int(self.var_workers.get())))
            timeout = max(0.05, float(self.var_timeout.get()))
        except (ValueError, ipaddress.AddressValueError) as e:
            messagebox.showerror("输入有误", str(e), parent=self)
            return
        if not (self.var_smb.get() or self.var_net.get()):
            messagebox.showinfo("提示", "请至少勾选一种扫描方式", parent=self)
            return
        if len(hosts) * max(1, len(ports)) > 8000:
            if not messagebox.askyesno("确认", "探测任务较多，可能耗时较久，继续？", parent=self):
                return
        self.stop_evt.clear()
        self.busy = True
        self.btn_scan.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.clear_rows()
        self.status(f"正在扫描… 0 / {len(hosts) * len(ports)}  [{note}]")
        threading.Thread(target=self._scan, args=(hosts, ports, workers, timeout,
                                                   self.var_smb.get(), self.var_net.get(),
                                                   self.var_deep.get(),
                                                   self.var_user.get().strip(), self.var_pass.get()),
                         daemon=True).start()

    def _scan(self, hosts, ports, workers, timeout, do_smb, do_net, deep, user, pwd):
        opened: dict[str, set[int]] = {h: set() for h in hosts}
        total = len(hosts) * len(ports)
        done = 0
        jobs = [(h, p) for h in hosts for p in ports]
        if do_net:
            with ThreadPoolExecutor(max_workers=workers) as ex:
                futs = {ex.submit(tcp_open, h, p, timeout): (h, p) for h, p in jobs}
                for fut in as_completed(futs):
                    h, p = futs[fut]
                    done += 1
                    try:
                        if fut.result():
                            opened[h].add(p)
                    except Exception:
                        pass
                    if done % 10 == 0 or done == total:
                        self.q.put(("progress", done, total))
                    if self.stop_evt.is_set():
                        break
        if self.stop_evt.is_set():
            self.q.put(("done", "扫描已停止"))
            return

        # 445 主机：枚举 SMB 打印共享（与端口列表无关，单独探测 445）
        smb_hosts = []
        if do_smb:
            self.q.put(("phase", "端口探测完成，正在枚举 SMB 打印队列…"))
            with ThreadPoolExecutor(max_workers=workers) as ex:
                f445 = {ex.submit(tcp_open, h, 445, timeout): h for h in hosts}
                for fut in as_completed(f445):
                    try:
                        if fut.result():
                            smb_hosts.append(f445[fut])
                    except Exception:
                        pass
            with ThreadPoolExecutor(max_workers=min(16, max(4, workers // 4))) as ex:
                fs = {ex.submit(enum_print_shares, h, user, pwd): h for h in smb_hosts}
                for fut in as_completed(fs):
                    h = fs[fut]
                    try:
                        shares, rc, who = fut.result()
                    except Exception as e:
                        shares, rc, who = [], -1, str(e)
                    for s in shares:
                        self.q.put(("row", {"kind": "SMB 共享打印机", "host": h,
                                            "name": s["name"], "path": s["path"],
                                            "model": who, "remark": s["remark"]}))
                    if self.stop_evt.is_set():
                        break

        # 网络打印机：对有开放端口的主机做深度识别
        candidates = [h for h, ps in opened.items() if ps] if do_net else []
        if candidates:
            self.q.put(("phase", f"正在识别 {len(candidates)} 台开放打印相关端口的设备…"))
            with ThreadPoolExecutor(max_workers=12) as ex:
                fs = {ex.submit(identify_host, h, opened[h], deep, min(1.2, timeout + 0.4)): h
                      for h in candidates}
                for fut in as_completed(fs):
                    h = fs[fut]
                    try:
                        model, labels, is_printer = fut.result()
                    except Exception as e:
                        model, labels, is_printer = "", str(e), False
                    if not is_printer:
                        continue
                    kind = "网络打印机" if any(p in opened[h] for p in RAW_PORTS) else "疑似打印设备"
                    self.q.put(("row", {"kind": kind, "host": h,
                                        "name": (model or "未识别型号")[:80], "path": labels,
                                        "model": model, "remark": "可连接/打开管理页" if model else "仅端口特征"}))
                    if self.stop_evt.is_set():
                        break
        self.q.put(("done", f"扫描完成：{len(hosts)} 个地址 / 445 开放 {len(smb_hosts)} 台 / "
                            f"端口开放 {len(candidates)} 台"))

    def _poll(self):
        try:
            while True:
                m = self.q.get_nowait()
                k = m[0]
                if k == "row":
                    self._add_row(m[1])
                elif k == "progress":
                    self.status(f"正在扫描端口… {m[1]} / {m[2]}")
                elif k == "phase":
                    self.status(m[1])
                elif k == "done":
                    self.busy = False
                    self.btn_scan.configure(state="normal")
                    self.btn_stop.configure(state="disabled")
                    self.status(f"{m[1]} / 结果 {len(self.rows)} 条")
                elif k == "error":
                    messagebox.showerror("错误", m[1], parent=self)
        except queue.Empty:
            pass
        self.after(80, self._poll)


def main():
    root = tk.Tk()
    root.withdraw()
    w = PrinterWindow(root)
    w.protocol("WM_DELETE_WINDOW", root.destroy)
    root.mainloop()


if __name__ == "__main__":
    main()

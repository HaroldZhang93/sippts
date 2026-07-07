# -*- coding: utf-8 -*-
"""扫描数据中心：在核心 CLI 模块与总览仪表盘之间传递结构化结果。

核心模块（SipScan / SipExten / SipRemoteCrack / SipDigestCrack）只把结果累积到
自身的 `found` 列表，不感知 GUI。MainWindow 轮询正在运行的实例，按模块类型解析
`found` 并喂入本单例，仪表盘订阅信号做可视化更新——核心模块零改动、松耦合。

各模块 `found` 条目格式（以 ### 分隔）：
  scan   : ip ## port ## proto ## response ## ua ## type ## fp      (7)
  exten  : ip ## port ## proto ## exten ## response ## ua           (6)
  rcrack : ip ## port ## proto ## user ## pwd                       (5)
  dcrack : ipsrc ## ipdst ## user ## pwd                            (4)
"""

from PyQt5.QtCore import QObject, pyqtSignal


# ---------------- 解析器 ----------------
def parse_found_line(line):
    """scan：'ip###port###proto###response###ua###type###fp' -> dict。"""
    parts = line.split("###")
    if len(parts) != 7:
        return None
    ip, port, proto, response, ua, typ, fp = parts
    res = response or ""
    auth = "required" if ("401" in res or "407" in res) else "none"
    return {"ip": ip, "port": port, "proto": (proto or "").upper(),
            "response": res, "ua": ua, "type": typ, "fp": fp, "auth": auth}


def parse_exten_line(line):
    """exten：'ip###port###proto###exten###response###ua' -> dict。"""
    parts = line.split("###")
    if len(parts) != 6:
        return None
    ip, port, proto, exten, response, ua = parts
    res = response or ""
    auth = "required" if ("401" in res or "407" in res) else "none"
    return {"ip": ip, "port": port, "proto": (proto or "").upper(),
            "exten": exten, "response": res, "ua": ua, "auth": auth}


def parse_cred_line(line, source):
    """rcrack(5) / dcrack(4) -> 统一凭证 dict。"""
    parts = line.split("###")
    if len(parts) == 5:        # rcrack: ip port proto user pwd
        ip, port, proto, user, pwd = parts
        return {"ip": ip, "port": port, "proto": (proto or "").upper(),
                "user": user, "pwd": pwd, "source": source}
    if len(parts) == 4:        # dcrack: ipsrc ipdst user pwd
        _ipsrc, ipdst, user, pwd = parts
        return {"ip": ipdst, "port": "-", "proto": "-",
                "user": user, "pwd": pwd, "source": source}
    return None


class DataStore(QObject):
    """全局单例数据中心。"""

    _instance = None

    host_found = pyqtSignal(dict)
    exten_found = pyqtSignal(dict)
    cred_found = pyqtSignal(dict)
    cve_updated = pyqtSignal(int)
    scan_started = pyqtSignal(str)    # kind
    scan_finished = pyqtSignal(str)   # kind
    cleared = pyqtSignal(str)         # scope: hosts|extensions|creds|all

    def __new__(cls):
        if cls._instance is None:
            inst = super().__new__(cls)
            QObject.__init__(inst)
            inst._init_state()
            cls._instance = inst
        return cls._instance

    def __init__(self):
        # no-op：初始化在 __new__ 完成，否则每次 DataStore() 都会重跑
        # QObject.__init__ 而断开已建立的信号连接。
        pass

    def _init_state(self):
        self.hosts = []
        self.extensions = []
        self.creds = []
        self.cve_count = 0
        self._seen_h = set()
        self._seen_e = set()
        self._seen_c = set()

    # -------- 写入 --------
    def reset(self, scope="all"):
        if scope in ("hosts", "all"):
            self.hosts = []
            self._seen_h = set()
            self.cve_count = 0
        if scope in ("extensions", "all"):
            self.extensions = []
            self._seen_e = set()
        if scope in ("creds", "all"):
            self.creds = []
            self._seen_c = set()
        self.cleared.emit(scope)

    def add_host(self, host):
        key = (host["ip"], host["port"], host["proto"])
        if key in self._seen_h:
            return False
        self._seen_h.add(key)
        self.hosts.append(host)
        self.host_found.emit(host)
        return True

    def add_extension(self, ext):
        key = (ext["ip"], ext["port"], ext["exten"])
        if key in self._seen_e:
            return False
        self._seen_e.add(key)
        self.extensions.append(ext)
        self.exten_found.emit(ext)
        return True

    def add_cred(self, cred):
        key = (cred["ip"], cred["user"])
        if key in self._seen_c:
            return False
        self._seen_c.add(key)
        self.creds.append(cred)
        self.cred_found.emit(cred)
        return True

    def set_cve_count(self, n):
        if n != self.cve_count:
            self.cve_count = n
            self.cve_updated.emit(n)

    # -------- 读取（聚合，主机+分机合并统计） --------
    def _proto_hosts(self):
        return self.hosts + self.extensions

    def proto_distribution(self):
        d = {"UDP": 0, "TCP": 0, "TLS": 0}
        for h in self._proto_hosts():
            p = h.get("proto", "")
            if p in d:
                d[p] += 1
        return d

    def response_distribution(self):
        buckets = {"200": 0, "401/407": 0, "403/404": 0, "其他": 0}
        for h in self._proto_hosts():
            res = h.get("response", "")
            if res.startswith("200"):
                buckets["200"] += 1
            elif res.startswith("401") or res.startswith("407"):
                buckets["401/407"] += 1
            elif res.startswith("403") or res.startswith("404"):
                buckets["403/404"] += 1
            else:
                buckets["其他"] += 1
        return buckets

    def total_findings(self):
        return len(self.hosts) + len(self.extensions) + len(self.creds)

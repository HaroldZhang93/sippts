#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = "Jose Luis Verdeguer"
__version__ = "4.1"
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2024, SIPPTS"
__email__ = "pepeluxx@gmail.com"


import pyshark
import signal
import os
import platform
import re
import socket
import threading
import time
import asyncio
from .lib.functions import parse_message, parse_digest, searchInterface
from .lib.color import Color
from .lib.logos import Logo
import netifaces


class SipSniff:
    def __init__(self):
        self.dev = "8890599A-308E-4612-8CAE-23E2FD6EA43C"
        self.ofile = "snifftest.pcap"
        self.proto = "ALL"
        self.verbose = 0
        self.auth = 0
        self.list_interfaces = False

        self.run = True

        self.found = []
        self.line = ["-", "\\", "|", "/"]
        self.pos = 0
        self.quit = False

        self.c = Color()

    def signal_handler(self, sig, frame):
        print(f"{self.c.BYELLOW}You pressed Ctrl+C!")
        print(f"{self.c.BWHITE}\nStopping sniffer ...")
        print(self.c.WHITE)

        self.stop()

    def stop(self):
        self.run = False
        exit()

    def list_available_interfaces(self):
        """列出所有可用的网络接口"""
        print(f"{self.c.BWHITE}可用的网络接口:")
        
        ifaces = netifaces.interfaces()
        for iface in ifaces:
            try:
                # 尝试获取接口的IP地址
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    ip = addrs[netifaces.AF_INET][0]['addr']
                    print(f"{self.c.GREEN}{iface} - IP: {ip}")
                else:
                    print(f"{self.c.YELLOW}{iface} - 无IP地址")
            except:
                print(f"{self.c.RED}{iface} - 无法获取信息")
        
        print(self.c.WHITE)
        return

    def start(self):
        try:
            self.verbose == int(self.verbose)
        except:
            self.verbose = 0

        try:
            self.auth == int(self.auth)
        except:
            self.auth = 0
            
        # 如果用户请求列出接口，则显示接口列表并退出
        if self.list_interfaces:
            self.list_available_interfaces()
            return

        if self.ofile and self.ofile != "":
            if not re.search(r".pcap$", self.ofile):
                self.ofile += ".pcap"

        current_user = os.popen("whoami").read()
        current_user = current_user.strip()
        ops = platform.system()

        if ops == "Linux" and current_user != "root":
            print(
                f"{self.c.WHITE}You must be {self.c.RED}root{self.c.WHITE} to use this module"
            )
            return

        logo = Logo("sipsniff")
        logo.print()

        self.proto = self.proto.upper()

        signal.signal(signal.SIGINT, self.signal_handler)
        print(f"{self.c.BYELLOW}\nPress Ctrl+C to stop")
        print(self.c.WHITE)

        # define capture object
        if self.dev == "":
            networkInterface = searchInterface()
        else:
            networkInterface = self.dev
            
        # 在Windows系统上，确保网络接口名称格式正确
        if ops == "Windows" and networkInterface and not networkInterface.startswith("\\Device\\NPF_"):
            # 检查是否只是GUID
            if networkInterface.startswith("{") and networkInterface.endswith("}"):
                networkInterface = f"\\Device\\NPF_{networkInterface}"

        print(f"{self.c.BWHITE}[✓] Listening on: {self.c.GREEN}{networkInterface}")

        if self.proto == "ALL":
            print(f"{self.c.BWHITE}[✓] Protocols: {self.c.GREEN}UDP, TCP, TLS")
        else:
            print(f"{self.c.BWHITE}[✓] Protocol: {self.c.GREEN}{self.proto}")

        if self.ofile != "":
            print(
                f"{self.c.BWHITE}[✓] Save captured data in the file: {self.c.GREEN}{self.ofile}"
            )
        if self.auth == 1:
            print(
                f"{self.c.BWHITE}[✓] {self.c.GREEN}Capture only authentication digest"
            )
        print(self.c.WHITE)

        self.run = True

        threads = list()

        if self.ofile and self.ofile != "":
            t = threading.Thread(
                target=self.sniff, args=(networkInterface, self.ofile), daemon=True
            )
            threads.append(t)
            t.start()
            time.sleep(0.1)

        t = threading.Thread(
            target=self.sniff, args=(networkInterface, ""), daemon=True
        )
        threads.append(t)
        t.start()

        t.join()

    def sniff(self, networkInterface, file):
        # 为每个线程创建新的事件循环
        asyncio.set_event_loop(asyncio.new_event_loop())
        print(f"file: {file}")
        if file != "":
            capture = pyshark.LiveCapture(interface=networkInterface, output_file=file)
        else:
            print(f"proto: {self.proto}")
            if self.proto == "UDP":
                print(f"udp port 5060")
                capture = pyshark.LiveCapture(
                    interface=networkInterface,
                    bpf_filter="udp port 5060",
                    include_raw=True,
                    use_json=True,
                )
            elif self.proto == "TCP":
                print(f"tcp port 5060")
                capture = pyshark.LiveCapture(
                    interface=networkInterface,
                    bpf_filter="tcp port 5060",
                    include_raw=True,
                    use_json=True,
                )
            elif self.proto == "TLS":
                print(f"tcp port 5061")
                capture = pyshark.LiveCapture(
                    interface=networkInterface,
                    bpf_filter="tcp port 5061",
                    include_raw=True,
                    use_json=True,
                )
            else:
                print(f"all")
                capture = pyshark.LiveCapture(
                    interface=networkInterface, include_raw=True, use_json=True
                )

        # for packet in capture.sniff_continuously(packet_count=100):
        print("capture.sniff_continuously()")
        for packet in capture.sniff_continuously():
            if self.run == False:
                try:
                    capture.clear()
                    capture.close()
                except:
                    pass
                return
            else:
                # adjusted output
                try:
                    if file == "":
                        # get packet content
                        protocol = packet.transport_layer  # protocol type
                        src_addr = packet.ip.src  # source address
                        src_port = packet[protocol].srcport  # source port
                        dst_addr = packet.ip.dst  # destination address
                        # destination port
                        dst_port = packet[protocol].dstport
                        
                        try:
                            mac_addr = packet.eth.src  # MAC address
                        except:
                            mac_addr = ""

                        print(f"src_addr: {src_addr}, src_port: {src_port}, dst_addr: {dst_addr}, dst_port: {dst_port}")
                        print(f"protocol: {protocol}, mac_addr: {mac_addr}")
                        # TLS connection
                        if self.proto == "TLS" or self.proto == "ALL":
                            if src_port == "5061" or dst_port == "5061":
                                if self.auth == 0:
                                    print(
                                        f"{self.c.YELLOW}Found TLS connection {src_addr}:{src_port} => {dst_addr}:{dst_port}"
                                    )

                        try:
                            # 尝试多种方式获取payload
                            msg = None
                            payload_obtained = False
                            
                            # 检查数据包是否有SIP层
                            if 'sip' in packet:
                                try:
                                    # 构建完整的SIP消息，包括Request-Line或Status-Line
                                    sip_message = ""
                                    
                                    # 添加Request-Line或Status-Line
                                    if hasattr(packet.sip, 'Request-Line'):
                                        sip_message += getattr(packet.sip, 'Request-Line') + "\r\n"
                                    elif hasattr(packet.sip, 'Status-Line'):
                                        sip_message += getattr(packet.sip, 'Status-Line') + "\r\n"
                                    elif hasattr(packet.sip, 'Request_Line'):
                                        sip_message += packet.sip.Request_Line + "\r\n"
                                    elif hasattr(packet.sip, 'Status_Line'):
                                        sip_message += packet.sip.Status_Line + "\r\n"
                                    
                                    # 添加消息头
                                    if hasattr(packet.sip, 'msg_hdr'):
                                        sip_message += packet.sip.msg_hdr
                                        
                                    # 如果成功构建了消息
                                    if sip_message:
                                        msg = sip_message
                                        payload_obtained = True
                                        # print("成功从SIP层构建完整消息")
                                    # 如果没有成功构建，尝试直接使用msg_hdr
                                    elif hasattr(packet.sip, 'msg_hdr'):
                                        msg = packet.sip.msg_hdr
                                        payload_obtained = True
                                        # print("成功从SIP层的msg_hdr获取消息内容")
                                except Exception as e:
                                    print(f"从SIP层获取消息内容失败: {str(e)}")
                                    
                                # 如果上面的方法失败，尝试从Request-Line字段获取
                                if not payload_obtained:
                                    try:
                                        # 尝试获取Request-Line字段
                                        if hasattr(packet.sip, 'Request_Line_raw'):
                                            request_line = packet.sip.Request_Line
                                            if request_line:
                                                # 尝试获取方法
                                                if hasattr(packet.sip, 'Request_Line') and 'Method' in dir(packet.sip.Request_Line):
                                                    method = packet.sip.Request_Line.Method
                                                    print(f"从Request-Line获取到方法: {method}")
                                                
                                                # 构建一个简单的SIP消息
                                                simple_msg = f"{request_line}\r\n"
                                                if hasattr(packet.sip, 'msg_hdr'):
                                                    simple_msg += packet.sip.msg_hdr
                                                
                                                msg = simple_msg
                                                payload_obtained = True
                                                print("成功从Request-Line构建简单消息")
                                    except Exception as e:
                                        print(f"从Request-Line获取消息内容失败: {str(e)}")
                            
                            # 如果没有找到SIP层或获取失败，尝试其他方法
                            if not payload_obtained:
                                # 方法1: 尝试获取payload_raw[0]
                                try:
                                    if hasattr(packet[protocol], 'payload_raw') and packet[protocol].payload_raw:
                                        if isinstance(packet[protocol].payload_raw, list) and len(packet[protocol].payload_raw) > 0:
                                            msg = packet[protocol].payload_raw[0]
                                            payload_obtained = True
                                            print("成功通过payload_raw[0]获取payload")
                                except Exception as e:
                                    print(f"方法1获取payload失败: {str(e)}")
                                
                            # 如果所有方法都失败，打印详细信息并跳过此数据包
                            if not payload_obtained or not msg:
                                # print(f"无法获取数据包payload，跳过此数据包")
                                
                                # # 打印数据包的所有层
                                # try:
                                #     print("数据包的所有层:")
                                #     for layer in packet.layers:
                                #         print(f"- {layer.layer_name}")
                                # except Exception as e:
                                #     print(f"打印数据包层时出错: {str(e)}")
                                
                                # # 尝试打印SIP层的详细信息
                                # if 'sip' in packet:
                                #     try:
                                #         print("SIP层属性:")
                                #         sip_attrs = dir(packet.sip)
                                #         print(sip_attrs)
                                        
                                #         # 尝试打印一些关键SIP字段
                                #         for field in ['Request_Line', 'Status_Line', 'request_line', 'status_line', 'msg_hdr']:
                                #             if hasattr(packet.sip, field):
                                #                 print(f"SIP字段 {field}: {getattr(packet.sip, field)}")
                                #     except Exception as e:
                                #         print(f"打印SIP层信息时出错: {str(e)}")
                                
                                # # 尝试打印更多调试信息
                                # try:
                                #     print(f"数据包协议: {protocol}")
                                #     if hasattr(packet[protocol], 'field_names'):
                                #         print(f"数据包字段名: {packet[protocol].field_names}")
                                #     print(f"数据包字符串表示: {str(packet[protocol])[:200]}")  # 只打印前200个字符
                                    
                                #     # 尝试打印一些常见字段的值
                                #     for field in ['srcport', 'dstport', 'length', 'checksum', 'value', 'status', 'stream']:
                                #         if hasattr(packet[protocol], field):
                                #             print(f"字段 {field} 的值: {getattr(packet[protocol], field)}")
                                # except Exception as e:
                                #     print(f"打印调试信息时出错: {str(e)}")
                                
                                continue
                            
                            # 尝试将payload转换为ASCII字符串
                            try:
                                if isinstance(msg, bytes):
                                    ascii_string = msg.decode("ASCII", errors="replace")
                                elif isinstance(msg, str):
                                    # 检查是否是十六进制字符串
                                    if all(c in '0123456789abcdefABCDEF' for c in msg):
                                        bytes_object = bytes.fromhex(msg)
                                        ascii_string = bytes_object.decode("ASCII", errors="replace")
                                    else:
                                        ascii_string = msg
                                else:
                                    # 尝试转换为字符串
                                    ascii_string = str(msg)
                                    
                                print(f"成功将payload转换为ASCII字符串")
                            except Exception as e:
                                print(f"转换payload为ASCII字符串失败: {str(e)}")
                                continue
                            
                            # 解析SIP消息
                            print(f"ascii_string: {ascii_string}")
                            headers = parse_message(ascii_string)
                            # print(f"headers: {headers}")
                            if headers:
                                ua = headers["ua"]
                                method = headers["method"]
                                sipuser = headers["sipuser"]
                                sipdomain = headers["sipdomain"]
                                if sipuser == "":
                                    sipuser = headers["fromuser"]

                                # Is a SIP message?
                                if method != "":
                                    if self.auth == 0:
                                        print(
                                            f"{self.c.YELLOW}[{method}] {src_addr}:{src_port} => {dst_addr}:{dst_port} - {ua}"
                                        )
                                        print(
                                            f"{self.c.CYAN}Found Domain {sipdomain} for user {sipuser} connecting to {dst_addr}:{dst_port}"
                                        )

                                    try:
                                        auth = headers["auth"]
                                        headers_auth = parse_digest(auth)
                                        if headers_auth:
                                            print(f"{self.c.GREEN}Auth={auth}\n")
                                            data = '%s"%s"%s"%s"%s"%s"%s"%s"%s"%s"MD5"%s' % (
                                            src_addr,
                                            dst_addr,
                                            headers_auth["username"],
                                            headers_auth["realm"],
                                            method,
                                            headers_auth["uri"],
                                            headers_auth["nonce"],
                                            headers_auth["cnonce"],
                                            headers_auth["nc"],
                                            headers_auth["qop"],
                                            headers_auth["response"],
                                        )

                                        f = open("snifftest.txt", "a+")
                                        f.write(data)
                                        f.write("\n")
                                        f.close()

                                        print(f"{self.c.RED}Auth data saved in file snifftest.txt")
                                    except Exception as e:
                                        print(f"save auth data failed: {str(e)}")

                                # Search in headers
                                headers = ascii_string.split("\r\n")
                                for header in headers:
                                    m = re.search(
                                        r"^Via:\s.*\s([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*",
                                        header,
                                    )
                                    if m:
                                        ipfound = "%s" % (m.group(1))
                                        if self.verbose == 1:
                                            print(
                                                f"{self.c.WHITE}\tFound IP {ipfound} in header Via"
                                            )

                                    m = re.search(
                                        r"^Route:\s\<sip:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*",
                                        header,
                                    )
                                    if m:
                                        ipfound = "%s" % (m.group(1))
                                        if self.verbose == 1:
                                            print(
                                                f"{self.c.WHITE}\tFound IP {ipfound} in header Route"
                                            )

                                    m = re.search(
                                        r"^Record-Route:\s\<sip:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*",
                                        header,
                                    )
                                    if m:
                                        ipfound = "%s" % (m.group(1))
                                        if self.verbose == 1:
                                            print(
                                                f"{self.c.WHITE}\tFound IP {ipfound} in header Record-Route"
                                            )

                                    m = re.search(
                                        r"^From:\s\"*(.*)\"*\s*\<[sip|sips]+:(.*)\@(.*)>.*",
                                        header,
                                    )
                                    if m:
                                        username = "%s" % (m.group(1))
                                        userfound = "%s" % (m.group(2))
                                        ipfound = "%s" % (m.group(3))
                                        if not username:
                                            username = ""
                                        if (
                                            username == ""
                                            and headers_auth["username"]
                                            and headers_auth["username"] != ""
                                        ):
                                            username = headers_auth["username"]
                                        # ipfound = socket.gethostbyname(ipfound)
                                        if self.verbose == 1:
                                            print(
                                                f"{self.c.WHITE}\tFound IP {ipfound} in header From"
                                            )

                                    m = re.search(
                                        r"^To:\s\"*(.*)\"*\s*\<[sip|sips]+:(.*)\@(.*)>.*",
                                        header,
                                    )

                                    if m:
                                        username = "%s" % (m.group(1))
                                        userfound = "%s" % (m.group(2))
                                        ipfound = "%s" % (m.group(3))
                                        if not username:
                                            username = ""
                                        if (
                                            username == ""
                                            and headers_auth["username"]
                                            and headers_auth["username"] != ""
                                        ):
                                            username = headers_auth["username"]
                                        # ipfound = socket.gethostbyname(ipfound)

                                        if self.verbose == 1:
                                            print(
                                                f"{self.c.WHITE}\tFound IP {ipfound} in header To"
                                            )

                                    m = re.search(
                                        r"^Contact:\s\<sip:(.*)\@(.*)>.*>", header
                                    )
                                    if m:
                                        userfound = "%s" % (m.group(1))
                                        ipfound = "%s" % (m.group(2))

                                        m = re.search(r"(.*):([0-9]*)", ipfound)
                                        if m:
                                            ipfound = "%s" % (m.group(1))
                                            portfound = "%s" % (m.group(2))
                                        else:
                                            portfound = "5060"

                                        if self.verbose == 1:
                                            print(
                                                f"{self.c.WHITE}\tFound user {userfound} from IP {ipfound}:{portfound} to IP {dst_addr}:{dst_port} in header Contact"
                                            )

                        except Exception as e:
                            print(f"except: {e}")
                            # Non ASCII data
                            pass
                except pyshark.capture.capture.TSharkCrashException:
                    print("Capture has crashed")
                except AttributeError as e:
                    print(f"AttributeError: {e}")
                    # ignore packets other than TCP, UDP and IPv4
                    pass
        print("capture.clear()") 
        capture.clear()
        print("capture.close()")
        capture.close()

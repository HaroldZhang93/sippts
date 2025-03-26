from PyQt5.QtWidgets import (
    QLabel, QLineEdit, QComboBox, QPushButton, QCheckBox,
    QHBoxLayout, QVBoxLayout, QGridLayout, QTextEdit, QFileDialog
)
from PyQt5.QtCore import Qt, pyqtSignal
import netifaces
import traceback
import platform
import os
import threading
import time
from scapy.all import ARP, sniff, IP, TCP, UDP, Raw

from sippts.gui.common.base_tab import BaseTab
from sippts.arpspoof import ArpSpoof
from sippts.lib.functions import get_machine_default_ip, get_default_gateway_windows, get_default_gateway_linux, system_call


class ArpSpoofWithMonitor(ArpSpoof):
    """扩展ArpSpoof类，添加数据包监控功能"""
    
    def __init__(self, callback=None):
        super().__init__()
        self.callback = callback
        self.monitor_thread = None
        self.stop_monitor = False
        self.interface = None
    
    def start_monitor(self, interface=None):
        """启动数据包监控"""
        self.interface = interface
        self.stop_monitor = False
        
        if self.monitor_thread is None or not self.monitor_thread.is_alive():
            self.monitor_thread = threading.Thread(target=self._monitor_packets, daemon=True)
            self.monitor_thread.start()
    
    def stop_monitoring(self):
        """停止数据包监控"""
        self.stop_monitor = True
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(2)  # 等待最多2秒
    
    def _monitor_packets(self):
        """监控数据包"""
        if self.callback:
            self.callback("开始监控网络流量...")
        
        # 使用scapy的sniff函数监控数据包
        try:
            sniff(prn=self._process_packet, 
                  store=0, 
                  stop_filter=lambda p: self.stop_monitor,
                  iface=self.interface)
        except Exception as e:
            if self.callback:
                self.callback(f"监控网络流量时出错: {str(e)}")
    
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
            if self.callback and info:
                self.callback(f"[{proto}] {info}")


class ArpSpoofTab(BaseTab):
    """ARP欺骗模块标签页"""
    
    def __init__(self, main_window):
        super().__init__(main_window)
        
        # 初始化UI
        self.setup_ui()
        
        # 从配置加载输入值
        self.load_input_values()
        
        # 存储网络接口映射
        self.interface_map = {}
    
    def setup_ui(self):
        """设置UI界面"""
        # 创建主布局
        layout = QGridLayout()
        self.setLayout(layout)
        
        # 设置列宽比例
        layout.setColumnStretch(0, 1)  # 标签列
        layout.setColumnStretch(1, 4)  # 输入框列
        layout.setColumnStretch(2, 1)  # 标签列
        layout.setColumnStretch(3, 4)  # 输入框列
        
        row = 0
        layout.addWidget(QLabel("目标IP/网段:"), row, 0)
        self.ip_input = QLineEdit()
        self.ip_input.setObjectName("ip_input")
        self.ip_input.setPlaceholderText("目标IP或网段 (例如: 192.168.1.0/24 或 192.168.1.100)")
        self.ip_input.setMinimumWidth(300)
        layout.addWidget(self.ip_input, row, 1)
        
        layout.addWidget(QLabel("网关IP:"), row, 2)
        self.gateway_input = QLineEdit()
        self.gateway_input.setObjectName("gateway_input")
        self.gateway_input.setPlaceholderText("网关IP地址 (留空自动获取)")
        self.gateway_input.setMinimumWidth(300)
        layout.addWidget(self.gateway_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("网络接口:"), row, 0)
        
        # 创建水平布局来放置输入框和按钮
        interface_layout = QHBoxLayout()
        
        self.interface_input = QComboBox()
        self.interface_input.setObjectName("interface_input")
        self.interface_input.setPlaceholderText("选择网络接口")
        self.interface_input.setMinimumWidth(240)
        interface_layout.addWidget(self.interface_input)
        
        # 添加刷新按钮
        refresh_btn = QPushButton("刷新")
        refresh_btn.setFixedWidth(60)
        refresh_btn.clicked.connect(self.refresh_interfaces)
        interface_layout.addWidget(refresh_btn)
        
        # 将水平布局添加到网格布局中
        layout.addLayout(interface_layout, row, 1)
        
        # IP文件选择
        layout.addWidget(QLabel("IP列表文件:"), row, 2)
        file_layout = QHBoxLayout()
        self.file_input = QLineEdit()
        self.file_input.setObjectName("file_input")
        self.file_input.setPlaceholderText("包含多个目标IP的文件路径")
        self.file_input.setMinimumWidth(240)
        file_layout.addWidget(self.file_input)
        
        # 添加选择文件按钮
        file_btn = QPushButton("选择")
        file_btn.setFixedWidth(60)
        file_btn.clicked.connect(self.choose_ip_file)
        file_layout.addWidget(file_btn)
        
        # 将水平布局添加到网格布局中
        layout.addLayout(file_layout, row, 3)
        
        # 详细日志选项
        row += 1
        self.verbose_check = QCheckBox("显示详细日志")
        self.verbose_check.setObjectName("verbose_check")
        self.verbose_check.setChecked(True)
        layout.addWidget(self.verbose_check, row, 0, 1, 2)
        
        # 点击链接监控选项
        self.monitor_check = QCheckBox("监控网络流量")
        self.monitor_check.setObjectName("monitor_check")
        self.monitor_check.setChecked(True)
        self.monitor_check.setToolTip("启用对欺骗流量的分析和监控")
        layout.addWidget(self.monitor_check, row, 2, 1, 2)
        
        # 按钮
        row += 1
        button_layout = QHBoxLayout()
        self.start_btn = QPushButton("开始ARP欺骗")
        self.start_btn.clicked.connect(self.start_module)
        button_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("停止ARP欺骗")
        self.stop_btn.clicked.connect(self.main_window.stop_module)
        self.stop_btn.setEnabled(False)
        button_layout.addWidget(self.stop_btn)
        
        layout.addLayout(button_layout, row, 0, 1, 4)
        
        # 结果文本区域
        row += 1
        self.create_result_text(layout, row)
        
        # 初始化网络接口列表
        try:
            self.refresh_interfaces()
            # 自动获取默认网关
            self.get_default_gateway()
        except Exception as e:
            self.result_text.append(f"初始化网络接口列表或网关时出错: {str(e)}")
            traceback.print_exc()
    
    def refresh_interfaces(self):
        """刷新网络接口列表"""
        try:
            self.interface_input.clear()
            self.interface_map = {}
            
            # 获取所有网络接口
            interfaces = netifaces.interfaces()
            
            for iface in interfaces:
                # 获取接口的IPv4地址
                addresses = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addresses:
                    for addr in addresses[netifaces.AF_INET]:
                        ip_addr = addr.get('addr')
                        if ip_addr and not ip_addr.startswith('127.'):
                            # 显示格式: 接口名称 (IP地址)
                            display_name = f"{iface} ({ip_addr})"
                            self.interface_input.addItem(display_name)
                            self.interface_map[display_name] = iface
            
            # 如果没有找到接口，添加提示
            if self.interface_input.count() == 0:
                self.interface_input.addItem("未找到可用的网络接口")
                
        except Exception as e:
            self.result_text.append(f"刷新网络接口列表时出错: {str(e)}")
            traceback.print_exc()
    
    def get_default_gateway(self):
        """获取默认网关"""
        try:
            ops = platform.system()
            gateway = ""
            
            if ops == "Linux":
                gateway = get_default_gateway_linux()
            elif ops == "Windows":
                gateway = get_default_gateway_windows()
            elif ops == "Darwin":  # macOS
                gateway = system_call("route -n get default | grep 'gateway' | awk '{print $2}'").decode().strip()
            
            if gateway:
                self.gateway_input.setText(gateway)
        except Exception as e:
            self.result_text.append(f"获取默认网关时出错: {str(e)}")
    
    def choose_ip_file(self):
        """选择IP列表文件"""
        file_name, _ = QFileDialog.getOpenFileName(
            self, "选择IP列表文件", "", "文本文件 (*.txt);;所有文件 (*)"
        )
        if file_name:
            self.file_input.setText(file_name)
    
    def start_module(self):
        """启动ARP欺骗模块"""
        # 检查权限
        if platform.system() == "Windows":
            # Windows需要管理员权限
            if not self.is_admin():
                self.result_text.append("警告: ARP欺骗需要管理员权限才能运行")
                self.result_text.append("请右键点击程序选择'以管理员身份运行'")
                return
        elif platform.system() in ["Linux", "Darwin"]:
            # Linux/macOS需要root权限
            if os.geteuid() != 0:
                self.result_text.append("警告: ARP欺骗需要root权限才能运行")
                self.result_text.append("请使用sudo命令运行程序")
                return
        
        # 验证输入
        ip_target = self.ip_input.text().strip()
        ip_file = self.file_input.text().strip()
        
        if not ip_target and not ip_file:
            self.result_text.append("错误: 请输入目标IP/网段或选择IP列表文件")
            return
        
        # 获取网关IP
        gateway = self.gateway_input.text().strip()
        
        # 获取选中的网络接口
        interface = ""
        interface_text = self.interface_input.currentText()
        if interface_text in self.interface_map:
            interface = self.interface_map[interface_text]
        
        # 获取详细日志选项
        verbose = 1 if self.verbose_check.isChecked() else 0
        
        # 显示配置信息
        self.result_text.clear()
        self.result_text.append("=== ARP欺骗配置 ===")
        self.result_text.append(f"目标IP/网段: {ip_target if ip_target else '(使用文件)'}")
        if ip_file:
            self.result_text.append(f"IP列表文件: {ip_file}")
        self.result_text.append(f"网关IP: {gateway}")
        self.result_text.append(f"网络接口: {interface}")
        self.result_text.append(f"详细日志: {'是' if verbose else '否'}")
        self.result_text.append(f"监控流量: {'是' if self.monitor_check.isChecked() else '否'}")
        self.result_text.append("==================")
        
        # 创建日志回调函数
        def log_callback(message):
            self.append_log(message)
        
        # 创建并配置ArpSpoof实例
        arpspoof = ArpSpoofWithMonitor(callback=log_callback)
        arpspoof.ip = ip_target
        arpspoof.gw = gateway
        arpspoof.verbose = verbose
        arpspoof.file = ip_file
        
        # 启用监控选项
        self.enable_monitoring = self.monitor_check.isChecked()
        
        # 存储实例
        self.module_instance = arpspoof
        
        # 通知主窗口模块启动
        self.on_module_started()
        
        # 如果启用了监控，则启动监控线程
        if self.enable_monitoring and interface:
            arpspoof.start_monitor(interface)
        
        # 启动模块线程
        self.main_window.start_module_thread(self, arpspoof.start)
    
    def load_input_values(self):
        """从配置加载输入值"""
        config = self.config_manager.get_tab_config(self.__class__.__name__)
        
        # 恢复保存的值
        for name, value in config.items():
            if hasattr(self, name) and value:
                widget = getattr(self, name)
                if isinstance(widget, QLineEdit):
                    widget.setText(value)
                elif isinstance(widget, QComboBox) and widget.findText(value) >= 0:
                    widget.setCurrentText(value)
                elif isinstance(widget, QCheckBox):
                    widget.setChecked(value.lower() == "true")
    
    def is_admin(self):
        """检查是否有管理员权限"""
        try:
            if platform.system() == "Windows":
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except:
            return False
            
    def on_module_stopped(self):
        """模块被停止时的处理"""
        if hasattr(self, 'module_instance') and self.module_instance:
            # 停止ARP欺骗
            self.module_instance.stop()
            
            # 如果是监控实例，也停止监控
            if hasattr(self.module_instance, 'stop_monitoring'):
                self.module_instance.stop_monitoring()
            
            # 确保按钮状态正确
            if self.start_btn:
                self.start_btn.setEnabled(True)
            if self.stop_btn:
                self.stop_btn.setEnabled(False)
            
            self.append_log("ARP欺骗已停止，ARP表已恢复") 
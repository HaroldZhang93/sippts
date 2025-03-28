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


class ArpSpoofTab(BaseTab):
    """ARP欺骗模块标签页"""
    
    def __init__(self, main_window):
        super().__init__(main_window)
        # 存储网络接口映射
        self.interface_map = {}
        # 初始化UI
        self.setup_ui()
        
        # 从配置加载输入值
        self.load_input_values()
        
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
                            # 确保interface_map已初始化为字典
                            if not hasattr(self, 'interface_map') or self.interface_map is None:
                                self.interface_map = {}
                            # 添加映射并打印确认
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
        else:
            print(f"接口不存在: {interface_text}")
            
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
        arpspoof = ArpSpoof(callback=log_callback)
        arpspoof.ip = ip_target
        arpspoof.gw = gateway
        arpspoof.verbose = verbose
        arpspoof.file = ip_file
        
        # 设置监控选项
        arpspoof.monitor_enabled = self.monitor_check.isChecked()
        arpspoof.interface = interface
        
        # 存储实例
        self.module_instance = arpspoof
        
        # 通知主窗口模块启动
        self.on_module_started()
        
        # 启动模块线程
        # self.main_window.start_module_thread(self, arpspoof.start)
        self.main_window.run_module(
            self.module_instance, 
            self.on_module_finished
        )
    
    def load_input_values(self):
        """从配置加载输入值"""
        config = self.config_manager.get_tab_config(self.__class__.__name__)
        
        # 恢复保存的值
        for name, value in config.items():
            if hasattr(self, name) and value is not None:
                widget = getattr(self, name)
                if isinstance(widget, QLineEdit):
                    widget.setText(value)
                elif isinstance(widget, QComboBox) and widget.findText(value) >= 0:
                    widget.setCurrentText(value)
                elif isinstance(widget, QCheckBox):
                    if isinstance(value, bool):
                        widget.setChecked(value)
                    else:
                        # 处理字符串情况
                        widget.setChecked(str(value).lower() == "true")
    
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
            
            # 确保按钮状态正确
            if self.start_btn:
                self.start_btn.setEnabled(True)
            if self.stop_btn:
                self.stop_btn.setEnabled(False)
            
            self.append_log("ARP欺骗已停止，ARP表已恢复") 
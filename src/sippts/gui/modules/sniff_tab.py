from PyQt5.QtWidgets import (
    QLabel, QLineEdit, QComboBox, QPushButton, QCheckBox, QGroupBox,
    QHBoxLayout, QVBoxLayout, QGridLayout, QTextEdit, QFileDialog, QListWidget
)
from PyQt5.QtCore import Qt, pyqtSignal
import netifaces
import traceback
import re
import os
import subprocess
import platform

from sippts.gui.common.base_tab import BaseTab
from sippts.sipsniff import SipSniff

# 创建SipSniff的包装类，避免在非主线程中使用信号处理
class SipSniffWrapper:
    """SipSniff的包装类，用于在GUI环境中使用"""
    
    def __init__(self):
        """初始化包装类"""
        self.sniff = SipSniff()
        
        # 复制SipSniff的属性
        self.dev = None
        self.ofile = None
        self.proto = None
        self.verbose = 0
        self.auth = 0
        self.run = True
        
        # 存储接口映射
        self.interface_map = {}
    
    def start(self):
        """启动嗅探，避免使用信号处理"""
        # 将属性传递给SipSniff实例
        self.sniff.dev = self.dev
        self.sniff.ofile = self.ofile
        self.sniff.proto = self.proto
        self.sniff.verbose = self.verbose
        self.sniff.auth = self.auth
        
        # 不使用信号处理，直接调用sniff方法
        try:
            # 调用sniff方法而不是start方法
            print(f"开始嗅探，接口: {self.dev}, 输出文件: {self.ofile}")
            self.sniff.sniff(self.dev, self.ofile)
        except KeyboardInterrupt:
            # 忽略KeyboardInterrupt异常
            pass
        except Exception as e:
            print(f"嗅探过程中出错: {str(e)}")
            traceback.print_exc()
    
    def stop(self):
        """停止嗅探"""
        print("停止嗅探...")
        self.sniff.run = False
        self.run = False

class SniffTab(BaseTab):
    """SIP嗅探模块标签页"""
    
    def __init__(self, main_window):
        super().__init__(main_window)
        
        # 初始化UI
        self.setup_ui()
        
        # 存储接口映射
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
        
        # 基本参数
        row = 0
        layout.addWidget(QLabel("网络接口:"), row, 0)
        
        # 创建水平布局来放置输入框和按钮
        interface_layout = QHBoxLayout()
        
        self.interface_input = QComboBox()
        self.interface_input.setPlaceholderText("选择网络接口")
        self.interface_input.setMinimumWidth(300)
        interface_layout.addWidget(self.interface_input)
        
        # 添加刷新按钮
        refresh_btn = QPushButton("刷新")
        refresh_btn.setFixedWidth(60)
        refresh_btn.clicked.connect(self.refresh_interfaces)
        interface_layout.addWidget(refresh_btn)
        
        # 将水平布局添加到网格布局中
        layout.addLayout(interface_layout, row, 1)
        
        layout.addWidget(QLabel("协议:"), row, 2)
        self.proto_input = QComboBox()
        self.proto_input.addItems(["ALL", "UDP", "TCP", "TLS"])
        self.proto_input.setCurrentText("UDP")
        self.proto_input.setMinimumWidth(300)
        layout.addWidget(self.proto_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("输出文件:"), row, 0)
        
        # 创建水平布局来放置输入框和按钮
        output_file_layout = QHBoxLayout()
        
        self.output_file_input = QLineEdit()
        self.output_file_input.setText("snifftest.pcap")
        self.output_file_input.setPlaceholderText("嗅探结果保存文件路径")
        self.output_file_input.setMinimumWidth(240)
        output_file_layout.addWidget(self.output_file_input)
        
        # 添加选择文件按钮
        output_file_btn = QPushButton("选择")
        output_file_btn.setFixedWidth(60)
        output_file_btn.clicked.connect(self.choose_output_file)
        output_file_layout.addWidget(output_file_btn)
        
        # 将水平布局添加到网格布局中
        layout.addLayout(output_file_layout, row, 1)
        
        # 选项
        options_group = QGroupBox("选项")
        options_layout = QHBoxLayout()
        
        self.verbose_check = QCheckBox("详细输出")
        self.verbose_check.setChecked(False)
        options_layout.addWidget(self.verbose_check)
        
        self.auth_check = QCheckBox("仅显示认证信息")
        self.auth_check.setChecked(False)
        options_layout.addWidget(self.auth_check)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group, row, 2, 1, 2)
        
        # 添加按钮布局
        row += 1
        button_layout = QHBoxLayout()
        
        # 开始按钮
        self.start_btn = QPushButton("开始嗅探")
        self.start_btn.clicked.connect(self.start_module)
        button_layout.addWidget(self.start_btn)
        
        # 停止按钮
        self.stop_btn = QPushButton("停止嗅探")
        self.stop_btn.clicked.connect(self.main_window.stop_module)
        self.stop_btn.setEnabled(False)  # 初始状态禁用
        button_layout.addWidget(self.stop_btn)
        
        # 将按钮布局添加到主布局
        layout.addLayout(button_layout, row, 0, 1, 4)
        
        # 使用QTextEdit显示结果
        row += 1
        self.create_result_text(layout, row)
        
        # 初始化网络接口列表
        try:
            self.refresh_interfaces()
        except Exception as e:
            self.result_text.append(f"初始化网络接口列表时出错: {str(e)}")
            traceback.print_exc()
    
    def find_tshark_path(self):
        """查找tshark可执行文件的路径"""
        # 可能的tshark路径
        possible_paths = []
        
        # Windows系统
        if platform.system() == "Windows":
            program_files = os.environ.get("ProgramFiles", "C:\\Program Files")
            program_files_x86 = os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")
            
            possible_paths.extend([
                os.path.join(program_files, "Wireshark", "tshark.exe"),
                os.path.join(program_files_x86, "Wireshark", "tshark.exe"),
                "C:\\Wireshark\\tshark.exe"
            ])
        # Linux/Mac系统
        else:
            possible_paths.extend([
                "/usr/bin/tshark",
                "/usr/local/bin/tshark",
                "/opt/wireshark/bin/tshark"
            ])
        
        # 检查PATH环境变量中的tshark
        for path_dir in os.environ.get("PATH", "").split(os.pathsep):
            if path_dir:
                path_dir = path_dir.strip('"')
                exe_file = os.path.join(path_dir, "tshark")
                if platform.system() == "Windows":
                    exe_file += ".exe"
                if os.path.isfile(exe_file) and os.access(exe_file, os.X_OK):
                    return exe_file
        
        # 检查可能的路径
        for path in possible_paths:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path
        
        return None
    
    def get_tshark_interfaces(self):
        """获取tshark可用的接口列表"""
        try:
            # 查找tshark路径
            tshark_path = self.find_tshark_path()
            if not tshark_path:
                self.result_text.append("警告：未找到tshark可执行文件，无法获取接口列表")
                return {}
            
            # 运行tshark -D命令获取接口列表
            # 不使用text=True，手动处理编码问题
            result = subprocess.run([tshark_path, '-D'], capture_output=True)
            if result.returncode != 0:
                error_msg = result.stderr
                try:
                    error_msg = error_msg.decode('utf-8')
                except UnicodeDecodeError:
                    try:
                        error_msg = error_msg.decode('gbk')
                    except UnicodeDecodeError:
                        error_msg = str(error_msg)
                
                self.result_text.append(f"获取tshark接口列表失败: {error_msg}")
                return {}
            
            # 解析输出，处理可能的编码问题
            interface_map = {}
            stdout_data = result.stdout
            if stdout_data:
                # 尝试不同的编码方式解码
                decoded_output = None
                for encoding in ['utf-8', 'gbk', 'latin1']:
                    try:
                        decoded_output = stdout_data.decode(encoding)
                        break
                    except UnicodeDecodeError:
                        continue
                
                # 如果所有编码都失败，使用latin1（它可以解码任何字节序列）
                if decoded_output is None:
                    decoded_output = stdout_data.decode('latin1', errors='replace')
                
                # 解析接口列表
                for line in decoded_output.splitlines():
                    # 尝试多种可能的格式匹配
                    match = re.match(r'(\d+)\.\s+(.*?)\s+\((.*)\)', line)
                    if match:
                        index, interface_name, description = match.groups()
                        interface_map[description] = interface_name
                    else:
                        # 尝试其他可能的格式
                        match = re.match(r'(\d+)\.\s+(.*)', line)
                        if match:
                            index, interface_name = match.groups()
                            interface_map[interface_name] = interface_name
            
            return interface_map
        except FileNotFoundError:
            self.result_text.append("警告：未找到tshark命令，无法获取接口列表")
            return {}
        except Exception as e:
            self.result_text.append(f"获取tshark接口列表时出错: {str(e)}")
            traceback.print_exc()
            return {}
    
    def refresh_interfaces(self):
        """刷新网络接口列表"""
        try:
            self.interface_input.clear()
            self.interface_map = {}
            
            # 获取tshark接口列表
            tshark_interfaces = self.get_tshark_interfaces()
            if tshark_interfaces:
                self.result_text.append(f"找到 {len(tshark_interfaces)} 个tshark接口")
                # 记录找到的接口
                for desc, name in tshark_interfaces.items():
                    self.result_text.append(f"tshark接口: {desc} -> {name}")
            
            # 直接使用netifaces获取接口列表
            ifaces = netifaces.interfaces()
            for iface in ifaces:
                try:
                    # 尝试获取接口的IP地址
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        ip = addrs[netifaces.AF_INET][0]['addr']
                        display_name = f"{iface} - IP: {ip}"
                        
                        # 尝试匹配tshark接口
                        tshark_iface = None
                        for desc, name in tshark_interfaces.items():
                            if iface in desc:
                                tshark_iface = name
                                break
                        
                        self.interface_input.addItem(display_name, tshark_iface or iface)
                        self.interface_map[display_name] = tshark_iface or iface
                    else:
                        display_name = f"{iface} - 无IP地址"
                        self.interface_input.addItem(display_name, iface)
                        self.interface_map[display_name] = iface
                except Exception as e:
                    self.result_text.append(f"处理接口 {iface} 时出错: {str(e)}")
                    display_name = f"{iface} - 无法获取信息"
                    self.interface_input.addItem(display_name, iface)
                    self.interface_map[display_name] = iface
            
            # 如果没有找到接口，显示错误信息
            if self.interface_input.count() == 0:
                self.result_text.append("警告：未找到可用的网络接口")
                
                # 添加tshark接口
                for desc, name in tshark_interfaces.items():
                    self.interface_input.addItem(f"{desc} (tshark)", name)
                    self.interface_map[desc] = name
        except Exception as e:
            self.result_text.append(f"刷新网络接口列表时出错: {str(e)}")
            traceback.print_exc()
    
    def choose_output_file(self):
        """选择输出文件"""
        try:
            file_name, _ = QFileDialog.getSaveFileName(
                self,
                "选择嗅探结果保存位置",
                "",
                "PCAP文件 (*.pcap);;所有文件 (*.*)"
            )
            if file_name:
                # 如果用户没有输入扩展名，自动添加.pcap
                if not file_name.endswith('.pcap'):
                    file_name += '.pcap'
                self.output_file_input.setText(file_name)
        except Exception as e:
            self.result_text.append(f"选择输出文件时出错: {str(e)}")
            traceback.print_exc()
    
    def start_module(self):
        """启动SIP嗅探模块"""
        try:
            # 清空结果文本
            self.result_text.clear()
            
            # 创建模块实例（使用包装类）
            self.module_instance = SipSniffWrapper()
            
            # 获取选中的接口
            selected_index = self.interface_input.currentIndex()
            if selected_index >= 0:
                interface_id = self.interface_input.itemData(selected_index)
                interface_text = self.interface_input.currentText()
                
                self.result_text.append(f"选择的接口: {interface_text} (ID: {interface_id})")
                
                # 设置参数
                # 检查接口ID是否已经是完整的设备路径
                if interface_id and not interface_id.startswith("\\Device\\NPF_") and not interface_id.startswith("/dev/"):
                    # 尝试构造设备路径
                    if platform.system() == "Windows":
                        # 检查是否已经是GUID格式
                        if re.match(r'^{[0-9A-F-]+}$', interface_id, re.IGNORECASE):
                            self.module_instance.dev = f"\\Device\\NPF_{interface_id}"
                        else:
                            # 检查是否是数字（tshark接口索引）
                            if interface_id.isdigit():
                                self.module_instance.dev = interface_id
                            else:
                                self.module_instance.dev = interface_id
                    else:
                        self.module_instance.dev = interface_id
                else:
                    self.module_instance.dev = interface_id
                
                self.result_text.append(f"使用接口: {self.module_instance.dev}")
                self.module_instance.ofile = self.output_file_input.text()
                
                # 处理协议选择
                proto = self.proto_input.currentText()
                if proto == "ALL":
                    self.module_instance.proto = "UDP|TCP|TLS"
                else:
                    self.module_instance.proto = proto
                
                if self.verbose_check.isChecked():
                    self.module_instance.verbose = 1
                else:
                    self.module_instance.verbose = 0
                    
                if self.auth_check.isChecked():
                    self.module_instance.auth = 1
                else:
                    self.module_instance.auth = 0
                
                # 更新UI状态
                self.on_module_started()
                
                # 启动模块
                self.main_window.run_module(
                    self.module_instance, 
                    self.on_module_finished
                )
            else:
                # 没有选择接口，显示错误信息
                self.result_text.append("错误：请选择一个网络接口")
        except Exception as e:
            self.result_text.append(f"启动SIP嗅探模块时出错: {str(e)}")
            traceback.print_exc()
            # 确保UI状态恢复
            self.on_module_finished() 
from PyQt5.QtWidgets import (
    QLabel, QLineEdit, QComboBox, QPushButton, QCheckBox,
    QHBoxLayout, QVBoxLayout, QGridLayout, QTextEdit, QFileDialog
)
from PyQt5.QtCore import Qt

from sippts.gui.common.base_tab import BaseTab
from sippts.rtphijack import RTPHijack, RTP_PAYLOAD_TYPES

class RTPHijackTab(BaseTab):
    """RTP劫持模块标签页"""
    
    def __init__(self, main_window):
        super().__init__(main_window)
        
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
        
        # SIP服务器设置区域
        row = 0
        layout.addWidget(QLabel("目标SIP服务器:"), row, 0)
        self.ip_input = QLineEdit()
        self.ip_input.setObjectName("ip_input")
        self.ip_input.setPlaceholderText("目标SIP服务器IP地址")
        self.ip_input.setMinimumWidth(300)
        layout.addWidget(self.ip_input, row, 1)
        
        layout.addWidget(QLabel("服务器端口:"), row, 2)
        self.port_input = QLineEdit()
        self.port_input.setObjectName("port_input")
        self.port_input.setText("5060")
        self.port_input.setPlaceholderText("SIP服务器端口")
        self.port_input.setMinimumWidth(300)
        layout.addWidget(self.port_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("协议:"), row, 0)
        self.proto_input = QComboBox()
        self.proto_input.setObjectName("proto_input")
        self.proto_input.addItems(["UDP", "TCP", "TLS"])
        self.proto_input.setCurrentText("UDP")
        self.proto_input.setMinimumWidth(300)
        layout.addWidget(self.proto_input, row, 1)
        
        layout.addWidget(QLabel("本地IP:"), row, 2)
        self.localip_input = QLineEdit()
        self.localip_input.setObjectName("localip_input")
        self.localip_input.setPlaceholderText("留空自动获取")
        self.localip_input.setMinimumWidth(300)
        layout.addWidget(self.localip_input, row, 3)
        
        # SIP用户设置
        row += 1
        layout.addWidget(QLabel("来源用户:"), row, 0)
        self.from_user_input = QLineEdit()
        self.from_user_input.setObjectName("from_user_input")
        self.from_user_input.setText("100")
        self.from_user_input.setPlaceholderText("From用户名")
        self.from_user_input.setMinimumWidth(300)
        layout.addWidget(self.from_user_input, row, 1)
        
        layout.addWidget(QLabel("目标用户:"), row, 2)
        self.to_user_input = QLineEdit()
        self.to_user_input.setObjectName("to_user_input")
        self.to_user_input.setText("100")
        self.to_user_input.setPlaceholderText("To用户名")
        self.to_user_input.setMinimumWidth(300)
        layout.addWidget(self.to_user_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("域名:"), row, 0)
        self.domain_input = QLineEdit()
        self.domain_input.setObjectName("domain_input")
        self.domain_input.setPlaceholderText("SIP域名(留空使用目标IP)")
        self.domain_input.setMinimumWidth(300)
        layout.addWidget(self.domain_input, row, 1)
        
        # IP欺骗设置
        layout.addWidget(QLabel("伪造源IP:"), row, 2)
        self.spoof_ip_input = QLineEdit()
        self.spoof_ip_input.setObjectName("spoof_ip_input")
        self.spoof_ip_input.setPlaceholderText("(可选) 伪造的源IP地址")
        self.spoof_ip_input.setMinimumWidth(300)
        layout.addWidget(self.spoof_ip_input, row, 3)
        
        # SIP标签设置
        row += 1
        layout.addWidget(QLabel("From标签:"), row, 0)
        self.from_tag_input = QLineEdit()
        self.from_tag_input.setObjectName("from_tag_input")
        self.from_tag_input.setPlaceholderText("(可选) From标签值")
        self.from_tag_input.setMinimumWidth(300)
        layout.addWidget(self.from_tag_input, row, 1)
        
        layout.addWidget(QLabel("To标签:"), row, 2)
        self.to_tag_input = QLineEdit()
        self.to_tag_input.setObjectName("to_tag_input")
        self.to_tag_input.setPlaceholderText("(可选) To标签值")
        self.to_tag_input.setMinimumWidth(300)
        layout.addWidget(self.to_tag_input, row, 3)
        
        # Call-ID设置
        row += 1
        layout.addWidget(QLabel("Call-ID:"), row, 0)
        self.call_id_input = QLineEdit()
        self.call_id_input.setObjectName("call_id_input")
        self.call_id_input.setPlaceholderText("(可选) 自定义Call-ID")
        self.call_id_input.setMinimumWidth(300)
        layout.addWidget(self.call_id_input, row, 1)
        
        layout.addWidget(QLabel("Contact域名:"), row, 2)
        self.contact_domain_input = QLineEdit()
        self.contact_domain_input.setObjectName("contact_domain_input")
        self.contact_domain_input.setPlaceholderText("Contact头域名或IP")
        self.contact_domain_input.setMinimumWidth(200)
        layout.addWidget(self.contact_domain_input, row, 3)
        
        # RTP设置
        row += 1
        layout.addWidget(QLabel("RTP负载类型:"), row, 0)
        self.payload_input = QComboBox()
        self.payload_input.setObjectName("payload_input")
        self.payload_input.addItems(list(RTP_PAYLOAD_TYPES.keys()))
        self.payload_input.setCurrentText("0 PCMU (audio)")
        self.payload_input.setMinimumWidth(300)
        layout.addWidget(self.payload_input, row, 1)
        
        layout.addWidget(QLabel("RTP本地端口:"), row, 2)
        self.rtp_port_input = QLineEdit()
        self.rtp_port_input.setObjectName("rtp_port_input")
        self.rtp_port_input.setText("10000")
        self.rtp_port_input.setPlaceholderText("用于接收RTP的本地端口")
        self.rtp_port_input.setMinimumWidth(300)
        layout.addWidget(self.rtp_port_input, row, 3)
        
        # 劫持设置
        row += 1
        layout.addWidget(QLabel("劫持时长(秒):"), row, 0)
        self.timeout_input = QLineEdit()
        self.timeout_input.setObjectName("timeout_input")
        self.timeout_input.setText("60")
        self.timeout_input.setPlaceholderText("劫持持续时间(秒)")
        self.timeout_input.setMinimumWidth(300)
        layout.addWidget(self.timeout_input, row, 1)
        
        # 音频文件
        layout.addWidget(QLabel("音频保存路径:"), row, 2)
        audio_file_layout = QHBoxLayout()
        self.audio_file_input = QLineEdit()
        self.audio_file_input.setObjectName("audio_file_input")
        self.audio_file_input.setText("hijacked_audio.wav")
        self.audio_file_input.setPlaceholderText("劫持的音频保存路径")
        self.audio_file_input.setMinimumWidth(240)
        audio_file_layout.addWidget(self.audio_file_input)
        
        audio_file_btn = QPushButton("选择")
        audio_file_btn.setFixedWidth(60)
        audio_file_btn.clicked.connect(self.choose_audio_file)
        audio_file_layout.addWidget(audio_file_btn)
        layout.addLayout(audio_file_layout, row, 3)
        
        # 详细日志
        row += 1
        self.verbose_check = QCheckBox("显示详细日志")
        self.verbose_check.setObjectName("verbose_check")
        layout.addWidget(self.verbose_check, row, 0, 1, 2)
        
        # 添加实时播放选项
        self.live_playback_check = QCheckBox("启用实时音频播放")
        self.live_playback_check.setObjectName("live_playback_check")
        self.live_playback_check.setChecked(True)
        self.live_playback_check.setToolTip("实时播放劫持的音频（需要安装PyAudio）")
        layout.addWidget(self.live_playback_check, row, 2, 1, 2)
        
        # 麦克风采集设置
        row += 1
        self.mic_capture_check = QCheckBox("启用麦克风采集")
        self.mic_capture_check.setObjectName("mic_capture_check")
        self.mic_capture_check.setChecked(False)
        self.mic_capture_check.setToolTip("采集麦克风音频并发送到目标（需要安装PyAudio）")
        layout.addWidget(self.mic_capture_check, row, 0, 1, 2)
        
        # 麦克风采集目标设置
        row += 1
        layout.addWidget(QLabel("麦克风目标IP:"), row, 0)
        self.mic_target_ip_input = QLineEdit()
        self.mic_target_ip_input.setObjectName("mic_target_ip_input")
        self.mic_target_ip_input.setPlaceholderText("接收麦克风音频的目标IP地址")
        self.mic_target_ip_input.setMinimumWidth(300)
        layout.addWidget(self.mic_target_ip_input, row, 1)
        
        layout.addWidget(QLabel("麦克风目标端口:"), row, 2)
        self.mic_target_port_input = QLineEdit()
        self.mic_target_port_input.setObjectName("mic_target_port_input")
        self.mic_target_port_input.setPlaceholderText("接收麦克风音频的目标端口")
        self.mic_target_port_input.setMinimumWidth(300)
        layout.addWidget(self.mic_target_port_input, row, 3)
        
        # 麦克风音频格式设置
        row += 1
        layout.addWidget(QLabel("麦克风音频格式:"), row, 0)
        self.mic_payload_input = QComboBox()
        self.mic_payload_input.setObjectName("mic_payload_input")
        self.mic_payload_input.addItems(["0 PCMU (audio)", "8 PCMA (audio)"])
        self.mic_payload_input.setCurrentText("0 PCMU (audio)")
        self.mic_payload_input.setMinimumWidth(300)
        layout.addWidget(self.mic_payload_input, row, 1)
        
        # 按钮
        row += 1
        button_layout = QHBoxLayout()
        self.start_btn = QPushButton("开始劫持")
        self.start_btn.clicked.connect(self.start_module)
        button_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("停止劫持")
        self.stop_btn.clicked.connect(self.main_window.stop_module)
        self.stop_btn.setEnabled(False)
        button_layout.addWidget(self.stop_btn)
        
        layout.addLayout(button_layout, row, 0, 1, 4)
        
        # 结果文本区域
        row += 1
        self.create_result_text(layout, row)
        
        # 连接信号
        self.mic_capture_check.stateChanged.connect(self.on_mic_capture_changed)
        
        # 初始化麦克风相关控件的状态
        self.on_mic_capture_changed()
    
    def choose_audio_file(self):
        """选择音频保存文件"""
        file_name, _ = QFileDialog.getSaveFileName(
            self,
            "选择音频保存位置",
            "",
            "WAV文件 (*.wav);;所有文件 (*.*)"
        )
        if file_name:
            # 如果用户没有输入扩展名，自动添加.wav
            if not file_name.endswith('.wav'):
                file_name += '.wav'
            self.audio_file_input.setText(file_name)
    
    def on_mic_capture_changed(self):
        """处理麦克风采集开关状态变化"""
        enabled = self.mic_capture_check.isChecked()
        self.mic_target_ip_input.setEnabled(enabled)
        self.mic_target_port_input.setEnabled(enabled)
        self.mic_payload_input.setEnabled(enabled)
    
    def start_module(self):
        """启动RTP劫持模块"""
        # 保存当前输入值
        self.save_input_values()
        
        # 获取参数
        target_ip = self.ip_input.text().strip()
        target_port = self.port_input.text().strip()
        proto = self.proto_input.currentText()
        local_ip = self.localip_input.text().strip()
        from_user = self.from_user_input.text().strip()
        to_user = self.to_user_input.text().strip()
        domain = self.domain_input.text().strip()
        spoof_ip = self.spoof_ip_input.text().strip()
        contact_domain = self.contact_domain_input.text().strip()
        payload_type = self.payload_input.currentText()
        rtp_port = self.rtp_port_input.text().strip()
        timeout = self.timeout_input.text().strip()
        audio_file = self.audio_file_input.text().strip()
        verbose = 1 if self.verbose_check.isChecked() else 0
        
        # 获取麦克风采集参数
        enable_mic = self.mic_capture_check.isChecked()
        mic_target_ip = self.mic_target_ip_input.text().strip()
        mic_target_port = self.mic_target_port_input.text().strip()
        mic_payload_type = self.mic_payload_input.currentText()
        
        # 参数验证
        if not target_ip:
            self.append_log("错误: 目标SIP服务器IP不能为空")
            return
        
        # 创建模块实例
        self.module_instance = RTPHijack()
        
        # 设置参数
        self.module_instance.ip = target_ip
        self.module_instance.rport = target_port
        self.module_instance.proto = proto
        self.module_instance.localip = local_ip
        self.module_instance.from_user = from_user
        self.module_instance.to_user = to_user
        self.module_instance.domain = domain
        self.module_instance.contact_domain = contact_domain
        self.module_instance.spoof_ip = spoof_ip
        self.module_instance.rtp_payload_type = payload_type
        
        if rtp_port:
            self.module_instance.rtp_local_port = int(rtp_port)
        
        if timeout:
            self.module_instance.timeout = int(timeout)
        
        self.module_instance.audio_file = audio_file
        self.module_instance.verbose = verbose
        
        # 设置是否启用实时音频播放
        self.module_instance.enable_live_playback = self.live_playback_check.isChecked()
        
        # 设置麦克风采集参数
        self.module_instance.enable_mic_capture = enable_mic
        if enable_mic:
            self.module_instance.mic_target_ip = mic_target_ip
            self.module_instance.mic_target_port = int(mic_target_port)
            self.module_instance.mic_payload_type = RTP_PAYLOAD_TYPES[mic_payload_type]
        
        # 获取并设置tag值
        from_tag = self.from_tag_input.text().strip()
        to_tag = self.to_tag_input.text().strip()
        call_id = self.call_id_input.text().strip()
        
        if from_tag:
            self.module_instance.from_tag = from_tag
        
        if to_tag:
            self.module_instance.to_tag = to_tag
        
        if call_id:
            self.module_instance.call_id = call_id
        
        # 清空结果文本
        self.result_text.clear()
        
        # 更新UI状态
        self.on_module_started()
        
        # 启动模块
        self.main_window.run_module(
            self.module_instance, 
            self.on_module_finished
        )

import os
import json
from pathlib import Path

class ConfigManager:
    """配置管理类，用于保存和加载用户界面设置"""
    
    # 单例实例
    _instance = None
    
    def __new__(cls):
        """实现单例模式"""
        if cls._instance is None:
            cls._instance = super(ConfigManager, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        """初始化配置管理器"""
        # 避免重复初始化
        if getattr(self, "_initialized", False):
            return
            
        self._initialized = True
        
        # 确定配置文件目录
        # 获取可执行文件所在目录
        self.config_dir = os.path.dirname(os.path.abspath(os.path.dirname(__file__)))
        # self.config_dir = os.path.join(executable_dir, 'config')
        self.config_file = os.path.join(self.config_dir, 'gui_config.json')
        
        # 确保配置目录存在
        if not os.path.exists(self.config_dir):
            os.makedirs(self.config_dir)
        
        # 加载配置
        self.config = self._load_config()
    
    def _load_config(self):
        """加载配置文件"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"加载配置文件失败: {e}")
                return {}
        return {}
    
    def save_config(self):
        """保存配置到文件"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"保存配置文件失败: {e}")
    
    def collect_tab_config(self, tab_name, config_data):
        """收集特定标签页的配置，但不立即保存到文件"""
        self.config[tab_name] = config_data
        return self.config
    
    def save_tab_config(self, tab_name, config_data, save_immediately=True):
        """保存特定标签页的配置
        
        Args:
            tab_name: 标签页名称
            config_data: 配置数据
            save_immediately: 是否立即保存到文件，默认为True
        """
        self.config[tab_name] = config_data
        
        if save_immediately:
            self.save_config()
    
    def get_tab_config(self, tab_name):
        """获取特定标签页的配置"""
        return self.config.get(tab_name, {}) 
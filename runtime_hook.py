# -*- coding: utf-8 -*-
import os
import sys
import tempfile

# 设置临时目录
if not hasattr(sys, '_MEIPASS'):
    sys._MEIPASS = os.path.abspath('.')

# 确保可以找到tshark
os.environ['PATH'] = os.path.dirname(sys.executable) + os.pathsep + os.environ.get('PATH', '')

# 创建临时目录用于运行时文件
def get_temp_dir():
    temp_dir = os.path.join(tempfile.gettempdir(), 'sippts_temp')
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)
    return temp_dir

os.environ['SIPPTS_TEMP'] = get_temp_dir()

from PyQt5.QtWidgets import QFileDialog

def choose_file(parent, caption="选择文件", directory="", filter="所有文件 (*.*)"):
    """
    打开文件选择对话框
    
    参数:
        parent: 父窗口
        caption: 对话框标题
        directory: 初始目录
        filter: 文件过滤器
        
    返回:
        选择的文件路径，如果取消则返回空字符串
    """
    options = QFileDialog.Options()
    file_path, _ = QFileDialog.getOpenFileName(
        parent, caption, directory, filter, options=options
    )
    return file_path

def choose_save_file(parent, caption="保存文件", directory="", filter="所有文件 (*.*)"):
    """
    打开保存文件对话框
    
    参数:
        parent: 父窗口
        caption: 对话框标题
        directory: 初始目录
        filter: 文件过滤器
        
    返回:
        选择的文件路径，如果取消则返回空字符串
    """
    options = QFileDialog.Options()
    file_path, _ = QFileDialog.getSaveFileName(
        parent, caption, directory, filter, options=options
    )
    return file_path 
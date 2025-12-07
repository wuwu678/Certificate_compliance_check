import sys
import os
import subprocess
from pathlib import Path


def main():
    """
    证书验证系统启动脚本
    负责启动GUI程序并处理可能的依赖问题
    """
    # 获取脚本所在目录
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # 获取项目根目录
    project_root = os.path.abspath(os.path.join(script_dir, '..'))
    
    # 添加项目根目录到Python路径
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    
    # 打印启动信息
    print("证书合规检查系统启动中...")
    print(f"项目根目录: {project_root}")
    print(f"当前Python版本: {sys.version}")
    
    # 检查必要的依赖
    check_dependencies()
    
    # 检测 Qt 平台插件路径，避免 "Could not find the Qt platform plugin \"windows\"" 错误
    qt_env = os.environ.copy()
    platform_path = _detect_qt_platform_path()
    if platform_path:
        qt_env["QT_QPA_PLATFORM_PLUGIN_PATH"] = str(platform_path)
        print(f"使用 Qt 平台插件目录: {platform_path}")
    else:
        print("未找到 Qt 平台插件目录，可能导致 GUI 无法启动。")
    
    # 启动GUI程序
    gui_script = os.path.join(script_dir, 'gui_certificate_verifier.py')
    
    try:
        print(f"启动GUI程序: {gui_script}")
        subprocess.run([sys.executable, gui_script], check=True, env=qt_env)
    except subprocess.CalledProcessError as e:
        print(f"GUI程序启动失败: {e}")
        input("按Enter键退出...")
    except KeyboardInterrupt:
        print("程序被用户中断")
    except Exception as e:
        print(f"发生未预期的错误: {e}")
        input("按Enter键退出...")


def check_dependencies():
    """
    检查必要的依赖包
    """
    print("检查依赖包...")
    missing_packages = []
    
    try:
        import PyQt5
        print("[OK] PyQt5 已安装")
    except ImportError:
        missing_packages.append('PyQt5')
    
    try:
        import cryptography
        print("[OK] cryptography 已安装")
    except ImportError:
        missing_packages.append('cryptography')
    
    if missing_packages:
        print(f"以下必要依赖未安装: {', '.join(missing_packages)}")
        print("请运行以下命令安装依赖:")
        print("  pip install -r requirements.txt")
        # 不强制退出，让用户决定是否继续


def _detect_qt_platform_path():
    """
    尝试自动定位 PyQt5 的平台插件目录。
    返回 Path 或 None。
    """
    try:
        import PyQt5
        base = Path(PyQt5.__file__).resolve().parent
        candidate = base / "Qt5" / "plugins" / "platforms"
        if candidate.exists():
            return candidate
    except Exception:
        return None
    return None


if __name__ == '__main__':
    main()

import sys
import os
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QFileDialog, QLabel, QTextEdit, QGroupBox, QMessageBox,
    QSplitter, QFrame
)
from PyQt5.QtCore import Qt

# 添加项目根目录到Python路径
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.core.certificate_system import CertificateComplianceSystem


class CertificateVerifierGUI(QMainWindow):
    """
    证书验证系统GUI主窗口
    """
    
    def __init__(self):
        super().__init__()
        self.cert_system = CertificateComplianceSystem()
        self.init_ui()
    
    def init_ui(self):
        """
        初始化UI界面
        """
        self.setWindowTitle('证书合规检查系统')
        self.setGeometry(20, 10, 1500, 1000)
        self._apply_styles()
        self._center_window()
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(22, 22, 22, 22)
        main_layout.setSpacing(16)
        
        hero = self._build_header()
        main_layout.addWidget(hero)
        
        stats_row = self._build_stats_row()
        main_layout.addLayout(stats_row)
        self._reset_stats()
        
        splitter = QSplitter(Qt.Vertical)
        self.info_group = self.create_info_group()
        splitter.addWidget(self.info_group)
        self.result_group = self.create_result_group()
        splitter.addWidget(self.result_group)
        splitter.setSizes([320, 400])
        
        main_layout.addWidget(splitter, 1)
        self.statusBar().showMessage('就绪')

    def _center_window(self):
        """让窗口居中显示"""
        screen = QApplication.desktop().availableGeometry(self)
        frame = self.frameGeometry()
        frame.moveCenter(screen.center())
        self.move(frame.topLeft())
    
    def create_info_group(self):
        """
        创建证书信息显示组
        """
        group = QGroupBox('证书基本信息')
        layout = QVBoxLayout()
        
        self.info_text = QTextEdit()
        self.info_text.setReadOnly(True)
        self.info_text.setStyleSheet('font-family: Consolas, monospace; font-size: 22px;')
        
        layout.addWidget(self.info_text)
        group.setLayout(layout)
        return group
    
    def create_result_group(self):
        """
        创建验证结果显示组
        """
        group = QGroupBox('验证结果')
        layout = QVBoxLayout()
        
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        self.result_text.setStyleSheet('font-family: Consolas, monospace; font-size: 22px;')
        
        layout.addWidget(self.result_text)
        group.setLayout(layout)
        return group
    
    def select_certificate(self):
        """
        选择证书文件
        """
        file_path, _ = QFileDialog.getOpenFileName(
            self, '选择证书文件', '', '证书文件 (*.pem *.cer *.crt *.der);;所有文件 (*)'
        )
        
        if file_path:
            self.load_certificate(file_path)
    
    def load_certificate(self, file_path):
        """
        加载证书并显示信息
        """
        try:
            # 更新状态
            self.statusBar().showMessage(f'正在加载证书: {os.path.basename(file_path)}')
            QApplication.processEvents()  # 刷新UI
            
            if self.cert_system.load_certificate(file_path):
                # 加载成功
                self.file_label.setText(f'当前文件: {os.path.basename(file_path)}')
                self.file_label.setProperty('state', 'success')
                self.file_label.setStyleSheet(self.file_label.styleSheet())
                self.verify_button.setEnabled(True)
                self._update_badge('待验证', '#bfa980')
                self._reset_stats()
                self.statusBar().showMessage('证书加载成功')
                
                # 显示证书信息
                info = self.cert_system.get_certificate_info()
                if info:
                    self._display_certificate_info(info)
                else:
                    self.info_text.setText('无法获取证书信息')
                
                # 清空之前的验证结果
                self.result_text.clear()
                self.result_group.setTitle('验证结果')
            else:
                # 加载失败
                self.file_label.setText(f'错误: 无法加载 {os.path.basename(file_path)}')
                self.file_label.setProperty('state', 'error')
                self.file_label.setStyleSheet(self.file_label.styleSheet())
                self.statusBar().showMessage('证书加载失败')
                QMessageBox.warning(
                    self, '错误', 
                    f'无法加载证书文件:\n{os.path.basename(file_path)}\n\n请检查文件格式是否正确。'
                )
        except Exception as e:
            # 异常处理
            error_msg = f'加载证书时发生错误: {str(e)}'
            self.file_label.setText('加载失败')
            self.file_label.setStyleSheet('color: #dc3545; font-weight: bold;')  # 红色文字
            self.statusBar().showMessage(error_msg)
            
            # 显示详细错误信息
            QMessageBox.critical(
                self, '错误', 
                f'加载证书时发生错误:\n\n{str(e)}\n\n请确保文件格式正确且可读。'
            )
    
    def verify_current_certificate(self):
        """
        验证当前加载的证书
        """
        try:
            self.statusBar().showMessage('正在验证证书...')
            QApplication.processEvents()  # 刷新UI
            
            # 执行验证
            result = self.cert_system.verify_certificate()
            
            # 显示验证结果
            self._display_verification_result(result)
            self._update_stats(result)
            
            # 更新组标题和状态
            status = '合规' if result['all_passed'] else '不合规'
            self.result_group.setTitle(f'验证结果 - {status}')
            
            # 设置结果组的样式
            if result['all_passed']:
                self.result_group.setStyleSheet('QGroupBox { color: #28a745; font-weight: bold; }')
            else:
                self.result_group.setStyleSheet('QGroupBox { color: #dc3545; font-weight: bold; }')
            
            # 更新状态栏
            percentage = result['summary'].get('percentage', 0)
            self.statusBar().showMessage(f'验证完成 - {status} ({percentage:.1f}% 通过)')
            
            # 显示完成消息
            if result['all_passed']:
                QMessageBox.information(self, '验证完成', '证书通过所有验证规则，符合安全要求。')
                self._update_badge('合规', '#9fb59e')
            else:
                # 计算未通过的规则数
                failed_count = result['summary'].get('total_count', 0) - result['summary'].get('passed_count', 0)
                QMessageBox.warning(self, '验证完成', 
                    f'证书未通过所有验证规则。\n\n未通过规则数: {failed_count}\n\n请查看下方的详细结果了解具体问题。')
                self._update_badge('不合规', '#c28b8e')
                    
        except Exception as e:
            error_msg = f'验证时发生错误: {str(e)}'
            self.statusBar().showMessage(error_msg)
            QMessageBox.critical(self, '错误', 
                f'验证证书时发生错误:\n\n{str(e)}\n\n请尝试重新加载证书后再次验证。')
    
    def _display_certificate_info(self, info):
        """
        显示证书信息
        """
        text = []
        text.append(f"主题: {info['subject']}")
        text.append(f"颁发者: {info['issuer']}")
        text.append(f"序列号: {info['serial_number']}")
        text.append(f"版本: {info['version']}")
        text.append(f"有效期开始: {info['not_valid_before']}")
        text.append(f"有效期结束: {info['not_valid_after']}")
        text.append(f"当前是否有效: {'是' if info['is_valid'] else '否'}")
        text.append(f"公钥类型: {info['public_key_type']}")
        text.append(f"签名算法: {info['signature_algorithm']}")
        
        self.info_text.setText('\n'.join(text))
    
    def _display_verification_result(self, result):
        """
        显示验证结果
        """
        text = []
        
        # 总体结果
        text.append(f"验证结果: {'通过' if result['all_passed'] else '未通过'}")
        text.append(f"通过规则数: {result['summary']['passed_count']}/{result['summary']['total_count']}")
        text.append(f"通过率: {result['summary']['percentage']:.1f}%")
        text.append("=" * 60)
        text.append("")
        
        # 详细规则结果
        for rule_result in result['results']:
            status = '✓ 通过' if rule_result['passed'] else '✗ 失败'
            text.append(f"规则: {rule_result['rule']}")
            text.append(f"状态: {status}")
            text.append(f"消息: {rule_result['message']}")
            
            # 如果有详细信息
            if 'details' in rule_result:
                text.append("详细信息:")
                for key, value in rule_result['details'].items():
                    text.append(f"  - {key}: {value}")
            
            text.append("")
        
        self.result_text.setText('\n'.join(text))

    def _build_header(self):
        """
        构建顶部标题和操作区
        """
        frame = QFrame()
        frame.setObjectName('headerFrame')
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(14)

        title_box = QVBoxLayout()
        title = QLabel('证书合规检查')
        title.setObjectName('heroTitle')
        title.setAlignment(Qt.AlignCenter)
        title_box.setAlignment(Qt.AlignCenter)
        title_box.addWidget(title)

        badge_row = QHBoxLayout()
        self.file_label = QLabel('未选择证书文件')
        self.file_label.setObjectName('fileLabel')
        self.file_label.setProperty('state', 'idle')
        self.status_badge = QLabel('待加载')
        self.status_badge.setObjectName('statusBadge')
        badge_row.addWidget(self.file_label)
        badge_row.addWidget(self.status_badge)
        badge_row.setAlignment(Qt.AlignCenter)
        title_box.addLayout(badge_row)

        layout.addLayout(title_box, 1)

        btn_box = QVBoxLayout()
        btn_box.setSpacing(8)
        self.select_button = QPushButton('选择证书文件')
        self.select_button.setMinimumHeight(48)
        self.select_button.clicked.connect(self.select_certificate)
        self.verify_button = QPushButton('开始验证')
        self.verify_button.setMinimumHeight(48)
        self.verify_button.setEnabled(False)
        self.verify_button.clicked.connect(self.verify_current_certificate)
        btn_box.addWidget(self.select_button)
        btn_box.addWidget(self.verify_button)
        layout.addLayout(btn_box)
        return frame

    def _build_stats_row(self):
        """
        构建统计卡片行
        """
        row = QHBoxLayout()
        row.setSpacing(18)
        row.setAlignment(Qt.AlignCenter)
        self.stat_status = self._create_stat_card('当前状态', '等待加载', '#000000')
        self.stat_rate = self._create_stat_card('通过率', '--', '#000000')
        self.stat_rules = self._create_stat_card('已通过规则', '0/0', '#000000')
        row.addStretch()
        row.addWidget(self.stat_status)
        row.addWidget(self.stat_rate)
        row.addWidget(self.stat_rules)
        row.addStretch()
        return row

    def _create_stat_card(self, title, value, accent_color):
        card = QFrame()
        card.setObjectName('statCard')
        card.setMinimumHeight(150)
        card.setMinimumWidth(260)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setAlignment(Qt.AlignCenter)
        caption = QLabel(title)
        caption.setObjectName('statCaption')
        caption.setStyleSheet(f"color: {accent_color};")
        caption.setAlignment(Qt.AlignCenter)
        number = QLabel(value)
        number.setObjectName('statNumber')
        number.setAlignment(Qt.AlignCenter)
        layout.addWidget(caption)
        layout.addWidget(number)
        return card

    def _update_badge(self, text, color):
        """
        更新状态徽章
        """
        self.status_badge.setText(text)
        self.status_badge.setStyleSheet(f"padding:4px 10px; border-radius: 12px; color: white; background: {color};")

    def _update_stats(self, result):
        """
        更新统计卡片
        """
        status_text = '合规' if result['all_passed'] else '不合规'
        status_color = '#9fb59e' if result['all_passed'] else '#c28b8e'
        self._update_badge(status_text, status_color)
        rate = f"{result['summary']['percentage']:.1f}%"
        rules = f"{result['summary']['passed_count']}/{result['summary']['total_count']}"
        self.stat_status.findChild(QLabel, 'statNumber').setText(status_text)
        self.stat_status.findChild(QLabel, 'statNumber').setStyleSheet(f"color:{status_color};")
        self.stat_rate.findChild(QLabel, 'statNumber').setText(rate)
        self.stat_rules.findChild(QLabel, 'statNumber').setText(rules)

    def _reset_stats(self):
        """
        重置统计卡片为初始状态
        """
        self.stat_status.findChild(QLabel, 'statNumber').setText('等待验证')
        self.stat_status.findChild(QLabel, 'statNumber').setStyleSheet("color:#8fa3ad;")
        self.stat_rate.findChild(QLabel, 'statNumber').setText('--')
        self.stat_rules.findChild(QLabel, 'statNumber').setText('0/0')
        self._update_badge('待验证', '#bfa980')

    def _apply_styles(self):
        """
        应用整体样式
        """
        self.setStyleSheet("""
        QWidget {
            font-family: 'Microsoft YaHei', 'Segoe UI', sans-serif;
            color: #000000;
            background: #f3f1ed;
            font-size: 20px;
        }
        QMainWindow {
            background: #f3f1ed;
        }
        #headerFrame {
            background: transparent;
            border: 2px solid #000000;
            border-radius: 20px;
            color: #000000;
        }
        #heroTitle {
            font-family: 'Microsoft YaHei', 'Segoe UI', sans-serif;
            font-size: 52px;
            font-weight: 950;
            color: #000000;
        }
        #fileLabel {
            color: #000000;
            font-weight: 650;
        }
        #statusBadge {
            padding: 4px 10px;
            border-radius: 12px;
            color: white;
            background: #7c8a94;
            font-size: 16px;
        }
        QPushButton {
            background: #e2dfd9;
            color: #000000;
            border: none;
            border-radius: 16px;
            padding: 14px 18px;
            font-weight: 800;
            font-size: 22px;
        }
        QPushButton:hover:!disabled {
            background: #d6d2cb;
        }
        QPushButton:disabled {
            background: #cfd4d8;
            color: #8c9094;
        }
        QGroupBox {
            border: 1px solid #8fa3ad;
            border-radius: 22px;
            margin-top: 16px;
            background: #ffffff;
            color: #000000;
            padding-top: 26px; /* 预留标题空间，避免被内容遮挡 */
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 12px;
            padding: 5px 12px;
            background: #d6d2cb;
            color: #000000;
            border-radius: 12px;
            font-size: 18px;
        }
        QTextEdit {
            background: #ffffff;
            color: #000000;
            border: 1px solid #8fa3ad;
            border-radius: 14px;
            padding: 14px;
            font-size: 28px;
        }
        #statCard {
            background: transparent;
            border: 1px solid #8fa3ad;
            border-radius: 20px;
        }
        #statCaption {
            font-size: 24px;
            letter-spacing: 0.5px;
            text-align: center;
        }
        #statNumber {
            font-size: 32px;
            font-weight: 800;
            text-align: center;
        }
        """)


def main():
    """
    主函数
    """
    try:
        # 确保中文显示正常
        import os
        if os.name == 'nt':  # Windows系统
            # 设置中文字体支持
            os.environ['QT_FONT_DPI'] = '96'  # 设置DPI
            
        # 创建应用实例
        app = QApplication(sys.argv)
        
        # 设置应用信息
        app.setApplicationName('证书合规检查系统')
        app.setApplicationVersion('1.0')
        
        # 创建并显示主窗口
        window = CertificateVerifierGUI()
        window.show()
        
        # 运行应用
        sys.exit(app.exec_())
    except ImportError as e:
        print(f"缺少依赖: {e}")
        print("请运行 'pip install -r requirements.txt' 安装所有依赖")
        input("按Enter键退出...")
        sys.exit(1)
    except Exception as e:
        print(f"程序启动失败: {e}")
        import traceback
        traceback.print_exc()
        input("按Enter键退出...")
        sys.exit(1)


if __name__ == '__main__':
    main()

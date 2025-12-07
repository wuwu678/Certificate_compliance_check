from .certificate_parser import CertificateParser
from .certificate_verifier import CertificateVerifier


class CertificateComplianceSystem:
    """
    证书合规检查系统主类
    整合证书解析和验证功能
    """
    
    def __init__(self):
        self.parser = CertificateParser()
        self.verifier = None
        self.current_certificate_path = None
    
    def load_certificate(self, file_path):
        """
        加载证书文件
        
        Args:
            file_path: 证书文件路径
            
        Returns:
            bool: 加载是否成功
        """
        if self.parser.load_certificate_from_file(file_path):
            self.verifier = CertificateVerifier(self.parser.certificate)
            self.current_certificate_path = file_path
            return True
        return False
    
    def get_certificate_info(self):
        """
        获取证书基本信息
        
        Returns:
            dict: 证书信息字典
        """
        return self.parser.get_certificate_info()
    
    def verify_certificate(self):
        """
        验证证书合规性
        
        Returns:
            dict: 验证结果
        """
        if not self.verifier:
            return {
                'all_passed': False,
                'results': [],
                'summary': {
                    'passed_count': 0,
                    'total_count': 0,
                    'percentage': 0,
                    'status': '未加载证书'
                }
            }
        
        return self.verifier.verify()
    
    def get_full_report(self):
        """
        获取完整的证书报告，包括信息和验证结果
        
        Returns:
            dict: 完整报告
        """
        if not self.current_certificate_path:
            return {
                'status': 'error',
                'message': '未加载证书'
            }
        
        certificate_info = self.get_certificate_info()
        verification_result = self.verify_certificate()
        
        return {
            'status': 'success',
            'certificate_path': self.current_certificate_path,
            'certificate_info': certificate_info,
            'verification_result': verification_result
        }

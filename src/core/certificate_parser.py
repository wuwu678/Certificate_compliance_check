from datetime import datetime, timezone
from asn1crypto import pem

import asn1crypto.x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

class CertificateParser:
    """
    证书解析器类
    用于加载和解析X.509证书文件
    """
    
    def __init__(self):
        self.certificate = None
        self.cert_data = None
    
    def load_certificate_from_file(self, file_path):
        """
        从文件加载证书
        
        Args:
            file_path: 证书文件路径
            
        Returns:
            bool: 加载是否成功
        """
        try:
            with open(file_path, 'rb') as f:
                cert_data = f.read()
                
            # 尝试不同的格式解析证书
            try:
                # PEM格式
                self.certificate = x509.load_pem_x509_certificate(cert_data, default_backend())
            except:
                try:
                    # DER格式
                    self.certificate = x509.load_der_x509_certificate(cert_data, default_backend())
                except:
                    return False
            
            self.cert_data = cert_data
            return True
        except Exception as e:
            print(f"加载证书失败: {e}")
            return False
    
    def get_certificate_info(self):
        """
        获取证书的基本信息
        
        Returns:
            dict: 证书信息字典
        """
        if not self.certificate:
            return None
        
        def safe_get(getter, fallback):
            try:
                return getter()
            except Exception as e:
                return f"{fallback}（{e}）"

        info = {
            'subject': safe_get(lambda: self._format_name(self.certificate.subject), "无法获取主题"),
            'issuer': safe_get(lambda: self._format_name(self.certificate.issuer), "无法获取颁发者"),
            'serial_number': safe_get(lambda: str(self.certificate.serial_number), "无法获取序列号"),
            'version': safe_get(lambda: self.certificate.version.value, "无法获取版本"),
            'not_valid_before': safe_get(
                lambda: self._get_datetime_attr('not_valid_before').strftime('%Y-%m-%d %H:%M:%S %Z'),
                "无法获取生效时间"
            ),
            'not_valid_after': safe_get(
                lambda: self._get_datetime_attr('not_valid_after').strftime('%Y-%m-%d %H:%M:%S %Z'),
                "无法获取到期时间"
            ),
            'is_valid': safe_get(self._is_certificate_valid, "无法判断有效期"),
            'public_key_type': safe_get(self._get_public_key_type, "无法识别公钥类型"),
            'signature_algorithm': safe_get(self._get_signature_algorithm, "无法获取签名算法"),
        }

        return info
    
    def _format_name(self, name):
        """
        格式化名称对象
        """
        try:
            components = []
            for attr in name:
                oid_name = attr.oid._name if hasattr(attr.oid, '_name') else str(attr.oid)
                components.append(f"{oid_name}={attr.value}")
            return ', '.join(components)
        except:
            return str(name)
    
    def _get_datetime_attr(self, attr_name):
        """
        返回带时区的时间属性，兼容 cryptography 新旧接口
        """
        attr_utc = f"{attr_name}_utc"
        if hasattr(self.certificate, attr_utc):
            dt = getattr(self.certificate, attr_utc)
        else:
            dt = getattr(self.certificate, attr_name)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
        return dt
    
    def _is_certificate_valid(self):
        """
        检查证书是否在有效期内
        """
        now = datetime.now(timezone.utc)
        not_before = self._get_datetime_attr('not_valid_before')
        not_after = self._get_datetime_attr('not_valid_after')
        return not_before <= now <= not_after
    
    def _get_public_key_type(self):
        """
        获取公钥类型
        """
        try:
            public_key = self.certificate.public_key()
        except Exception as e:
            # 如果 cryptography 不支持 SM2，尝试通过 ASN.1 解析判断
            if self._is_sm2_certificate():
                return "SM2 (256 bits)"
            return f"无法解析公钥（{e}）"

        if isinstance(public_key, rsa.RSAPublicKey):
            return f"RSA ({public_key.key_size} bits)"
        elif isinstance(public_key, dsa.DSAPublicKey):
            return "DSA"
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            # cryptography 42+ 会支持 SM2 曲线并给出 name="SM2"
            curve_name = getattr(public_key.curve, 'name', None)
            if not curve_name and hasattr(public_key.curve, 'oid'):
                curve_name = getattr(public_key.curve.oid, 'dotted_string', str(public_key.curve))
            return f"EC ({curve_name})"
        else:
            return "Unknown"

    def _get_signature_algorithm(self):
        """
        获取签名算法
        """
        oid = self.certificate.signature_algorithm_oid
        known = {
            "1.2.156.10197.1.501": "SM2-with-SM3",
        }
        dotted = getattr(oid, "dotted_string", str(oid))
        if dotted in known:
            return known[dotted]
        name = getattr(oid, "_name", None)
        # cryptography 在 SM2 OID 上会返回 "Unknown OID"，这里回退到 OID 字符串
        if name and name not in ("Unknown OID", "undefined"):
            return name
        return dotted

    def _is_sm2_certificate(self):
        """
        通过 ASN.1 解析判定证书是否使用 SM2 曲线。
        """
        if not self.cert_data:
            return False
        try:
            der_data = self.cert_data
            if pem.detect(der_data):
                _, _, der_data = pem.unarmor(der_data)
            cert = asn1_x509.Certificate.load(der_data)
            spki = cert['tbs_certificate']['subject_public_key_info']
            alg_oid = spki['algorithm']['algorithm'].dotted
            # 参数里携带曲线 OID（SM2 为 1.2.156.10197.1.301）
            params = spki['algorithm'].native.get('parameters')
            curve_oid = None
            if isinstance(params, str):
                curve_oid = params
            elif isinstance(params, dict):
                curve_oid = params.get('named')
            # 直接声明为 SM2 OID，或者 EC 公钥 + 曲线 OID 为 SM2 都视为 SM2
            return alg_oid == '1.2.156.10197.1.301' or curve_oid == '1.2.156.10197.1.301'
        except Exception:
            return False
    
    def get_key_usage(self):
        """
        获取密钥用途扩展
        
        Returns:
            dict or None: 密钥用途信息
        """
        if not self.certificate:
            return None
        
        try:
            key_usage = self.certificate.extensions.get_extension_for_oid(x509.ExtensionOID.KEY_USAGE)
            ku_value = key_usage.value
            
            return {
                'digital_signature': ku_value.digital_signature,
                'content_commitment': ku_value.content_commitment,
                'key_encipherment': ku_value.key_encipherment,
                'data_encipherment': ku_value.data_encipherment,
                'key_agreement': ku_value.key_agreement,
                'key_cert_sign': ku_value.key_cert_sign,
                'crl_sign': ku_value.crl_sign,
                'encipher_only': ku_value.encipher_only,
                'decipher_only': ku_value.decipher_only
            }
        except x509.ExtensionNotFound:
            return {'status': 'No key usage extension found'}
        except Exception as e:
            print(f"获取密钥用途失败: {e}")
            return None

from datetime import datetime, timezone

import asn1crypto.x509 as asn1_x509
from asn1crypto import pem
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID


class CertificateVerifier:
    """
    证书验证器类
    用于验证证书的合规性
    """
    
    def __init__(self, certificate):
        """
        初始化验证器
        
        Args:
            certificate: cryptography.x509.Certificate对象
        """
        self.certificate = certificate
        self.verification_results = []
    
    def verify(self):
        """
        执行所有验证规则
        
        Returns:
            dict: 验证结果
        """
        # 清空之前的验证结果
        self.verification_results = []
        
        # 运行各项验证
        self._verify_basic_compliance()
        self._verify_key_strength()
        self._verify_signature_algorithm()
        self._verify_validity_period()
        self._verify_key_usage_and_purpose()
        self._verify_gbt_20518_format()
        
        # 汇总结果
        all_passed = all(result['passed'] for result in self.verification_results)
        
        return {
            'all_passed': all_passed,
            'results': self.verification_results,
            'summary': self._generate_summary()
        }
    
    def _verify_basic_compliance(self):
        """
        验证基本合规性
        """
        try:
            # 检查证书版本
            version_valid = self.certificate.version in [x509.Version.v1, x509.Version.v3]
            
            # 检查序列号
            serial_bits = self.certificate.serial_number.bit_length()
            serial_valid = 0 < serial_bits <= 160  # 1~20 字节
            
            # 基本合规要求
            basic_compliant = version_valid and serial_valid
            
            self.verification_results.append({
                'rule': '基本合规性检查',
                'passed': basic_compliant,
                'details': {
                    'version_valid': version_valid,
                    'serial_valid': serial_valid,
                    'serial_bit_length': serial_bits
                },
                'message': '证书满足基本格式要求' if basic_compliant else '证书格式不符合基本要求'
            })
        except Exception as e:
            self.verification_results.append({
                'rule': '基本合规性检查',
                'passed': False,
                'message': f'验证失败: {str(e)}'
            })
    
    def _verify_key_strength(self):
        """
        验证密钥强度
        """
        try:
            key_info, key_strength_valid = self._inspect_public_key()

            self.verification_results.append({
                'rule': '密钥强度检查',
                'passed': key_strength_valid,
                'details': {
                    'key_type': key_info
                },
                'message': f'{key_info} - 密钥强度满足要求' if key_strength_valid else f'{key_info} - 密钥强度不足（RSA应至少2048位）'
            })
        except Exception as e:
            self.verification_results.append({
                'rule': '密钥强度检查',
                'passed': False,
                'message': f'验证失败: {str(e)}'
            })
    
    def _verify_signature_algorithm(self):
        """
        验证签名算法
        """
        try:
            algorithm_name = str(self.certificate.signature_algorithm_oid)
            
            # 检查是否使用了不安全的算法
            insecure_algorithms = ['md5', 'sha1', 'rsa-pkcs1-v1_5']
            algorithm_valid = not any(insecure.lower() in algorithm_name.lower() for insecure in insecure_algorithms)
            
            self.verification_results.append({
                'rule': '签名算法检查',
                'passed': algorithm_valid,
                'details': {
                    'algorithm': algorithm_name
                },
                'message': f'使用算法: {algorithm_name} - 算法安全' if algorithm_valid else f'使用算法: {algorithm_name} - 算法不安全，不推荐使用'
            })
        except Exception as e:
            self.verification_results.append({
                'rule': '签名算法检查',
                'passed': False,
                'message': f'验证失败: {str(e)}'
            })
    
    def _verify_validity_period(self):
        """
        验证有效期
        """
        try:
            now = datetime.now(timezone.utc)
            
            # 检查是否在有效期内
            not_before = self._get_datetime_attr('not_valid_before')
            not_after = self._get_datetime_attr('not_valid_after')
            is_valid = not_before <= now <= not_after
            
            # 检查有效期长度（不过长）
            validity_days = (not_after - not_before).days
            reasonable_period = validity_days <= 1095  # 最多3年
            
            # 有效期验证结果
            validity_valid = is_valid and reasonable_period
            
            self.verification_results.append({
                'rule': '有效期检查',
                'passed': validity_valid,
                'details': {
                    'is_currently_valid': is_valid,
                    'validity_period_days': validity_days,
                    'reasonable_period': reasonable_period
                },
                'message': self._generate_validity_message(is_valid, reasonable_period, validity_days)
            })
        except Exception as e:
            self.verification_results.append({
                'rule': '有效期检查',
                'passed': False,
                'message': f'验证失败: {str(e)}'
            })

    def _verify_key_usage_and_purpose(self):
        """
        核对密钥用途与证书用途，避免滥用（包含私钥用途约束）
        """
        try:
            key_usage_ext = self._get_extension(ExtensionOID.KEY_USAGE)
            eku_ext = self._get_extension(ExtensionOID.EXTENDED_KEY_USAGE)
            basic_constraints = self._get_extension(ExtensionOID.BASIC_CONSTRAINTS)

            key_usage_present = key_usage_ext is not None
            basic_present = basic_constraints is not None

            # 如果缺少关键扩展，直接判定不通过
            if not (key_usage_present and basic_present):
                self.verification_results.append({
                    'rule': '密钥用途核对',
                    'passed': False,
                    'details': {
                        'key_usage_present': key_usage_present,
                        'basic_constraints_present': basic_present
                    },
                    'message': '缺少 KeyUsage 或 BasicConstraints 扩展，无法确认密钥用途合规'
                })
                return

            ku = key_usage_ext.value
            bc = basic_constraints.value
            eku_value = eku_ext.value if eku_ext else None

            # CA 证书：必须具备签发/吊销用途，不得用于数据/密钥加解密
            if bc.ca:
                ca_sign_ok = ku.key_cert_sign and ku.crl_sign
                ca_misuse = ku.key_encipherment or ku.data_encipherment or ku.key_agreement
                passed = ca_sign_ok and not ca_misuse
                messages = []
                if not ca_sign_ok:
                    messages.append('CA 证书需具备 keyCertSign 与 cRLSign 权限')
                if ca_misuse:
                    messages.append('CA 证书不应包含数据加解密或密钥协商用途')
                message = '；'.join(messages) if messages else 'CA 密钥用途符合要求'
            else:
                # 终端实体：禁止签发/吊销权限，按 EKU 校验常见用途
                no_ca_bits = (not ku.key_cert_sign) and (not ku.crl_sign)
                messages = []
                passed = no_ca_bits
                if not no_ca_bits:
                    messages.append('终端实体证书不应包含签发或吊销权限')

                if eku_value:
                    server_auth = ExtendedKeyUsageOID.SERVER_AUTH in eku_value
                    client_auth = ExtendedKeyUsageOID.CLIENT_AUTH in eku_value
                    code_signing = ExtendedKeyUsageOID.CODE_SIGNING in eku_value
                    email_protection = ExtendedKeyUsageOID.EMAIL_PROTECTION in eku_value

                    if server_auth:
                        server_ok = ku.digital_signature and (ku.key_encipherment or ku.key_agreement)
                        passed = passed and server_ok
                        if not server_ok:
                            messages.append('服务器认证需同时具备 digitalSignature 且 keyEncipherment/KeyAgreement 之一')
                    if client_auth:
                        client_ok = ku.digital_signature
                        passed = passed and client_ok
                        if not client_ok:
                            messages.append('客户端认证需具备 digitalSignature')
                    if code_signing and not ku.digital_signature:
                        passed = False
                        messages.append('代码签名需具备 digitalSignature')
                    if email_protection and not (ku.digital_signature or ku.content_commitment):
                        passed = False
                        messages.append('邮件保护需具备 digitalSignature 或 contentCommitment')

                message = '；'.join(messages) if messages else '密钥用途与扩展用途匹配，未发现滥用'

            # encipher_only/decipher_only 只有在 key_agreement 为 True 时才有定义，需防止 cryptography 抛错
            enc_only = ku.encipher_only if ku.key_agreement else None
            dec_only = ku.decipher_only if ku.key_agreement else None

            self.verification_results.append({
                'rule': '密钥用途核对',
                'passed': passed,
                'details': {
                    'basic_constraints_ca': bc.ca,
                    'key_usage': {
                        'digital_signature': ku.digital_signature,
                        'content_commitment': ku.content_commitment,
                        'key_encipherment': ku.key_encipherment,
                        'data_encipherment': ku.data_encipherment,
                        'key_agreement': ku.key_agreement,
                        'key_cert_sign': ku.key_cert_sign,
                        'crl_sign': ku.crl_sign,
                        'encipher_only': enc_only,
                        'decipher_only': dec_only
                    },
                    'extended_key_usage': self._format_eku(eku_value)
                },
                'message': message
            })
        except Exception as e:
            self.verification_results.append({
                'rule': '密钥用途核对',
                'passed': False,
                'message': f'验证失败: {str(e)}'
            })

    def _verify_gbt_20518_format(self):
        """
        依据 GB/T 20518-2018 进行格式合规性检查
        """
        try:
            issues = []
            version_ok = self.certificate.version == x509.Version.v3
            if not version_ok:
                issues.append('证书版本应为 V3')

            serial_bits = self.certificate.serial_number.bit_length()
            serial_ok = 1 <= serial_bits <= 160  # 标准要求序列号不超过20字节
            if not serial_ok:
                issues.append('序列号长度应在1~20字节内')

            not_before = self._get_datetime_attr('not_valid_before')
            not_after = self._get_datetime_attr('not_valid_after')
            date_order_ok = not_after > not_before
            if not date_order_ok:
                issues.append('有效期起止顺序异常')

            basic_constraints = self._get_extension(ExtensionOID.BASIC_CONSTRAINTS)
            key_usage_ext = self._get_extension(ExtensionOID.KEY_USAGE)
            critical_ok = True
            if basic_constraints and not basic_constraints.critical:
                critical_ok = False
                issues.append('BasicConstraints 推荐标记为关键扩展')
            if key_usage_ext and not key_usage_ext.critical:
                critical_ok = False
                issues.append('KeyUsage 推荐标记为关键扩展')

            mandatory_ext_ok = basic_constraints is not None and key_usage_ext is not None
            if not mandatory_ext_ok:
                issues.append('缺少 BasicConstraints 或 KeyUsage 扩展')

            passed = version_ok and serial_ok and date_order_ok and mandatory_ext_ok and critical_ok

            self.verification_results.append({
                'rule': 'GB/T 20518-2018 格式检查',
                'passed': passed,
                'details': {
                    'version_is_v3': version_ok,
                    'serial_bit_length': serial_bits,
                    'date_order_ok': date_order_ok,
                    'basic_constraints_present': basic_constraints is not None,
                    'key_usage_present': key_usage_ext is not None,
                    'critical_extensions_ok': critical_ok
                },
                'message': '格式满足 GB/T 20518-2018 要求' if passed else '；'.join(issues)
            })
        except Exception as e:
            self.verification_results.append({
                'rule': 'GB/T 20518-2018 格式检查',
                'passed': False,
                'message': f'验证失败: {str(e)}'
            })
    
    def _inspect_public_key(self):
        """
        解析公钥类型并判断强度，兼容 SM2。
        """
        try:
            public_key = self.certificate.public_key()
            if isinstance(public_key, rsa.RSAPublicKey):
                key_size = public_key.key_size
                key_strength_valid = key_size >= 2048
                key_info = f"RSA {key_size}位密钥"
                return key_info, key_strength_valid
            if isinstance(public_key, ec.EllipticCurvePublicKey):
                # 对于椭圆曲线，默认认为强度满足要求
                curve_name = getattr(public_key.curve, 'name', None)
                key_info = f"椭圆曲线密钥 ({curve_name})"
                return key_info, True
        except UnsupportedAlgorithm:
            # cryptography 对 SM2 曲线会抛出不支持异常
            pass

        # 如果走到这里，尝试 ASN.1 判断是否为 SM2
        if self._is_sm2_certificate():
            return "SM2 (256-bit)", True

        return "未知或不受支持的公钥类型", False

    def _is_sm2_certificate(self):
        """
        通过 ASN.1 解析判断证书是否使用 SM2 曲线。
        """
        try:
            der = self.certificate.public_bytes(Encoding.DER)
            cert = asn1_x509.Certificate.load(der)
            spki = cert['tbs_certificate']['subject_public_key_info']
            alg_oid = spki['algorithm']['algorithm'].dotted
            params = spki['algorithm'].native.get('parameters')
            curve_oid = None
            if isinstance(params, str):
                curve_oid = params
            elif isinstance(params, dict):
                curve_oid = params.get('named')
            return alg_oid == '1.2.156.10197.1.301' or curve_oid == '1.2.156.10197.1.301'
        except Exception:
            return False
    
    def _get_datetime_attr(self, attr_name):
        """
        返回带时区的时间属性，兼容 cryptography 新旧接口。
        """
        attr_utc = f"{attr_name}_utc"
        if hasattr(self.certificate, attr_utc):
            dt = getattr(self.certificate, attr_utc)
        else:
            dt = getattr(self.certificate, attr_name)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
        return dt

    def _get_extension(self, oid):
        """
        安全获取扩展，缺失时返回 None
        """
        try:
            return self.certificate.extensions.get_extension_for_oid(oid)
        except x509.ExtensionNotFound:
            return None

    def _format_eku(self, eku_value):
        """
        将扩展用途转换为可读列表
        """
        if not eku_value:
            return []
        names = []
        for oid in eku_value:
            name = getattr(oid, '_name', None) or str(oid.dotted_string)
            names.append(name)
        return names
    
    def _generate_validity_message(self, is_valid, reasonable_period, validity_days):
        """
        生成有效期检查的消息
        """
        messages = []
        
        if not is_valid:
            messages.append('证书当前不在有效期内')
        if not reasonable_period:
            messages.append(f'证书有效期过长 ({validity_days}天)，推荐不超过3年')
        
        if not messages:
            return f'证书在有效期内，有效期为{validity_days}天'
        else:
            return '; '.join(messages)
    
    def _generate_summary(self):
        """
        生成验证结果摘要
        """
        passed_count = sum(1 for result in self.verification_results if result['passed'])
        total_count = len(self.verification_results)
        
        return {
            'passed_count': passed_count,
            'total_count': total_count,
            'percentage': (passed_count / total_count * 100) if total_count > 0 else 0,
            'status': '合规' if passed_count == total_count else '不合规'
        }

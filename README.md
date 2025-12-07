# 证书合规检查系统

## 系统概览
- 图形化工具，用于加载并解析 PEM/DER 等数字证书，展示主题、颁发者、有效期、公钥类型、签名算法等基础信息。
- 依据多条合规规则对证书进行验证，并输出通过/未通过明细及统计摘要。
- 核心逻辑位于 `src/core`，GUI 入口在 `examples/start_gui.py`，示例证书位于 `certificates/`。

## 运行环境与安装
- 安装依赖：`pip install -r requirements.txt`。
- 如需重新生成 SM2 示例证书，请确保本机 OpenSSL 3 可用，然后执行 `python certificates/generate_sample_certs.py`。

## 使用说明
1) 运行 GUI：`python examples/start_gui.py`。  
2) 在界面中选择证书文件（支持 `.pem`/`.cer`/`.crt`/`.der`）。  
3) 点击“开始验证”查看合规检查结果。

## 验证规则说明
系统会按顺序执行以下规则，并给出每条规则的通过情况与详情：
1. **基本合规性**：证书版本必须为 V1 或 V3；序列号长度需在 1~160 位（不超过 20 字节）。  
2. **密钥强度**：RSA 密钥需≥2048 位；椭圆曲线（含 SM2）视为满足要求；无法识别的公钥类型视为不合规。  
3. **签名算法**：推荐使用 RSA-PSS、ECDSA、SM2 等更安全的算法族。  
4. **有效期**：当前时间必须处于 NotBefore 与 NotAfter 之间。
5. **密钥用途与扩展用途**：要求同时存在 BasicConstraints 和 KeyUsage。  
   - CA 证书需包含 `keyCertSign` 和 `cRLSign` 且不得带数据加/解密或密钥协商用途。  
   - 终端实体证书不得包含签发相关权限；若出现 EKU，则逐项校验：服务器认证需 `digitalSignature` 且 `keyEncipherment` 或 `keyAgreement`；客户端认证需 `digitalSignature`；代码签名需 `digitalSignature`；邮件保护需 `digitalSignature` 或 `contentCommitment`。  
6. **GB/T 20518-2018 格式检查**：要求 V3 版本、序列号≤160 位、NotAfter 大于 NotBefore，必须存在 BasicConstraints 与 KeyUsage，且二者推荐标记为关键（critical），否则视为未通过。

## 示例证书
- `certificates/sm2_ca_cert.pem`：SM2 根 CA（配套私钥 `sm2_ca.key.pem`）。  
- `certificates/sm2_valid_cert.pem`：合规的 SM2 终端实体证书（配套私钥 `sm2_valid_key.pem`）。  
- `certificates/sm2_invalid_cert.pem`：故意违反合规项的 SM2 证书（配套私钥 `sm2_invalid_key.pem`）。  
- 需重新生成时运行 `python certificates/generate_sample_certs.py`（依赖本机 OpenSSL 3）。

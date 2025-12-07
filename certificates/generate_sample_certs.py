import shutil
import subprocess
from pathlib import Path
from typing import List


OPENSSL_BIN = shutil.which("openssl")


def run_cmd(args, workdir):
    """
    以子进程调用 OpenSSL，失败时抛出异常并输出 stderr。
    """
    result = subprocess.run(
        args,
        cwd=workdir,
        capture_output=True,
        text=True,
        shell=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"命令执行失败: {' '.join(args)}\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return result.stdout


def write_ext_file(path: Path, section: str, lines: List[str]):
    content = [f"[{section}]"] + lines
    path.write_text("\n".join(content), encoding="utf-8")


def generate_sm2_certificates():
    """
    生成基于 SM2/SM3 的示例证书（合规与不合规各一份）。
    """
    if not OPENSSL_BIN:
        raise RuntimeError("未找到 openssl 可执行文件，无法生成 SM2 证书")

    cert_dir = Path(__file__).resolve().parent
    print(f"生成证书到目录: {cert_dir}")

    # 文件路径
    ca_key = cert_dir / "sm2_ca.key.pem"
    ca_cert = cert_dir / "sm2_ca_cert.pem"
    valid_key = cert_dir / "sm2_valid_key.pem"
    valid_csr = cert_dir / "sm2_valid.csr"
    valid_cert = cert_dir / "sm2_valid_cert.pem"
    valid_ext = cert_dir / "sm2_valid_ext.cnf"
    invalid_key = cert_dir / "sm2_invalid_key.pem"
    invalid_csr = cert_dir / "sm2_invalid.csr"
    invalid_cert = cert_dir / "sm2_invalid_cert.pem"
    invalid_ext = cert_dir / "sm2_invalid_ext.cnf"
    ca_serial = cert_dir / "sm2_ca_cert.srl"
    openssl_conf = cert_dir / "sm2_openssl.cnf"

    # 清理旧文件
    for path in [
        ca_key,
        ca_cert,
        valid_key,
        valid_csr,
        valid_cert,
        valid_ext,
        invalid_key,
        invalid_csr,
        invalid_cert,
        invalid_ext,
        ca_serial,
        openssl_conf,
    ]:
        if path.exists():
            path.unlink()

    # 写入最小化 openssl 配置，避免依赖系统默认 openssl.cnf
    openssl_conf.write_text(
        "\n".join(
            [
                "[ req ]",
                "distinguished_name = req_distinguished_name",
                "prompt = no",
                "string_mask = utf8only",
                "",
                "[ req_distinguished_name ]",
                "CN = placeholder",
            ]
        ),
        encoding="utf-8",
    )

    # 1) 生成 SM2 根 CA
    print("生成 SM2 根 CA ...")
    run_cmd([OPENSSL_BIN, "ecparam", "-genkey", "-name", "SM2", "-out", str(ca_key)], cert_dir)
    run_cmd(
        [
            OPENSSL_BIN,
            "req",
            "-x509",
            "-new",
            "-key",
            str(ca_key),
            "-out",
            str(ca_cert),
            "-days",
            "365",
            "-config",
            str(openssl_conf),
            "-sm3",
            "-subj",
            "/C=CN/ST=Beijing/L=Beijing/O=Sample CA/OU=Compliance/CN=SM2 Test Root",
            "-addext",
            "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-addext",
            "subjectKeyIdentifier=hash",
            "-addext",
            "authorityKeyIdentifier=keyid:always",
        ],
        cert_dir,
    )

    # 2) 生成合规的终端实体证书
    print("生成合规 SM2 证书 ...")
    run_cmd([OPENSSL_BIN, "ecparam", "-genkey", "-name", "SM2", "-out", str(valid_key)], cert_dir)
    run_cmd(
        [
            OPENSSL_BIN,
            "req",
            "-new",
            "-key",
            str(valid_key),
            "-out",
            str(valid_csr),
            "-config",
            str(openssl_conf),
            "-sm3",
            "-subj",
            "/C=CN/ST=Beijing/L=Beijing/O=Sample Company/OU=Server/CN=sm2.valid.example.com",
        ],
        cert_dir,
    )

    write_ext_file(
        valid_ext,
        "sm2_valid",
        [
            "basicConstraints=critical,CA:FALSE",
            "keyUsage=critical,digitalSignature,keyAgreement",
            "extendedKeyUsage=serverAuth,clientAuth",
            "subjectAltName=DNS:sm2.valid.example.com",
        ],
    )

    run_cmd(
        [
            OPENSSL_BIN,
            "x509",
            "-req",
            "-in",
            str(valid_csr),
            "-CA",
            str(ca_cert),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-out",
            str(valid_cert),
            "-days",
            "365",
            "-sm3",
            "-extfile",
            str(valid_ext),
            "-extensions",
            "sm2_valid",
        ],
        cert_dir,
    )

    # 3) 生成不合规的终端实体证书（故意缺少 BasicConstraints 且滥用 keyCertSign）
    print("生成不合规 SM2 证书 ...")
    run_cmd(
        [OPENSSL_BIN, "ecparam", "-genkey", "-name", "SM2", "-out", str(invalid_key)],
        cert_dir,
    )
    run_cmd(
        [
            OPENSSL_BIN,
            "req",
            "-new",
            "-key",
            str(invalid_key),
            "-out",
            str(invalid_csr),
            "-config",
            str(openssl_conf),
            "-sm3",
            "-subj",
            "/C=CN/ST=Beijing/L=Beijing/O=Invalid Company/OU=Misuse/CN=sm2.invalid.example.com",
        ],
        cert_dir,
    )

    write_ext_file(
        invalid_ext,
        "sm2_invalid",
        [
            # 故意省略 basicConstraints，且滥用 keyCertSign、dataEncipherment
            "keyUsage=digitalSignature,dataEncipherment,keyCertSign",
            "extendedKeyUsage=serverAuth",
            "subjectAltName=DNS:sm2.invalid.example.com",
        ],
    )

    run_cmd(
        [
            OPENSSL_BIN,
            "x509",
            "-req",
            "-in",
            str(invalid_csr),
            "-CA",
            str(ca_cert),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-out",
            str(invalid_cert),
            "-days",
            "365",
            "-sm3",
            "-extfile",
            str(invalid_ext),
            "-extensions",
            "sm2_invalid",
        ],
        cert_dir,
    )

    # 清理中间 CSR
    for temp in [valid_csr, invalid_csr]:
        if temp.exists():
            temp.unlink()

    print("SM2 示例证书生成完成：")
    print(f"- 合规证书: {valid_cert}")
    print(f"- 不合规证书: {invalid_cert}")
    print(f"- CA 证书: {ca_cert}")
    print("对应私钥已保存在同目录的 .key.pem 文件中。")


def main():
    generate_sm2_certificates()


if __name__ == "__main__":
    main()

# EVP_test

本项目用于学习和验证 OpenSSL EVP 接口的基本用法，包含对称加密、非对称加密、信封加密以及 RSA 签名验签等示例代码。

## 项目内容

- `symmetric_encrypt_evp.c`：使用 EVP 接口进行 AES 对称加密和解密。
- `asymmetric_encrypt_evp.c`：使用 EVP 接口进行 RSA 非对称加密和解密。
- `envelope_evp.c`：使用 EVP Seal/Open 接口实现信封加密。
- `rsa_sign_verify_evp.c`：使用 EVP 接口进行 RSA 签名和验签。
- `rsa.key` / `rsa.pub`：示例 RSA 私钥和公钥。
- `plaintext`：用于加密测试的示例明文文件。

## 编译与运行

项目依赖 OpenSSL libcrypto，可直接使用 Makefile 编译：

```sh
make
```

编译后会生成对应的可执行文件，例如：

```sh
./symmetric_encrypt_evp
./asymmetric_encrypt_evp
./envelope_evp
./rsa_sign_verify_evp
```

清理编译产物：

```sh
make clean
```

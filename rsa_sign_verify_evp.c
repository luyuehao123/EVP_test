/*
 * @Author: Lu, Yuehao
 * @Date: 2026-07-01 20:42:58
 * @Last Modified by: Lu, Yuehao
 * @Last Modified time: 2026-07-01 20:42:58
 * @Description: test for rsa sign and verify using EVP interface
 */

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>

#define BUF_SIZE 1024

static void print_openssl_error(const char *msg)
{
    fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
}

static EVP_PKEY *read_private_key(const char *path)
{
    FILE *fp = NULL;
    EVP_PKEY *key = NULL;

    fp = fopen(path, "r");
    if (fp == NULL) {
        perror("fopen private key");
        goto cleanup;
    }

    key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    if (key == NULL) {
        print_openssl_error("PEM_read_PrivateKey failed");
        goto cleanup;
    }

cleanup:
    if (fp != NULL) {
        fclose(fp);
    }
    return key;
}

static EVP_PKEY *read_public_key(const char *path)
{
    FILE *fp = NULL;
    EVP_PKEY *key = NULL;

    fp = fopen(path, "r");
    if (fp == NULL) {
        perror("fopen public key");
        goto cleanup;
    }

    key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    if (key == NULL) {
        print_openssl_error("PEM_read_PUBKEY failed");
        goto cleanup;
    }

cleanup:
    if (fp != NULL) {
        fclose(fp);
    }
    return key;
}

static int digest_file(EVP_MD_CTX *ctx, const char *path, int is_sign)
{
    FILE *fp = NULL;
    unsigned char buffer[BUF_SIZE];
    int ret = 0;

    fp = fopen(path, "rb");
    if (fp == NULL) {
        perror("fopen input file");
        goto cleanup;
    }

    for (;;) {
        size_t bytes_read = fread(buffer, 1, sizeof(buffer), fp);
        if (bytes_read > 0) {
            if (is_sign) {
                if (EVP_DigestSignUpdate(ctx, buffer, bytes_read) <= 0) {
                    print_openssl_error("EVP_DigestSignUpdate failed");
                    goto cleanup;
                }
            } else {
                if (EVP_DigestVerifyUpdate(ctx, buffer, bytes_read) <= 0) {
                    print_openssl_error("EVP_DigestVerifyUpdate failed");
                    goto cleanup;
                }
            }
        }

        if (bytes_read < sizeof(buffer)) {
            if (ferror(fp)) {
                perror("fread input file");
                goto cleanup;
            }
            break;
        }
    }

    ret = 1;

cleanup:
    if (fp != NULL) {
        fclose(fp);
    }
    return ret;
}

static int sign_file(EVP_PKEY *private_key, const char *path,
                     unsigned char **sig, size_t *sig_len)
{
    EVP_MD_CTX *ctx = NULL;
    int ret = 0;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        print_openssl_error("EVP_MD_CTX_new failed");
        goto cleanup;
    }

    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, private_key) <= 0) {
        print_openssl_error("EVP_DigestSignInit failed");
        goto cleanup;
    }

    if (!digest_file(ctx, path, 1)) {
        goto cleanup;
    }

    if (EVP_DigestSignFinal(ctx, NULL, sig_len) <= 0) {
        print_openssl_error("EVP_DigestSignFinal length failed");
        goto cleanup;
    }

    *sig = malloc(*sig_len);
    if (*sig == NULL) {
        perror("malloc signature");
        goto cleanup;
    }

    if (EVP_DigestSignFinal(ctx, *sig, sig_len) <= 0) {
        print_openssl_error("EVP_DigestSignFinal failed");
        free(*sig);
        *sig = NULL;
        goto cleanup;
    }

    ret = 1;

cleanup:
    EVP_MD_CTX_free(ctx);
    return ret;
}

static int verify_file(EVP_PKEY *public_key, const char *path,
                       const unsigned char *sig, size_t sig_len)
{
    EVP_MD_CTX *ctx = NULL;
    int verify_ret = 0;
    int ret = -1;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        print_openssl_error("EVP_MD_CTX_new failed");
        goto cleanup;
    }

    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, public_key) <= 0) {
        print_openssl_error("EVP_DigestVerifyInit failed");
        goto cleanup;
    }

    if (!digest_file(ctx, path, 0)) {
        goto cleanup;
    }

    verify_ret = EVP_DigestVerifyFinal(ctx, sig, sig_len);
    if (verify_ret < 0) {
        print_openssl_error("EVP_DigestVerifyFinal failed");
        goto cleanup;
    }

    ret = verify_ret;

cleanup:
    EVP_MD_CTX_free(ctx);
    return ret;
}

static void print_hex(const unsigned char *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main(void)
{
    const char *private_key_path = "rsa.key";
    const char *public_key_path = "rsa.pub";
    const char *data_path = "plaintext";
    EVP_PKEY *private_key = NULL;
    EVP_PKEY *public_key = NULL;
    unsigned char *sig = NULL;
    size_t sig_len = 0;
    int verify_ret;
    int ret = EXIT_FAILURE;

    private_key = read_private_key(private_key_path);
    if (private_key == NULL) {
        goto cleanup;
    }

    if (!sign_file(private_key, data_path, &sig, &sig_len)) {
        goto cleanup;
    }

    printf("signature length: %zu\n", sig_len);
    printf("signature hex: ");
    print_hex(sig, sig_len);

    public_key = read_public_key(public_key_path);
    if (public_key == NULL) {
        goto cleanup;
    }

    verify_ret = verify_file(public_key, data_path, sig, sig_len);
    if (verify_ret == 1) {
        printf("Signature is valid.\n");
        ret = EXIT_SUCCESS;
    } else if (verify_ret == 0) {
        printf("Signature is invalid.\n");
    } else {
        fprintf(stderr, "Signature verification failed.\n");
    }

cleanup:
    free(sig);
    EVP_PKEY_free(public_key);
    EVP_PKEY_free(private_key);
    return ret;
}

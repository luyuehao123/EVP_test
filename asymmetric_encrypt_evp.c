#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_LEN 256

/* 打印 OpenSSL 错误信息 */
void print_err(void) {
    ERR_print_errors_fp(stderr);
}

int main(){
    const char *msg = "Hello EVP asymmetric crypto!";
    unsigned char *cipher = NULL;
    unsigned char *plain = NULL;
    size_t cipher_len = 0, plain_len = 0;
    EVP_PKEY_CTX* md = NULL;
    int ret = EXIT_FAILURE;

    EVP_PKEY *pubkey = NULL;
    EVP_PKEY *privkey = NULL;
    FILE *fp1 = fopen("rsa.pub", "r");
    FILE *fp2 = NULL;
    if (!fp1) {
        perror("fopen pubkey");
        goto cleanup;
    }

    pubkey = PEM_read_PUBKEY(fp1, NULL, NULL, NULL);
    if (!pubkey) {
        print_err();
        goto cleanup;
    }

    //加密
    md = EVP_PKEY_CTX_new(pubkey, NULL);
    if (!md) {
        print_err();
        goto cleanup;
    }
    if (EVP_PKEY_encrypt_init(md) <= 0){
        print_err();
        goto cleanup;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(md, RSA_PKCS1_OAEP_PADDING) <= 0) {
        print_err();
        goto cleanup;
    }
    if(EVP_PKEY_encrypt(md, NULL, &cipher_len, (unsigned char*)msg, strlen(msg)) <= 0){
        print_err();
        goto cleanup;
    }
    cipher = malloc(cipher_len);
    if(!cipher){
        perror("malloc cipher");
        goto cleanup;
    }

    if (EVP_PKEY_encrypt(md, cipher, &cipher_len, (unsigned char*)msg, strlen(msg)) <= 0) {
        print_err();
        goto cleanup;
    }

    for(size_t i = 0; i < cipher_len; i++){
        printf("%02x", cipher[i]);
    }
    printf("\n");
    EVP_PKEY_CTX_free(md);
    md = NULL;
    EVP_PKEY_free(pubkey);
    pubkey = NULL;
    fclose(fp1);
    fp1 = NULL;

    //解密
    fp2 = fopen("rsa.key", "r");
    if (!fp2) {
        perror("fopen privkey");
        goto cleanup;
    }
    privkey = PEM_read_PrivateKey(fp2, NULL, NULL, NULL);
    if (!privkey) {
        print_err();
        goto cleanup;
    }
    
    md = EVP_PKEY_CTX_new(privkey, NULL);
    if (!md) {
        print_err();
        goto cleanup;
    }
    if (EVP_PKEY_decrypt_init(md) <= 0){
        print_err();
        goto cleanup;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(md, RSA_PKCS1_OAEP_PADDING) <= 0) {
        print_err();
        goto cleanup;
    }
    if(EVP_PKEY_decrypt(md, NULL, &plain_len, cipher, cipher_len) <= 0){
        print_err();
        goto cleanup;
    }
    plain = malloc(plain_len);
    if(!plain){
        perror("malloc plain");
        goto cleanup;
    }
    if (EVP_PKEY_decrypt(md, plain, &plain_len, cipher, cipher_len) <= 0) {
        print_err();
        goto cleanup;
    }
    for(size_t i = 0; i < plain_len; i++){
        printf("%c", plain[i]);
    }
    printf("\n");

    ret = EXIT_SUCCESS;

cleanup:
    if (fp1) {
        fclose(fp1);
    }
    if (fp2) {
        fclose(fp2);
    }
    EVP_PKEY_CTX_free(md);
    EVP_PKEY_free(pubkey);
    EVP_PKEY_free(privkey);
    free(cipher);
    free(plain);

    return ret;
}

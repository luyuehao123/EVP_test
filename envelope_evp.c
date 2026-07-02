/*
 * @Author: Lu, Yuehao
 * @Date: 2026-07-01 22:19:29
 * @Last Modified by: Lu, Yuehao
 * @Last Modified time: 2026-07-01 22:19:29
 * @Description: test for envelope
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

int seal(char* pubkey_file,char* in,char *out,int* outlen,unsigned char **encrypted_keys,int *encrypted_key_len,unsigned char *iv);
int envelope_open(char* prikey_file,char* in,int *inlen,char *out,int* outlen,unsigned char *encrypted_keys,int *encrypted_key_len,unsigned char *iv);

int main(int argc, char *argv[])
{
    char *pubkey_file = "rsa.pub";
    char *prikey_file = "rsa.key";
    char *plaintext = "Hello, this is a test message for envelope encryption!";
    char ciphertext[1024];
    char decrypted[1024];
    int ciphertext_len = 0;
    int decrypted_len = 0;

    unsigned char *encrypted_keys = NULL;
    int encrypted_key_len = 0;
    unsigned char iv[EVP_MAX_IV_LENGTH];

    if(seal(pubkey_file, plaintext, ciphertext, &ciphertext_len, &encrypted_keys, &encrypted_key_len, iv)){
        free(encrypted_keys);
        return 1;
    }
    for(int i=0;i<ciphertext_len;++i){
        printf("%02x", (unsigned char)ciphertext[i]);
    }
    printf("\n");

    if(envelope_open(prikey_file, ciphertext, &ciphertext_len, decrypted, &decrypted_len, encrypted_keys, &encrypted_key_len, iv)){
        free(encrypted_keys);
        return 1;
    }
    decrypted[decrypted_len] = '\0';
    printf("Decrypted message: %s\n", decrypted);

    free(encrypted_keys);
    
    return 0;
}
int seal(char* pubkey_file,char* in,char *out,int* outlen,unsigned char **encrypted_keys,int *encrypted_key_len,unsigned char *iv)
{
    FILE* public_key_file = NULL;
    EVP_PKEY *public_key = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    int res = 0;
    int len = 0;

    public_key_file = fopen(pubkey_file, "rb");
    if(public_key_file == NULL) {
        perror("fopen public key");
        goto error;
    }
    
    public_key = PEM_read_PUBKEY(public_key_file, NULL, NULL, NULL);
    if(public_key == NULL) {
        perror("PEM_read_PUBKEY");
        goto error;
    }

    *encrypted_keys = malloc(EVP_PKEY_size(public_key));
    if(*encrypted_keys == NULL) {
        perror("malloc encrypted key");
        goto error;
    }

    ctx = EVP_CIPHER_CTX_new();
    if(ctx == NULL) {
        ERR_print_errors_fp(stderr);
        goto error;
    }
    res = EVP_SealInit(ctx, EVP_aes_256_cbc(),encrypted_keys, encrypted_key_len, iv, &public_key, 1);
    if(res != 1) {
        perror("EVP_SealInit");
        goto error;
    }

    if(EVP_SealUpdate(ctx, (unsigned char*)out, &len, (unsigned char*)in, strlen(in)) != 1) {
        ERR_print_errors_fp(stderr);
        goto error;
    }
    *outlen = len;
    if(EVP_SealFinal(ctx, (unsigned char*)out + *outlen, &len) != 1) {
        ERR_print_errors_fp(stderr);
        goto error;
    }
    *outlen += len;

    fclose(public_key_file);
    EVP_PKEY_free(public_key);
    EVP_CIPHER_CTX_free(ctx);
    return 0;

error:
    if(public_key_file) {
        fclose(public_key_file);
    }
    EVP_PKEY_free(public_key);
    EVP_CIPHER_CTX_free(ctx);
    free(*encrypted_keys);
    *encrypted_keys = NULL;

    return 1;
}

int envelope_open(char* prikey_file,char* in,int *inlen,char *out,int* outlen,unsigned char *encrypted_keys,int *encrypted_key_len,unsigned char *iv)
{
    FILE* private_key_file = NULL;
    EVP_PKEY *private_key = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    int res = 0;
    int len = 0;

    private_key_file = fopen(prikey_file, "rb");
    if(private_key_file == NULL) {
        perror("fopen private key");
        goto error;
    }
    
    private_key = PEM_read_PrivateKey(private_key_file, NULL, NULL, NULL);
    if(private_key == NULL) {
        perror("PEM_read_PrivateKey");
        goto error;
    }
    
    ctx = EVP_CIPHER_CTX_new();
    if(ctx == NULL) {
        ERR_print_errors_fp(stderr);
        goto error;
    }
    res = EVP_OpenInit(ctx, EVP_aes_256_cbc(), encrypted_keys, *encrypted_key_len, iv, private_key);
    if(res != 1) {
        perror("EVP_OpenInit");
        goto error;
    }

    if(EVP_OpenUpdate(ctx, (unsigned char*)out, &len, (unsigned char*)in, *inlen) != 1) {
        ERR_print_errors_fp(stderr);
        goto error;
    }
    *outlen = len;
    if(EVP_OpenFinal(ctx, (unsigned char*)out + *outlen, &len) != 1) {
        ERR_print_errors_fp(stderr);
        goto error;
    }
    *outlen += len;

    fclose(private_key_file);
    EVP_PKEY_free(private_key);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
error:
    if(private_key_file) {
        fclose(private_key_file);
    }
    EVP_PKEY_free(private_key);
    EVP_CIPHER_CTX_free(ctx);

    return 1;
}

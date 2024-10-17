#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#define MAX 100000

#define MAX_CIPHERTEXT_LEN 256

int checkKey(char* db_path, size_t key, char *password) {
    FILE *fp;
    char *line = NULL;
    size_t max;
    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    const EVP_MD* digest = EVP_sha256();
    unsigned char* salt = NULL;
    unsigned char derived_key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];

    if (EVP_BytesToKey(cipher, digest, salt, (unsigned char*)password, strlen(password), 1, derived_key, iv) == 0) {
        printf("Error in key derivation\n");
        return 1;
    }
    fp = fopen(db_path, "a+");
    if (fp == NULL) {
        printf("Error opening file\n");
        return 1;
    }
    unsigned char ciphertext_f[MAX_CIPHERTEXT_LEN];
    while (getline(&line, &max, fp) != -1) {
        char* token = strtok(line, ",");
        if (token == NULL) {
            printf("Error in reading key\n");
            break;
        }

        int lenb = 0;

        for (int i = 0; i < strlen(token); i += 2) {
            sscanf(token + i, "%2hhx", &ciphertext_f[i / 2]);
            lenb++;
        }
        unsigned char decrypted_data[MAX_CIPHERTEXT_LEN];
        int decrypted_data_len;
        EVP_CIPHER_CTX* ctx_d = EVP_CIPHER_CTX_new();
        if (EVP_DecryptInit_ex(ctx_d, cipher, NULL, derived_key, iv) == 0) {
            printf("Error in DecryptInit\n");
            return 1;
        }
        if (EVP_DecryptUpdate(ctx_d, decrypted_data, &decrypted_data_len, ciphertext_f, lenb) != 1) {
            printf("Error in DecryptUpdate\n");
            return 1;
        }
        if (EVP_DecryptFinal_ex(ctx_d, decrypted_data + decrypted_data_len, &decrypted_data_len) == 1) {
            size_t k = *(size_t*)decrypted_data;
            if (k == key) {
                printf("Key already exists\n");
                free(line);
                fclose(fp);
                EVP_CIPHER_CTX_free(ctx_d);
                return 1;
            }
        }

        EVP_CIPHER_CTX_free(ctx_d);
    }
    fclose(fp);
    free(line);
    return 0;
}
int addKV(char* db_path,size_t key,size_t value){
    FILE * fp;
    char password[MAX];
    printf("Enter password: ");
    fgets(password, MAX, stdin);
    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    const EVP_MD* digest= EVP_sha256();
    unsigned char* salt=NULL;
    unsigned char derived_key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];

    if(EVP_BytesToKey(cipher, digest, salt, (unsigned char*)password, strlen(password), 1,derived_key, iv)==0){
        printf("Error in key derivation\n");
        return 1;
    }

    unsigned char* ciphertext = (unsigned char*)malloc( EVP_CIPHER_block_size(cipher) +sizeof(size_t)*2);
    size_t ciphertext_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    if(EVP_EncryptInit_ex(ctx, cipher, NULL, derived_key, iv)==0){
        printf("Error in EncryptInit\n");
        return 1;
    }

    if(EVP_EncryptUpdate(ctx, ciphertext, (int*)&ciphertext_len, (unsigned char*)&key, sizeof(size_t))!=1){
        printf("Error in EncryptUpdate\n");
        return 1;
    }

    if(EVP_EncryptFinal_ex(ctx, ciphertext+ciphertext_len, (int*)&ciphertext_len)==0){
        printf("Error in EncryptFinal\n");
        return 1;
    }

    char *line=malloc(MAX);
    if(checkKey(db_path,key,password)==1){
        free(line);
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    fp = fopen(db_path, "a");
    if(!fp){
        printf("Error opening file\n");
        return 1;
    }
    for(int i=0;i<ciphertext_len;i++){
        fprintf(fp, "%02x",ciphertext[i]);
    }
    fprintf(fp, ",");
    if(EVP_EncryptInit_ex(ctx, cipher, NULL, derived_key, iv)==0){
        printf("Error in EncryptInit\n");
        return 1;
    }
    EVP_CIPHER_CTX_free(ctx);
    ctx = EVP_CIPHER_CTX_new();
    if(EVP_EncryptInit_ex(ctx, cipher, NULL, derived_key, iv)==0){
        printf("Error in EncryptInit\n");
        return 1;
    }
    if(EVP_EncryptUpdate(ctx, ciphertext, (int*)&ciphertext_len, (unsigned char*)&value, sizeof(size_t))!=1){
        printf("Error in EncryptUpdate\n");
        return 1;
    }

    if(EVP_EncryptFinal_ex(ctx, ciphertext+ciphertext_len, (int*)&ciphertext_len)!=1){
        printf("Error in EncryptFinal\n");
        return 1;
    }

    for(int i=0;i<ciphertext_len;i++){
        fprintf(fp, "%02x",ciphertext[i]);
    }
    fprintf(fp,"\n");
    fclose(fp);
    EVP_CIPHER_CTX_free(ctx);
    free(line);
    free(ciphertext);
    return 0;
}

int readKV(char* db_path,size_t key){
    FILE *fp;
    char *line = NULL;
    size_t max;
    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    const EVP_MD* digest = EVP_sha256();
    unsigned char* salt = NULL;
    unsigned char derived_key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];

    printf("Enter password: ");
    char password[MAX];
    fgets(password, MAX, stdin);

    if (EVP_BytesToKey(cipher, digest, salt, (unsigned char*)password, strlen(password), 1, derived_key, iv) == 0) {
        printf("Error in key derivation\n");
        return 1;
    }
    fp = fopen(db_path, "a+");
    if (fp == NULL) {
        printf("Error opening file\n");
        return 1;
    }
    unsigned char ciphertext[MAX_CIPHERTEXT_LEN];
    while (getline(&line, &max, fp) != -1) {
        char* token = strtok(line, ",");
        if (token == NULL) {
            printf("Error in reading key\n");
            break;
        }
        int lenk = 0;
        for (int i = 0; i < strlen(token); i += 2) {
            sscanf(token + i, "%2hhx", &ciphertext[i / 2]);
            lenk++;
        }

        unsigned char decrypted_data[MAX_CIPHERTEXT_LEN*2];
        int decrypted_data_len;
        EVP_CIPHER_CTX* ctx_d = EVP_CIPHER_CTX_new();
        if (EVP_DecryptInit_ex(ctx_d, cipher, NULL, derived_key, iv) == 0) {
            printf("Error in DecryptInit\n");
            return 1;
        }
        if (EVP_DecryptUpdate(ctx_d, decrypted_data, &decrypted_data_len, ciphertext, lenk) != 1) {
            printf("Error in DecryptUpdate\n");
            return 1;
        }
        if (EVP_DecryptFinal_ex(ctx_d, decrypted_data + decrypted_data_len, &decrypted_data_len) == 1) {
            EVP_CIPHER_CTX_free(ctx_d);
            size_t k = *(size_t*)decrypted_data;
            if (k == key) {
                //decrypt value
                token = strtok(NULL, ",");
                if (token == NULL) {
                    printf("Error in reading value\n");
                    break;
                }
                int lenv = 0;

                for (int i = 0; i < strlen(token); i += 2) {
                    sscanf(token + i, "%2hhx", &ciphertext[i / 2]);
                    lenv++;
                }
                lenv--;
                ctx_d = EVP_CIPHER_CTX_new();

                if (EVP_DecryptInit_ex(ctx_d, cipher, NULL, derived_key, iv) == 0) {
                    printf("Error in DecryptInit\n");
                    return 1;
                }
                if (EVP_DecryptUpdate(ctx_d, decrypted_data, &decrypted_data_len, ciphertext, lenv) != 1) {
                    printf("Error in DecryptUpdate\n");
                    return 1;
                }
                if (EVP_DecryptFinal_ex(ctx_d, decrypted_data + decrypted_data_len, &decrypted_data_len) != 1) {
                    printf("Error in DecryptFinal\n");
                    return 1;
                }

                size_t result =*(size_t*)decrypted_data;
                printf("Key: %ld has value: %ld\n",k, result);
                EVP_CIPHER_CTX_free(ctx_d);
                break;
            }
        }else{
            EVP_CIPHER_CTX_free(ctx_d);
        }

    }
    fclose(fp);
    free(line);
    return 0;
}
int range_read(char* db_path,size_t key1,size_t key2){
    FILE *fp;
    char *line = NULL;
    size_t max;
    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    const EVP_MD* digest = EVP_sha256();
    unsigned char* salt = NULL;
    unsigned char derived_key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];

    printf("Enter password: ");
    char password[MAX];
    fgets(password, MAX, stdin);

    if (EVP_BytesToKey(cipher, digest, salt, (unsigned char*)password, strlen(password), 1, derived_key, iv) == 0) {
        printf("Error in key derivation\n");
        return 1;
    }
    fp = fopen(db_path, "a+");
    if (fp == NULL) {
        printf("Error opening file\n");
        return 1;
    }
    unsigned char ciphertext[MAX_CIPHERTEXT_LEN];
    while (getline(&line, &max, fp) != -1) {
        char* token = strtok(line, ",");
        if (token == NULL) {
            printf("Error in reading key\n");
            break;
        }
        int lenk = 0;
        for (int i = 0; i < strlen(token); i += 2) {
            sscanf(token + i, "%2hhx", &ciphertext[i / 2]);
            lenk++;
        }

        unsigned char decrypted_data[MAX_CIPHERTEXT_LEN*2];
        int decrypted_data_len;
        EVP_CIPHER_CTX* ctx_d = EVP_CIPHER_CTX_new();
        if (EVP_DecryptInit_ex(ctx_d, cipher, NULL, derived_key, iv) == 0) {
            printf("Error in DecryptInit\n");
            return 1;
        }
        if (EVP_DecryptUpdate(ctx_d, decrypted_data, &decrypted_data_len, ciphertext, lenk) != 1) {
            printf("Error in DecryptUpdate\n");
            return 1;
        }
        if (EVP_DecryptFinal_ex(ctx_d, decrypted_data + decrypted_data_len, &decrypted_data_len) == 1) {
            EVP_CIPHER_CTX_free(ctx_d);
            size_t k = *(size_t*)decrypted_data;
            if (k>=key1&&k<=key2) {
                //decrypt value
                token = strtok(NULL, ",");
                if (token == NULL) {
                    printf("Error in reading value\n");
                    break;
                }
                int lenv = 0;

                for (int i = 0; i < strlen(token); i += 2) {
                    sscanf(token + i, "%2hhx", &ciphertext[i / 2]);
                    lenv++;
                }
                lenv--;
                ctx_d = EVP_CIPHER_CTX_new();

                if (EVP_DecryptInit_ex(ctx_d, cipher, NULL, derived_key, iv) == 0) {
                    printf("Error in DecryptInit\n");
                    return 1;
                }
                if (EVP_DecryptUpdate(ctx_d, decrypted_data, &decrypted_data_len, ciphertext, lenv) != 1) {
                    printf("Error in DecryptUpdate\n");
                    return 1;
                }
                if (EVP_DecryptFinal_ex(ctx_d, decrypted_data + decrypted_data_len, &decrypted_data_len) != 1) {
                    printf("Error in DecryptFinal\n");
                    return 1;
                }

                size_t result =*(size_t*)decrypted_data;
                printf("Key: %ld has value: %ld\n",k, result);
            }
            EVP_CIPHER_CTX_free(ctx_d);
        }
    }
    fclose(fp);
    free(line);
    return 0;
}
int main(int argc, char* argv[]) {
    if (argc < 4) {
        printf("Usage: %s <operation> -f <filename> [key] [value]\n", argv[0]);
        return 1;
    }
    char* operation = argv[1];
    char* filename = argv[3];
    char* key = NULL;
    char* value = NULL;

    if (argc > 4) {
        key = argv[4];
    }
    if (argc > 5) {
        value = argv[5];
    }
    if (strcmp(operation, "add") == 0) {
        if (key == NULL || value == NULL) {
            printf("Usage: %s add -f <filename> key value\n", argv[0]);
            return 1;
        }
        size_t k = atol(key);
        size_t v = atol(value);
        int status = addKV(filename,k,v);
        if (status != 0) {
            printf("Error adding key-value pair to %s\n", filename);
            return 1;
        }
        printf("Adding key-value pair to %s\n", filename);
        printf("Key: %s\n", key);
        printf("Value: %s\n", value);

    } else if (strcmp(operation, "read") == 0) {
        if (key == NULL) {
            printf("Usage: %s read -f <filename> key\n", argv[0]);
            return 1;
        }
        size_t k = atol(key);
        int status = readKV(filename,k);
        if (status != 0) {
            printf("Error reading value for key %s from %s\n", key, filename);
            return 1;
        }
    } else if (strcmp(operation, "range-read") == 0) {
        if (key == NULL || value == NULL) {
            printf("Usage: %s range-read -f <filename> key1 key2\n", argv[0]);
            return 1;
        }
        int k1 = atol(key);
        int k2 = atol(value);
        if(k1>k2){
            printf("Invalid range\n");
            return 1;
        }
        int status = range_read(filename,k1,k2);
        if (status != 0) {
            printf("Error reading value for key %s from %s\n", key, filename);
            return 1;
        }
    } else {
        printf("Invalid operation: %s\n", operation);
        return 1;
    }
    return 0;
}
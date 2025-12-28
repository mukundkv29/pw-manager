#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "include/pw_man_main.h"

void derive_key(const char *password, const unsigned char *salt, unsigned char *key, unsigned char *iv) {
    PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_LEN, 1000, EVP_sha256(), KEY_LEN, key);
    unsigned char temp[SALT_LEN+4];
    memcpy(temp, salt, SALT_LEN);
    memcpy(temp+SALT_LEN, "IV", 2);

    PKCS5_PBKDF2_HMAC(password, strlen(password), temp, SALT_LEN+2, 1000, EVP_sha256(), IV_LEN, iv);
}

int encrypt_credential(Credential *cred, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) {
        return -1;
    }

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, 
                              (unsigned char*)cred, sizeof(Credential))) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int decrypt_credential(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, Credential *cred) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) {
        return -1;
    }

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if(1 != EVP_DecryptUpdate(ctx, (unsigned char*)cred, &len, 
                              ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, (unsigned char*)cred + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int file_exists() {
    FILE *file;
    file = fopen(filename, "rb");
    if(
        file != NULL
    ) {
        fclose(file);
        return 1;
    }

    return 0;
}

int create_new_file(char *username, char *password) {
    printf("------------------------------");
    printf("\nCreating file...\n");
    printf("Entered Username: %s\n", username);
    if(strlen(username) > USERNAME_MAX_LEN - 1) {
        fprintf(stderr, "Too long username!\n");
        printf("------------------------------\n");
        return 1;
    }
    printf("Entered Password: %s\n", password);
    if(strlen(password) > PASSWORD_MAX_LEN - 1) {
        fprintf(stderr, "Too long password!\n");
        printf("------------------------------\n");
        return 1;
    }
    printf("------------------------------\n");
    
    User user;
    strncpy(user.username, username, USERNAME_MAX_LEN);
    strncpy(user.password, password, PASSWORD_MAX_LEN);

    Header *header = calloc(1, sizeof(Header));
    if(!header) {
        fprintf(stderr, "Memory allocation failed!\n");
        return 1;
    }

    strcpy(header->anchor_string, anchor_string_version);

    if(RAND_bytes(header->salt, SALT_LEN) != 1) {
        fprintf(stderr, "Failed to generate random salt!\n");
        free(header);
        return 1;
    }
    
    header->user = user;
    header->total_credentials = 0;

    FILE* file = fopen(filename, "wb");
    if (file == NULL) {
        fprintf(stderr, "Error creating file!\n");
        free(header);
        return 1;
    }

    if(fwrite(header, sizeof(Header), 1, file) != 1) {
        fprintf(stderr, "Error while creating header\n");
        free(header);
        fclose(file);
        return 1;
    }
    
    free(header);
    fclose(file);
    return 0;
}

uint16_t check_header(User *user_credentials) {
    FILE *file;
    file = fopen(filename, "rb");

    if (file == NULL) {
        return -1;
    }
    
    char anchor_string[8];
    if (fread(anchor_string, sizeof(anchor_string), 1, file) != 1) {
        fprintf(stderr, "Anchor string not found!\n");
        fclose(file);
        return -1;
    }

    if(strcmp(anchor_string, anchor_string_version)) {
        fprintf(stderr, "Mismatched Anchor String\n");
        fclose(file);
        return -1;
    }

    unsigned char salt[SALT_LEN];
    if (fread(salt, SALT_LEN, 1, file) != 1) {
        fprintf(stderr, "Error reading salt!\n");
        fclose(file);
        return -1;
    }

    User user;
    if(fread(user.username, sizeof(user.username), 1, file)!=1 ||
       fread(user.password, sizeof(user.password), 1, file)!=1) {
        fprintf(stderr, "Error fetching user credentials!\n");
        fclose(file);
        return -1;
    }

    if(strcmp(user.username, user_credentials->username) ||
       strcmp(user.password, user_credentials->password)) {
        fprintf(stderr, "Invalid username and/or password!\n");
        fclose(file);
        return -1;
    }

    uint16_t total;
    if(fread(&total, sizeof(total), 1, file)!=1) {
        fprintf(stderr, "Error fetching the entries count\n");
        fclose(file);
        return -1;
    }

    fclose(file);
    return total;
}

int read_count(char *username, char* password) {

    User user;
    strcpy(user.username, username);
    strcpy(user.password, password);
    int16_t total = check_header(&user);

    if(total == -1) {
        fprintf(stderr, "Error while checking User Credentials!\n");
        return 1;
    }
    
    printf("User authentication successful!!\n");
    printf("Count: %d\n", total);
    return 0;
}

int add_credential(int argc, char *argv[]) {
    User user;
    strcpy(user.username, argv[0]);
    strcpy(user.password, argv[1]);
    int16_t total = check_header(&user);

    if(total<0) {
        fprintf(stderr, "User authentication failed!\n");
        return 1;
    }

    total++;

    FILE* file;
    file = fopen(filename, "rb+");
    if(file == NULL) {
        fprintf(stderr, "Error while opening file\n");
        return 1;
    }

    if (fseek(file, sizeof(Header)-sizeof(uint16_t), SEEK_SET)) {
        fprintf(stderr, "Error duing file positioning\n");
        return 1;
    }

    if (fwrite(&total, sizeof(total), 1, file)!=1) {
        fprintf(stderr, "Error while updating total\n");
        return 1;
    }
    
    Credential *credential = calloc(1, sizeof(Credential));
    
    strcpy(credential->alias, argv[2]);
    strcpy(credential->password, argv[3]);
    
    if(argc == 5) {
        strcpy(credential->website, argv[4]);
    }else {
        strcpy(credential->website, ".");
    }
    
    if(fclose(file) == EOF) {
        fprintf(stderr, "Error while closing file\n");
        return -1;
    }
    file = fopen(filename, "ab");
    if (fwrite(credential, sizeof(*credential), 1, file)!=1) {
        fprintf(stderr, "Error while adding credential\n");
        return 1;
    }

    free(credential);
    if(fclose(file) == EOF) {
        fprintf(stderr, "Error while closing file\n");
        return -1;
    }

    return 0;
}

int get_credential(int argc, char *argv[]) {
    User user;
    strcpy(user.username, argv[0]);
    strcpy(user.password, argv[1]);
    int16_t total = check_header(&user);

    if(total<0) {
        fprintf(stderr, "User authentication failed!\n");
        return 1;
    }

    if(total==0) {
        fprintf(stderr, "No record is present!\n");
        return 1;
    }

    FILE *file;
    file=fopen(filename, "rb");

    if (file==NULL) {
        fprintf(stderr, "Error while opening file!\n");
        return 1;
    }

    fseek(file, sizeof(Header), SEEK_SET);

    int8_t found=0;
    for(int i=0;i<total;i++) {
        Credential current_credential;
        if(fread(&current_credential, sizeof(Credential), 1, file)!=1){
            fprintf(stderr, "Error while reading!\n");
            return 1;
        }

        if(strcmp(current_credential.website, argv[2])==0) {
            found=1;
            printf("\nAlias: %s\n", current_credential.alias);
            printf("Password: %s\n", current_credential.password);
        }
    }

    if(!found) {
        printf("No record found!\n");
    }

    fclose(file);
    return 0;
}

int main(int argc, char *argv[]) {

    if(argc < 2) {
        fprintf(stderr, "Invalid command\n");
        fprintf(stderr, "See --help\n");
        return 1;
    }

    if(strcmp(argv[1], "create") == 0) {
        if(argc != 4) {
            fprintf(stderr, "Enter all arugments for create command\n");
            fprintf(stderr, "See --help\n");
            return 1;
        }
        if(create_new_file(argv[2], argv[3])) {
           fprintf(stderr, "Error creating file!\n");
           return 1; 
        }
        printf("File created!!\n");
        return 0;
    }

    if(strcmp(argv[1], "read") == 0) {
        if(argc != 4) {
            fprintf(stderr, "Enter all arugments for read command\n");
            fprintf(stderr, "See --help\n");
            return 1;
        }
        if(read_count(argv[2], argv[3])) {
            fprintf(stderr, "Error while reading the file!\n");
            return 1;
        }
        return 0;
    }

    if(strcmp(argv[1], "add") == 0) { // add <username> <password> <alias> <password> <website>
        if(argc != 6 && argc != 7) {
            fprintf(stderr, "Enter all arugments for read command\n");
            fprintf(stderr, "See --help\n");
            return 1;
        }
        if(add_credential(argc-2, argv+2)) {
            fprintf(stderr, "Error while adding the credential\n");
            return 1;
        }
        printf("New Credential added!\n");
        return 0;
    }

    if(strcmp(argv[1], "get")==0) { // get <username> <password> <website>
        if(argc != 5) {
            fprintf(stderr, "Enter all arugments for read command\n");
            fprintf(stderr, "See --help\n");
            return 1;
        }
        printf("Searching records...\n");
        printf("-----------------------------\n");
        if(get_credential(argc-2, argv+2)) {
            fprintf(stderr, "Error while getting the credential\n");
            return 1;
        }
        printf("-----------------------------\n");
        return 0;
    }
    
    fprintf(stderr, "Invalid command\n");
    fprintf(stderr, "See --help\n");

    return 1;
}

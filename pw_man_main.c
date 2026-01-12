#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#ifdef _WIN32
#include <windows.h>
#elif
#include <termio.h>
#endif
#include <unistd.h>

#include "include/pw_man_main.h"
#include "include/version.h"

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
    printf("------------------------------\n");
    
    User user;
    strncpy(user.username, username, USERNAME_MAX_LEN);
    
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
    
    unsigned char password_hash[32];
    PKCS5_PBKDF2_HMAC(password, strlen(password), header->salt, SALT_LEN, 100000, EVP_sha256(), 32, password_hash);

    memcpy(user.password_hash, password_hash, 32);
    
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

    User stored_user;
    if(fread(stored_user.username, sizeof(stored_user.username), 1, file) != 1 ||
       fread(stored_user.password_hash, sizeof(stored_user.password_hash), 1, file) != 1) {
        fprintf(stderr, "Error fetching user credentials!\n");
        fclose(file);
        return -1;
    }

    if(strcmp(stored_user.username, user_credentials->username) != 0) {
        fprintf(stderr, "Incorrect username!\n");
        fclose(file);
        return -1;
    }

    unsigned char input_password_hash[32];
    PKCS5_PBKDF2_HMAC(user_credentials->password_hash, strlen(user_credentials->password_hash),
                      salt, SALT_LEN,
                      100000,
                      EVP_sha256(),
                      32, input_password_hash);
    
    if(memcmp(stored_user.password_hash, input_password_hash, 32) != 0) {
        fprintf(stderr, "Incorrect password!\n");
        fclose(file);
        return -1;
    }

    uint16_t total;
    if(fread(&total, sizeof(total), 1, file) != 1) {
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
    strcpy(user.password_hash, password);
    int16_t total = check_header(&user);

    if(total == -1) {
        fprintf(stderr, "Error while checking User Credentials!\n");
        return 1;
    }
    
    printf("User authentication successful!!\n");
    printf("Count: %d\n", total);
    return 0;
}

void report_error_and_suggest_issue_report() {
    fprintf(stderr, "An unexpected error occurred. Please report this issue at: " GITHUB_ISSUES_URL "\n");
    fprintf(stderr, "When reporting, please include additional details like: steps to reproduce, expected vs. actual behavior, and/or your system details.\n");
}

int add_credential(int argc, char *argv[]) {
    User user;
    strcpy(user.username, argv[0]);
    char original_password[PASSWORD_MAX_LEN];
    strcpy(original_password, argv[1]);
    strcpy(user.password_hash, argv[1]);

    int16_t total = check_header(&user);
    if(total < 0) {
        fprintf(stderr, "User authentication failed!\n");
        return 1;
    }

    total++;

    FILE* file = fopen(filename, "rb+");
    if(file == NULL) {
        fprintf(stderr, "Error while opening file\n");
        return 1;
    }

    long total_position = 8 + SALT_LEN + sizeof(User);
    if(fseek(file, total_position, SEEK_SET) != 0) {
        fprintf(stderr, "Error during file positioning\n");
        fclose(file);
        return 1;
    }

    if(fwrite(&total, sizeof(total), 1, file) != 1) {
        fprintf(stderr, "Error while updating total\n");
        fclose(file);
        return 1;
    }
    
    fclose(file);

    Credential *credential = calloc(1, sizeof(Credential));
    if(!credential) {
        fprintf(stderr, "Memory allocation failed!\n");
        return 1;
    }
    
    if(strlen(argv[3]) >= ALIAS_MAX_LEN) {
        fprintf(stderr, "Alias too long! Max %d characters\n", ALIAS_MAX_LEN - 1);
        free(credential);
        return 1;
    }
    strcpy(credential->alias, argv[3]);
    
    if(strlen(argv[4]) >= CRED_PASSWORD_MAX_LEN) {
        fprintf(stderr, "Password too long! Max %d characters\n", CRED_PASSWORD_MAX_LEN - 1);
        free(credential);
        return 1;
    }
    strcpy(credential->password, argv[4]);

    if(strlen(argv[2]) >= WEBSITE_MAX_LEN) {
        fprintf(stderr, "Website too long! Max %d characters\n", WEBSITE_MAX_LEN - 1);
        free(credential);
        return 1;
    }
    strcpy(credential->website, argv[2]);

    file = fopen(filename, "rb");
    if(file == NULL) {
        fprintf(stderr, "Error opening file to read salt\n");
        free(credential);
        return 1;
    }
    
    unsigned char salt[SALT_LEN];
    if(fseek(file, 8, SEEK_SET) != 0) {
        fprintf(stderr, "Error seeking to salt\n");
        fclose(file);
        free(credential);
        return 1;
    }
    
    if(fread(salt, SALT_LEN, 1, file) != 1) {
        fprintf(stderr, "Error reading salt\n");
        fclose(file);
        free(credential);
        return 1;
    }
    fclose(file);

    unsigned char key[KEY_LEN];
    unsigned char iv[IV_LEN];
    derive_key(original_password, salt, key, iv);

    unsigned char ciphertext[sizeof(Credential) + 16];
    int ciphertext_len = encrypt_credential(credential, key, iv, ciphertext);
    
    if(ciphertext_len < 0) {
        fprintf(stderr, "Encryption failed!\n");
        free(credential);
        return 1;
    }

    if(ciphertext_len > ENCRYPTED_CRED_MAX_LEN) {
        fprintf(stderr, "Ciphertext length exceeds maximum limit!\n");
        report_error_and_suggest_issue_report();
        free(credential);
        return 1;
    }

    EncryptedCredential encrypted_cred;
    memset(&encrypted_cred, 0, sizeof(EncryptedCredential));
    encrypted_cred.deleted = 0;
    encrypted_cred.credential_len = ciphertext_len;
    memcpy(encrypted_cred.credential, ciphertext, ciphertext_len);

    file = fopen(filename, "ab");
    if(file == NULL) {
        fprintf(stderr, "Error opening file for appending\n");
        free(credential);
        return 1;
    }
    
    if(fwrite(&encrypted_cred, sizeof(EncryptedCredential), 1, file) != 1) {
        fprintf(stderr, "Error writing encrypted credential\n");
        fclose(file);
        free(credential);
        return 1;
    }

    free(credential);
    fclose(file);
    
    memset(key, 0, KEY_LEN);
    memset(iv, 0, IV_LEN);
    memset(original_password, 0, PASSWORD_MAX_LEN);
    
    return 0;
}

int get_credential(int argc, char *argv[]) {
    User user;
    strcpy(user.username, argv[0]);
    
    char original_password[PASSWORD_MAX_LEN];
    strcpy(original_password, argv[1]);
    strcpy(user.password_hash, argv[1]);
    
    int16_t total = check_header(&user);
    if(total < 0) {
        fprintf(stderr, "User authentication failed!\n");
        memset(original_password, 0, PASSWORD_MAX_LEN);
        return 1;
    }

    if(total == 0) {
        fprintf(stderr, "No records present!\n");
        memset(original_password, 0, PASSWORD_MAX_LEN);
        return 1;
    }

    FILE *file = fopen(filename, "rb");
    if(file == NULL) {
        fprintf(stderr, "Error while opening file!\n");
        memset(original_password, 0, PASSWORD_MAX_LEN);
        return 1;
    }

    unsigned char salt[SALT_LEN];
    if(fseek(file, 8, SEEK_SET) != 0) {
        fprintf(stderr, "Error seeking to salt\n");
        fclose(file);
        memset(original_password, 0, PASSWORD_MAX_LEN);
        return 1;
    }
    
    if(fread(salt, SALT_LEN, 1, file) != 1) {
        fprintf(stderr, "Error reading salt\n");
        fclose(file);
        memset(original_password, 0, PASSWORD_MAX_LEN);
        return 1;
    }

    unsigned char key[KEY_LEN];
    unsigned char iv[IV_LEN];
    derive_key(original_password, salt, key, iv);

    if(fseek(file, sizeof(Header), SEEK_SET) != 0) {
        fprintf(stderr, "Error seeking to credentials\n");
        fclose(file);
        memset(key, 0, KEY_LEN);
        memset(iv, 0, IV_LEN);
        memset(original_password, 0, PASSWORD_MAX_LEN);
        return 1;
    }

    int8_t found = 0;
    
    for(int i = 0; i < total; i++) {
        EncryptedCredential encrypted_cred;
        if(fread(&encrypted_cred, sizeof(EncryptedCredential), 1, file) != 1) {
            fprintf(stderr, "Error reading encrypted credential at position %d!\n", i);
            fclose(file);
            memset(key, 0, KEY_LEN);
            memset(iv, 0, IV_LEN);
            memset(original_password, 0, PASSWORD_MAX_LEN);
            return 1;
        }

        if(encrypted_cred.deleted != 0) {
            continue;
        }

        if(encrypted_cred.credential_len <= 0 || encrypted_cred.credential_len > ENCRYPTED_CRED_MAX_LEN) {
            fprintf(stderr, "Invalid credential length: %d\n", encrypted_cred.credential_len);
            fclose(file);
            memset(key, 0, KEY_LEN);
            memset(iv, 0, IV_LEN);
            memset(original_password, 0, PASSWORD_MAX_LEN);
            return 1;
        }

        Credential current_credential;
        memset(&current_credential, 0, sizeof(Credential));
        
        int plaintext_len = decrypt_credential(encrypted_cred.credential, encrypted_cred.credential_len, 
                                               key, iv, &current_credential);
        
        if(plaintext_len < 0) {
            fprintf(stderr, "Decryption failed at position %d!\n", i);
            fclose(file);
            memset(key, 0, KEY_LEN);
            memset(iv, 0, IV_LEN);
            memset(original_password, 0, PASSWORD_MAX_LEN);
            return 1;
        }
        
        if(strcmp(current_credential.website, argv[2]) == 0) {
            found = 1;
            printf("\nAlias: %s\n", current_credential.alias);
            printf("Password: %s\n", current_credential.password);
            printf("Website: %s\n", current_credential.website);
        }
        
        memset(&current_credential, 0, sizeof(Credential));
    }

    if(!found) {
        printf("No record found for website: %s\n", argv[2]);
    }

    fclose(file);
    memset(key, 0, KEY_LEN);
    memset(iv, 0, IV_LEN);
    memset(original_password, 0, PASSWORD_MAX_LEN);
    
    return 0;
}

int list_credentials(int argc, char *argv[]) {
    User user;
    strcpy(user.username, argv[0]);
    char input_password[PASSWORD_MAX_LEN];
    strcpy(input_password, argv[1]);
    strcpy(user.password_hash, argv[1]);

    int16_t total = check_header(&user);
    if(total < 0) {
        fprintf(stderr, "User authentication failed!\n");
        memset(input_password, 0, PASSWORD_MAX_LEN);
        return 1;
    }

    if(total == 0) {
        fprintf(stderr, "No records present!\n");
        memset(input_password, 0, PASSWORD_MAX_LEN);
        return 1;
    }

    FILE *file = fopen(filename, "rb");

    if(file == NULL) {
        fprintf(stderr, "Error while opening file!\n");
        memset(input_password, 0, PASSWORD_MAX_LEN);
        return 1;
    }

    unsigned char salt[SALT_LEN];
    if(fseek(file, 8, SEEK_SET) != 0) {
        fprintf(stderr, "Error seeking to salt\n");
        fclose(file);
        memset(input_password, 0, PASSWORD_MAX_LEN);
        return 1;
    }

    if(fread(salt, SALT_LEN, 1, file) != 1) {
        fprintf(stderr, "Error reading salt\n");
        fclose(file);
        memset(input_password, 0, PASSWORD_MAX_LEN);
        return 1;
    }

    unsigned char key[KEY_LEN];
    unsigned char iv[IV_LEN];
    derive_key(input_password, salt, key, iv);

    if(fseek(file, sizeof(Header), SEEK_SET) != 0) {
        fprintf(stderr, "Error seeking to credentials\n");
        fclose(file);
        memset(key, 0, KEY_LEN);
        memset(iv, 0, IV_LEN);
        memset(input_password, 0, PASSWORD_MAX_LEN);
        return 1;
    }

    for(int i = 0, record = 0; i < total; i++) {
        EncryptedCredential encrypted_cred;
        if(fread(&encrypted_cred, sizeof(EncryptedCredential), 1, file) != 1) {
            fprintf(stderr, "Error reading encrypted credential at position %d!\n", i);
            fclose(file);
            memset(key, 0, KEY_LEN);
            memset(iv, 0, IV_LEN);
            memset(input_password, 0, PASSWORD_MAX_LEN);
            return 1;
        }

        if(encrypted_cred.deleted != 0) {
            continue;
        }

        if(encrypted_cred.credential_len <= 0 || encrypted_cred.credential_len > ENCRYPTED_CRED_MAX_LEN) {
            fprintf(stderr, "Invalid credential length: %d\n", encrypted_cred.credential_len);
            fclose(file);
            memset(key, 0, KEY_LEN);
            memset(iv, 0, IV_LEN);
            memset(input_password, 0, PASSWORD_MAX_LEN);
            return 1;
        }

        Credential current_credential;
        memset(&current_credential, 0, sizeof(Credential));

        int plaintext_len = decrypt_credential(encrypted_cred.credential, encrypted_cred.credential_len,
                                               key, iv, &current_credential);

        if(plaintext_len < 0) {
            fprintf(stderr, "Decryption failed at position %d!\n", i);
            fclose(file);
            memset(key, 0, KEY_LEN);
            memset(iv, 0, IV_LEN);
            memset(input_password, 0, PASSWORD_MAX_LEN);
            return 1;
        }
        record++;
        printf("\nRecord %d:\n", record);
        printf("Alias: %s\n", current_credential.alias);
        printf("Website: %s\n", current_credential.website);
        printf("Password: %s\n", current_credential.password);

        memset(&current_credential, 0, sizeof(Credential));
    }

    fclose(file);
    memset(key, 0, KEY_LEN);
    memset(iv, 0, IV_LEN);
    memset(input_password, 0, PASSWORD_MAX_LEN);
    return 0;
}

int delete_credential(int argc, char *argv[]) {
    User user;
    strcpy(user.username, argv[0]);
    
    char original_password[PASSWORD_MAX_LEN];
    strcpy(original_password, argv[1]);
    strcpy(user.password_hash, argv[1]);
    
    int16_t total = check_header(&user);
    if(total < 0) {
        fprintf(stderr, "User authentication failed!\n");
        memset(original_password, 0, PASSWORD_MAX_LEN);
        return 1;
    }

    if(total == 0) {
        fprintf(stderr, "No records present!\n");
        memset(original_password, 0, PASSWORD_MAX_LEN);
        return 1;
    }

    FILE *file = fopen(filename, "rb+");
    if(file == NULL) {
        fprintf(stderr, "Error while opening file!\n");
        memset(original_password, 0, PASSWORD_MAX_LEN);
        return 1;
    }

    unsigned char salt[SALT_LEN];
    if(fseek(file, 8, SEEK_SET) != 0) {
        fprintf(stderr, "Error seeking to salt\n");
        fclose(file);
        memset(original_password, 0, PASSWORD_MAX_LEN);
        return 1;
    }
    
    if(fread(salt, SALT_LEN, 1, file) != 1) {
        fprintf(stderr, "Error reading salt\n");
        fclose(file);
        memset(original_password, 0, PASSWORD_MAX_LEN);
        return 1;
    }

    unsigned char key[KEY_LEN];
    unsigned char iv[IV_LEN];
    derive_key(original_password, salt, key, iv);

    if(fseek(file, sizeof(Header), SEEK_SET) != 0) {
        fprintf(stderr, "Error seeking to credentials\n");
        fclose(file);
        memset(key, 0, KEY_LEN);
        memset(iv, 0, IV_LEN);
        memset(original_password, 0, PASSWORD_MAX_LEN);
        return 1;
    }

    int8_t found = 0;
    
    for(int i = 0; i < total; i++) {
        long current_pos = ftell(file);
        EncryptedCredential encrypted_cred;
        if(fread(&encrypted_cred, sizeof(EncryptedCredential), 1, file) != 1) {
            fprintf(stderr, "Error reading encrypted credential at position %d!\n", i);
            fclose(file);
            memset(key, 0, KEY_LEN);
            memset(iv, 0, IV_LEN);
            memset(original_password, 0, PASSWORD_MAX_LEN);
            return 1;
        }

        if(encrypted_cred.deleted != 0) {
            continue;
        }

        if(encrypted_cred.credential_len <= 0 || encrypted_cred.credential_len > ENCRYPTED_CRED_MAX_LEN) {
            fprintf(stderr, "Invalid credential length: %d\n", encrypted_cred.credential_len);
            fclose(file);
            memset(key, 0, KEY_LEN);
            memset(iv, 0, IV_LEN);
            memset(original_password, 0, PASSWORD_MAX_LEN);
            return 1;
        }

        Credential current_credential;
        memset(&current_credential, 0, sizeof(Credential));
        
        int plaintext_len = decrypt_credential(encrypted_cred.credential, encrypted_cred.credential_len, 
                                               key, iv, &current_credential);
        
        if(plaintext_len < 0) {
            fprintf(stderr, "Decryption failed at position %d!\n", i);
            fclose(file);
            memset(key, 0, KEY_LEN);
            memset(iv, 0, IV_LEN);
            memset(original_password, 0, PASSWORD_MAX_LEN);
            return 1;
        }

        if(strcmp(current_credential.website, argv[2]) == 0) {
            found = 1;
            encrypted_cred.deleted = 1;
            if(fseek(file, current_pos, SEEK_SET) != 0) {
                fprintf(stderr, "Error seeking back to update credential\n");
                fclose(file);
                memset(key, 0, KEY_LEN);
                memset(iv, 0, IV_LEN);
                memset(original_password, 0, PASSWORD_MAX_LEN);
                return 1;
            }
            if(fwrite(&encrypted_cred, sizeof(EncryptedCredential), 1, file) != 1) {
                fprintf(stderr, "Error updating credential\n");
                fclose(file);
                memset(key, 0, KEY_LEN);
                memset(iv, 0, IV_LEN);
                memset(original_password, 0, PASSWORD_MAX_LEN);
                return 1;
            }
            printf("Credential for website %s marked as deleted.\n", argv[2]);
            break;
        }
        
        memset(&current_credential, 0, sizeof(Credential));
    }

    if(!found) {
        printf("No active record found for website: %s\n", argv[2]);
    }

    fclose(file);
    memset(key, 0, KEY_LEN);
    memset(iv, 0, IV_LEN);
    memset(original_password, 0, PASSWORD_MAX_LEN);
    
    return 0;
}

int update_credential(int argc, char *argv[]) {
    User user;
    strcpy(user.username, argv[0]);
    
    char original_password[PASSWORD_MAX_LEN];
    strcpy(original_password, argv[1]);
    strcpy(user.password_hash, argv[1]);
    
    int16_t total = check_header(&user);
    if(total < 0) {
        fprintf(stderr, "User authentication failed!\n");
        memset(original_password, 0, PASSWORD_MAX_LEN);
        return 1;
    }

    if(total == 0) {
        fprintf(stderr, "No records present!\n");
        memset(original_password, 0, PASSWORD_MAX_LEN);
        return 1;
    }
    
    if(strlen(argv[3]) >= ALIAS_MAX_LEN) {
        fprintf(stderr, "New alias too long! Max %d characters\n", ALIAS_MAX_LEN - 1);
        memset(original_password, 0, PASSWORD_MAX_LEN);
        return 1;
    }
    if(strlen(argv[4]) >= CRED_PASSWORD_MAX_LEN) {
        fprintf(stderr, "New password too long! Max %d characters\n", CRED_PASSWORD_MAX_LEN - 1);
        memset(original_password, 0, PASSWORD_MAX_LEN);
        return 1;
    }

    FILE *file = fopen(filename, "rb+");
    if(file == NULL) {
        fprintf(stderr, "Error while opening file!\n");
        memset(original_password, 0, PASSWORD_MAX_LEN);
        return 1;
    }

    unsigned char salt[SALT_LEN];
    if(fseek(file, 8, SEEK_SET) != 0) {
        fprintf(stderr, "Error seeking to salt\n");
        fclose(file);
        memset(original_password, 0, PASSWORD_MAX_LEN);
        return 1;
    }
    
    if(fread(salt, SALT_LEN, 1, file) != 1) {
        fprintf(stderr, "Error reading salt\n");
        fclose(file);
        memset(original_password, 0, PASSWORD_MAX_LEN);
        return 1;
    }

    unsigned char key[KEY_LEN];
    unsigned char iv[IV_LEN];
    derive_key(original_password, salt, key, iv);

    if(fseek(file, sizeof(Header), SEEK_SET) != 0) {
        fprintf(stderr, "Error seeking to credentials\n");
        fclose(file);
        memset(key, 0, KEY_LEN);
        memset(iv, 0, IV_LEN);
        memset(original_password, 0, PASSWORD_MAX_LEN);
        return 1;
    }

    int8_t found = 0;
    
    for(int i = 0; i < total; i++) {
        long current_pos = ftell(file);
        EncryptedCredential encrypted_cred;
        if(fread(&encrypted_cred, sizeof(EncryptedCredential), 1, file) != 1) {
            fprintf(stderr, "Error reading encrypted credential at position %d!\n", i);
            fclose(file);
            memset(key, 0, KEY_LEN);
            memset(iv, 0, IV_LEN);
            memset(original_password, 0, PASSWORD_MAX_LEN);
            return 1;
        }

        if(encrypted_cred.deleted != 0) {
            continue;
        }

        if(encrypted_cred.credential_len <= 0 || encrypted_cred.credential_len > ENCRYPTED_CRED_MAX_LEN) {
            fprintf(stderr, "Invalid credential length: %d\n", encrypted_cred.credential_len);
            fclose(file);
            memset(key, 0, KEY_LEN);
            memset(iv, 0, IV_LEN);
            memset(original_password, 0, PASSWORD_MAX_LEN);
            return 1;
        }

        Credential current_credential;
        memset(&current_credential, 0, sizeof(Credential));
        
        int plaintext_len = decrypt_credential(encrypted_cred.credential, encrypted_cred.credential_len, 
                                               key, iv, &current_credential);
        
        if(plaintext_len < 0) {
            fprintf(stderr, "Decryption failed at position %d!\n", i);
            fclose(file);
            memset(key, 0, KEY_LEN);
            memset(iv, 0, IV_LEN);
            memset(original_password, 0, PASSWORD_MAX_LEN);
            return 1;
        }

        if(strcmp(current_credential.website, argv[2]) == 0) {
            found = 1;
            strcpy(current_credential.alias, argv[3]);
            strcpy(current_credential.password, argv[4]);

            unsigned char new_ciphertext[sizeof(Credential) + 16];
            int new_ciphertext_len = encrypt_credential(&current_credential, key, iv, new_ciphertext);
            
            if(new_ciphertext_len < 0) {
                fprintf(stderr, "Re-encryption failed!\n");
                fclose(file);
                memset(key, 0, KEY_LEN);
                memset(iv, 0, IV_LEN);
                memset(original_password, 0, PASSWORD_MAX_LEN);
                return 1;
            }

            if(new_ciphertext_len > ENCRYPTED_CRED_MAX_LEN) {
                fprintf(stderr, "Updated credential too large!\n");
                fclose(file);
                memset(key, 0, KEY_LEN);
                memset(iv, 0, IV_LEN);
                memset(original_password, 0, PASSWORD_MAX_LEN);
                return 1;
            }

            encrypted_cred.credential_len = new_ciphertext_len;
            memcpy(encrypted_cred.credential, new_ciphertext, new_ciphertext_len);
            memset(encrypted_cred.credential + new_ciphertext_len, 0, ENCRYPTED_CRED_MAX_LEN - new_ciphertext_len);

            if(fseek(file, current_pos, SEEK_SET) != 0) {
                fprintf(stderr, "Error seeking back to update credential\n");
                fclose(file);
                memset(key, 0, KEY_LEN);
                memset(iv, 0, IV_LEN);
                memset(original_password, 0, PASSWORD_MAX_LEN);
                return 1;
            }
            if(fwrite(&encrypted_cred, sizeof(EncryptedCredential), 1, file) != 1) {
                fprintf(stderr, "Error updating credential\n");
                fclose(file);
                memset(key, 0, KEY_LEN);
                memset(iv, 0, IV_LEN);
                memset(original_password, 0, PASSWORD_MAX_LEN);
                return 1;
            }
            printf("Credential for website %s updated.\n", argv[2]);
            break;
        }
        
        memset(&current_credential, 0, sizeof(Credential));
    }

    if(!found) {
        printf("No active record found for website: %s\n", argv[2]);
    }

    fclose(file);
    memset(key, 0, KEY_LEN);
    memset(iv, 0, IV_LEN);
    memset(original_password, 0, PASSWORD_MAX_LEN);
    
    return 0;
}

void print_usage() {
    printf("Password Manager Version: %s\n", VER_PRODUCT_VERSION_STR);
    printf("Usage:\n");
    printf("\thelp                                                                          : Show this help message\n");
    printf("\tcreate <username>                                                             : Create a new password manager file\n");
    printf("\tread <username> <master-password>                                             : Read the count of stored credentials\n");
    printf("\tadd <username> <master-password> <website> <alias/username> <cred_password>   : Add a new credential\n");
    printf("\tget <username> <master-password> <website>                                    : Get credential for a website\n");
    printf("\tdelete <username> <master-password> <website>                                 : Delete credential for a website\n");
    printf("\tupdate <username> <master-password> <website> <new_alias> <new_password>      : Update credential for a website\n");
    printf("\tversion                                                                       : Show version information\n");
}

int get_password(char *password) {
    int len;
    
#ifdef _WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD oldMode;

    if (!GetConsoleMode(hStdin, &oldMode)) {
        return -1;
    }

    if(!SetConsoleMode(hStdin, oldMode & ~ENABLE_ECHO_INPUT)) {
        return -1;
    }

    if(!fgets(password, PASSWORD_MAX_LEN, stdin)) {
        SetConsoleMode(hStdin, oldMode);
        return -1;
    }

    SetConsoleMode(hStdin, oldMode);

    len = (int)strlen(password);

#elif
    struct  termios
        attr, old;

    if (tcgetattr(STDIN_FILENO, &old) != 0) {
        return -1;
    }
    attr = old;
    attr.c_lflag &= ~ECHO;
    attr.c_lflag |= ICANON;

    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &attr) != 0) {
        return -1;
    }

    len = read(STDIN_FILENO, password, PASSWORD_MAX_LEN-1);

    if (tcsetattr(STDIN_FILENO, TCSANOW, &old) != 0) {
        return -1;
    }
#endif
    if (len > 0 && password[len-1]!='\0') {
        password[len-1]='\0';
        len--;
    }
    return len;
}

int verify_password(char *orgPassword, int orgPasswordLen) {
    char password[PASSWORD_MAX_LEN];
    int len;

    printf("Retype Password: ");
    fflush(stdout);

    len = get_password(password);
    if (len < 0)
        return -1;

    if (len != orgPasswordLen)
        return 1;

    return abs(strcmp(orgPassword, password));
}

int main(int argc, char *argv[]) {

    if(argc < 2) {
        fprintf(stderr, "Invalid command\n");
        fprintf(stderr, "See help\n");
        return 1;
    }

    if(strcmp(argv[1], "help") == 0) {
        print_usage();
        return 0;
    }

    if(strcmp(argv[1], "create") == 0) {
        if(argc != 3) {
            fprintf(stderr, "Enter all arugments for create command\n");
            fprintf(stderr, "See help\n");
            return 1;
        }

        char password[PASSWORD_MAX_LEN];

        printf("Enter Password: ");
        (void)fflush(stdout);
        int len = get_password(password);

        if(len < 0) {
            fprintf(stderr, "Error while Capturing Password\n");
            return 1;
        }
        
        int res = verify_password(password, len);
        if(res<0) {
            fprintf(stderr, "Error while Retyping Password!\n");
            return 1;
        }

        if(res>0) {
            fprintf(stderr, "Retyped Password is different!\n");
            printf("Try Again. Password and Retyped Password should be same.\n");
            return 1;
        }
        
        if(create_new_file(argv[2], password)) {
           fprintf(stderr, "Error creating file!\n");
           return 1; 
        }
        printf("File created!!\n");
        return 0;
    }

    if(strcmp(argv[1], "read") == 0) {
        if(argc != 4) {
            fprintf(stderr, "Enter all arugments for read command\n");
            fprintf(stderr, "See help\n");
            return 1;
        }
        if(read_count(argv[2], argv[3])) {
            fprintf(stderr, "Error while reading the file!\n");
            return 1;
        }
        return 0;
    }

    if(strcmp(argv[1], "add") == 0) { // add <username> <password> <website> <alias> <password>
        if(argc != 7) {
            fprintf(stderr, "Enter all arugments for read command\n");
            fprintf(stderr, "See help\n");
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
            fprintf(stderr, "See help\n");
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

    if(strcmp(argv[1], "list") == 0) {
        if(argc != 4) {
            fprintf(stderr, "Enter all arugments for read command\n");
            fprintf(stderr, "See help\n");
            return 1;
        }
        printf("Listing all records...\n");
        printf("-----------------------------\n");
        if(list_credentials(argc-2, argv+2)) {
            fprintf(stderr, "Error while listing the credentials\n");
            return 1;
        }
        printf("-----------------------------\n");
        return 0;
    }
    if(strcmp(argv[1], "delete") == 0) { // delete <username> <password> <website>
        if(argc != 5) {
            fprintf(stderr, "Enter all arguments for delete command\n");
            fprintf(stderr, "See help\n");
            return 1;
        }
        printf("Deleting credential...\n");
        printf("-----------------------------\n");
        if(delete_credential(argc-2, argv+2)) {
            fprintf(stderr, "Error while deleting the credential\n");
            return 1;
        }
        printf("-----------------------------\n");
        return 0;
    }
    if(strcmp(argv[1], "update") == 0) { // update <username> <password> <website> <new_alias> <new_password>
        if(argc != 7) {
            fprintf(stderr, "Enter all arguments for update command\n");
            fprintf(stderr, "See help\n");
            return 1;
        }
        printf("Updating credential...\n");
        printf("-----------------------------\n");
        if(update_credential(argc-2, argv+2)) {
            fprintf(stderr, "Error while updating the credential\n");
            return 1;
        }
        printf("-----------------------------\n");
        return 0;
    }
    if(strcmp(argv[1], "generate") == 0) {
        fprintf(stderr, "Generate command not implemented yet\n");
        return 1;
    }
 
    if(strcmp(argv[1], "version") == 0) {
        printf("Password Manager Version: %s\n", VER_PRODUCT_VERSION_STR);
        return 0;
    }
    
    fprintf(stderr, "Invalid command\n");
    fprintf(stderr, "See help\n");

    return 1;
}

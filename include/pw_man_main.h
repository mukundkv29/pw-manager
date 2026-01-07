#ifndef PW_MAN_MAIN_H
#define PW_MAN_MAIN_H

#include <stdint.h>

#define SALT_LEN 16
#define KEY_LEN 32
#define IV_LEN 16

#define USERNAME_MAX_LEN 16
#define PASSWORD_MAX_LEN 32

#define ALIAS_MAX_LEN 64
#define CRED_PASSWORD_MAX_LEN 128
#define WEBSITE_MAX_LEN 256

#define ENCRYPTED_CRED_MAX_LEN 512

#define GITHUB_ISSUES_URL "<https://https://github.com/mukundkv29/pw-manager/issues>"

static const char* filename = "bfile.bin";
static const char* anchor_string_version = "_PW0_";

typedef struct {
    char username[USERNAME_MAX_LEN];
    unsigned char password_hash[PASSWORD_MAX_LEN];
} User;

typedef struct {
    char alias[ALIAS_MAX_LEN];
    char password[CRED_PASSWORD_MAX_LEN];
    char website[WEBSITE_MAX_LEN];
} Credential;

typedef struct {
    char deleted;
    int credential_len;
    unsigned char credential[ENCRYPTED_CRED_MAX_LEN];
} EncryptedCredential;

typedef struct {
    char anchor_string[8];
    unsigned char salt[SALT_LEN];
    User user;
    uint16_t total_credentials;
} Header;

#endif
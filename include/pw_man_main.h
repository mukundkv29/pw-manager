#pragma once
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#define USERNAME_MAX_LEN 16
#define PASSWORD_MAX_LEN 16
#define CREDENTIAL_ALIAS_MAX_LEN 16
#define CREDENTIAL_PASSWORD_MAX_LEN 32 
#define CREDENTIAL_WEBSITE_MAX_LEN 32
#define SALT_LEN 16
#define KEY_LEN 32
#define IV_LEN 16

const char anchor_string_version[8] = "_PW0_";

typedef struct
{
    char username[USERNAME_MAX_LEN];
    char password[PASSWORD_MAX_LEN];
} User;

typedef struct {
    char anchor_string[8];
    unsigned char salt[SALT_LEN];
    User user;
    uint16_t total_credentials;
} Header;

typedef struct {
    char alias[CREDENTIAL_ALIAS_MAX_LEN];
    char password[CREDENTIAL_PASSWORD_MAX_LEN];
    char website[CREDENTIAL_WEBSITE_MAX_LEN];
} Credential;

const char filename[] = "bfile.bin";

void derive_key(const char *password, const unsigned char *salt, 
                unsigned char *key, unsigned char *iv);
int encrypt_credential(Credential *cred, unsigned char *key, 
                      unsigned char *iv, unsigned char *ciphertext);
int decrypt_credential(unsigned char *ciphertext, int ciphertext_len,
                      unsigned char *key, unsigned char *iv, Credential *cred);
#ifndef PW_MAN_MAIN_H
#define PW_MAN_MAIN_H

#include <stdint.h>

#define SALT_LEN 16
#define KEY_LEN 32
#define IV_LEN 16

#define USERNAME_MAX_LEN 64
#define PASSWORD_MAX_LEN 128

#define ALIAS_MAX_LEN 64
#define CRED_PASSWORD_MAX_LEN 128
#define WEBSITE_MAX_LEN 256

static const char* filename = "bfile.bin";
static const char* anchor_string_version = "_PW0_";

typedef struct {
    char username[USERNAME_MAX_LEN];
    char password[PASSWORD_MAX_LEN];
} User;

typedef struct {
    char alias[ALIAS_MAX_LEN];
    char password[CRED_PASSWORD_MAX_LEN];
    char website[WEBSITE_MAX_LEN];
} Credential;

typedef struct {
    char anchor_string[8];
    unsigned char salt[SALT_LEN];
    User user;
    uint16_t total_credentials;
} Header;

#endif
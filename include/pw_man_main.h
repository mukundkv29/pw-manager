#pragma once

#define USERNAME_MAX_LEN 16
#define PASSWORD_MAX_LEN 16
#define CREDENTIAL_ALIAS_MAX_LEN 16
#define CREDENTIAL_PASSWORD_MAX_LEN 32
#define CREDENTIAL_WEBSITE_MAX_LEN 32

const char anchor_string_version[8] = "_PW0_";
typedef struct
{
    char username[USERNAME_MAX_LEN];
    char password[PASSWORD_MAX_LEN];
} User;

typedef struct {
    char anchor_string[8];
    User user;
    uint16_t total_credentials;
} Header;

typedef struct {
    char alias[CREDENTIAL_ALIAS_MAX_LEN];
    char password[CREDENTIAL_PASSWORD_MAX_LEN];
    char website[CREDENTIAL_WEBSITE_MAX_LEN];
} Credential;

const char filename[] = "bfile.bin";

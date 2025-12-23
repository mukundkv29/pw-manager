#pragma once

#define USERNAME_MAX_LEN 16
#define PASSWORD_MAX_LEN 16

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
    char name[64];
    char alias[128];
    char password[128];
} Credential;

const char filename[] = "bfile.bin";


#pragma once

const int USERNAME_MAX_LEN = 20;
const int PASSWORD_MAX_LEN = 20;

typedef struct
{
    char username[USERNAME_MAX_LEN];
    char password[PASSWORD_MAX_LEN];
} User;

const char filename[] = "bfile.bin";

const char anchor_string_version[8] = "_PW0_";

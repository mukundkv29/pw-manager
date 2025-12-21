#include <stdio.h>
#include <string.h>

const int USERNAME_MAX_LEN = 20;
const int PASSWORD_MAX_LEN = 20;

typedef struct
{
    char username[USERNAME_MAX_LEN];
    char password[PASSWORD_MAX_LEN];
} User;

const char filename[] = "bfile.bin";

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

// username 20 bytes
// password 20 bytes

int create_new_file(char *username, char *password) {

    printf("------------------------------");
    printf("\nCreating file...\n");
    printf("Entered Username: %s\n", username);
    if(strlen(username) > 20) {
        fprintf(stderr, "Too long username! Length should be less than 20!\n");
        printf("------------------------------\n");
        return 1;
    }
    printf("Entered Password: %s\n", password);
    if(strlen(password) > 20) {
        fprintf(stderr, "Too long password! Length should be less than 20!\n");
        printf("------------------------------\n");
        return 1;
    }
    printf("------------------------------\n");
    User user;
    strncpy(user.username, username, USERNAME_MAX_LEN);
    strncpy(user.password, password, PASSWORD_MAX_LEN);
    FILE* file;
    file = fopen(filename, "wb");

    if (file == NULL) {
        fprintf(stderr, "Error creating file!\n");
        return 1;
    }

    char anchor_string[8] = "_PW0_";

    if (
        fwrite(anchor_string, sizeof(anchor_string), 1, file) != 1
    ) {
        fprintf(stderr, "Error adding Achor string\n");
        return 1;
    }

    if (
        fwrite(user.username, sizeof(user.username), 1, file) !=1 ||
        fwrite(user.password, sizeof(user.password), 1, file) !=1
    ) {
        fprintf(stderr, "Error adding username and password\n");
        return 1;
    }

    return 0;
}

int main(int argc, char *argv[]) {

    if(argc < 2) {
        return 1;
    }

    if(argc < 4 && strcmp(argv[1], "create") == 0) {
        fprintf(stderr, "Enter all arugments for create command\n");
        fprintf(stderr, "See --help\n");
        return 1;
    }
    
    if(argc == 4 && !create_new_file(argv[2], argv[3])) {
        printf("File created!!\n");
        return 0;
    }
    fprintf(stderr, "Enter all arugments\n");
    fprintf(stderr, "See --help\n");

    return 1;
}

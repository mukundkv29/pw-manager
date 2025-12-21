#include <stdio.h>
#include <string.h>

#include "include/pw_man_main.h"

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

    if (
        fwrite(anchor_string_version, sizeof(anchor_string_version), 1, file) != 1
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

    int total = 1;

    if(
        fwrite(&total, sizeof(int), 1, file) != 1
    ) {
        fprintf(stderr, "Error adding total number of entries in file\n");
        return 1;
    }

    fclose(file);

    return 0;
}


int read_count(char *username, char* password) {
    FILE *file;
    file = fopen(filename, "rb");

    if (file == NULL)
        return 1;
    
    char anchor_string[8];
    if (
        fread(anchor_string, sizeof(anchor_string), 1, file) != 1
    ) {
        fprintf(stderr, "Anchor string not found!\n");
        return 1;
    }

    if(strcmp(anchor_string, anchor_string_version)) {
        fprintf(stderr, "Mismatched Anchor String\n");
        return 1;
    }
    
    User user;

    if(
        fread(user.username, sizeof(user.username), 1, file)!=1 ||
        fread(user.password, sizeof(user.password), 1, file)!=1
    ) {
        fprintf(stderr, "Error fetching user credentials!\n");
        return 1;
    }

    if(
        strcmp(user.username, username) ||
        strcmp(user.password, password)
    ) {
        fprintf(stderr, "Invalid username and/or password!\n");
        return 1;
    }

    int total;

    if(
        fread(&total, sizeof(int), 1, file)!=1
    ) {
        fprintf(stderr, "Error fetching the entries count\n");
        return 1;
    }

    printf("%d Entities count fetched!!\n", total);

    return 0;
}

int main(int argc, char *argv[]) {

    if(argc < 2) {
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
    
    fprintf(stderr, "Invalid command\n");
    fprintf(stderr, "See --help\n");

    return 1;
}

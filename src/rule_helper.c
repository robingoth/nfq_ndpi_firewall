#include <stdio.h>
#include <stdlib.h>
#include <string.h>

 /*
  * checks if a string array contains a specified string
  * IMPORTANT: last element of the string array must be NULL
  */
int is_blacklisted(char *string, char **blacklist)
{
    int i = 0;
    while (blacklist[i] != NULL) {
	if (!strcmp(string, blacklist[i])) {
	    return 1;
	}
	i++;
    }
    return 0;
}

/*
 * checks if string consists of -_0..9 a..z A..Z only
 */
int is_proto_name_valid(char *name)
{
    int result;
    int i = 0;
    for (i = 0; i < strlen(name); i++) {
	if ((name[i] >= 48 && name[i] <= 57) ||
		(name[i] >= 65 && name[i] <= 90) ||
		(name[i] >= 97 && name[i] <= 122) ||
		name[i] == 45 || name[i] == 95) {
	    result = 1;
	} else {
	    return 0;
	}
    }

    return result;
}

/*
 *  read the list of blacklisted protocols from file
 *  
 *  Inputs: 
 *      fileapth - path to file
 *  Return values:
 *      array of protocol names if successfull
 *      NULL in case of error
 */
char **get_blacklist(char *filepath)
{
    char **result = NULL;
    char **result_tmp = NULL;
    FILE *fp;
    char current_line[256];

    fp = fopen(filepath, "r");
    if (fp == NULL) {
	printf("Could not open the file %s\n", filepath);
	return NULL;
    }

    int line_num = 0;
    while (fgets(current_line, sizeof(current_line), fp)) {
	current_line[strlen(current_line) - 1] = '\0';

	if (!is_proto_name_valid(current_line)) {
	    printf("Protocol name %s is invalid.\n", current_line);
	} else {
	    result_tmp = (char **)realloc(result, (line_num + 1) * sizeof(char *));

	    if(result_tmp != NULL) {
		result = result_tmp;
		result[line_num] = malloc(sizeof(char) * strlen(current_line));
		strcpy(result[line_num], current_line);
	    } else {
		printf("Memory could not be reallocated.\n");
		return NULL;
	    }

	    line_num++;
	}
    }

    fclose(fp);

    result_tmp = (char **)realloc(result, (line_num) * sizeof(char *));
    if (result_tmp != NULL) {
	result = result_tmp;

	result[line_num] = NULL;
    } else {
	printf("Memory could not be reallocated.\n");
	return NULL;
    }

    return result;
}

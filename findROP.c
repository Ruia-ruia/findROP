#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

#define BASE16 16
#define BASE10 10
#define MAX_STRLEN 30

struct ProcMap {
	long int address_st;
	long int address_en;
  	long int size;
	char *permissions;
	struct ProcMap *next;
};
struct ProcMap *pm_head = NULL;

int link_procmap(struct ProcMap *pm) {
    
	if (pm == NULL) return -1;

	if (pm_head == NULL) {
		pm_head = pm;
	} else {
		pm->next = pm_head;
		pm_head = pm;
	}

	return 0;
}

void get_data(const char *curr_line, const size_t line_len, struct ProcMap *pm) {

	char start_addr[MAX_STRLEN];
	char end_addr[MAX_STRLEN];
	char perms[MAX_STRLEN];
	long int address_st;
	long int address_en;
	unsigned int i, j, k;

	//start address
	for (i = 0; curr_line[i] != '-'; i++) {
		start_addr[i] = curr_line[i];

	} if (i > MAX_STRLEN) return;
	start_addr[i] = '\0';

	//end address
	for (j = i + 1, k = 0; curr_line[j] != ' '; j++) {
		end_addr[k] = curr_line[j];
		k++;

	} if (k > MAX_STRLEN) return;
	end_addr[k + 1] = '\0';

	//permissions
	for (j = k + 1, k = 0; curr_line[j] != ' '; j++) {
		perms[k] = curr_line[j];
		k++;

	} if (k > MAX_STRLEN) return;
	perms[k + 1] = '\0';

	address_st = strtol(start_addr, NULL, BASE16);
	address_en = strtol(end_addr, NULL, BASE16);

	if (address_st == 0 || address_en == 0) {
		if (errno == EINVAL) {
			printf("Could not convert addresses in maps file.\n");
			return;
		}
	}

	pm->address_st = address_st;
	pm->address_en = address_en;
	pm->size = address_en - address_st;
    	pm->permissions = perms;

}

void read_mapfile(FILE *fd) {

	char *curr_line;
	size_t line_len;
	struct ProcMap *pm;

	//use heap for linked list nodes
	while (getline(&curr_line, &line_len, fd) != -1) {

		pm = malloc(sizeof(struct ProcMap));
		get_data(curr_line, line_len, pm);
        	//performs NULL test on pm as well 
		if (link_procmap(pm) < 0) continue; 

		printf("0x%lx\n0x%lx\n0x%lx\n\n", pm->address_st, pm->address_en, pm->size);
	}
}

int prep_mapfile(const long pid) {

	char filename[MAX_STRLEN];
	FILE *fd;

	if (snprintf(filename, MAX_STRLEN, "/proc/%ld/maps", pid) < 0) {
		return -1;
	}

	fd = fopen(filename, "r");
	if (fd == NULL) {
		printf("Could not open file.\n");
		return -1;
	}

	read_mapfile(fd);

	fclose(fd);
	return 0;
}

int main(int argc, char *argv[]) {

	if (argc < 2) {
		printf("Not enough arguments.\n");
		return -1;
	}

	pid_t pid;

	//parse pid
	pid = strtol(argv[1], NULL, BASE10);
	if (pid == 0) {
	    if (errno == EINVAL) {
		printf("Invalid process identifier. \
		   Specifically, %d.\n", errno);
			    return -1;
            }
	}

	prep_mapfile(pid);

	return 0;
}

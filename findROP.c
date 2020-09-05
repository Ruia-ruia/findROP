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
#define BAD_WORD 0xffffffffffffffff

enum { R, RW, RX, RWX };

struct ProcMap {
        long int pid;
        long int address_st;
        long int address_en;
        long int size;
        char *permissions;
        struct ProcMap *next;
};
struct ProcMap *pm_head;
struct ProcMap *pm_cursor;

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

void get_data(const char *curr_line, 
                    const size_t line_len, 
                            struct ProcMap *pm, 
                                    const long pid) {

        char start_addr[MAX_STRLEN];
        char end_addr[MAX_STRLEN];
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
        char *perms = malloc(MAX_STRLEN);
        for (j = j + 1, k = 0; curr_line[j] != ' '; j++) {
                perms[k] = curr_line[j];
                k++;

        } if (k > MAX_STRLEN) return;
        perms[k] = '\0';

        address_st = strtol(start_addr, NULL, BASE16);
        address_en = strtol(end_addr, NULL, BASE16);

        if (address_st == 0 || address_en == 0) {
                if (errno == EINVAL) {
                        printf("Could not convert addresses in maps file.\n");
                        return;
                }
        }

        pm->pid = pid;
        pm->address_st = address_st;
        pm->address_en = address_en;
        pm->size = address_en - address_st;
        pm->permissions = perms;   
}

void read_mapfile(FILE *fd, const long pid) {

        char *curr_line;
        size_t line_len;
        struct ProcMap *pm;

        //use heap for linked list nodes
        while (getline(&curr_line, &line_len, fd) != -1) {

                pm = malloc(sizeof(struct ProcMap));
                get_data(curr_line, line_len, pm, pid);
                //performs NULL test on pm as well 
                if (link_procmap(pm) < 0) continue; 

        }

        //initialise global cursor to start at head of list
        pm_cursor = pm_head;
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

        read_mapfile(fd, pid);

        fclose(fd);
        return 0;
}

void read_proc(struct ProcMap *pm) {

        printf("Entered proc_map\n");
        long int curr_word;

        for (int i = 0; i < pm->size;  i += 8) {
                curr_word = ptrace(PTRACE_PEEKTEXT, pm->pid, pm->address_st + i, NULL);
                if (curr_word == BAD_WORD) return;
                printf("0x%lx\n", curr_word);
        }

        //ptrace(PTRACE_DETACH)
}

struct ProcMap *rx_procmaps() {
/*
pm_cursor is a global pointer used to search
the linked list of procmap nodes for r-xp 
permission nodes (at first, pm_cursor == pm_head). 
*/
        struct ProcMap *tmp_pm;

        for (; pm_cursor != NULL; pm_cursor = pm_cursor->next) {

                if (strncmp("r-xp", pm_cursor->permissions, 4) == 0) {
                        tmp_pm = pm_cursor;
                        pm_cursor = pm_cursor->next;
                        return tmp_pm; 
                }
        }

        return NULL;
}

int search_procmaps(const unsigned int mode) {

        struct ProcMap *moded_pm;

        switch (mode) {
        case (RX):
                moded_pm = rx_procmaps();
                if (moded_pm == NULL) {
                        printf("Failed to get any RX procmaps\n");
                        return -1;
                }

                printf("0x%lx\n0x%lx\n0x%lx\n%s\n%ld\n\n", 
                moded_pm->address_st, moded_pm->address_en, 
                moded_pm->size, moded_pm->permissions, moded_pm->pid);

                //use rx_pm data to attach and scan proc memory
                read_proc(moded_pm);
                
                break;

        default:
                moded_pm = NULL;
                return -1;
        }

        return 0;
}

int main(int argc, char *argv[]) {

        if (argc < 2) {
                printf("Not enough arguments.\n");
                return -1;
        }

        pid_t pid;
        int status;

        //parse pid
        pid = strtol(argv[1], NULL, BASE10);
        if (pid == 0) {
                if (errno == EINVAL) {
                        printf("Invalid process identifier. \
                        Specifically, %d.\n", errno);
                        return -1;
                }
        }

        //open, read, populate ProcMap obj, link 
        if (prep_mapfile(pid) < 0) return -1;

        //attach to pid
        ptrace(PTRACE_ATTACH, pid, NULL, NULL);
        wait(NULL);

        //get r-xp maps and use PTRACE_PEEKTEXT
        do {
                status = search_procmaps(RX);
        } while (status == 0);

        return 0;
}

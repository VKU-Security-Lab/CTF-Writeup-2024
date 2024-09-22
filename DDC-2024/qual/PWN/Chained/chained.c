#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

char EXPOSED_SYSTEM[100];

void probe_forum(){
    char process_logs[100];
    char intrusion_details[100];
    printf("Intrusion detected.\nPlease enter process logs:\n > ");
    scanf("%s", process_logs);
    printf("Analyzing process logs for ***");
    printf(process_logs);
    printf("***\nPlease enter intrusion details: \n > ");
    scanf("%s", intrusion_details);
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
    if(!strcmp(intrusion_details, "malicious_binary")){
        printf("Intrusion confirmed!\n");
        strncpy(EXPOSED_SYSTEM, process_logs, sizeof(EXPOSED_SYSTEM));
    }
    else{
        printf("Intrusion not confirmed. Exiting analysis.\n");
        exit(-37);
    }
}

void analyze_binary() {
    char binary_operations[400];
    printf("Enter suspected binary operations:\n");
    gets(binary_operations);
    printf("Process Logs: %s Suspected Operations: %s\n", EXPOSED_SYSTEM, binary_operations);
}

void delve_operations() {
    char *argv[] = {"/bin/sh", NULL};
    char *envp[] = {NULL};
    execve("/bin/sh", argv, envp);
}

int main(int argc, char *argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    probe_forum();
    analyze_binary();
    return 0;
}

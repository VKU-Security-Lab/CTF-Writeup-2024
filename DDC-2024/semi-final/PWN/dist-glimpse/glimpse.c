#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char flag[64];

// Code to disable IO buffering
void setup()
{
    setvbuf(stdin, 0LL, 2, 0LL);
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stderr, 0LL, 2, 0LL);
}

void read_flag(char *filename, int peek_length)
{
    int read_length = peek_length + 1;
    FILE *file = fopen(filename, "r");
    if (file == NULL)
    {
        printf("\nUnable to open file\n");
        exit(1);
    }
    fgets(flag, read_length, file);
    fclose(file);
    puts(flag);
}

int main()
{
    setup();
    char input[512];
    int i;

    for(i = 0; i < 3; i++){
        putchar('\n');
        printf("Need the flag? ¬‿¬ please me~\n");
        printf("e.g. please!please!please!?\n>");

        gets(input);
        int input_length = strlen(input);
        if(!strcmp(input, "please!please!please!")){
            puts("That's the spirit :)");
        }
        else if(!strcmp(input, "gimme one chanceee")){
            puts("Alright here's a sneakpeek:");
            read_flag("flag.txt", 8);
        }
        else{
            puts("I like your determination");
        }
    }
    puts("Hope you enjoyed the hint ^^");
    return 0;
}

#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    setuid(0);
    FILE *fp;
    char ch;

    fp = fopen("/app/flag.txt", "r");
    if (fp == NULL)
    {
        printf("Error in opening file\n");
        return 0;
    }

    while ((ch = fgetc(fp)) != EOF)
        printf("%c", ch);
    printf("\n");
    fclose(fp);
    return 0;
}
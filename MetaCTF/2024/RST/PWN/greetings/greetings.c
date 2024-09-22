// Compiled with `gcc -g -fno-stack-protector -no-pie greetings.c -o greetings`
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <unistd.h>

void setup() {
  setbuf(stdout, 0);
  setbuf(stdin, 0);
  setbuf(stderr, 0);
}

void win() {
  puts("");
  puts("========================");
  puts("*** WINNER! ***");
  puts("========================");
  puts("");

  sendfile(STDOUT_FILENO, open("./flag.txt", 0), 0, 100);
  fflush(stdout);
}

int main(int argc, char **argv) {

  char name[20];
  char greeting[280];

  // Disable buffering
  setup();

  puts("========================");
  puts("*** Greetings! ***");
  puts("========================");

  puts("");
  puts("Welcome! Enter your name and a greeting.");

  printf("Name: ");
  scanf("%19s", name);

  printf("Greeting: ");
  scanf("%s", greeting);

  printf("Generating your custom greeting....\n");
  usleep(500);

  puts("");
  puts("Your custom greeting:");
  puts("========================");

  printf("Why hello there %s, %s\n", name, greeting);

  return 0;
}

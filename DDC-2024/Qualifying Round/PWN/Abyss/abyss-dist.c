#include <stdio.h>

int main() {
  char* flag = "flag{f4ke_fl4g}";
  char buffer[64];

  printf("Welcome to the Abyss\n");
  printf("Provide darkness code to lighten up the flag: "); 
  fgets(buffer, 64, stdin);
  printf(buffer);
  return 0;
}


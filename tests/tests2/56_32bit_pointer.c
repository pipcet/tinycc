#include <stdio.h>

int main (int argc, char **argv)
{
  if((void *)0x100000000)
    printf("good\n");
  else
    printf("bad\n");

  return 0;
}

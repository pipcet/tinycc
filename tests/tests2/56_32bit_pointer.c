#include <stdio.h>

int main (int argc, char **argv)
{
  void *ptr = (void *)0x100000000;
  if(ptr)
    printf("good\n");
  else
    printf("bad\n");

  return 0;
}

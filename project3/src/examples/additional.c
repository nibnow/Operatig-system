#include <stdio.h>
#include <string.h>
#include <syscall.h>

int convert (char *str) {
  int result = 0;
  int x = 1;
  for (int i = strlen(str) - 1; i>=0; i--) {
    result += x * (str[i] - '0');
    x *= 10;
  }
  return result;
}

int
main (int argc, char **argv)
{
  int a = convert(argv[1]);
  int b = convert(argv[2]);
  int c = convert(argv[3]);
  int d = convert(argv[4]);

  //printf("a b c d : %d %d %d %d\n", a, b, c, d);
  printf("%d ", fibonacci(a));
  printf("%d\n", max_of_four_int(a, b, c, d));

  return EXIT_SUCCESS;
}

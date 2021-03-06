#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern void forth_init(void);
extern int forth_parse(char* buf, size_t n);

int main(void)
{
  char buf[1024];

  forth_init();

  /* print status */
  (void)forth_parse(buf,0);

  while (fgets(buf,sizeof(buf),stdin) != NULL) {
    size_t n = strlen(buf+0);
    if (forth_parse(buf+0,n)<0) {
      return EXIT_FAILURE;
    }
  }

  return EXIT_SUCCESS;
}

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include "input_buffer.h"
#include "bt_parse.h"

void printline(char *line, void *cbdata, bt_config_t *config, int x) {
  printf("LINE:  %s\n", line);
  printf("CBDATA:  %s\n", (char *)cbdata);
}


int main() {

  
  struct user_iobuf *u;

  u = create_userbuf();
  assert(u != NULL);

  while (1) {
    process_user_input(STDIN_FILENO, u, printline, "Cows moo!", NULL, 0);
  }
  
  return 0;
}

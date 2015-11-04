#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "input_buffer.h"
#include "bt_parse.h"

struct user_iobuf *create_userbuf() {
  struct user_iobuf *b;
  b = malloc(sizeof(struct user_iobuf));
  if (!b) return NULL;

  b->buf = malloc(USERBUF_SIZE + 1);
  if (!b->buf) {
    free(b);
    return NULL;
  }

  b->cur = 0;
  bzero(b->buf, USERBUF_SIZE+1);
  return b;
}

void process_user_input(int fd, struct user_iobuf *userbuf, 
			void (*handle_line)(char *, void *, bt_config_t *config, int sock), void *cbdata, 
                        bt_config_t *config, int sock)
{
  int nread;
  char *ret;

  assert(userbuf != NULL);
  assert(userbuf->buf != NULL);
  printf("Reached here.. in process user input\n");
  /* A real program would propagate this error back to the select loop or
   * implement some other form of error handling */

  if (userbuf->cur >= (USERBUF_SIZE - 1)) {
    fprintf(stderr, "process_user_input error:  buffer full;  line too long!\n");
    printf("process_user_input error:  buffer full;  line too long!\n");
    exit(-1);
  }
  printf("Reached here.. before read syscall in process user input\n");
  nread = read(fd, userbuf->buf + userbuf->cur, 
	       (USERBUF_SIZE - userbuf->cur));

  printf("Reached here.. after read syscall in process user input userbuf->buf is %s\n", userbuf->buf);
  printf("(Outside if) No. of bytes read are %d\n", nread);

  if (nread > 0) {
    printf("No. of bytes read are %d\n", nread);
    userbuf->cur += nread;
  }

 while ((ret = strchr(userbuf->buf, '\n')) != NULL) {
  printf("Entered while..\n");
  *ret = '\0';
  printf("Calling handle_line\n");
  handle_line(userbuf->buf, cbdata, config, sock);
  /* Shift the remaining contents of the buffer forward */
  memmove(userbuf->buf, ret + 1, USERBUF_SIZE - (ret - userbuf->buf));
  userbuf->cur -= (ret - userbuf->buf + 1);
 }

}

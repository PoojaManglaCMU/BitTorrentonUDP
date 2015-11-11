/*
 * peer.c
 *
 * Authors: Ed Bardsley <ebardsle+441@andrew.cmu.edu>,
 *          Dave Andersen
 * Class: 15-441 (Spring 2005)
 *
 * Skeleton for 15-441 Project 2.
 *
 */

#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "debug.h"
#include "spiffy.h"
#include "bt_parse.h"
#include "input_buffer.h"
#include "whohas_handler.h"

#define BUFLEN 1500
 #define FC_RECV

/* Global variables*/
mapping_per_get_req_t   mapping_per_get_req;
bt_config_t             config;
int   peer_sfd = 0;
FILE *fp_data = NULL;

void peer_run(bt_config_t *config);

int main(int argc, char **argv)
{

  //bt_config_t config;
  bt_init(&config, argc, argv);

  DPRINTF(DEBUG_INIT, "peer.c main beginning\n");

#ifdef TESTING
  config.identity = 1; // your group number here
  strcpy(config.chunk_file, "chunkfile");
  strcpy(config.has_chunk_file, "haschunks");
#endif

  bt_parse_command_line(&config);

#ifdef DEBUG
  if (debug & DEBUG_INIT) {
    bt_dump_config(&config);
  }
#endif
  peer_run(&config);

  return 0;
}


void process_inbound_udp(int sock, bt_config_t *config)
{
  struct sockaddr_in from;
  socklen_t fromlen;
  char buf[BUFLEN];
  int i;
  
  fromlen = sizeof(from);
  int nbytes = spiffy_recvfrom(sock, buf, BUFLEN, 0, (struct sockaddr *)&from, &fromlen);

  printf("process_inbound_udp: %s:%d\n\n", inet_ntoa(from.sin_addr), ntohs(from.sin_port));
 
  char token = buf[3];

  /* change the endianess of the header */
  netToHost((data_packet_t*)buf);

  /* based on ip, identify the peer id */
  bt_peer_t* peer = bt_peer_get(config,(struct sockaddr *)&from);
  printf("Got peer %x %d\n", peer, peer->id);

 if (token == 0x0)  /* whohas */
	 whohas_resp(buf, config->has_chunk_file, sock, config);
 else if (token == 0x1) /* IHAVE */
	 ihave_resp_recv_handler(buf, sock, config, (struct sockaddr *) &from);
 else if (token == 0x2)  /* GET packet */
    get_resp(config, buf, (struct sockaddr *) &from, sock);
 else if (token == 0x3)  /* DATA packet */
	 data_packet_handler(config, buf, peer, sock);
 else if (token == 0x4) /* ACK packet */
   notify_ack_recvied(peer->id, ((data_packet_t *)buf)->header.ack_num, 0);
 else if (token == 0x5) /* DENIED packet */
   ;

 return;
}

void process_get(char *chunkfile, char *outputfile, bt_config_t *config, int sock)
{
  init_mapping_per_get_req(chunkfile, outputfile);
  fp_data = fopen(outputfile, "w");

  /* Prepare a whohas packet */
  whohas_req(chunkfile, sock, config);

  return;
}

void handle_user_input(char *line, void *cbdata, bt_config_t *config, int sock)
{
  char chunkf[128], outf[128];
  
  bzero(chunkf, sizeof(chunkf));
  bzero(outf, sizeof(outf));
  if (sscanf(line, "GET %120s %120s", chunkf, outf)) {
	  if (strlen(outf) > 0) {
		  process_get(chunkf, outf, config, sock);
	  }
  }
  return;
}

void peer_run(bt_config_t *config)
{
  int sock;
  struct sockaddr_in myaddr;
  fd_set readfds;
  struct user_iobuf *userbuf;
  int nfds;
  
  if ((userbuf = create_userbuf()) == NULL) {
    perror("peer_run could not allocate userbuf");
    exit(-1);
  }
  
  if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1) {
    perror("peer_run could not create socket");
    exit(-1);
  }
  
  bzero(&myaddr, sizeof(myaddr));
  myaddr.sin_family = AF_INET;
  myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  myaddr.sin_port = htons(config->myport);
  
  if (bind(sock, (struct sockaddr *) &myaddr, sizeof(myaddr)) == -1) {
    perror("peer_run could not bind socket");
    exit(-1);
  }
  
  spiffy_init(config->identity, (struct sockaddr *)&myaddr, sizeof(myaddr));
  config->sock = sock;
  peer_sfd = sock;
  
  printf("identity is %d and sock is %d\n", config->identity, sock);

#ifdef FC_RECV
  flow_ctrl_init();
#endif

  while (1)
  {
    printf("looping for next invocation of select\n");
    FD_ZERO(&readfds);
    FD_SET(STDIN_FILENO, &readfds);
    FD_SET(sock, &readfds);
    
    nfds = select(sock+1, &readfds, NULL, NULL, NULL);
    
    if (nfds > 0) {
      if (FD_ISSET(sock, &readfds))
	       process_inbound_udp(sock, config);
      
      if (FD_ISSET(STDIN_FILENO, &readfds))
	         process_user_input(STDIN_FILENO, userbuf, handle_user_input,
			                         "Currently unused", config , sock);
    }
  }
}

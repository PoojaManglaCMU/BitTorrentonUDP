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

/* Global variables*/
mapping_per_get_req_t mapping_per_get_req;
bt_config_t config;
char data[CHUNK_SIZE];
int data_received;
void peer_run(bt_config_t *config);

int main(int argc, char **argv) {
  bt_config_t config;

  bt_init(&config, argc, argv);
  
  data_received = 0;
  
  memset(&data[0], 0, sizeof(data));

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
  printf("identity is %d\n", config.identity); 
  peer_run(&config);
  return 0;
}


void process_inbound_udp(int sock, bt_config_t *config) {
  #define BUFLEN 1500
  struct sockaddr_in from;
  socklen_t fromlen;
  char buf[BUFLEN];
  int i;
  fromlen = sizeof(from);
  spiffy_recvfrom(sock, buf, BUFLEN, 0, (struct sockaddr *)&from, &fromlen);

  printf("PROCESS_INBOUND_UDP SKELETON -- replace!\n"
	 "Incoming message from %s:%d\n%s\n\n", 
	 inet_ntoa(from.sin_addr),
	 ntohs(from.sin_port),
	 buf);
 
 char token = buf[3];
 printf("self id is %d, packet is %s , size is %zd and packet type is %2X\n, sock is %d", config->identity, (unsigned char*)buf, sizeof(buf),token, sock);
 netToHost((data_packet_t*)buf);
 //print_pkt((data_packet_t *)buf);
 printf("Reached here.. \n");
 bt_peer_t* peer = bt_peer_get(config,(struct sockaddr *)&from);
 printf("Got peer %x %d\n", peer, peer->id);
 if (token == 0x0) { // WHOHAS packet
	 printf("It is a WHOHAS request %s\n", buf);
	 whohas_resp(buf, config->has_chunk_file, sock, config);
 } else if (token == 0x1) { //IHAVE packet
	 printf("It is an IHAVE packet %s\n",buf);
	 ihave_resp_recv_handler(buf, sock, config, (struct sockaddr *) &from);
 } else if (token == 0x2) { //GET packet
	 printf("It is a GET packet %s\n", buf);
	 get_resp(config, buf, (struct sockaddr *) &from);
 } else if (token == 0x3) { //DATA packet
	 printf("It is a DATA packet %s\n", buf);
	 data_packet_handler(config, buf, peer, sock);
 } else if (token == 0x4) { //ACK packet
	 printf("It is an ACK , number is %d\n", ((data_packet_t *)buf)->header.ack_num);
         //print_pkt(((data_packet_t *)buf))->header.seq_num;
	 //handle_ack();
 } else if (token == 0x5) { //DENIED packet
	 printf("It is a DENIED response %s\n", buf);
	 //handle_denied();
 }

 return;
}

void process_get(char *chunkfile, char *outputfile, bt_config_t *config, int sock) {
  printf("PROCESS GET SKELETON CODE CALLED.  Fill me in!  (%s, %s)\n", 
	chunkfile, outputfile);
   
  printf("peer is %x\n", config->peers);
  /* Prepare a whohas packet */
  init_mapping_per_get_req(chunkfile, outputfile);
  printf(" Calling whohas_req\n");
  whohas_req(chunkfile, sock, config);
  printf(" GET processed successfully\n");
  return;
}

void handle_user_input(char *line, void *cbdata, bt_config_t *config, int sock) {
  char chunkf[128], outf[128];
  char token = line[3];
  printf("packet type is %c\n", token);
  printf("peer is %x\n", config->peers);
  
  bzero(chunkf, sizeof(chunkf));
  bzero(outf, sizeof(outf));
  if (sscanf(line, "GET %120s %120s", chunkf, outf)) {
	  if (strlen(outf) > 0) {
		  process_get(chunkf, outf, config, sock);
	  }
  }
  printf("Handled user input\n");
  return;
}


void peer_run(bt_config_t *config) {
  int sock;
  struct sockaddr_in myaddr;
  fd_set readfds;
  struct user_iobuf *userbuf;
  
  if ((userbuf = create_userbuf()) == NULL) {
    perror("peer_run could not allocate userbuf");
    exit(-1);
  }
  
  if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1) {
    perror("peer_run could not create socket");
    exit(-1);
  }
  printf("identity is %d and sock is %d\n", config->identity, sock);
  
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
  
  while (1) {
    printf("looping for next invocation of select\n");
    int nfds;
    FD_ZERO(&readfds);
    FD_SET(STDIN_FILENO, &readfds);
    FD_SET(sock, &readfds);
    
    nfds = select(sock+1, &readfds, NULL, NULL, NULL);
    printf("identity is %d and sock is %d\n", config->identity, sock);
    
    if (nfds > 0) {
      if (FD_ISSET(sock, &readfds)) {
	process_inbound_udp(sock, config);
      }
      
      if (FD_ISSET(STDIN_FILENO, &readfds)) {
	process_user_input(STDIN_FILENO, userbuf, handle_user_input,
			   "Currently unused", config , sock);
      }
    }
  }
}

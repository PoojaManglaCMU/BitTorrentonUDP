#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "bt_parse.h"

#define MAX_LINE_SIZE           80
#define CHUNK_HSIZE             20
#define MAX_PACKET_SIZE         512
#define HDR_LEN                 16
#define MAX_NUM_CHUNKS          (MAX_PACKET_SIZE - HDR_LEN - 4)/CHUNK_HSIZE
#define PACKETLEN       1500
#define DATALEN         PACKETLEN - HDR_LEN
#define MAX_CHUNK		74   //Max number of chunk in a single whohas pkt
#define BUF_SIZE                60
#define PKT_WHOHAS 		0
#define PKT_IHAVE		1
#define PKT_GET			2
#define PKT_DATA		3
#define PKT_ACK 		4
#define PKT_DENIED		5      
#define CHUNK_SIZE      (1 << 19)  //size of a single chunk in Bytes

typedef struct{
  short magicnum;
  char version;
  char packet_type;
  short header_len;
  short packet_len; 
  unsigned int seq_num;
  unsigned ack_num;
} header_t;

/*typedef struct mapping_per_get_req {
	char chunk_hash[CHUNK_HSIZE];
	peer_t *peer;
	int downloaded;
	int sent_request;
} mapping_per_get_req_t;

typedef struct mapping_per_get_req {
        char chunk_hash[CHUNK_HSIZE];
        peer_t *peer;
        int downloaded;
        int sent_request;
} mapping_per_get_req_t; */

typedef struct chunk_s {
	int id;
	uint8_t hash[CHUNK_HSIZE];
	char *data;
	int cur_size;
	int num_p;
	int downloaded;
	bt_peer_t *providers; /* providers */
} chunk_t;
 
// num_chunk * 512 * 1024 = file_size;max num_chunk = 4095
// largest file supports is 2GB - 512KB
typedef struct mapping_per_get_req_s {
    int num_chunk;   
    int num_need;
    int num_downloaded;
    chunk_t* chunks;
    char get_chunk_file[BT_FILENAME_LEN];
} mapping_per_get_req_t;

typedef struct data_packet {
    header_t header;
    uint8_t data[DATALEN];
} data_packet_t;

int whohas_req(char *chunkfile, int sock, bt_config_t *config);
int whohas_resp(char *whohas_packet, char* chunkfile, int sock, bt_config_t *config);
void prep_ihave_hdr(char* ihave_packet, int nchunks);
char text2num(char* input);
int char2digit(char ch);

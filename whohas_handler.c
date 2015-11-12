#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include "whohas_handler.h"
#include "bt_parse.h"
#include "spiffy.h"
#include "chunk.h"

#define FC_RECV
void flow_ctrl_init();

/* DUT as sender */
/* should be invoked on a get request */
void notify_chunk_trans_start(int peer_num, int chunk_num);
int update_sender_window(int peer_num, int ack_num);
void notify_packet_sent(int peer_num, int seq_num, int chunk_num);
void notify_ack_recvied(int peer_num, int ack_num, int chunk_num);

/* DUT as receiver */
/* should be invoked on sending a get request */
void notify_chunk_dwnl_start(int peer_num, int chunk_num);
int update_receiver_window(int peer_num, int seq_num);
/* should be invoked when correct packet of a chunk received */
int notify_packet_recv(int peer_num, int seq_num, int chunk_num);
void notify_ack_sent(int peer_num, int ack_num, int chunk_num);

#define MAX_PEER 10
#define HASH_HEX_SIZE 40

#define SEND_DATA_PKT_SIZE 1040

extern mapping_per_get_req_t mapping_per_get_req;
extern bt_config_t config;
extern FILE *fp_data;
extern int peer_sfd;
typedef struct {
	char data[CHUNK_SIZE];
	int data_received;
} peer_buf_t;

peer_buf_t peer_buf[MAX_PEER];

typedef struct {
	char data[512*1040];
    int  chunk_id;
    unsigned npkts_sent;
	bt_peer_t* peer;
} peer_send_info_t;

peer_send_info_t    peer_send_info[MAX_PEER];

/** @brief Print out hash
 *  @param hash the pointer to the hash to be printed out
 *  @return void
 */
void print_hash(uint8_t *hash) {
	int i;
    for (i = 0; i < CHUNK_HSIZE;) {
        printf("%2X ", hash[i++]);
    }
    printf("\n");
}

void print_pkt(data_packet_t* pkt) {
    header_t* hdr = &pkt->header;
    uint8_t* hash;
    int num;
    int i;
    fprintf(stderr, ">>>>>>>>>START<<<<<<<<<<<<<\n");
    fprintf(stderr, "magicnum:\t\t%d\n", hdr->magicnum);
    fprintf(stderr, "version:\t\t%d\n", hdr->version);
    fprintf(stderr, "packet_type:\t\t%d\n", hdr->packet_type);
    fprintf(stderr, "header_len:\t\t%d\n", hdr->header_len);
    fprintf(stderr, "packet_len:\t\t%d\n", hdr->packet_len);
    fprintf(stderr, "seq_num:\t\t%d\n", hdr->seq_num);
    fprintf(stderr, "ack_num:\t\t%d\n", hdr->ack_num);
    if (PKT_WHOHAS == hdr->packet_type || PKT_IHAVE == hdr->packet_type) {
        num = pkt->data[0];
		fprintf(stderr, "1st bytes data:\t\t%x\n", pkt->data[0]);
        hash = (uint8_t *)(pkt->data + 4);
        for (i = 0; i < num; i++) {
			print_hash(hash);
            hash += CHUNK_HSIZE;
		}
    }
    fprintf(stderr, ">>>>>>>>>END<<<<<<<<<<<<<\n");
}

/** @brief Convert data from local format to network format
 *  @param pkt pkt to be send
 *  @return void
 */

void hostToNet(data_packet_t* pkt) {
    pkt->header.magicnum = htons(pkt->header.magicnum);
    pkt->header.header_len = htons(pkt->header.header_len);
    pkt->header.packet_len = htons(pkt->header.packet_len);
    pkt->header.seq_num = htonl(pkt->header.seq_num);
    pkt->header.ack_num = htonl(pkt->header.ack_num);
}

/** @brief Convert data from network format to local format
 *  @param pkt to be send
 *  @return void
 */
void netToHost(data_packet_t* pkt) {
    pkt->header.magicnum = ntohs(pkt->header.magicnum);
    pkt->header.header_len = ntohs(pkt->header.header_len);
    pkt->header.packet_len = ntohs(pkt->header.packet_len);
    pkt->header.seq_num = ntohl(pkt->header.seq_num);
    pkt->header.ack_num = ntohl(pkt->header.ack_num);
}

/* Create packet to be sent */
data_packet_t *create_packet(int type, short pkt_len, u_int seq,
                            u_int ack, uint8_t *data) {
    data_packet_t *pkt = (data_packet_t *)malloc(sizeof(data_packet_t));
    pkt->header.magicnum = 15441; /* Magic number */
    pkt->header.version = 1;      /* Version number */
    pkt->header.packet_type = type; /* Packet Type */
    pkt->header.header_len = HDR_LEN;    /* Header length is always 16 */
    pkt->header.packet_len = pkt_len;
    pkt->header.seq_num = seq;
    pkt->header.ack_num = ack;
    if( data != NULL) {
	    memcpy(pkt->data, data, pkt_len-HDR_LEN);
    } 
    return pkt;
}

void create_chunk_pkts(int type, short pkt_len, u_int seq, u_int ack, uint8_t *data, char* dst) {
    data_packet_t *pkt = (data_packet_t *) dst;
    pkt->header.magicnum = 15441; /* Magic number */
    pkt->header.version = 1;      /* Version number */
    pkt->header.packet_type = type; /* Packet Type */
    pkt->header.header_len = HDR_LEN;    /* Header length is always 16 */
    pkt->header.packet_len = pkt_len;
    pkt->header.seq_num = seq;
    pkt->header.ack_num = ack;
    if( data != NULL) {
        memcpy(pkt->data, data, pkt_len-HDR_LEN);
    } 
    return;
}

/* Create ACK packet */
data_packet_t* ACK_maker(int ack, data_packet_t* pkt) {
    assert(pkt->header.packet_type == PKT_DATA);
    data_packet_t* ack_pkt = create_packet(PKT_ACK, HDR_LEN, 0, ack, NULL);
    return ack_pkt;
}

/* API to send packet */
ssize_t packet_sender(bt_config_t *config, data_packet_t* pkt, bt_peer_t *peer, int sock) {
    int pkt_size = pkt->header.packet_len;
    int type = pkt->header.packet_type;
    ssize_t get;
    int flag;
    hostToNet(pkt);
    get = spiffy_sendto(config->sock, pkt, pkt_size, 0, (struct sockaddr *) &peer->addr, sizeof(peer->addr));
    if (get == -1) {
       printf("error\n");
       flag = fcntl(sock, F_GETFL,0);
       if(flag == -1) printf("%d\n", errno);
    }
    netToHost(pkt);
    return get;
}


/* Initialize mapping per get request on a GET request from user */
int init_mapping_per_get_req(char* chunkFile, char* output_file) {
    
    FILE* file = fopen(chunkFile,"r");
    if( file == NULL)
        return -1; // fail to open mapping_per_get_req file

    int line_number = 0;
    int i = 0;
    int k,j;
    char read_buffer[BUF_SIZE];
    char *ptr_hash;
    char line[MAX_LINE_SIZE];
    int nchunks;
    j=0;
    
    /* get chunks number */
    while (fgets(read_buffer, BUF_SIZE,file)) {
        line_number++;
    }
    memset(read_buffer,0,BUF_SIZE);
    
    mapping_per_get_req.num_chunk = line_number;
    mapping_per_get_req.num_need = line_number;
    mapping_per_get_req.num_downloaded = 0;
    mapping_per_get_req.chunks = malloc(sizeof(chunk_t) * mapping_per_get_req.num_chunk);
    
    /* set ptr to the beginning */
    fseek(file,0,SEEK_SET);
    
    
     /* read chunks from the file */
    while(fgets(line, MAX_LINE_SIZE, file) != NULL)
    {
        /* parse the line */
        for(i=0; i<MAX_LINE_SIZE; i++)
            if(line[i] == ' ')
                break;

        if(i == MAX_LINE_SIZE)
        {
            printf("Error parsing chunk line\n");
            return -1;
        }

        ptr_hash = &(line[i+1]);
        for(k=0; k<CHUNK_HSIZE; k++)
        {
            mapping_per_get_req.chunks[j].hash[k] = text2num(ptr_hash); // Copying from file to packet
            ptr_hash += 2;
            printf("%2x ", mapping_per_get_req.chunks[j].hash[k]);
        }

        nchunks++;

        if(nchunks == MAX_NUM_CHUNKS)
        {
            printf("Exceeds MAX_NUM_CHUNKS. Need to prepare another packet\n");
            //TODO: Handle more than one packet condition
        }
        mapping_per_get_req.chunks[j].providers = NULL;
        mapping_per_get_req.chunks[j].num_p = 0;
        mapping_per_get_req.chunks[j].cur_size = 0;
        mapping_per_get_req.chunks[j].data = malloc(sizeof(char)*512*1024);

        j++;

    }

    fclose(file);
    // set output file address and format
    strcpy(config.output_file,output_file);
    strcpy(mapping_per_get_req.get_chunk_file,chunkFile);
    config.output_file[strlen(output_file)] = '\0';
    mapping_per_get_req.get_chunk_file[strlen(mapping_per_get_req.get_chunk_file)] = '\0';
    
    return 0;
}

/* Send whohas request */ 
int whohas_req(char *chunkfile, int sock, bt_config_t *config) {
    FILE*   fp_chunks;
    char    line[MAX_LINE_SIZE];
    char    chunk_hash[CHUNK_HSIZE];
    unsigned char    whohas_packet[MAX_PACKET_SIZE];

    int     nchunks = 0;
    int     i, offset, k;
    char*   ptr;
    char*   ptr_hash;
    ssize_t whohas;
    int j;
    bt_peer_t *peer = config->peers; 

    /*** prepare payload for whohas packet ***/

    /* open the chunk file */
    if(!(fp_chunks = fopen(chunkfile, "r")))
    {
      printf("Error opening chunkfile\n");
      exit(-1);
    }

    /* read chunks from the file */
    while(fgets(line, MAX_LINE_SIZE, fp_chunks) != NULL)
    {
        /* parse the line */
        for(i=0; i<MAX_LINE_SIZE; i++)
            if(line[i] == ' ')
                break;

        if(i == MAX_LINE_SIZE)
        {
            printf("Error parsing chunk line\n");
            return -1;
        }

        /* 4 bytes for num_chunks + padding */
        offset = HDR_LEN + 4 + nchunks * CHUNK_HSIZE;
        ptr =  whohas_packet + offset;
        ptr_hash = &(line[i+1]);
        for(k=0; k<CHUNK_HSIZE; k++)
        {
            *ptr = text2num(ptr_hash); // Copying from file to packet 
            ptr++;
            ptr_hash += 2;
        }

        for(j=0; j<5; j++)
            printf("%.2x ", whohas_packet[offset+j]);
        printf("\n");
        nchunks++;

        if(nchunks == MAX_NUM_CHUNKS)
        {
            printf("Exceeds MAX_NUM_CHUNKS. Need to prepare another packet\n");
            //TODO: Handle more than one packet condition
        }

    }

    prep_whohas_hdr(whohas_packet, nchunks);

    while (peer != NULL) {
		whohas = spiffy_sendto(sock, whohas_packet, 60, 0, 
				(struct sockaddr *) &peer->addr, sizeof(peer->addr));
		if (whohas == -1)
			printf("error\n");
		peer = peer->next;
	}

    fclose(fp_chunks);
    return 0;

}

/* Send IHAVE packet */
int whohas_resp(char *whohas_packet, char* chunkfile, int sock, bt_config_t *config) {

    assert(whohas_packet != NULL);

    FILE*   fp_chunks;
    char    line[MAX_LINE_SIZE];
    char    chunk_hash[CHUNK_HSIZE];
    char    temp_hash[CHUNK_HSIZE];
    unsigned char    ihave_packet[MAX_PACKET_SIZE];

    int     nchunks = 0;
    int     nuchunks_incoming = (unsigned char)(whohas_packet[HDR_LEN+0]);
    int     i, offset, k, t, j;
    char*   ptr;
    char*   ptr_hash;
    char*   ptr_hash_cpy;
    unsigned char tchar;
    ssize_t ihave;
    bt_peer_t *peer = config->peers;

    int hash_matched = 0;

    /*** prepare payload for ihave packet ***/

    /* open the chunk file */
    if(!(fp_chunks = fopen(chunkfile, "r")))
    {
      printf("Error opening chunkfile\n");
      exit(-1);
    }

    //TODO: need to reverse the logic
    // Inefficient with large chunks.. really? Don't think so 
    /* read chunks from the file */
    while(fgets(line, MAX_LINE_SIZE, fp_chunks) != NULL)
    {
		/* parse the line */
		for(i=0; i<MAX_LINE_SIZE; i++)
			if(line[i] == ' ')
				break;

		if(i == MAX_LINE_SIZE)
        {
            printf("Error parsing chunk line\n");
			return -1;
        }

        /* 4 bytes for num_chunks + padding */
		offset = HDR_LEN + 4 + nchunks * CHUNK_HSIZE;
        ptr =  ihave_packet + offset;
		ptr_hash = &(line[i+1]);

		for(k=0; k<CHUNK_HSIZE; k++)
		{
			temp_hash[k]    = text2num(ptr_hash); 
			ptr_hash += 2;
		}

		for(t=0; t < nuchunks_incoming; t++)
        {
		hash_matched = 1;
		for(k=0; k<CHUNK_HSIZE; k++)
		{
			if(temp_hash[k] != whohas_packet[HDR_LEN+4+(t*CHUNK_HSIZE)+k])
			{
				hash_matched = 0;
				break;              
			}
		}

		if (hash_matched == 1)
		{
			memcpy(ptr, temp_hash, CHUNK_HSIZE);
			nchunks++;
			if(nchunks == MAX_NUM_CHUNKS)
			{
				printf("Exceeds MAX_NUM_CHUNKS. Need to prepare another packet\n");
				//TODO: Handle more than one packet condition
			}

			for(j=0; j<20; j++)
				printf("%.2x ", whohas_packet[offset+j]);
			printf("\n");
		}
		}

	}
	prep_ihave_hdr(ihave_packet, nchunks);

    if(nchunks != 0){
		while (peer != NULL) {
			ihave = spiffy_sendto(sock, ihave_packet, (20+nchunks*20), 0,
					(struct sockaddr *) &peer->addr, sizeof(peer->addr));
			if (ihave == -1)
				printf("error\n");
			peer = peer->next;
		}
	}

	fclose(fp_chunks);
	return 0;
}

void prep_whohas_hdr(char* whohas_packet, int nchunks) {
	header_t header;
	char* pWhoHas = whohas_packet;

	//TODO: remove hard-coding

    header.magicnum = 15441;
	header.version = 1;
    header.packet_type = 0;
	header.header_len = HDR_LEN;
    header.packet_len = HDR_LEN + 4 + (nchunks*CHUNK_HSIZE); 
    header.seq_num = 0;
    header.ack_num = 0;

    *((unsigned short*) (pWhoHas + 0)) = htons((header.magicnum));
    *((char*)           (pWhoHas + 2)) = (header.version);
    *((char*)           (pWhoHas + 3)) = (header.packet_type);
    *((unsigned short*) (pWhoHas + 4)) = htons((header.header_len));
    *((unsigned short*) (pWhoHas + 6)) = htons((header.packet_len));
    *((unsigned int*)   (pWhoHas + 8)) = (header.seq_num);
    *((unsigned int*)   (pWhoHas + 12)) = (header.ack_num);

    /* write num chunks */
    *((char*)           (pWhoHas + 16)) = nchunks;
}

void prep_ihave_hdr(char* ihave_packet, int nchunks) {
    
	header_t header;
    char* pIhave = ihave_packet;

    //TODO: remove hard-coding

    header.magicnum = 15441;
    header.version = 1;
    header.packet_type = 1;
    header.header_len = HDR_LEN;
    header.packet_len = HDR_LEN + 4 + (nchunks*CHUNK_HSIZE); 
    header.seq_num = 0;
    header.ack_num = 0;

    *((unsigned short*) (pIhave + 0)) = htons(header.magicnum);
    *((char*)           (pIhave + 2)) = (header.version);
    *((char*)           (pIhave + 3)) = (header.packet_type);
    *((unsigned short*) (pIhave + 4)) = htons(header.header_len);
    *((unsigned short*) (pIhave + 6)) = htons(header.packet_len);
    *((unsigned int*)   (pIhave + 8)) = htonl(header.seq_num);
    *((unsigned int*)   (pIhave + 12)) = htonl(header.ack_num);

    /* write num chunks */
    *((char*)           (pIhave + 16)) = nchunks;
}

char text2num(char* input) {
    
	int num = 0;
    int d1 = char2digit(input[0]);
    int d0 = char2digit(input[1]);

    num = 16*d1 + d0;
    //printf("num: %d\n", num);
    return (char)num;
}

int char2digit(char ch) {
    
	int num;

    if(ch >= 48 && ch <= 57)
        num = ch-48;
    else if (ch >= 97 && ch <= 102)
        num = (ch-97)+10;
    else if (ch >= 65 && ch <= 70)
        num = (ch-65)+10;
    else
    {
        printf("Invalid character\n");
    }

    return num;
}

/* Check if we need to download the chunk we have received IHAVE response for */
int match_need(uint8_t *hash, int j) {
	int i,k;
	chunk_t* chk = mapping_per_get_req.chunks;
	int hash_matched = 1;
	if (mapping_per_get_req.num_chunk == 0) {
		printf("Number of available chunks is zero\n");
        return -1;
    }

    // TODO : Add more checks. Basic checks added for now
	for (i=0; i < mapping_per_get_req.num_chunk; i++) {
		if (chk[i].providers != NULL) {
			printf("Provider already present for that chunk\n");
			continue;
		}
        
		for(k=0; k<CHUNK_HSIZE; k++) {
			printf("%2X ", chk[i].hash[k]);
		}
		printf("\n ");
		for(k=0; k<CHUNK_HSIZE; k++) {
			printf("%2X ", hash[k]);
		}

		for(k=0; k<CHUNK_HSIZE; k++)
		{
			if(chk[i].hash[k] != hash[k])
			{
				hash_matched = 0;
				break;
			}

		}
		if(hash_matched == 0) {
			printf("Hash did not match");
			continue;
		} else {
			printf("Chunk hash found at %d\n", i);
			if(!chk[i].downloaded)
				return i;
		}
	}
	printf("Chunk hash not found\n");
	return -1;
}

/* Send GET data packet to download the chunk data */
void send_get_request(bt_config_t *config, uint8_t* hash, bt_peer_t *peer, int sock) {
	/* create GET pkt and send to the peer */
	data_packet_t *packet;
	packet = create_packet(PKT_GET, HDR_LEN + CHUNK_HSIZE, 0, 0, (uint8_t *)hash);
	packet_sender(config, packet, peer, sock);
    
    /* notify congestion cntrl about the download */
#ifdef FC_RECV
	notify_chunk_dwnl_start(peer->id, 0);
#endif
}  

/* Handle IHAVE data packet, Decide whether to send GET or not */
void ihave_resp_recv_handler (char *ihave_packet, int sock, bt_config_t *config, struct sockaddr *from) {
	int i;
	assert(ihave_packet != NULL);
	char chunk_hash[CHUNK_HSIZE];
	bt_peer_t* peer = bt_peer_get(config, from);

	chunk_t* chk = mapping_per_get_req.chunks;
	uint8_t *hash; // incoming hash to meet my needs
    uint8_t *hash_cpy;
    int match_idx, t, k;
    hash_cpy = (uint8_t *)malloc(CHUNK_HSIZE);
	int nuchunks_incoming = (unsigned char)(ihave_packet[HDR_LEN+0]);
	if (nuchunks_incoming == 0) {
		printf("no chunks in ihave packet\n"); 
		return NULL;
    }
    
	for(t=0; t < nuchunks_incoming; t++)
	{
		for(k=0; k<CHUNK_HSIZE; k++)
	    {
			hash[(t*CHUNK_HSIZE)+k] = ihave_packet[HDR_LEN+4+(t*CHUNK_HSIZE)+k];
			printf("%2X ", hash[(t*CHUNK_HSIZE)+k]);
		}
		printf("\n");
	}
  //  printf("No. of incoming chunks is %d\n", nuchunks_incoming);
	if(!peer->sent_req) {
		for (i = 0; i < nuchunks_incoming; i++) {
			match_idx = match_need(hash,i);
			if (match_idx != -1) {
				chk[match_idx].providers = peer;
				peer->sent_req = 1;
				chk[match_idx].num_p = 1;
				chk[match_idx].downloaded = 1;
				mapping_per_get_req.num_downloaded |= (1 << match_idx);
				memcpy(hash_cpy, hash, CHUNK_HSIZE);
				send_get_request(config, hash_cpy, peer, sock);
				peer_buf[peer->id].data_received = 0;
				break;
			}
			hash += CHUNK_HSIZE;
		} 
	}
}		

/* DATA packet handler */
void data_packet_handler(bt_config_t *config1, char* buf, bt_peer_t *peer, int sock) {
	
	chunk_t *chunk;
	data_packet_t* ack_pkt;
	int i,k;
	FILE*   fp_chunks;
	char    line[MAX_LINE_SIZE];
	char    temp_hash[CHUNK_HSIZE];
	char* ptr_hash;
	int hash_matched = 0;
	int offset;
	char datafile[BT_FILENAME_LEN];
	uint8_t hash[CHUNK_HSIZE];

	int size = (int)(((data_packet_t*)buf)->header.packet_len) - 16;
	for (k=0; k < size; k++)
		peer_buf[peer->id].data[k+ peer_buf[peer->id].data_received] = ((data_packet_t*)buf)->data[k];

	peer_buf[peer->id].data_received += size;
	printf("pkt_len: %d data_received: %d peer_id:%d seq_num:%d\n", size, peer_buf[peer->id].data_received, peer->id, (((data_packet_t*)buf)->header.seq_num));
	float kb = peer_buf[peer->id].data_received/1024;

#ifdef FC_RECV
	//TODO: check the return val to discard the packet
	notify_packet_recv(peer->id, ((data_packet_t*)buf)->header.seq_num, 0);
#else
	/* send ack */
	send_ack(peer->id, ((data_packet_t*)buf)->header.seq_num, 0);
#endif 

	if (peer_buf[peer->id].data_received != CHUNK_SIZE) {
		return 0;
	}

	printf("Received complete chunk, Store in data file\n");
	shahash(peer_buf[peer->id].data,peer_buf[peer->id].data_received, hash);
	print_hash(hash);
        
	// open the chunk file
	printf("chunk file is %s\n", mapping_per_get_req.get_chunk_file);
	if(!(fp_chunks = fopen(mapping_per_get_req.get_chunk_file, "r")))
	{
		printf("Error opening chunkfile\n");
		exit(-1);
	}
	int index = 0;
	while(fgets(line, MAX_LINE_SIZE, fp_chunks) != NULL)
	{
		for(i=0; i<MAX_LINE_SIZE; i++)
			if(line[i] == ' ')
				break;

		if(i == MAX_LINE_SIZE)
		{
			printf("Error parsing chunk line\n");
			return -1;
		}

		ptr_hash = &(line[i+1]);

		for(k=0; k<CHUNK_HSIZE; k++)
		{
			temp_hash[k] = text2num(ptr_hash);
			ptr_hash += 2;
		}
		hash_matched = 1;
		if(memcmp(hash, temp_hash, CHUNK_HSIZE)) {
			printf("Hash did not match\n");   
			hash_matched = 0;
			index++;
			continue;
		}
		if (hash_matched == 1)
		{
			offset = index*512*1024;
			int foffset = fseek(fp_data, offset, SEEK_SET);
			int fwrite_data = fwrite(peer_buf[peer->id].data, CHUNK_SIZE, 1, fp_data);
			peer->sent_req = 0;
			return;
		}
	}

	return; 
}

/* GET packet handler */
void get_resp(bt_config_t *config, char *buf, struct sockaddr *from, int sock) {

	unsigned cur_size = 0;
	int seq_num = 1;
	int bytes,i;
	bt_peer_t* peer = bt_peer_get(config, from);
	bytes = 1420;
	char *data_send;
	int index = 0;
	char hash_buffer[HASH_HEX_SIZE] = {0};
	char hash_hex[HASH_HEX_SIZE] = {0};
	char buffer[BT_FILENAME_LEN+5] = {0};
	char datafile[BT_FILENAME_LEN] = {0};
	char index_buffer[5] = {0};
	char *src;
	struct stat statbuf;
	data_packet_t *pkt = (data_packet_t *)buf;
	int data_fd;
   

	/* retrieve name of master_data_file from first line of master_chunk_file */
	FILE* index_file = fopen(config->chunk_file,"r");
	if(index_file == NULL) {
		fprintf(stderr, "Fail to open chunk file!!\n"); 
		return NULL;
	}
	fgets(buffer,BT_FILENAME_LEN,index_file);
	sscanf(buffer,"File: %s\n",datafile);


	// skip the next line
	fgets(buffer,BT_FILENAME_LEN,index_file);

	// open file to read 
	data_fd = open(datafile, O_RDONLY);
	fstat (data_fd, &statbuf);
	src = mmap(0, statbuf.st_size, PROT_READ, MAP_SHARED, data_fd, 0);
	close(data_fd);

	/* get hex hash value from get packet */
	binary2hex((uint8_t*)pkt->data,CHUNK_HSIZE,hash_hex);

	/* TODO: use Ihave file for comparing */
	/* get desired chunk data and put into packets */
	while(fgets(buffer,60,index_file) != NULL) {

		/* incorrect formated line */
		if(sscanf(buffer,"%s %s\n",index_buffer,hash_buffer) < 2 ) {
			fprintf(stderr, "wrong file format!\n");
			fclose(index_file);
			munmap(src,statbuf.st_size);
			return NULL;
		} else {
			/* check for hash match */
			if(memcmp(hash_hex,hash_buffer,HASH_HEX_SIZE) == 0) {
				/* Get index of the chunk based on hash match*/
				index = atoi(index_buffer);
				/* Divide data of a chunk into 512 pkts */
				printf(" get_resp : creating chunks\n");
				for (i = 0;i < 512;i++) {
					// load data
					create_chunk_pkts(PKT_DATA, 1040, i+1, 0, src+index*CHUNK_SIZE+i*1024, 
							&(peer_send_info[peer->id].data[1040*i]));
				}
				printf(" get_resp : created chunks\n");
				munmap(src,statbuf.st_size);
			}
		}
	}
	fclose(index_file);

	(peer_send_info[peer->id].npkts_sent) = 0;
	notify_chunk_trans_start(peer->id, 0);

	return;
}
  
void send_ack(int peer_num, int seq_num, int chunk_num) {

	if(seq_num > 512)        // max_num of packets possible for a chunk: access using some global
	{
		printf("send_ack: Total Packet received\n");
		seq_num = 512;
    }

	bt_peer_t* peer = bt_peer_get_addr(&config, peer_num);
	data_packet_t* ack_pkt = create_packet(PKT_ACK, HDR_LEN, 0, seq_num, NULL);
	hostToNet(ack_pkt);
	spiffy_sendto(peer_sfd, ack_pkt, 16, 0, (struct sockaddr *) &peer->addr, sizeof(peer->addr));
	printf("send_ack - peer_num:%d  seq_num:%d   chunk_num:%d\n", peer_num, seq_num, chunk_num);
	free(ack_pkt);
}

int testing_done = 0;

/* Invoked by flow control: application needs to implement these */
void send_chunk(int peer_num, int seq_num, int chunk_num) {
    
	if(seq_num > 512)        // max_num of packets possible for a chunk: access using some global
	{
		printf("send_chunk: Transmission done\n");
        return;
	}

	printf("send_chunk - peer_num:%d  seq_num:%d   chunk_num:%d\n", peer_num, seq_num, chunk_num);
    bt_peer_t* peer = bt_peer_get_addr(&config, peer_num);
	(((data_packet_t*)(&(peer_send_info[peer_num].data[1040*(seq_num-1)])))->header.packet_len) = 1040;
	hostToNet(&(peer_send_info[peer_num].data[1040*(seq_num-1)]));
	spiffy_sendto(peer_sfd, &(peer_send_info[peer_num].data[1040*(seq_num-1)]), 1040, 0, (struct sockaddr *) &peer->addr, sizeof(peer->addr));
    /*if(seq_num != 500)
	  {
	  spiffy_sendto(peer_sfd, &(peer_send_info[peer_num].data[1040*(seq_num-1)]), 1040, 0, (struct sockaddr *) &peer->addr, sizeof(peer->addr));
	  }
	  else
	  {
	  if(testing_done == 1)
	  {
	  spiffy_sendto(peer_sfd, &(peer_send_info[peer_num].data[1040*(seq_num-1)]), 1040, 0, (struct sockaddr *) &peer->addr, sizeof(peer->addr));
	  }
	  else
	  {
	  testing_done = 1;
	  }
	  }*/
	(peer_send_info[peer_num].npkts_sent)++;
	notify_packet_sent(peer_num, seq_num, chunk_num);
}

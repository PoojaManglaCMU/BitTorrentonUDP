#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>
#include <sys/types.h>
#include <unistd.h>
#include "whohas_handler.h"
#include "bt_parse.h"
#include "spiffy.h"
#include "chunk.h"

static const char *type2str[] = { "WHOHAS",
                                  "IHAVE",
                                  "GET",
                                  "DATA",
                                  "ACK",
                                  "DENIED" };

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
            //print_hash(hash);
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

data_packet_t *create_packet(int type, short pkt_len, u_int seq,
                            u_int ack, char *data) {
    data_packet_t *pkt = (data_packet_t *)malloc(sizeof(data_packet_t));
    pkt->header.magicnum = 15441; /* Magic number */
    pkt->header.version = 1;      /* Version number */
    pkt->header.packet_type = type; /* Packet Type */
    pkt->header.header_len = HDR_LEN;    /* Header length is always 16 */
    pkt->header.packet_len = pkt_len;
    pkt->header.seq_num = seq;
    pkt->header.ack_num = ack;
    if( pkt->data != NULL) 
        memcpy(pkt->data, data, pkt_len - HDR_LEN);
    return pkt;
}

void packet_sender(data_packet_t* pkt, struct sockaddr* to, int sock) {
    int pkt_size = pkt->header.packet_len;
    int type = pkt->header.packet_type;
    fprintf(stderr, "send %s pkt!*********\n", type2str[type]);
    print_pkt(pkt);
    hostToNet(pkt);
    spiffy_sendto(sock, pkt, pkt_size, 0, to, sizeof(*to));
    netToHost(pkt);
}

void store_data(chunk_t* chunk, data_packet_t* pkt) {
    int size = pkt->header.packet_len - pkt->header.header_len;
    memcpy(chunk->data+chunk->cur_size,pkt->data,size);
    chunk->cur_size += size;
}

/* Check if data for a  chunk has finished downloading */
int is_chunk_finished(chunk_t* chunk, bt_config_t *config) {
    FILE*   fp_chunks;
    FILE*   fp_data;
    char    line[MAX_LINE_SIZE];
    char    temp_hash[CHUNK_HSIZE];
    char* ptr_hash;
    int hash_matched = 0;
    int cur_size = chunk->cur_size;
    float kb = cur_size / 1024;
    int i,k, offset;
    char datafile[BT_FILENAME_LEN];
    fprintf(stderr, "check finished!!!\n");
    if (cur_size != CHUNK_SIZE) {
	    fprintf(stderr, "Not finished yet, cur_size = %.5f\n", kb);
        return 0;
    }
    uint8_t hash[CHUNK_HSIZE];
    // get hash code
    shahash((uint8_t*)chunk->data,cur_size,hash);

    /* open the chunk file */
    if(!(fp_chunks = fopen(config->who_has_chunk_file, "r")))
    {
      printf("Error opening chunkfile\n");
      exit(-1);
    }
    int index = 0;
    // check hash code
    while(fgets(line, MAX_LINE_SIZE, fp_chunks) != NULL)
    {
        index++;
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
                temp_hash[k] = text2num(ptr_hash);
                ptr_hash += 2;
            }
            hash_matched = 1;
            if(memcmp(hash, temp_hash, CHUNK_HSIZE))
		hash_matched = 0;
          /*  for(k=0; k<CHUNK_HSIZE; k++)
            {
                if(temp_hash[k] != hash)
                {
                    hash_matched = 0;
                    break;
                }

            }*/

            if (hash_matched == 1)
            {
                offset = index*512*1024;
                // Open a data file and write the data at that offset
                fp_data = fopen(datafile, "a");
                //int offset_file = lseek(fp_data, offset,SEEK_SET);
               // fprintf(fp_data, "%s", chunk->data); 
                //FILE * f = fopen ("x.txt", "w");
                fseek (fp_data, offset, SEEK_SET);
                fwrite (chunk->data, 1, 1, fp_data);
 
                chunk->downloaded = 1;
                // Set peer to available
                return 1;
            }
       } 

       return -1;
}

/*void recur_send(data_packet_t** pkt_array, struct sockaddr* to) {
	while(chunk not completely transferred) {
		fprintf(stderr, "send data:%d!!!!\n",conn->l_available);
		//print_pkt((data_packet_t*)(conn->pkt_array[conn->l_available-1]));
		packet_sender((data_packet_t*)(conn->pkt_array[conn->l_available-1]),
			          to);
		conn->l_available++;
	}
}*/

int init_mapping_per_get_req(char* chunkFile, char* output_file) {
    mapping_per_get_req_t mapping_per_get_req;
    bt_config_t config;
    FILE* file = fopen(chunkFile,"r");
    if( file == NULL)
        return -1; // fail to open mapping_per_get_req file

    int line_number = 0;
    int i = 0;
    char read_buffer[BUF_SIZE];
    char hash_buffer[CHUNK_HSIZE*2];

    
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
    
    while (fgets(read_buffer,BUF_SIZE,file)) {
        sscanf(read_buffer,"%d %s",&(mapping_per_get_req.chunks[i].id),hash_buffer);
        /* convert ascii to binary hash code */
        hex2binary(hash_buffer,CHUNK_HSIZE*2,mapping_per_get_req.chunks[i].hash);        
        memset(read_buffer,0,BUF_SIZE);
        memset(hash_buffer,0,CHUNK_HSIZE*2);
        mapping_per_get_req.chunks[i].providers = NULL;
        mapping_per_get_req.chunks[i].num_p = 0;
        mapping_per_get_req.chunks[i].cur_size = 0;
        mapping_per_get_req.chunks[i].data = malloc(sizeof(char)*512*1024);
        i++;
    }    
    fclose(file);
    // set output file address and format
    strcpy(config.output_file,output_file);
    strcpy(mapping_per_get_req.get_chunk_file,chunkFile);
    config.output_file[strlen(output_file)] = '\0';
    mapping_per_get_req.get_chunk_file[strlen(mapping_per_get_req.get_chunk_file)] = '\0';

    return 0;
}


int whohas_req(char *chunkfile, int sock, bt_config_t *config)
{
    printf("whohas_req ENTRY: %s\n", chunkfile);

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
        //memcpy(whohas_packet + offset, line+i+1, CHUNK_HSIZE);
        for(k=0; k<CHUNK_HSIZE; k++)
        {
            *ptr = text2num(ptr_hash); 
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
    printf("Printing WHOHAS PACKET\n");

    for(i=0; i<20; i++)
        printf("%2X ", whohas_packet[i]);
    printf("\n");
    for(i=20; i<40; i++)
        printf("%2X ", whohas_packet[i]);
    printf("\n");
    for(i=40; i<60; i++)
        printf("%2X ", whohas_packet[i]);
    printf("\n");

    while (peer != NULL) {
            printf("Entered while loop\n");
            printf("size of whohas packet is %d", strlen(whohas_packet));
	    whohas = spiffy_sendto(sock, whohas_packet, 60, 0, 
                      (struct sockaddr *) &peer->addr, sizeof(peer->addr));
	    printf("packet sent to peer %d ip address %s:%d and size of packet sent is %zu \n", peer->id, inet_ntoa(peer->addr.sin_addr), ntohs(peer->addr.sin_port), whohas);
	    if (whohas == -1)
		    printf("error\n");
	    peer = peer->next;
    }

    fclose(fp_chunks);
    return 0;

}

int whohas_resp(char *whohas_packet, char* chunkfile, int sock, bt_config_t *config)
{

    assert(whohas_packet != NULL);
    printf("whohas_resp ENTRY: %s\n", chunkfile);

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
	    printf("Inside the loop with t: %d\n", t);
            hash_matched = 1;

           /* for(k=0; k<CHUNK_HSIZE; k++)
            {
                temp_hash[k]    = text2num(ptr_hash); 
                ptr_hash += 2;
            }*/

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

                //break;
            }
        }

    }

    prep_ihave_hdr(ihave_packet, nchunks);
    printf("Printing IHAVE PACKET\n");

    for(i=0; i<20; i++)
        printf("%2X ", ihave_packet[i]);
    printf("\n");
    for(i=20; i<40; i++)
        printf("%2X ", ihave_packet[i]);
    printf("\n");
    for(i=40; i<60; i++)
        printf("%2X ", ihave_packet[i]);
    printf("\n");


    printf("Printing WHOHAS PACKET\n");
    for(i=0; i<20; i++)
        printf("%2X ", whohas_packet[i]);
    printf("\n");
    for(i=20; i<40; i++)
        printf("%2X ", whohas_packet[i]);
    printf("\n");
    for(i=40; i<60; i++)
        printf("%2X ", whohas_packet[i]);
    printf("\n");
    /* send to all peers */
    /*for(i=0; i<num_peers; i++)
        send(whohas_packet);*/
  
    if(nchunks != 0){
	while (peer != NULL) {
            printf("Entered while loop\n");
            printf("size of ihave packet is %d", strlen(ihave_packet));
            ihave = spiffy_sendto(sock, ihave_packet, (20+nchunks*20), 0,
                      (struct sockaddr *) &peer->addr, sizeof(peer->addr));
            printf("size of packet sent is %zu \n", ihave);
            if (ihave == -1)
                    printf("error\n");
            peer = peer->next;
    }
 }

    fclose(fp_chunks);
    return 0;
}

void prep_whohas_hdr(char* whohas_packet, int nchunks)
{
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

void prep_ihave_hdr(char* ihave_packet, int nchunks)
{
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

char text2num(char* input)
{
    int num = 0;

    int d1 = char2digit(input[0]);
    int d0 = char2digit(input[1]);

    num = 16*d1 + d0;
    //printf("num: %d\n", num);
    return (char)num;
}

int char2digit(char ch)
{
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

int match_need(uint8_t *hash, mapping_per_get_req_t mapping_per_get_req) {
    int i;
    chunk_t* chk = mapping_per_get_req.chunks;
    if (mapping_per_get_req.num_chunk == 0)
        return -1;

    // TODO : Add more checks. Basic checks added for now
    for (i = 0; i < mapping_per_get_req.num_chunk; i++) {
        if (chk[i].providers != NULL)
            continue;
        if (memcmp(hash, chk[i].hash, CHUNK_HSIZE)) {
            continue;
        } else {
     return i;        
    }
}
    return -1;
}

void send_get_request(char* hash, bt_peer_t *peer, int sock)
{
        data_packet_t *packet; // GET packet
	packet = create_packet(PKT_GET,
                               HDR_LEN + CHUNK_HSIZE,
                               0, 0, (char *)hash);
        packet_sender(packet, peer, sock);
}  


void ihave_resp_recv_handler (char *ihave_packet, int sock, bt_config_t *config, struct sockaddr *from)
{
    assert(ihave_packet != NULL);
    char chunk_hash[CHUNK_HSIZE];
    bt_peer_t* peer = bt_peer_get(&config,(struct sockaddr *)&from);
    mapping_per_get_req_t mapping_per_get_req;
    chunk_t* chk = mapping_per_get_req.chunks;
    uint8_t *hash; // incoming hash to meet my needs
    int i, match_idx;
    int nuchunks_incoming = (unsigned char)(ihave_packet[HDR_LEN+0]);
    if (nuchunks_incoming == 0)
        return NULL;
    hash = (uint8_t *)(ihave_packet[HDR_LEN+4]); // the start of hash
    for (i = 0; i < nuchunks_incoming; i++) {
			match_idx = match_need(hash, mapping_per_get_req);
			if (match_idx != -1) {
					chk[match_idx].providers = peer;
					chk[match_idx].num_p = 1;
					mapping_per_get_req.num_downloaded |= (1 << match_idx);
					send_get_request((char *)hash, peer, sock);
			}
			hash += CHUNK_HSIZE;
	} 
}		

/** @brief Generate data pkt array
 *  @param pkt incoming get pkt 
 *  @return NULL if failed to generate pkt.
 *          data packet array 
 */
/* void data_packet_t** DATA_pkt_array_maker(data_packet_t* pkt) {
    data_packet_t** data_pkt_array = (data_packet_t**)malloc(512*sizeof(data_packet_t*));
    int index = 0, i = 0;
    char hash_buffer[HASH_HEX_SIZE] = {0};
    char hash_hex[HASH_HEX_SIZE] = {0};
    char buffer[BT_FILENAME_LEN+5] = {0};
    char datafile[BT_FILENAME_LEN] = {0};
    char index_buffer[5] = {0};
    char *src;
    struct stat statbuf;

    FILE* index_file = fopen(config.chunk_file,"r");
    int data_fd;

    if(index_file == NULL) {
        fprintf(stderr, "Fail to open chunk file!!\n"); 
        return NULL;
    }
    // match chunk hash from chunk file, get index
    // offset = 512*1024*index
    // read 512*1024 bytes of data from that offset
    fgets(buffer, BT_FILENAME_LEN, index_file);

    sscanf(buffer,"File: %s\n",datafile);
    // skip the next line
    fgets(buffer,BT_FILENAME_LEN,index_file);

    // open file to read 
    data_fd = open(datafile, O_RDONLY);
    fstat (data_fd, &statbuf);
    src = mmap(0, statbuf.st_size, PROT_READ, MAP_SHARED, data_fd, 0);
    close(data_fd);
    binary2hex((uint8_t*)pkt->data,CHUNK_HSIZE,hash_hex);
    while(fgets(buffer,60,index_file) != NULL) {
        if(sscanf(buffer,"%s %s\n",index_buffer,hash_buffer) < 2 ) {
            // wrong file format!
            fprintf(stderr, "wrong file format!\n");
            fclose(index_file);
            munmap(src,statbuf.st_size);
            return NULL;
        } else {
            if(memcmp(hash_hex,hash_buffer,HASH_HEX_SIZE) == 0) {
                index = atoi(index_buffer);
                //fseek(data_file,index,SEEK_SET);
                for (i = 0;i < 512;i++) {
                    // load data
                    data_pkt_array[i] = packet_maker(PKT_DATA,
                                                1040,i+1,0,
                                                src+index*CHUNK_SIZE+i*1024);
                }
                munmap(src,statbuf.st_size);
                print_pkt((data_packet_t*)(data_pkt_array[0]));
                return data_pkt_array;
            }
        }
    }
    return NULL;
}*/

void data_packet_handler(char* buf, struct sockaddr *from, int sock, bt_config_t *config) 
{  
	chunk_t *chunk;
        data_packet_t* ack_pkt;
	fprintf(stderr, "receive data pkt,seq%d\n",
                         ((data_packet_t*)buf)->header.seq_num);
	   // TODO storing data in a chunk structure for now. 
	   // Will store in file once completely downloaded
	   store_data(chunk, (data_packet_t*)buf);
           int finished = is_chunk_finished(chunk, config);
            if(finished == 1) {
	   // Construct ACK pkt
	   //data_packet_t* ack_pkt = ACK_maker(++(down_conn->next_pkt),
	     //                                         (data_packet_t*)buf);
	   // send ACK pkt
	  packet_sender(ack_pkt,(struct sockaddr *) &from, sock);
         } else if (finished == -1) {
           // send GET request again
         }
}

void get_resp(char *buf, bt_config_t config, struct sockaddr *from, int sock)
{
/*  if (sending to all peers i.e. no peer free, send a denied packet) {
		  data_packet_t* denied_pkt = DENIED_maker();
		  //send denied pkt
		  packet_sender(denied_pkt,(struct sockaddr*) &from, sock);
	} else {
       // get data pkt array
    data_packet_t** data_pkt_array = DATA_pkt_array_maker((data_packet_t*)buf);
    //recur_send(data_pkt_array,(struct sockaddr*) &from);
    }*/
}
  

	

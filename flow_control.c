//extern void send_chunk(int peer_num, int seq_num, int chunk_num);
extern void send_ack(int peer_num, int seq_num, int chunk_num);
/* should invoke notify_packet_sent */
/* applicable only for data packet */
/* packet b/w last_packet_acked and last_pkt_avail must be buffered */
/* implement this either by buffering or regenerate from datab file */

/* assumption one peer : one connection in one direction */
/* i.e. peer1 can't download two chunks at a time from same peer */

/* which chunk is currently being download from that peer: outside this module */

#include <stdio.h>

/*** Sender Related Functionalities ***/

#define MAX_PEER_NUMS		20
#define	MAX_CONNECTION		MAX_PEER_NUMS
#define	MAX_PKT_SIZE		1024
#define	MAX_PKT_PER_CHUNK	(512*1024)/MAX_PKT_SIZE
#define MAX_SEQ_NUM			MAX_PKT_PER_CHUNK
#define	INITIAL_SEND_CWND	8
#define	INITIAL_RECV_CWND	8

unsigned get_ts();


typedef struct
{
	unsigned ts;
}timer_t;

typedef struct
{
	int is_recv;
}recv_pkt_t;

typedef struct 
{
	unsigned 	cwnd;
	unsigned 	last_pkt_sent;
	unsigned 	last_pkt_acked;
	unsigned 	last_pkt_avail;
	unsigned	dup_ack_num;
	unsigned	n_dup_acks;
	timer_t  	send_ts[MAX_PKT_PER_CHUNK];

}sender_cwnd_t;

typedef struct 
{
	unsigned 	cwnd;
	unsigned 	next_pkt_expec;
	unsigned 	last_pkt_read;
	unsigned 	last_pkt_recv;		/* last pkt in seq */
	unsigned	last_pkt_alwd;
	recv_pkt_t	recv_pkts[MAX_PKT_PER_CHUNK];

}receiver_cwnd_t;


sender_cwnd_t		sender_cwnd[MAX_PEER_NUMS];
receiver_cwnd_t		receiver_cwnd[MAX_PEER_NUMS];

void flow_ctrl_init()
{
	int i, j;

	for(i=0; i<MAX_PEER_NUMS; i++)
	{
		sender_cwnd[i].cwnd 			= 8;
		sender_cwnd[i].last_pkt_sent	= 0;
		sender_cwnd[i].last_pkt_acked 	= 0;
		sender_cwnd[i].last_pkt_avail	= sender_cwnd[i].last_pkt_acked + sender_cwnd[i].cwnd ;
		sender_cwnd[i].dup_ack_num		= 0;
		sender_cwnd[i].n_dup_acks		= 0;
		for(j = 0; j<MAX_SEQ_NUM; j++)
			sender_cwnd[i].send_ts[j].ts = 0;

		receiver_cwnd[i].cwnd 			= INITIAL_RECV_CWND;
		receiver_cwnd[i].next_pkt_expec = 1;
		receiver_cwnd[i].last_pkt_read 	= 0;
		receiver_cwnd[i].last_pkt_recv 	= 0;
		receiver_cwnd[i].last_pkt_alwd 	= receiver_cwnd[i].last_pkt_read + receiver_cwnd[i].cwnd;
		for( j = 0; j<MAX_SEQ_NUM; j++)
			receiver_cwnd[i].recv_pkts[j].is_recv = 0;
	}
}

/* should be invoked on a get request */
void notify_chunk_trans_start(int peer_num, int chunk_num)
{
	int j;
	sender_cwnd[peer_num].cwnd 				= 8;
	sender_cwnd[peer_num].last_pkt_sent		= 0;
	sender_cwnd[peer_num].last_pkt_acked 	= 0;
	sender_cwnd[peer_num].last_pkt_avail	= sender_cwnd[peer_num].last_pkt_acked + sender_cwnd[peer_num].cwnd ;
	sender_cwnd[peer_num].dup_ack_num		= 0;
	sender_cwnd[peer_num].n_dup_acks		= 0;
	for(j = 0; j<MAX_SEQ_NUM; j++)
		sender_cwnd[peer_num].send_ts[j].ts = 0;

	while(sender_cwnd[peer_num].last_pkt_sent < sender_cwnd[peer_num].last_pkt_avail)
		send_chunk(peer_num, ++(sender_cwnd[peer_num].last_pkt_sent), chunk_num);

}

int update_sender_window(int peer_num, int ack_num)
{
	int resend_seq = 0;

	if(ack_num > sender_cwnd[peer_num].last_pkt_sent)	/* error condition */
		return -1;

	/* handle duplicate ack */
	if(ack_num <= sender_cwnd[peer_num].last_pkt_acked)
	{
		if(ack_num == sender_cwnd[peer_num].dup_ack_num)
		{
			sender_cwnd[peer_num].n_dup_acks++;
			if(sender_cwnd[peer_num].n_dup_acks >= 3)
			{
				resend_seq = sender_cwnd[peer_num].dup_ack_num;
				sender_cwnd[peer_num].dup_ack_num = 0;
				sender_cwnd[peer_num].n_dup_acks  = 0;
				return (resend_seq+1);		/* packet that needs to be resend */
			}

		}
		else
		{
			/* this is the second ack */
			sender_cwnd[peer_num].n_dup_acks = 2;			/* TODO: check - total 3 acks ?*/
			sender_cwnd[peer_num].dup_ack_num = ack_num;
			return 0;
		}
	}

	sender_cwnd[peer_num].last_pkt_acked 	= ack_num;
	sender_cwnd[peer_num].last_pkt_avail	= sender_cwnd[peer_num].last_pkt_acked + sender_cwnd[peer_num].cwnd ;

	return 0;
}

void notify_packet_sent(int peer_num, int seq_num, int chunk_num)
{
	/* start timer and keep TS */
	sender_cwnd[peer_num].send_ts[seq_num].ts = get_ts();
}

void notify_ack_recvied(int peer_num, int ack_num, int chunk_num)
{
	int seq_num = 0;

	/* stop the timer for that packet */
	sender_cwnd[peer_num].send_ts[ack_num].ts = 0;

	/* update the send sliding window */
	seq_num = update_sender_window(peer_num, ack_num);

	if(seq_num > 0)		/* resend triggered by duplicate acks */
		send_chunk(peer_num, seq_num, chunk_num);
	else
	{
		while(sender_cwnd[peer_num].last_pkt_sent < sender_cwnd[peer_num].last_pkt_avail)
			send_chunk(peer_num, ++(sender_cwnd[peer_num].last_pkt_sent), chunk_num);

	}
}

/* should be invoked on sending a get request */
void notify_chunk_dwnl_start(int peer_num, int chunk_num)
{
	int j;
	receiver_cwnd[peer_num].cwnd 			= INITIAL_RECV_CWND;
	receiver_cwnd[peer_num].next_pkt_expec 	= 1;
	receiver_cwnd[peer_num].last_pkt_read 	= 0;
	receiver_cwnd[peer_num].last_pkt_recv 	= 0;
	receiver_cwnd[peer_num].last_pkt_alwd 	= receiver_cwnd[peer_num].last_pkt_read + receiver_cwnd[peer_num].cwnd;
	for(j = 0; j<MAX_SEQ_NUM; j++)
		receiver_cwnd[peer_num].recv_pkts[j].is_recv = 0;
}

/* should be invoked when correct packet of a chunk received */
int update_receiver_window(int peer_num, int seq_num)
{
	//printf("entry: seq_num: %d\n", seq_num);
	int i;

	/* outside window: discard it: return -1*/
	if(seq_num <= receiver_cwnd[peer_num].last_pkt_read)
	{
		//printf("last_pkt_read: %d\n", receiver_cwnd[peer_num].last_pkt_read);
		return -1;
	}


	if(seq_num > receiver_cwnd[peer_num].last_pkt_alwd)
	{
		//printf("last_pkt_alwd: %d\n", receiver_cwnd[peer_num].last_pkt_alwd);
		//return -1;		//TODO: check correct behavior
		return receiver_cwnd[peer_num].next_pkt_expec - 1;
	}

	/* TODO: should we send some ack here also */

	/* update the recv of chunk within the pkt */
	receiver_cwnd[peer_num].recv_pkts[seq_num].is_recv = 1;

	/* invoke retransimision if some prev packet is missing */
	if(seq_num != receiver_cwnd[peer_num].next_pkt_expec)
	{
		//printf("next_pkt_expec: %d\n", receiver_cwnd[peer_num].next_pkt_expec);
		return (receiver_cwnd[peer_num].next_pkt_expec-1);				//TODO: check this		
	}

	/* recived expected frame: update window and send cumulative ack */
	for(i = (receiver_cwnd[peer_num].next_pkt_expec+1); i<=receiver_cwnd[peer_num].last_pkt_alwd; i++)
	{
		if(!(receiver_cwnd[peer_num].recv_pkts[i].is_recv))
			break;
	}
	
	receiver_cwnd[peer_num].next_pkt_expec 	= i;
	receiver_cwnd[peer_num].last_pkt_read 	= i-1;
	receiver_cwnd[peer_num].last_pkt_alwd 	= receiver_cwnd[peer_num].last_pkt_read + receiver_cwnd[peer_num].cwnd;

	//printf("next_expec: %d  last_read: %d  last_alwd: %d\n", receiver_cwnd[peer_num].next_pkt_expec, receiver_cwnd[peer_num].last_pkt_read, receiver_cwnd[peer_num].last_pkt_alwd);
	//printf("exit: (i-1): %d\n", (i-1));
	return (i-1);
}

int notify_packet_recv(int peer_num, int seq_num, int chunk_num)
{
	int next_seq_num;

	/* update the receiver sliding window */
	next_seq_num = update_receiver_window(peer_num, seq_num);

	if(next_seq_num < 0)			/* -1 to discard the packet: out of window */
		return -1;

	send_ack(peer_num, next_seq_num, chunk_num);

	return 0;
}

void notify_ack_sent(int peer_num, int ack_num, int chunk_num)
{
	return;
}

void timer_timeout_check()
{
	/* scan through timer lists */
	/* timer identifier: seqNum, peerNum */

	/* check for timers which have expired */

	/* resend that particular packet */
	/* invoke the send for the next packet in seqNum */

	/* packet identifier:  seqNum, peerNum */
	/* need to maintain which chunk is being exchanged with which peer */
}

unsigned get_ts()
{
	return 1000;
}

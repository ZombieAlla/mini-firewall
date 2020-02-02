
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <string.h>
#include <time.h>
#include <getopt.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include<net/ethernet.h>

#include <libnetfilter_queue/libnetfilter_queue.h>


#define SHELLSCRIPT_INPUT "\
sudo iptables -A INPUT -j NFQUEUE --queue-num 0\n\
"

#define SHELLSCRIPT_OUTPUT "\
sudo iptables -D INPUT -j NFQUEUE --queue-num 0\n\
"
//helper function to count substring in string
int countFreq(const char *, const char *); 

//Struct to keep input Data
struct Input 
{
            char * ip;
            int port;
	    int num_of_iter;
	    char * substr;
	    int i;
};

struct Input in;

//otput out.txt file
FILE *logfile;

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int i=0;
	int id = 0;
	int header_size;
	int countFrequency1=0;
	int countFrequency2=0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;
	int ssport;

	

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		//printf("hw_protocol=0x%04x hook=%u id=%u ",
		//	ntohs(ph->hw_protocol), ph->hook, id);
	}
/*
	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);*/

	ret = nfq_get_payload(tb, &data);
	/*if (ret >= 0)
		printf("payload_len=%d ", ret);

	fputc('\n', stdout);*/


    // parse the packet headers
    struct iphdr *iph = ((struct iphdr *) data);
    unsigned short iphdrlen = iph->ihl*4;
    //fprintf(stdout,"iphdrlen is %d\n", iphdrlen);

    // display IP HEADERS : ip.h line 45
    // ntohs convert short unsigned int, ntohl do the same for long unsigned int
    /*fprintf(stdout, "IP{v=%u; ihl=%u; tos=%u; tot_len=%u; id=%u; ttl=%u; protocol=%u; " ,iph->version, iph->ihl*4, iph->tos, ntohs(iph->tot_len), ntohs(iph->id), iph->ttl, iph->protocol);*/


    const char *saddr = inet_ntoa(*(struct in_addr *)&iph->saddr);
    //fprintf(stdout,"saddr=%s; ",saddr);
    
    countFrequency1 = countFreq(saddr,in.ip);
    //fprintf(stdout,"\nCountFreq saddr=%d\n",countFrequency1);

    

    //char *daddr = inet_ntoa(*(struct in_addr *)&iph->daddr);
    //fprintf(stdout,"daddr=%s}\n",daddr);
    
    //fprintf(stdout,"saddr=%s; daddr=%s",saddr,daddr);
    //fprintf(stdout,"\nIn.ip is =%s\n",in.ip);
    //countFrequency2 = countFreq(daddr,in.ip);
    //fprintf(stdout,"\nCountFreq daddr=%d\n",countFrequency2);	

    //1.Check that saddr appears in the ip
    //if ((countFrequency1==0) && (countFrequency2==0)){
    if (countFrequency1==0){
	in.i-=1;
	return id;
    }

    // if protocol is tcp
    if (iph->protocol == 6){
        // extract tcp header from packet
        /* Calculate the size of the IP Header. iph->ihl contains the number of 32 bit
        words that represent the header size. Therfore to get the number of bytes
        multiple this number by 4 */
        struct tcphdr *tcp = ((struct tcphdr *) (data + (iph->ihl << 2)));
    
        /* Calculate the size of the TCP Header. tcp->doff contains the number of 32 bit
        words that represent the header size. Therfore to get the number of bytes
        multiple this number by 4 */
        //int tcphdr_size = (tcp->doff << 2); 

        /* to print the TCP headers, we access the structure defined in tcp.h line 89
        and convert values from hexadecimal to ascii */
        /*fprintf(stdout, "TCP{sport=%u; dport=%u; seq=%u; ack_seq=%u; flags=u%ua%up%ur%us%uf%u; window=%u; urg=%u}\n",
            ntohs(tcp->source), ntohs(tcp->dest), ntohl(tcp->seq), ntohl(tcp->ack_seq)
            ,tcp->urg, tcp->ack, tcp->psh, tcp->rst, tcp->syn, tcp->fin, ntohs(tcp->window), tcp->urg_ptr);
	*/
       //2.Check source port
       ssport= ntohs(tcp->source);
       /*if (ssport!=in.port){
	  in.i-=1;
	  return id;
       }*/
	

	//header_size =  sizeof(struct ethhdr) + iphdrlen + tcp->doff*4;
 	//header size of tcp is from 20 to 60 bytes
	header_size =  iphdrlen + tcp->doff*4;	
	//header_size =  iphdrlen + tcp->doff;
	//fprintf(stdout,"header_size is %d\n", header_size);
	/*fprintf(stdout, "\nData is printed\n");
	PrintData(data + header_size , ret - header_size );
	fprintf(stdout, "\nData is finished\n");*/
    }

    // if protocol is udp
    if(iph->protocol == 17){
        struct udphdr *udp = ((struct udphdr *) (data + (iph->ihl << 2)));
        /*fprintf(stdout,"UDP{sport=%u; dport=%u; len=%u}\n",
            ntohs(udp->source), ntohs(udp->dest), udp->len);*/
	//header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof(udp);

       //2.Check source port
       ssport= ntohs(udp->source);
       /*if (ssport!=in.port){
	  in.i-=1;
	  return id;
       }*/

	//UDP header is 8-bytes fixed and simple header
	header_size =  iphdrlen + 8;
	//fprintf(stdout,"header_size is %d\n", header_size);
	/*fprintf(stdout, "\nData is printed\n");
	PrintData(data + header_size , ret - header_size);
	fprintf(stdout, "\nData is finished\n");*/
    }

    //fprintf(stdout,"\n");


       //2.Check source port
       if (ssport!=in.port){
	  in.i-=1;
	  return id;
       }

       //3.Check substring in payload
       /*char * payload = data+header_size;
       int countFrequency = countFreq(in.substr,payload);
       if (countFrequency==0){
	  in.i-=1;
	  return id;
       }*/
	int total_count=0;
	int len = strlen(in.substr);
	for(i=header_size;i<ret;i++){
	int temp_count=0;
		for(int j=0;j<len;j++){
        		if (in.substr[j]==data[i+j]) temp_count++;
			else continue;
    		}
		if (len==temp_count) total_count++;
    	}
	if (total_count==0){
	  in.i-=1;
	  return id;
       }


//Printing the payload in hexa
	//fprintf(logfile , "\n");
    	fprintf(logfile,"payload: ");
	//printf("payload: ");
	//printf("substr len is %d:\n",len);
    	for(i=header_size;i<ret;i++){
        	//printf("%x ", data[i] & 0xff);
		//printf("%1X ", data[i]);
		//printf("%c ", data[i]);
		fprintf(logfile,"%c", data[i]);
		/*int temp_count=0;
		for(int j=0;j<len;j++){
        		if (in.substr[j]==data[i+j]) temp_count++;
			else continue;
    		}
		if (len==temp_count) total_count++;*/
    	}
	//printf("\n");
     	/*for(i=44;i<ret;i++){
        	data[i]=0;
    	} */
	
	fprintf(logfile,"appearances: %d\n",total_count);
	//fprintf(logfile,"\nappearance: %d\n",countFrequency);
	//fprintf(logfile,"Source Ip is %s\n", saddr);
	//fprintf(logfile,"Protocol is %d\n", iph->protocol);
	//fprintf(logfile,"S port is %d\n", ssport);
	fprintf(logfile , "\n###########################################################\n\n");

	return id;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	//printf("entering callback\n");
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	if (argc!=5) {
		printf("Wrong number of parameters were inserted. Please insert 4\n");
		exit(0);
	}
	system(SHELLSCRIPT_INPUT);
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	//int i;

	in.ip = argv[1];
	in.port = atoi(argv[2]);
	in.num_of_iter=atoi(argv[3]);
	in.substr = argv[4];
	in.i=0;
	
	/*char *ip=argv[1];
	//printf("ip is %s \n",ip);
	//printf("string is %s \n",str);
	int port=atoi(argv[2]);
	int num_of_iterations=atoi(argv[3]);
	char *str=argv[4];
	//printf("num of iterations is:%d\n",num_of_iterations);*/
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	remove("out.txt");
        logfile=fopen("out.txt","w");
        if(logfile==NULL) 
        {
            printf("Unable to create file.");
        }

	//printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	//printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	//printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	//printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	//printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (in.i=0;in.i<in.num_of_iter;++in.i) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			//printf("\n\ni is %d\n",in.i);
			//printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	//printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	//printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	//printf("closing library handle\n");
	nfq_close(h);
	
	system(SHELLSCRIPT_OUTPUT);

	exit(0);
}


int countFreq(const char *string2find, const char *txt) 
{
	//printf("\nstring2find is :%s\n",string2find);
	//printf("\ntxt is :%s\n",txt);
	int count = 0;
	while(txt = strstr(txt, string2find))
	{
	   count++;
	   txt += strlen(string2find);
	} 
  	return count;
}

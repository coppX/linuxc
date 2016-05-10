#include"unp.h"
#include<netinet/in_systm.h>
#include<netinet/ip.h>
#include<netinet/ip_icmp.h>
#include<netinet/udp.h>

#define BUFSIZE       1500
struct rec{
    u_short   rec_seq;
    u_short   rec_ttl;
    struct timeval  rec_tv;
};
char  recvbuf[BUFSIZE];
char  sendbuf[BUFSIZE];
int datalen;
char *host;
u_short sport,dport;
int nsent;
pid_t pid;
int probe,nprobles;
int sendfd,recvfd;
int ttl,max_ttl;
int verbase;

const char *icmpcode_v4(int);
const char *icmpcode_v6(int);
int recv_v4(int,struct timeval);
int recv_v6(int,struct timeval);
void sig_alrm(int);
void traceloop(void);
void tv_sub(struct timeval *,struct timeval *);
struct proto{
      const char *(*icmpcode)(int);
      int (*recv)(int,struct timeval *);
      struct sockaddr *sasend;
      struct sockaddr *sarecv;
      struct sockaddr *salast;
      struct sockaddr *sabind;
      socklen_t salen;
      int icmpproto;
      int ttllevel;
      int ttloptname;
}*pr;
#ifdef    IPV6

#include<netinet/ip6.h>
#include<netinet/icmp6.h>

#endif


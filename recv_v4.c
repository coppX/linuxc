#include "trace.h"
extern int gotalarm;
int recv_v4(int seq,struct timeval *tv)
{
      int hlenl,hlen2,icmplen,ret;
      socklen_t len;
      ssize_t n;
      struct ip *ip,*hip;
      struct icmp *icmp;
      struct udphdr *udp;
      gotalarm=0;
      alarm(3);
      for(;;){
          if(gotalarm)
              return(-3);
          len=pr->salen;
          n=recvfrom(recvfd,recvbuf,sizeof(recvbuf),0,pr->sarecv,&len);
          if(n<0){
              if(errno==EINTR)
                  continue;
              else
                  err_sys("recvfrom error");
          }
          ip=(struct ip *)recvbuf;
          hlen1=ip->ip_hl<<2;
          icmp=(struct icmp *)(recvbuf+hlen1);
          if((icmplen=n-hlen1)<8)
              continue;
          if(icmp->icmp_type==ICMP_TIMXCEED&&
              icmp->icmp_code==ICMP_TIMXCEED_INTRANS){
              if(icmplen<8+sizeof(struct ip))
                  continue;
              hip=(struct ip *)(recvbuf+hlen1+8);
              hlen2=hip->ip_hl<<2;
              if(icmplen<8+hlen2+4)
                  continue;
              udp=(struct udphdr *)(recvbuf+hlen1+8+hlen2);
              if(hip->ip_p==IPPROTO_UDP&&
                  udp->uh_sport==htons(sport)&&
                  udp->uh_dport==htons(dport+seq)){
                  ret=-2;
                  break;
              }
          }else if(icmp->icmp_type==ICMP_UNREACH){
              if(icmplen<8+sizeof(struct ip))
                  continue;
              hip=(struct ip*)(recvbuf+hlen1+8);
              hlen2=hip->ip_hl<<2;
              if(icmplen<8+hlen2+4)
                  continue;
              udp=(struct udphdr *)(recvbuf+hlen1+8+hlen2);
              if(hip->ip_p==IPPROTO_UDP&&
                udp->uh_sport==htons(sport)&&
                udp->uh_dport==htons(dport+seq)){
                if(icmp->icmp_code==ICMP_UNREACH_PORT)
                    ret=-1;
                else
                    ret=icmp->icmp_code;
                break;
              }
          }
          if(verbose){
              printf(" (from %s:type=%d,code=%d)\n",
                        sock_ntop_host(pr->sarecv,pr->salen),
                        icmp->icmp_type,icmp->icmp_code);
          }
      }
      alarm(0);
      gettimeofday(tv,NULL);
      return(ret);
}

#include <netinet/in.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv)
{
  int sockfd;
  unsigned char msg[60] = {0};
  unsigned char recvmsg[1514];
  ssize_t recvd;
  struct sockaddr_in sin;
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0)
  {
    abort();
  }
  msg[0] = 2;
  msg[1] = 1; // map, request
  msg[7] = 255; // lifetime: 255 seconds
  msg[18] = 0xff;
  msg[19] = 0xff;
  msg[20] = 10;
  msg[21] = 150;
  msg[22] = 1;
  msg[23] = 101;
  msg[36] = 6;
  msg[40] = 1234>>8;
  msg[41] = 1234&0xff;
  msg[42] = 1235>>8;
  msg[43] = 1235&0xff;
  
  sin.sin_family = AF_INET;
  sin.sin_port = htons(5351);
  sin.sin_addr.s_addr = htonl((10<<24) | (150<<16) | (1<<8) | 1);
  if (sendto(sockfd, msg, sizeof(msg), 0, (struct sockaddr*)&sin, sizeof(sin)) != sizeof(msg))
  {
    abort();
  }
  recvd = recv(sockfd, recvmsg, sizeof(recvmsg), 0);
  if (recvd < 0)
  {
    abort();
  }
  printf("port is %d\n", (recvmsg[42]<<8) | recvmsg[43]);
  return 0;
}

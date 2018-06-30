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
  int intport, desired_extport, lifetime;
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0)
  {
    abort();
  }
  if (argc != 4)
  {
    printf("Usage: %s intport desiredextport lifetime\n", argv[0]);
    exit(1);
  }
  intport = atoi(argv[1]);
  desired_extport = atoi(argv[2]);
  lifetime = atoi(argv[3]);
  if (intport <= 0 || intport > 65535 ||
      desired_extport <= 0 || desired_extport > 65535 || lifetime < 0)
  {
    printf("Usage: %s intport desiredextport lifetime\n", argv[0]);
    exit(1);
  }
  msg[0] = 2;
  msg[1] = 1; // map, request
  msg[4] = (lifetime>>24)&0xff;
  msg[5] = (lifetime>>16)&0xff;
  msg[6] = (lifetime>>8)&0xff;
  msg[7] = lifetime&0xff;
  msg[18] = 0xff;
  msg[19] = 0xff;
  msg[20] = 10;
  msg[21] = 150;
  msg[22] = 1;
  msg[23] = 101;
  msg[36] = 6;
  msg[40] = intport>>8;
  msg[41] = intport&0xff;
  msg[42] = desired_extport>>8;
  msg[43] = desired_extport&0xff;
  
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
  if (recvmsg[0] != 2)
  {
    printf("Incorrect protocol version\n");
    exit(1);
  }
  if (recvmsg[1] != 0x81)
  {
    printf("Incorrect opcode\n");
    exit(1);
  }
  if (recvmsg[3] != 0)
  {
    printf("Result not success\n");
    exit(1);
  }
  printf("Lifetime %u\n", (recvmsg[4]<<24) | (recvmsg[5]<<16) | (recvmsg[6]<<8) | recvmsg[7]);
  printf("port is %d\n", (recvmsg[42]<<8) | recvmsg[43]);
  return 0;
}

#include <netinet/in.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>

static uint32_t get_default_gateway(void)
{
  FILE *f = fopen("/proc/net/route", "r");
  char *line = NULL;
  size_t sz = 0;
  ssize_t nread;
  char iname[25];
  unsigned dst, gw, flags, refcnt, use, metric, mask, mtu, window, irtt;
  if (f == NULL)
  {
    return 0;
  }
  nread = getline(&line, &sz, f);
  if (nread < 0)
  {
    return 0;
  }
  for (;;)
  {
    nread = getline(&line, &sz, f);
    if (nread < 0)
    {
      break;
    }
    if (sscanf(line, "%20s %X %X %X %u %u %u %X %u %u %u",
              iname, &dst, &gw, &flags, &refcnt, &use, &metric, &mask, &mtu, 
              &window, &irtt) != 11)
    {
      break;
    }
    if (dst == 0 && mask == 0)
    {
      fclose(f);
      return ntohl(gw);
    }
  }
  fclose(f);
  return 0;
}

int main(int argc, char **argv)
{
  int sockfd;
  unsigned char msg[60] = {0};
  unsigned char recvmsg[1514];
  ssize_t recvd;
  struct sockaddr_in sin;
  uint32_t default_gateway;
  int intport, desired_extport, lifetime;
  socklen_t addrlen;

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
  msg[36] = 6;
  msg[40] = intport>>8;
  msg[41] = intport&0xff;
  msg[42] = desired_extport>>8;
  msg[43] = desired_extport&0xff;

  default_gateway = get_default_gateway();
  
  sin.sin_family = AF_INET;
  sin.sin_port = htons(5351);
  sin.sin_addr.s_addr = htonl(default_gateway);

  if (connect(sockfd, (struct sockaddr*)&sin, sizeof(sin)) != 0)
  {
    printf("Can't connect\n");
    exit(1);
  }
  addrlen = sizeof(sin);
  if (getsockname(sockfd, (struct sockaddr*)&sin, &addrlen) != 0)
  {
    printf("Can't get bound address\n");
    exit(1);
  }
  msg[20] = (ntohl(sin.sin_addr.s_addr)>>24) & 0xFF;
  msg[21] = (ntohl(sin.sin_addr.s_addr)>>16) & 0xFF;
  msg[22] = (ntohl(sin.sin_addr.s_addr)>>8) & 0xFF;
  msg[23] = (ntohl(sin.sin_addr.s_addr)>>0) & 0xFF;
  printf("Local address is %d.%d.%d.%d\n", msg[20], msg[21], msg[22], msg[23]);
  
  if (send(sockfd, msg, sizeof(msg), 0) != sizeof(msg))
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

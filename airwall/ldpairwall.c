#include <stdint.h>
#include <stdio.h>
#include <stdatomic.h>
#include <poll.h>
#include "ldp.h"
#include "linkcommon.h"
#include "time64.h"
#include "packet.h"

uint32_t ext_ip = (10<<24)|(2<<8)|15;

#define NUM_THR 1
#define MAX_RX_TX 64

struct ldp_interface *dlintf, *ulintf;
struct ldp_in_queue *dlinq[MAX_RX_TX];
struct ldp_in_queue *ulinq[MAX_RX_TX];
struct ldp_out_queue *dloutq[MAX_RX_TX];
struct ldp_out_queue *uloutq[MAX_RX_TX];

atomic_int exit_threads = 0;

int main(int argc, char **argv)
{
  int idx = 0;
  int i;
  struct pollfd pfds[2];

  ulintf = ldp_interface_open("veth1", NUM_THR, NUM_THR);
  if (ulintf == NULL)
  {
    abort();
  }
  dlintf = ldp_interface_open("veth2", NUM_THR, NUM_THR);
  if (dlintf == NULL)
  {
    abort();
  }
  for (i = 0; i < NUM_THR; i++)
  {
    dlinq[i] = dlintf->inq[i];
    ulinq[i] = ulintf->inq[i];
    dloutq[i] = dlintf->outq[i];
    uloutq[i] = ulintf->outq[i];
  }
  while (!atomic_load(&exit_threads))
  {
    if (ldp_in_eof(dlinq[idx]) && ldp_in_eof(ulinq[idx]))
    {
      break;
    }
    pfds[0].fd = dlinq[idx]->fd;
    pfds[0].events = POLLIN;
    pfds[1].fd = ulinq[idx]->fd;
    pfds[1].events = POLLIN;

    worker_local_rdlock(local);
    expiry = timer_linkheap_next_expiry_time(&local->timers);
    time64 = gettime64();
    if (expiry > time64 + 1000*1000)
    {
      expiry = time64 + 1000*1000;
    }
    worker_local_rdunlock(local);
    
    timeout = (expiry > time64 ? (999 + expiry - time64)/1000 : 0);
    if (timeout > 0)
    {
      ldp_out_txsync(dloutq[idx]);
      ldp_out_txsync(uloutq[idx]);
      if (pfds[0].fd >= 0 && pfds[1].fd >= 0)
      {
        poll(pfds, 2, timeout);
      }
    }

    time64 = gettime64();
    worker_local_rdlock(local);
    try = (timer_linkheap_next_expiry_time(&local->timers) < time64);
    worker_local_rdunlock(local);

    if (time64 >= periodic.next_time64)
    {
      periodic_fn(&periodic);
    }

    if (try)
    {
      worker_local_wrlock(local);
      while (timer_linkheap_next_expiry_time(&local->timers) < time64)
      {
        struct timer_link *timer = timer_linkheap_next_expiry_timer(&local->timers);
        timer_linkheap_remove(&local->timers, timer);
        worker_local_wrunlock(local);
        timer->fn(timer, &local->timers, timer->userdata);
        worker_local_wrlock(local);
      }
      worker_local_wrunlock(local);
    }

    struct ldp_packet pkts[1000];
    struct ldp_packet pkts2[1000];
    int num;

    j = 0;
    for (i = 0; i < num; i++)
    {
      struct packet pktstruct;
      //pktstruct = ll_alloc_st(&st, packet_size(0));
      pktstruct.data = pkts[i].data;
      pktstruct.direction = PACKET_DIRECTION_UPLINK;
      pktstruct.sz = pkts[i].sz;
      if (numpkts)
      {
        printf("pkt %llu\n", (unsigned long long)(pktnum++));
      }

      if (uplink(airwall, local, &pktstruct, &outport, time64, &st))
      {
        //ll_free_st(&st, pktstruct);
      }
      else
      {
        pkts2[j].data = pktstruct.data;
        pkts2[j].sz = pktstruct.sz;
        j++;
      }
      periodic.ulpkts++;
      periodic.ulbytes += pkts[i].sz;
#if 0
      if (in)
      {
        if (pcapng_out_ctx_write(&inctx, pkts[i].data, pkts[i].sz, gettime64(), "out"))
        {
          log_log(LOG_LEVEL_CRIT, "LDPPROXY", "can't record packet");
          exit(1);
        }
      }
      if (lan)
      {
        if (pcapng_out_ctx_write(&lanctx, pkts[i].data, pkts[i].sz, gettime64(), "in"))
        {
          log_log(LOG_LEVEL_CRIT, "LDPPROXY", "can't record packet");
          exit(1);
        }
      }
#endif
    }
    ldp_out_inject(uloutq[idx], pkts2, j);
    ldp_in_deallocate_some(dlinq[idx], pkts, num);

    num = ldp_in_nextpkts(ulinq[idx], pkts, sizeof(pkts)/sizeof(*pkts));
    
    j = 0;
    for (i = 0; i < num; i++)
    {
      struct packet pktstruct;
      //pktstruct = ll_alloc_st(&st, packet_size(0));
      pktstruct.data = pkts[i].data;
      pktstruct.direction = PACKET_DIRECTION_DOWNLINK;
      pktstruct.sz = pkts[i].sz;
      if (numpkts)
      {
        printf("pkt %llu\n", (unsigned long long)(pktnum++));
      }

      if (downlink(airwall, local, &pktstruct, &outport, time64, &st))
      {
        //ll_free_st(&st, pktstruct);
      }
      else
      {
        pkts2[j].data = pktstruct.data;
        pkts2[j].sz = pktstruct.sz;
        j++;
      }
      periodic.dlpkts++;
      periodic.dlbytes += pkts[i].sz;
#if 0
      if (in)
      {
        if (pcapng_out_ctx_write(&inctx, pkts[i].data, pkts[i].sz, gettime64(), "in"))
        {
          log_log(LOG_LEVEL_CRIT, "LDPPROXY", "can't record packet");
          exit(1);
        }
      }
      if (wan)
      {
        if (pcapng_out_ctx_write(&wanctx, pkts[i].data, pkts[i].sz, gettime64(), "in"))
        {
          log_log(LOG_LEVEL_CRIT, "LDPPROXY", "can't record packet");
          exit(1);
        }
      }
#endif
    }
    ldp_out_inject(dloutq[idx], pkts2, j);
    ldp_in_deallocate_some(ulinq[idx], pkts, num);
  }
  return 0;
}

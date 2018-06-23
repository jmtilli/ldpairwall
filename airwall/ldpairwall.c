#include <stdint.h>
#include <stdio.h>
#include <stdatomic.h>
#include <poll.h>
#include "ldp.h"
#include "linkcommon.h"
#include "time64.h"
#include "packet.h"
#include "airwall.h"
#include "ports.h"
#include "ldpports.h"
#include "mypcapng.h"
#include "yyutils.h"

#define POOL_SIZE 48
#define BLOCK_SIZE 65664

uint32_t ext_ip = (10<<24)|(2<<8)|15;

#define NUM_THR 1
#define MAX_RX_TX 64

struct ldp_interface *dlintf, *ulintf;
struct ldp_in_queue *dlinq[MAX_RX_TX];
struct ldp_in_queue *ulinq[MAX_RX_TX];
struct ldp_out_queue *dloutq[MAX_RX_TX];
struct ldp_out_queue *uloutq[MAX_RX_TX];

atomic_int exit_threads = 0;

struct rx_args {
  struct airwall *airwall;
  struct worker_local *local;
  int idx;
};

struct periodic_userdata {
  struct rx_args *args;
  uint64_t dlbytes, ulbytes;
  uint64_t dlpkts, ulpkts;
  uint64_t last_dlbytes, last_ulbytes;
  uint64_t last_dlpkts, last_ulpkts;
  uint64_t last_time64;
  uint64_t next_time64;
};

static void periodic_fn(
  struct periodic_userdata *ud)
{
  uint64_t time64 = gettime64();
  double diff = (time64 - ud->last_time64)/1000.0/1000.0;
  uint64_t ulbdiff = ud->ulbytes - ud->last_ulbytes;
  uint64_t dlbdiff = ud->dlbytes - ud->last_dlbytes;
  uint64_t ulpdiff = ud->ulpkts - ud->last_ulpkts;
  uint64_t dlpdiff = ud->dlpkts - ud->last_dlpkts;
  ud->last_ulbytes = ud->ulbytes;
  ud->last_dlbytes = ud->dlbytes;
  ud->last_ulpkts = ud->ulpkts;
  ud->last_dlpkts = ud->dlpkts;
  worker_local_rdlock(ud->args->local);
  log_log(LOG_LEVEL_INFO, "LDPAIRWALL",
         "worker/%d %g MPPS %g Gbps ul %g MPPS %g Gbps dl"
         " %u conns synproxied %u conns not",
         ud->args->idx,
         ulpdiff/diff/1e6, 8*ulbdiff/diff/1e9,
         dlpdiff/diff/1e6, 8*dlbdiff/diff/1e9,
         ud->args->local->synproxied_connections,
         ud->args->local->direct_connections);
  worker_local_rdunlock(ud->args->local);
  ud->last_time64 = time64;
  ud->next_time64 += 2*1000*1000;
}

int in = 0;
struct pcapng_out_ctx inctx;
int out = 0;
struct pcapng_out_ctx outctx;
int lan = 0;
struct pcapng_out_ctx lanctx;
int wan = 0;
struct pcapng_out_ctx wanctx;

int main(int argc, char **argv)
{
  int idx = 0;
  int i;
  struct pollfd pfds[2];
  uint64_t expiry, time64;
  int timeout;
  int try;
  struct airwall sairwall = {};
  struct airwall *airwall = &sairwall;
  struct worker_local slocal = {};
  struct worker_local *local = &slocal;
  struct rx_args args = {};
  struct periodic_userdata periodic = {};
  int j;
  const int numpkts = 0;
  unsigned long long pktnum = 0;
  struct ll_alloc_st st;
  struct allocif intf = {.ops = &ll_allocif_ops_st, .userdata = &st};
  struct port outport;
  struct ldpfunc2_userdata ud;
  struct conf conf = {};

  hash_seed_init();

  conf_init(&conf);
  confyydirparse(argv[0], "conf.txt", &conf, 0);
  airwall_init(airwall, &conf);
  worker_local_init(local, airwall, 1, 0); // FIXME change to non-deterministic


  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  args.idx = 0;
  args.airwall = airwall;
  args.local = local;

  periodic.last_time64 = gettime64();
  periodic.next_time64 = periodic.last_time64 + 2*1000*1000;
  periodic.args = &args;

  ulintf = ldp_interface_open("veth1", NUM_THR, NUM_THR);
  if (ulintf == NULL)
  {
    log_log(LOG_LEVEL_CRIT, "LDPAIRWALL", "Can't open uplink interface");
    exit(1);
  }
  dlintf = ldp_interface_open("veth2", NUM_THR, NUM_THR);
  if (dlintf == NULL)
  {
    log_log(LOG_LEVEL_CRIT, "LDPAIRWALL", "Can't open downlink interface");
    exit(1);
  }
  for (i = 0; i < NUM_THR; i++)
  {
    dlinq[i] = dlintf->inq[i];
    ulinq[i] = ulintf->inq[i];
    dloutq[i] = dlintf->outq[i];
    uloutq[i] = ulintf->outq[i];
  }

  if (ldp_interface_mac_addr(ulintf, airwall->ul_mac) != 0)
  {
    log_log(LOG_LEVEL_CRIT, "LDPAIRWALL", "can't get uplink MAC");
    exit(1);
  }
  if (ldp_interface_mac_addr(dlintf, airwall->dl_mac) != 0)
  {
    log_log(LOG_LEVEL_CRIT, "LDPAIRWALL", "can't get downlink MAC");
    exit(1);
  }

  ud.intf = &intf;
  ud.dloutq = dloutq[idx];
  ud.uloutq = uloutq[idx];
  ud.lan = lan;
  ud.wan = wan;
  ud.out = out;
  ud.lanctx = &lanctx;
  ud.wanctx = &wanctx;
  ud.outctx = &outctx;
  outport.portfunc = ldpfunc2;
  outport.userdata = &ud;

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

    num = ldp_in_nextpkts(dlinq[idx], pkts, sizeof(pkts)/sizeof(*pkts));

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
          log_log(LOG_LEVEL_CRIT, "LDPAIRWALL", "can't record packet");
          exit(1);
        }
      }
      if (lan)
      {
        if (pcapng_out_ctx_write(&lanctx, pkts[i].data, pkts[i].sz, gettime64(), "in"))
        {
          log_log(LOG_LEVEL_CRIT, "LDPAIRWALL", "can't record packet");
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
          log_log(LOG_LEVEL_CRIT, "LDPAIRWALL", "can't record packet");
          exit(1);
        }
      }
      if (wan)
      {
        if (pcapng_out_ctx_write(&wanctx, pkts[i].data, pkts[i].sz, gettime64(), "in"))
        {
          log_log(LOG_LEVEL_CRIT, "LDPAIRWALL", "can't record packet");
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

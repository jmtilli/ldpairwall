#include "airwall.h"
#include "ipcksum.h"
#include "branchpredict.h"
#include <sys/time.h>
#include <arpa/inet.h>
#include "time64.h"
#include "detect.h"

const char http_connect_revdatabuf[19] = {
  'H','T','T','P','/','1','.','1', ' ', '2', '0', '0', ' ', 'O', 'K',
  '\r', '\n',
  '\r', '\n',
};

#define MAX_FRAG 65535
#define INITIAL_WINDOW (1<<14)
#define IPV6_FRAG_CUTOFF 512

#define UDP_TIMEOUT_SECS 300
#define ICMP_TIMEOUT_SECS 60

#define TCP_CONNECTED_TIMEOUT_SECS 86400 // 1 day
#define TCP_ONE_FIN_TIMEOUT_SECS 7440 // 2 hours 4 minutes (RFC5382)
#define TCP_BOTH_FIN_TIMEOUT_SECS 240 // 4 minutes (RFC5382)
#define TCP_UPLINK_SYN_SENT_TIMEOUT_USEC 240 // 4 minutes (RFC5382)
#define TCP_UPLINK_SYN_RCVD_TIMEOUT_SECS 240 // 4 minutes (RFC5382)
#define TCP_WINDOW_UPDATE_SENT_TIMEOUT_SECS 240 // 4 minutes (RFC5382)
#define TCP_DOWNLINK_SYN_SENT_TIMEOUT_SECS 240 // 4 minutes (RFC5382)
#define TCP_DOWNLINK_HALF_OPEN_TIMEOUT_SECS 240 // 4 minutes (RFC5382)
#define TCP_TIME_WAIT_TIMEOUT_SECS 120 // no RFC5382 restrictions here
#define TCP_RESETED_TIMEOUT_SECS 45
#define TCP_RETX_TIMEOUT_SECS 1

#define ENABLE_ARP

#ifdef ENABLE_ARP

static void send_arp(
  struct port *port, uint32_t dst, enum packet_direction direction,
  uint32_t my_addr, const void *my_mac, struct ll_alloc_st *st)
{
  char etherarp[14+28] = {0};
  void *arp;
  struct packet *pktstruct;
  memset(ether_dst(etherarp), 0xff, 6);
  memcpy(ether_src(etherarp), my_mac, 6);
  ether_set_type(etherarp, ETHER_TYPE_ARP);
  arp = ether_payload(etherarp);
  arp_set_ether(arp);
  arp_set_req(arp);
  arp_set_spa(arp, my_addr);
  arp_set_tpa(arp, dst);
  memset(arp_tha(arp), 0xff, 6);
  memcpy(arp_sha(arp), my_mac, 6);

  pktstruct = ll_alloc_st(st, packet_size(sizeof(etherarp)));
  pktstruct->data = packet_calc_data(pktstruct);
  pktstruct->direction = direction;
  pktstruct->sz = sizeof(etherarp);
  memcpy(pktstruct->data, etherarp, sizeof(etherarp));
  port->portfunc(pktstruct, port->userdata);
}

static int send_via_arp(struct packet *pkt,
                        struct worker_local *local,
                        struct airwall *airwall,
                        struct ll_alloc_st *st,
                        struct port *port,
                        enum packet_direction dir,
                        uint64_t time64)
{
  void *ether = packet_data(pkt);
  struct arp_entry *arpe;
  struct arp_cache *cache;
  uint32_t addr;
  const void *mac;
  uint32_t dst = ip_dst(ether_payload(ether));
  if (dir == PACKET_DIRECTION_UPLINK)
  {
    memcpy(ether_src(ether), airwall->ul_mac, 6);
    cache = &local->ul_arp_cache;
    addr = airwall->conf->ul_addr;
    mac = airwall->ul_mac;
    if (ul_addr_is_mine(airwall->conf, dst))
    {
      char *ip = ether_payload(ether);
      int version = ip_version(ip);
      int proto = ip_proto(ip);
      size_t ip_len = pkt->sz - ETHER_HDR_LEN;
      size_t tcp_len = ip46_total_len(ip) - ip46_hdr_len(ip);
      char *ippay = ip_payload(ip);
      //pkt->direction = PACKET_DIRECTION_DOWNLINK;
      memcpy(ether_dst(ether), airwall->ul_mac, 6);
      if (version == 4)
      {
        ip_set_src_cksum_update(ip, ip_len, proto, ippay, tcp_len, dst);
      }
      else
      {
        abort();
      }
      return downlink(airwall, local, pkt, port, time64, st);
    }
    if ((dst & airwall->conf->ul_mask) !=
        (airwall->conf->ul_addr & airwall->conf->ul_mask))
    {
      dst = airwall->conf->ul_defaultgw;
    }
  }
  else if (dir == PACKET_DIRECTION_DOWNLINK)
  {
    memcpy(ether_src(ether), airwall->dl_mac, 6);
    cache = &local->dl_arp_cache;
    addr = airwall->conf->dl_addr;
    mac = airwall->dl_mac;
    if ((dst & airwall->conf->dl_mask) !=
        (airwall->conf->dl_addr & airwall->conf->dl_mask))
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "IP not to subnet, dropping");
      return 1;
    }
  }
  else
  {
    abort();
  }
  if (pkt->sz > 1514) // FIXME make MTU configurable
  {
    struct fragment frags[64];
    size_t i, count;
    char *ip = ether_payload(ether);
    size_t ihl = ip46_hdr_len(ip);
    i = 0;
    for (;;)
    {
      if (i >= 64)
      {
        abort();
      }
      frags[i].pkt = NULL;
      frags[i].datastart = (1500-ihl)*i;
      frags[i].datalen = (1500-ihl);
      if (frags[i].datastart + frags[i].datalen >= (pkt->sz-14-ihl))
      {
        frags[i].datalen = (pkt->sz-14-ihl) - frags[i].datastart;
        i++;
        break;
      }
      i++;
    }
    count = i;
    fragment4(&local->mallocif, pkt->data, pkt->sz, frags, count);
    for (i = 0; i < count; i++)
    {
      struct packet *pktstruct = ll_alloc_st(st, packet_size(frags[i].pkt->sz));
      pktstruct->data = packet_calc_data(pktstruct);
      pktstruct->direction = pkt->direction;
      pktstruct->sz = frags[i].pkt->sz;
      memcpy(pktstruct->data, frags[i].pkt->data, frags[i].pkt->sz);
      if (send_via_arp(pktstruct, local, airwall, st, port, dir, time64))
      {
        ll_free_st(st, pktstruct);
      }
      else
      {
        port->portfunc(pktstruct, port->userdata);
      }
      allocif_free(&local->mallocif, frags[i].pkt);
    }
    return 1;
  }
  arpe = arp_cache_get(cache, dst);
  if (arpe == NULL)
  {
    struct packet *pktstruct = ll_alloc_st(st, packet_size(pkt->sz));
    pktstruct->data = packet_calc_data(pktstruct);
    pktstruct->direction = dir;
    pktstruct->sz = pkt->sz;
    memcpy(pktstruct->data, ether, pkt->sz);
    arpe = arp_cache_put_packet(cache, dst, pktstruct, &local->timers, time64);
    if (time64 >= arpe->last_tx + 1000ULL*1000ULL)
    {
      send_arp(port, dst, dir, addr, mac, st);
      arpe->last_tx = time64;
    }
    return 1;
  }
  memcpy(ether_dst(ether), arpe->mac, 6);
  if (dir == PACKET_DIRECTION_DOWNLINK && pkt->direction == PACKET_DIRECTION_UPLINK)
  {
    struct packet *pktstruct = ll_alloc_st(st, packet_size(pkt->sz));
    pktstruct->data = packet_calc_data(pktstruct);
    pktstruct->direction = dir;
    pktstruct->sz = pkt->sz;
    memcpy(pktstruct->data, ether, pkt->sz);
    port->portfunc(pktstruct, port->userdata);
    return 1;
  }
  return 0;
}

#endif

static inline uint32_t gen_flowlabel(const void *local_ip, uint16_t local_port,
                                     const void *remote_ip, uint16_t remote_port)
{
  struct siphash_ctx ctx;
  siphash_init(&ctx, hash_seed_get());
  siphash_feed_buf(&ctx, local_ip, 16);
  siphash_feed_buf(&ctx, remote_ip, 16);
  siphash_feed_u64(&ctx, ((uint32_t)local_port)<<16 | remote_port);
  return siphash_get(&ctx) & ((1U<<20) - 1);
}

static inline uint32_t gen_flowlabel_entry(struct airwall_hash_entry *e)
{
  if (e->version != 6)
  {
    abort();
  }
  return gen_flowlabel(&e->local_ip, e->local_port, &e->remote_ip, e->remote_port);
}

static size_t airwall_state_to_str(
  char *str, size_t bufsiz, struct airwall_hash_entry *e)
{
  size_t off = 0;
  int already = 0;
  off += snprintf(str + off, bufsiz - off, "<");
  if (e->flag_state & FLAG_STATE_UPLINK_SYN_SENT)
  {
    if (already)
    {
      off += snprintf(str + off, bufsiz - off, ",");
    }
    already = 1;
    off += snprintf(str + off, bufsiz - off, "UPLINK_SYN_SENT");
  }
  if (e->flag_state & FLAG_STATE_UPLINK_SYN_RCVD)
  {
    if (already)
    {
      off += snprintf(str + off, bufsiz - off, ",");
    }
    already = 1;
    off += snprintf(str + off, bufsiz - off, "UPLINK_SYN_RCVD");
  }
  if (e->flag_state & FLAG_STATE_WINDOW_UPDATE_SENT)
  {
    if (already)
    {
      off += snprintf(str + off, bufsiz - off, ",");
    }
    already = 1;
    off += snprintf(str + off, bufsiz - off, "WINDOW_UPDATE_SENT");
  }
  if (e->flag_state & FLAG_STATE_DOWNLINK_SYN_SENT)
  {
    if (already)
    {
      off += snprintf(str + off, bufsiz - off, ",");
    }
    already = 1;
    off += snprintf(str + off, bufsiz - off, "DOWNLINK_SYN_SENT");
  }
  if (e->flag_state & FLAG_STATE_ESTABLISHED)
  {
    if (already)
    {
      off += snprintf(str + off, bufsiz - off, ",");
    }
    already = 1;
    off += snprintf(str + off, bufsiz - off, "ESTABLISHED");
  }
  if (e->flag_state & FLAG_STATE_UPLINK_FIN)
  {
    if (already)
    {
      off += snprintf(str + off, bufsiz - off, ",");
    }
    already = 1;
    off += snprintf(str + off, bufsiz - off, "UPLINK_FIN");
  }
  if (e->flag_state & FLAG_STATE_UPLINK_FIN_ACK)
  {
    if (already)
    {
      off += snprintf(str + off, bufsiz - off, ",");
    }
    already = 1;
    off += snprintf(str + off, bufsiz - off, "UPLINK_FIN_ACK");
  }
  if (e->flag_state & FLAG_STATE_DOWNLINK_FIN)
  {
    if (already)
    {
      off += snprintf(str + off, bufsiz - off, ",");
    }
    already = 1;
    off += snprintf(str + off, bufsiz - off, "DOWNLINK_FIN");
  }
  if (e->flag_state & FLAG_STATE_DOWNLINK_FIN_ACK)
  {
    if (already)
    {
      off += snprintf(str + off, bufsiz - off, ",");
    }
    already = 1;
    off += snprintf(str + off, bufsiz - off, "DOWNLINK_FIN_ACK");
  }
  if (e->flag_state & FLAG_STATE_TIME_WAIT)
  {
    if (already)
    {
      off += snprintf(str + off, bufsiz - off, ",");
    }
    already = 1;
    off += snprintf(str + off, bufsiz - off, "TIME_WAIT");
  }
  if (e->flag_state & FLAG_STATE_DOWNLINK_HALF_OPEN)
  {
    if (already)
    {
      off += snprintf(str + off, bufsiz - off, ",");
    }
    already = 1;
    off += snprintf(str + off, bufsiz - off, "DOWNLINK_HALF_OPEN");
  }
  if (e->flag_state & FLAG_STATE_RESETED)
  {
    if (already)
    {
      off += snprintf(str + off, bufsiz - off, ",");
    }
    already = 1;
    off += snprintf(str + off, bufsiz - off, "RESETED");
  }
  off += snprintf(str + off, bufsiz - off, ">");
  return off;
}

static size_t airwall_entry_to_str(
  char *str, size_t bufsiz, struct airwall_hash_entry *e)
{
  size_t off = 0;
  off += airwall_state_to_str(str + off, bufsiz - off, e);
  off += snprintf(str + off, bufsiz - off, ", ");
  if (e->version == 4)
  {
    off += snprintf(str + off, bufsiz - off, "local_end=%d.%d.%d.%d:%d",
                    (ntohl(e->local_ip.ipv4)>>24)&0xFF,
                    (ntohl(e->local_ip.ipv4)>>16)&0xFF,
                    (ntohl(e->local_ip.ipv4)>>8)&0xFF,
                    (ntohl(e->local_ip.ipv4)>>0)&0xFF,
                    e->local_port);
    off += snprintf(str + off, bufsiz - off, ", ");
    off += snprintf(str + off, bufsiz - off, "remote_end=%d.%d.%d.%d:%d",
                    (ntohl(e->remote_ip.ipv4)>>24)&0xFF,
                    (ntohl(e->remote_ip.ipv4)>>16)&0xFF,
                    (ntohl(e->remote_ip.ipv4)>>8)&0xFF,
                    (ntohl(e->remote_ip.ipv4)>>0)&0xFF,
                    e->remote_port);
  }
  else
  {
    struct in6_addr in6loc, in6rem;
    char str6loc[INET6_ADDRSTRLEN] = {0};
    char str6rem[INET6_ADDRSTRLEN] = {0};
    memcpy(in6loc.s6_addr, &e->local_ip, 16);
    memcpy(in6rem.s6_addr, &e->remote_ip, 16);
    if (inet_ntop(AF_INET6, &in6loc, str6loc, sizeof(str6loc)) == NULL)
    {
      strncpy(str6loc, "UNKNOWN", sizeof(str6loc));
    }
    if (inet_ntop(AF_INET6, &in6rem, str6rem, sizeof(str6rem)) == NULL)
    {
      strncpy(str6rem, "UNKNOWN", sizeof(str6rem));
    }
    off += snprintf(str + off, bufsiz - off, "local_end=[%s]:%d",
                    str6loc, e->local_port);
    off += snprintf(str + off, bufsiz - off, ", ");
    off += snprintf(str + off, bufsiz - off, "remote_end=[%s]:%d",
                    str6rem, e->remote_port);
  }
  off += snprintf(str + off, bufsiz - off, ", ");
  off += snprintf(str + off, bufsiz - off, "wscalediff=%d", e->wscalediff);
  off += snprintf(str + off, bufsiz - off, ", ");
  off += snprintf(str + off, bufsiz - off, "lan_wscale=%d", e->lan_wscale);
  off += snprintf(str + off, bufsiz - off, ", ");
  off += snprintf(str + off, bufsiz - off, "wan_wscale=%d", e->wan_wscale);
  off += snprintf(str + off, bufsiz - off, ", ");
  off += snprintf(str + off, bufsiz - off, "was_synproxied=%d", e->was_synproxied);
  off += snprintf(str + off, bufsiz - off, ", ");
  off += snprintf(str + off, bufsiz - off, "lan_sack_was_supported=%d", e->lan_sack_was_supported);
  off += snprintf(str + off, bufsiz - off, ", ");
  off += snprintf(str + off, bufsiz - off, "seqoffset=%u", e->seqoffset);
  off += snprintf(str + off, bufsiz - off, ", ");
  off += snprintf(str + off, bufsiz - off, "tsoffset=%u", e->tsoffset);
  off += snprintf(str + off, bufsiz - off, ", ");
  off += snprintf(str + off, bufsiz - off, "lan_sent=%u", e->lan_sent);
  off += snprintf(str + off, bufsiz - off, ", ");
  off += snprintf(str + off, bufsiz - off, "wan_sent=%u", e->wan_sent);
  off += snprintf(str + off, bufsiz - off, ", ");
  off += snprintf(str + off, bufsiz - off, "lan_acked=%u", e->lan_acked);
  off += snprintf(str + off, bufsiz - off, ", ");
  off += snprintf(str + off, bufsiz - off, "wan_acked=%u", e->wan_acked);
  off += snprintf(str + off, bufsiz - off, ", ");
  off += snprintf(str + off, bufsiz - off, "lan_max=%u", e->lan_max);
  off += snprintf(str + off, bufsiz - off, ", ");
  off += snprintf(str + off, bufsiz - off, "wan_max=%u", e->wan_max);
  off += snprintf(str + off, bufsiz - off, ", ");
  off += snprintf(str + off, bufsiz - off, "lan_max_window_unscaled=%u", e->lan_max_window_unscaled);
  off += snprintf(str + off, bufsiz - off, ", ");
  off += snprintf(str + off, bufsiz - off, "wan_max_window_unscaled=%u", e->wan_max_window_unscaled);
  return off;
}

static size_t airwall_packet_to_str(
  char *str, size_t bufsiz, const void *ether)
{
  size_t off = 0;
  const void *ip = ether_const_payload(ether);
  const void *ippay;
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;

  if (ip_version(ip) == 4)
  {
    ippay = ip_const_payload(ip);
    src_ip = ip_src(ip);
    dst_ip = ip_dst(ip);
    src_port = tcp_src_port(ippay);
    dst_port = tcp_dst_port(ippay);
    off += snprintf(str + off, bufsiz - off, "src_end=%d.%d.%d.%d:%d",
                    (src_ip>>24)&0xFF,
                    (src_ip>>16)&0xFF,
                    (src_ip>>8)&0xFF,
                    (src_ip>>0)&0xFF,
                    src_port);
    off += snprintf(str + off, bufsiz - off, ", ");
    off += snprintf(str + off, bufsiz - off, "dst_end=%d.%d.%d.%d:%d",
                    (dst_ip>>24)&0xFF,
                    (dst_ip>>16)&0xFF,
                    (dst_ip>>8)&0xFF,
                    (dst_ip>>0)&0xFF,
                    dst_port);
    off += snprintf(str + off, bufsiz - off, ", flags=");
    if (tcp_syn(ippay))
    {
      off += snprintf(str + off, bufsiz - off, "S");
    }
    if (tcp_ack(ippay))
    {
      off += snprintf(str + off, bufsiz - off, "A");
    }
    if (tcp_fin(ippay))
    {
      off += snprintf(str + off, bufsiz - off, "F");
    }
    if (tcp_rst(ippay))
    {
      off += snprintf(str + off, bufsiz - off, "R");
    }
    off += snprintf(str + off, bufsiz - off, ", ");
    off += snprintf(str + off, bufsiz - off, "seq=%u", tcp_seq_number(ippay));
    off += snprintf(str + off, bufsiz - off, ", ");
    off += snprintf(str + off, bufsiz - off, "ack=%u", tcp_ack_number(ippay));
    return off;
  }
  else if (ip_version(ip) == 6)
  {
    uint8_t proto;
    struct in6_addr in6src, in6dst;
    char str6src[INET6_ADDRSTRLEN] = {0};
    char str6dst[INET6_ADDRSTRLEN] = {0};
    ippay = ipv6_const_proto_hdr(ip, &proto);
    if (ippay == NULL || proto != 6)
    {
      off += snprintf(str + off, bufsiz - off, "unknown protocol");
      return off;
    }
    memcpy(in6src.s6_addr, ipv6_const_src(ip), 16);
    memcpy(in6dst.s6_addr, ipv6_const_dst(ip), 16);
    if (inet_ntop(AF_INET6, &in6src, str6src, sizeof(str6src)) == NULL)
    {
      strncpy(str6src, "UNKNOWN", sizeof(str6src));
    }
    if (inet_ntop(AF_INET6, &in6dst, str6dst, sizeof(str6dst)) == NULL)
    {
      strncpy(str6dst, "UNKNOWN", sizeof(str6dst));
    }
    src_port = tcp_src_port(ippay);
    dst_port = tcp_dst_port(ippay);
    off += snprintf(str + off, bufsiz - off, "src_end=[%s]", str6src);
    off += snprintf(str + off, bufsiz - off, ", ");
    off += snprintf(str + off, bufsiz - off, "dst_end=[%s]", str6dst);
    off += snprintf(str + off, bufsiz - off, ", flags=");
    if (tcp_syn(ippay))
    {
      off += snprintf(str + off, bufsiz - off, "S");
    }
    if (tcp_ack(ippay))
    {
      off += snprintf(str + off, bufsiz - off, "A");
    }
    if (tcp_fin(ippay))
    {
      off += snprintf(str + off, bufsiz - off, "F");
    }
    if (tcp_rst(ippay))
    {
      off += snprintf(str + off, bufsiz - off, "R");
    }
    off += snprintf(str + off, bufsiz - off, ", ");
    off += snprintf(str + off, bufsiz - off, "seq=%u", tcp_seq_number(ippay));
    off += snprintf(str + off, bufsiz - off, ", ");
    off += snprintf(str + off, bufsiz - off, "ack=%u", tcp_ack_number(ippay));
    return off;
  }
  else
  {
    off += snprintf(str + off, bufsiz - off, "unknown protocol");
    return off;
  }
}

static inline int rst_is_valid(uint32_t rst_seq, uint32_t ref_seq)
{
  int32_t diff = rst_seq - ref_seq;
  if (diff >= 0)
  {
    if (diff > 512*1024*1024)
    {
      log_log(LOG_LEVEL_EMERG, "WORKER",
        "TOO GREAT SEQUENCE NUMBER DIFFERENCE %u %u", rst_seq, ref_seq);
    }
    return diff <= 3;
  }
  if (diff < -512*1024*1024)
  {
    log_log(LOG_LEVEL_EMERG, "WORKER",
      "TOO GREAT SEQUENCE NUMBER DIFFERENCE %u %u", rst_seq, ref_seq);
  }
  return diff >= -3;
}

static inline int resend_request_is_valid_win(uint32_t seq, uint32_t ref_seq,
                                              uint32_t window)
{
  int32_t diff = seq - ref_seq;
  if (diff >= 0)
  {
    if (diff > 512*1024*1024)
    {
      log_log(LOG_LEVEL_EMERG, "WORKER",
        "TOO GREAT SEQUENCE NUMBER DIFFERENCE %u %u", seq, ref_seq);
    }
    return ((uint32_t)diff) <= window + 3;
  }
  if (diff < -512*1024*1024)
  {
    log_log(LOG_LEVEL_EMERG, "WORKER",
      "TOO GREAT SEQUENCE NUMBER DIFFERENCE %u %u", seq, ref_seq);
  }
  return diff >= -3;
}


static inline int resend_request_is_valid(uint32_t seq, uint32_t ref_seq)
{
  int32_t diff = seq - ref_seq;
  if (diff >= 0)
  {
    if (diff > 512*1024*1024)
    {
      log_log(LOG_LEVEL_EMERG, "WORKER",
        "TOO GREAT SEQUENCE NUMBER DIFFERENCE %u %u", seq, ref_seq);
    }
    return diff <= 3;
  }
  if (diff < -512*1024*1024)
  {
    log_log(LOG_LEVEL_EMERG, "WORKER",
      "TOO GREAT SEQUENCE NUMBER DIFFERENCE %u %u", seq, ref_seq);
  }
  return diff >= -3;
}

// caller must not have worker_local lock
// caller must not have bucket lock
static void airwall_expiry_fn(
  struct timer_link *timer, struct timer_linkheap *heap, void *ud, void *td)
{
  struct worker_local *local = ud;
  struct airwall_hash_entry *e;
  e = CONTAINER_OF(timer, struct airwall_hash_entry, timer);
  if (e->local_port != 0)
  {
    hash_table_delete(&local->local_hash, &e->local_node, airwall_hash_local(e));
  }
  hash_table_delete(&local->nat_hash, &e->nat_node, airwall_hash_nat(e));
  if (e->port_alloced)
  {
    deallocate_udp_port(local->airwall->porter, e->nat_port, !e->was_synproxied);
  }
  if (e->retxtimer_set)
  {
    timer_linkheap_remove(&local->timers, &e->retx_timer);
    e->retxtimer_set = 0;
  }
  worker_local_wrlock(local);
  if (e->was_synproxied)
  {
    local->synproxied_connections--;
  }
  else
  {
    local->direct_connections--;
  }
  if (e->flag_state == FLAG_STATE_DOWNLINK_HALF_OPEN)
  {
    linked_list_delete(&e->state_data.downlink_half_open.listnode);
    local->half_open_connections--;
  }
  worker_local_wrunlock(local);
  if (e->detect)
  {
    local->detect_count--;
    linked_list_delete(&e->detect_node);
  }
  free(e->detect);
  e->detect = NULL;
  free(e);
}

static void retx_timer_del(
  struct airwall_hash_entry *entry, struct worker_local *local)
{
  if (!entry->retxtimer_set)
  {
    return;
  }
  timer_linkheap_remove(&local->timers, &entry->retx_timer);
  entry->retxtimer_set = 0;
}

static void retx_http_connect_response(
  struct airwall_hash_entry *entry, struct port *port,
  struct ll_alloc_st *st, struct airwall *airwall, struct worker_local *local);

static void airwall_retx_fn(
  struct timer_link *timer, struct timer_linkheap *heap, void *ud, void *vtd)
{
  struct worker_local *local = ud;
  struct airwall_hash_entry *e;
  struct timer_thread_data *td = vtd;
  e = CONTAINER_OF(timer, struct airwall_hash_entry, retx_timer);
  retx_http_connect_response(e, td->port, td->st, local->airwall, local);
  e->retx_timer.time64 += TCP_RETX_TIMEOUT_SECS*1000ULL*1000ULL;
  timer_linkheap_add(&local->timers, &e->retx_timer);
}

static void airwall_udp_expiry_fn(
  struct timer_link *timer, struct timer_linkheap *heap, void *ud, void *td)
{
  struct worker_local *local = ud;
  struct airwall_udp_entry *e;
  e = CONTAINER_OF(timer, struct airwall_udp_entry, timer);
  hash_table_delete(&local->local_udp_hash, &e->local_node, airwall_hash_local_udp(e));
  hash_table_delete(&local->nat_udp_hash, &e->nat_node, airwall_hash_nat_udp(e));
  deallocate_udp_port(local->airwall->udp_porter, e->nat_port, !e->was_incoming);
  worker_local_wrlock(local);
  if (e->was_incoming)
  {
    local->incoming_udp_connections--;
  }
  else
  {
    local->direct_udp_connections--;
  }
  worker_local_wrunlock(local);
  free(e);
}

static void airwall_icmp_expiry_fn(
  struct timer_link *timer, struct timer_linkheap *heap, void *ud, void *td)
{
  struct worker_local *local = ud;
  struct airwall_icmp_entry *e;
  e = CONTAINER_OF(timer, struct airwall_icmp_entry, timer);
  hash_table_delete(&local->local_icmp_hash, &e->local_node, airwall_hash_local_icmp(e));
  hash_table_delete(&local->nat_icmp_hash, &e->nat_node, airwall_hash_nat_icmp(e));
  deallocate_udp_port(local->airwall->icmp_porter, e->nat_identifier, !e->was_incoming);
  worker_local_wrlock(local);
  if (e->was_incoming)
  {
    local->incoming_icmp_connections--;
  }
  else
  {
    local->direct_icmp_connections--;
  }
  worker_local_wrunlock(local);
  free(e);
}

static inline int seq_cmp(uint32_t x, uint32_t y)
{
  int32_t result = x-y;
  if (result > 512*1024*1024 || result < -512*1024*1024)
  {
    log_log(LOG_LEVEL_EMERG, "WORKER",
      "TOO GREAT SEQUENCE NUMBER DIFFERENCE %u %u", x, y);
  }
  if (result > 0)
  {
    return 1;
  }
  if (result < 0)
  {
    return -1;
  }
  return result;
}

static inline uint32_t between(uint32_t a, uint32_t x, uint32_t b)
{
  if (b - a > 512*1024*1024)
  {
    log_log(LOG_LEVEL_EMERG, "WORKER",
      "TOO GREAT SEQUENCE NUMBER DIFFERENCE %u %u %u", a, x, b);
  }
  if (b >= a)
  {
    return x >= a && x < b;
  }
  else
  {
    return x >= a || x < b;
  }
}

static struct airwall_hash_entry *alloc_airwall_hash_entry(struct worker_local *local)
{
  if (local->synproxied_connections + local->direct_connections
      >= local->airwall->conf->max_tcp_connections)
  {
    return NULL;
  }
  return malloc(sizeof(struct airwall_hash_entry));
}

static struct airwall_udp_entry *alloc_airwall_udp_entry(struct worker_local *local)
{
  if (local->incoming_udp_connections + local->direct_udp_connections
      >= local->airwall->conf->max_udp_connections)
  {
    return NULL;
  }
  return malloc(sizeof(struct airwall_udp_entry));
}

static struct airwall_icmp_entry *alloc_airwall_icmp_entry(struct worker_local *local)
{
  if (local->incoming_icmp_connections + local->direct_icmp_connections
      >= local->airwall->conf->max_icmp_connections)
  {
    return NULL;
  }
  return malloc(sizeof(struct airwall_icmp_entry));
}


struct airwall_hash_entry *airwall_hash_put(
  struct worker_local *local,
  int version,
  const void *local_ip,
  uint16_t local_port,
  const void *nat_ip,
  uint16_t nat_port,
  const void *remote_ip,
  uint16_t remote_port,
  uint8_t was_synproxied,
  uint64_t time64,
  int port_alloced)
{
  struct airwall_hash_entry *e;
  struct airwall_hash_ctx ctx;
  if (local_ip != 0 && local_port != 0)
  {
    if (airwall_hash_get_local(local, version, local_ip, local_port, remote_ip, remote_port, &ctx))
    {
      return NULL;
    }
  }
  if (airwall_hash_get_nat(local, version, nat_ip, nat_port, remote_ip, remote_port, &ctx))
  {
    return NULL;
  }
  e = alloc_airwall_hash_entry(local);
  if (e == NULL)
  {
    return NULL;
  }
  memset(e, 0, sizeof(*e));
  e->version = version;
  if (local_ip != NULL)
  {
    memcpy(&e->local_ip, local_ip, (version == 4) ? 4 : 16);
  }
  memcpy(&e->nat_ip, nat_ip, (version == 4) ? 4 : 16);
  memcpy(&e->remote_ip, remote_ip, (version == 4) ? 4 : 16);
  e->detect = NULL;
  e->port_alloced = port_alloced;
  e->local_port = local_port;
  e->nat_port = nat_port;
  e->remote_port = remote_port;
  e->was_synproxied = was_synproxied;
  e->timer.time64 = time64 + TCP_CONNECTED_TIMEOUT_SECS*1000ULL*1000ULL;
  e->timer.fn = airwall_expiry_fn;
  e->timer.userdata = local;
  worker_local_wrlock(local);
  timer_linkheap_add(&local->timers, &e->timer);
  if (local_port != 0)
  {
    hash_table_add_nogrow_already_bucket_locked(
      &local->local_hash, &e->local_node, airwall_hash_local(e));
  }
  hash_table_add_nogrow_already_bucket_locked(
    &local->nat_hash, &e->nat_node, airwall_hash_nat(e));
  if (was_synproxied)
  {
    local->synproxied_connections++;
  }
  else
  {
    local->direct_connections++;
  }
  worker_local_wrunlock(local);
  return e;
}

struct airwall_udp_entry *airwall_hash_put_udp(
  struct worker_local *local,
  int version,
  const void *local_ip,
  uint16_t local_port,
  const void *nat_ip,
  uint16_t nat_port,
  const void *remote_ip,
  uint16_t remote_port,
  uint8_t was_incoming,
  uint64_t time64)
{
  struct airwall_udp_entry *ue;
  struct airwall_hash_ctx ctx;

  if (airwall_hash_get_local_udp(local, version, local_ip, local_port, remote_ip, remote_port, &ctx))
  {
    return NULL;
  }
  if (airwall_hash_get_nat_udp(local, version, nat_ip, nat_port, remote_ip, remote_port, &ctx))
  {
    return NULL;
  }
  ue = alloc_airwall_udp_entry(local);
  if (ue == NULL)
  {
    return NULL;
  }
  memset(ue, 0, sizeof(*ue));
  ue->version = version;
  if (local_ip != NULL)
  {
    memcpy(&ue->local_ip, local_ip, (version == 4) ? 4 : 16);
  }
  memcpy(&ue->nat_ip, nat_ip, (version == 4) ? 4 : 16);
  memcpy(&ue->remote_ip, remote_ip, (version == 4) ? 4 : 16);
  ue->local_port = local_port;
  ue->nat_port = nat_port;
  ue->remote_port = remote_port;
  ue->was_incoming = was_incoming;
  ue->timer.time64 = time64 + UDP_TIMEOUT_SECS*1000ULL*1000ULL;
  ue->timer.fn = airwall_udp_expiry_fn;
  ue->timer.userdata = local;
  worker_local_wrlock(local);
  timer_linkheap_add(&local->timers, &ue->timer);
  hash_table_add_nogrow_already_bucket_locked(
    &local->local_udp_hash, &ue->local_node, airwall_hash_local_udp(ue));
  hash_table_add_nogrow_already_bucket_locked(
    &local->nat_udp_hash, &ue->nat_node, airwall_hash_nat_udp(ue));
  if (was_incoming)
  {
    local->incoming_udp_connections++;
  }
  else
  {
    local->direct_udp_connections++;
  }
  worker_local_wrunlock(local);
  return ue;
}

struct airwall_icmp_entry *airwall_hash_put_icmp(
  struct worker_local *local,
  int version,
  const void *local_ip,
  uint16_t local_identifier,
  const void *nat_ip,
  uint16_t nat_identifier,
  const void *remote_ip,
  uint8_t was_incoming,
  uint64_t time64)
{
  struct airwall_icmp_entry *ue;
  struct airwall_hash_ctx ctx;

  if (airwall_hash_get_local_icmp(local, version, local_ip, remote_ip, local_identifier, &ctx))
  {
    return NULL;
  }
  if (airwall_hash_get_nat_icmp(local, version, nat_ip, remote_ip, nat_identifier, &ctx))
  {
    return NULL;
  }
  ue = alloc_airwall_icmp_entry(local);
  if (ue == NULL)
  {
    return NULL;
  }
  memset(ue, 0, sizeof(*ue));
  ue->version = version;
  if (local_ip != NULL)
  {
    memcpy(&ue->local_ip, local_ip, (version == 4) ? 4 : 16);
  }
  memcpy(&ue->nat_ip, nat_ip, (version == 4) ? 4 : 16);
  memcpy(&ue->remote_ip, remote_ip, (version == 4) ? 4 : 16);
  ue->local_identifier = local_identifier;
  ue->nat_identifier = nat_identifier;
  ue->was_incoming = was_incoming;
  ue->timer.time64 = time64 + ICMP_TIMEOUT_SECS*1000ULL*1000ULL;
  ue->timer.fn = airwall_icmp_expiry_fn;
  ue->timer.userdata = local;
  worker_local_wrlock(local);
  timer_linkheap_add(&local->timers, &ue->timer);
  hash_table_add_nogrow_already_bucket_locked(
    &local->local_icmp_hash, &ue->local_node, airwall_hash_local_icmp(ue));
  hash_table_add_nogrow_already_bucket_locked(
    &local->nat_icmp_hash, &ue->nat_node, airwall_hash_nat_icmp(ue));
  if (was_incoming)
  {
    local->incoming_icmp_connections++;
  }
  else
  {
    local->direct_icmp_connections++;
  }
  worker_local_wrunlock(local);
  return ue;
}


uint32_t airwall_hash_fn_local(struct hash_list_node *node, void *userdata)
{
  return airwall_hash_local(CONTAINER_OF(node, struct airwall_hash_entry, local_node));
}
uint32_t airwall_hash_fn_nat(struct hash_list_node *node, void *userdata)
{
  return airwall_hash_nat(CONTAINER_OF(node, struct airwall_hash_entry, nat_node));
}

uint32_t airwall_hash_fn_local_udp(struct hash_list_node *node, void *userdata)
{
  return airwall_hash_local_udp(CONTAINER_OF(node, struct airwall_udp_entry, local_node));
}
uint32_t airwall_hash_fn_nat_udp(struct hash_list_node *node, void *userdata)
{
  return airwall_hash_nat_udp(CONTAINER_OF(node, struct airwall_udp_entry, nat_node));
}

uint32_t airwall_hash_fn_local_icmp(struct hash_list_node *node, void *userdata)
{
  return airwall_hash_local_icmp(CONTAINER_OF(node, struct airwall_icmp_entry, local_node));
}
uint32_t airwall_hash_fn_nat_icmp(struct hash_list_node *node, void *userdata)
{
  return airwall_hash_nat_icmp(CONTAINER_OF(node, struct airwall_icmp_entry, nat_node));
}

static void delete_closing_already_bucket_locked(
  struct airwall *airwall, struct worker_local *local,
  struct airwall_hash_entry *entry)
{
  int ok = 0;
  if (entry->flag_state == FLAG_STATE_RESETED ||
      entry->flag_state == FLAG_STATE_TIME_WAIT ||
      ((entry->flag_state & FLAG_STATE_UPLINK_FIN) &&
       (entry->flag_state & FLAG_STATE_DOWNLINK_FIN)))
  {
    ok = 1;
  }
  if (!ok)
  {
    abort();
  }
  log_log(LOG_LEVEL_NOTICE, "SYNPROXY",
          "deleting closing connection to make room for new");
  timer_linkheap_remove(&local->timers, &entry->timer);
  if (entry->retxtimer_set)
  {
    timer_linkheap_remove(&local->timers, &entry->retx_timer);
    entry->retxtimer_set = 0;
  }
  if (entry->port_alloced)
  {
    deallocate_udp_port(local->airwall->porter, entry->nat_port, !entry->was_synproxied);
  }
  if (entry->local_port != 0)
  {
    hash_table_delete_already_bucket_locked(&local->local_hash, &entry->local_node);
  }
  hash_table_delete_already_bucket_locked(&local->nat_hash, &entry->nat_node);
  worker_local_wrlock(local);
  if (entry->was_synproxied)
  {
    local->synproxied_connections--;
  }
  else
  {
    local->direct_connections--;
  }
  worker_local_wrunlock(local);
  if (entry->detect)
  {
    local->detect_count--;
    linked_list_delete(&entry->detect_node);
  }
  free(entry->detect);
  entry->detect = NULL;
  free(entry);
  entry = NULL;
}

static void send_syn(
  void *orig, struct worker_local *local, struct port *port,
  struct ll_alloc_st *st,
  uint16_t mss, uint8_t wscale, uint8_t sack_permitted,
  struct airwall_hash_entry *entry,
  uint64_t time64, int was_keepalive, struct airwall *airwall);

static void ack_data(
  void *orig, struct worker_local *local, struct airwall *airwall,
  struct port *port, struct ll_alloc_st *st, uint64_t time64,
  struct airwall_hash_entry *entry, uint32_t acked)
{
  char ack[14+40+20+12] = {0};
  char *origip, *origtcp;
  void *ip, *tcp;
  int version;
  uint32_t seqack;
  unsigned char *tcpopts;
  struct packet *pktstruct;
  size_t sz;
  struct tcp_information info;
  uint32_t sh;

  origip = ether_payload(orig);
  version = ip_version(origip);
  origtcp = ip46_payload(origip);
  tcp_parse_options(origtcp, &info);

  seqack = entry->remote_isn + 1 + acked;

  version = entry->version;
  sz = (version == 4) ? (sizeof(ack) - 20) : sizeof(ack);

  memcpy(ether_src(ack), ether_dst(orig), 6);
  memcpy(ether_dst(ack), ether_src(orig), 6);
  ether_set_type(ack, (version == 4) ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
  ip = ether_payload(ack);
  ip_set_version(ip, version);
#if 0 // FIXME this needs to be thought carefully
  if (version == 6)
  {
    ipv6_set_flow_label(ip, entry->ulflowlabel);
  }
#endif
  ip46_set_min_hdr_len(ip);
  ip46_set_payload_len(ip, sizeof(ack) - 14 - 40);
  ip46_set_dont_frag(ip, 1);
  ip46_set_id(ip, 0); // XXX
  ip46_set_ttl(ip, 64);
  ip46_set_proto(ip, 6);
  ip46_set_src(ip, ip46_dst(origip));
  ip46_set_dst(ip, ip46_src(origip));
  ip46_set_hdr_cksum_calc(ip);
  tcp = ip46_payload(ip);
  tcp_set_src_port(tcp, tcp_dst_port(origtcp));
  tcp_set_dst_port(tcp, tcp_src_port(origtcp));
  tcp_set_ack_on(tcp);
  tcp_set_data_offset(tcp, sizeof(ack) - 14 - 40);
  tcp_set_seq_number(tcp, entry->local_isn + 1);
  tcp_set_ack_number(tcp, seqack);

  sh = (1<<airwall->conf->own_wscale) - 1;
  tcp_set_window(tcp, (INITIAL_WINDOW - acked + sh)>>airwall->conf->own_wscale);
  tcpopts = &((unsigned char*)tcp)[20];
  if (info.options_valid && info.ts_present)
  {
    tcpopts[0] = 1;
    tcpopts[1] = 1;
    tcpopts[2] = 8;
    tcpopts[3] = 10;
    hdr_set32n(&tcpopts[4], info.tsecho);
    hdr_set32n(&tcpopts[8], info.ts);
  }
  else
  {
    memset(&tcpopts[0], 0, 12);
  }
  tcp46_set_cksum_calc(ip);

  pktstruct = ll_alloc_st(st, packet_size(sz));
  pktstruct->data = packet_calc_data(pktstruct);
  pktstruct->direction = PACKET_DIRECTION_UPLINK;
  pktstruct->sz = sz;
  memcpy(pktstruct->data, ack, sz);
  port->portfunc(pktstruct, port->userdata);
}

static void send_rst(
  void *orig, struct worker_local *local, struct airwall *airwall,
  struct port *port, struct ll_alloc_st *st, uint64_t time64,
  struct airwall_hash_entry *entry)
{
  char windowupdate[14+40+20+12] = {0};
  void *ip, *origip;
  void *tcp, *origtcp;
  struct packet *pktstruct;
  unsigned char *tcpopts;
  int version;
  size_t sz;

  struct tcp_information info;

  origip = ether_payload(orig);
  version = ip_version(origip);
  origtcp = ip46_payload(origip);
  tcp_parse_options(origtcp, &info);

  version = entry->version;
  sz = (version == 4) ? (sizeof(windowupdate) - 20) : sizeof(windowupdate);

  memcpy(ether_src(windowupdate), ether_dst(orig), 6);
  memcpy(ether_dst(windowupdate), ether_src(orig), 6);
  ether_set_type(windowupdate, (version == 4) ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
  ip = ether_payload(windowupdate);
  ip_set_version(ip, version);
#if 0 // FIXME this needs to be thought carefully
  if (version == 6)
  {
    ipv6_set_flow_label(ip, entry->ulflowlabel);
  }
#endif
  ip46_set_min_hdr_len(ip);
  ip46_set_payload_len(ip, sizeof(windowupdate) - 14 - 40);
  ip46_set_dont_frag(ip, 1);
  ip46_set_id(ip, 0); // XXX
  ip46_set_ttl(ip, 64);
  ip46_set_proto(ip, 6);
  ip46_set_src(ip, ip46_dst(origip));
  ip46_set_dst(ip, ip46_src(origip));
  ip46_set_hdr_cksum_calc(ip);
  tcp = ip46_payload(ip);
  tcp_set_src_port(tcp, tcp_dst_port(origtcp));
  tcp_set_dst_port(tcp, tcp_src_port(origtcp));
  tcp_set_rst_on(tcp);
  tcp_set_data_offset(tcp, sizeof(windowupdate) - 14 - 40);
  tcp_set_seq_number(tcp, tcp_ack_number(origtcp));
  tcp_set_window(tcp, 0);
  tcpopts = &((unsigned char*)tcp)[20];
  if (info.options_valid && info.ts_present)
  {
    tcpopts[0] = 1;
    tcpopts[1] = 1;
    tcpopts[2] = 8;
    tcpopts[3] = 10;
    hdr_set32n(&tcpopts[4], info.tsecho);
    hdr_set32n(&tcpopts[8], info.ts);
  }
  else
  {
    memset(&tcpopts[0], 0, 12);
  }
  tcp46_set_cksum_calc(ip);

  pktstruct = ll_alloc_st(st, packet_size(sz));
  pktstruct->data = packet_calc_data(pktstruct);
  pktstruct->direction = PACKET_DIRECTION_UPLINK;
  pktstruct->sz = sz;
  memcpy(pktstruct->data, windowupdate, sz);
  port->portfunc(pktstruct, port->userdata);
}

static void process_data(
  void *orig, struct worker_local *local, struct airwall *airwall,
  struct port *port, struct ll_alloc_st *st, uint64_t time64,
  struct airwall_hash_entry *entry)
{
  //int version;
  char *origip, *origtcp;
  char *tcppay;
  uint16_t tcppay_len;
  uint32_t acked;
  uint32_t seqdiff;
  int res;
  char *strr = NULL;

  if (entry->flag_state != FLAG_STATE_WINDOW_UPDATE_SENT)
  {
    abort();
  }

  if (entry->detect == NULL)
  {
    while (local->detect_count &&
           local->detect_count >= airwall->conf->detect_cache_max)
    {
      struct linked_list_node *node = local->detect_list.node.next;
      //uint32_t hashval;
      struct airwall_hash_entry *e =
        CONTAINER_OF(node, struct airwall_hash_entry, detect_node);
      //hashval = airwall_hash(e);
      timer_linkheap_remove(&local->timers, &e->timer);
      if (e->retxtimer_set)
      {
        timer_linkheap_remove(&local->timers, &e->retx_timer);
        e->retxtimer_set = 0;
      }
      if (!e->detect)
      {
        abort();
      }
      if (!e->was_synproxied)
      {
        abort();
      }
      local->synproxied_connections--;
      local->detect_count--;
      linked_list_delete(&e->detect_node);
      free(e->detect);
      e->detect = NULL;
      if (e->port_alloced)
      {
        deallocate_udp_port(airwall->porter, e->nat_port, !e->was_synproxied);
      }
      if (e->local_port != 0)
      {
        hash_table_delete_already_bucket_locked(&local->local_hash, &e->local_node);
      }
      hash_table_delete_already_bucket_locked(&local->nat_hash, &e->nat_node);
      free(e);
    }
    entry->detect = malloc(sizeof(*entry->detect));
    proto_detect_ctx_init(entry->detect);
    linked_list_add_tail(
      &entry->detect_node, &local->detect_list);
    local->detect_count++;
  }

  origip = ether_payload(orig);
  //version = ip_version(origip);
  origtcp = ip46_payload(origip);
  tcppay = origtcp + tcp_data_offset(origtcp);
  tcppay_len = ip46_payload_len(origip) - tcp_data_offset(origtcp);
  seqdiff = tcp_seq_number(origtcp) - entry->remote_isn - 1;
#if 0
  if (seqdiff < 0)
  {
    log_log(LOG_LEVEL_ERR, "AIRWALL", "seqdiff < 0");
    return;
  }
#endif
  res = proto_detect_feed(entry->detect, tcppay, seqdiff, tcppay_len, &acked);
  if (res == -EAGAIN)
  {
    if (airwall->conf->enable_ack)
    {
      ack_data(orig, local, airwall, port, st, time64, entry, acked);
    }
    return;
  }
  else if (res == -ENOTSUP)
  {
    log_log(LOG_LEVEL_ERR, "AIRWALL", "can't detect protocol and host");
    send_rst(orig, local, airwall, port, st, time64, entry);
    entry->timer.time64 = time64 + TCP_RESETED_TIMEOUT_SECS*1000ULL*1000ULL;
    entry->flag_state = FLAG_STATE_RESETED;
    timer_linkheap_modify(&local->timers, &entry->timer);
  }
  else if (res == -EBADMSG)
  {
    log_log(LOG_LEVEL_ERR, "AIRWALL", "content conflict");
    send_rst(orig, local, airwall, port, st, time64, entry);
    entry->timer.time64 = time64 + TCP_RESETED_TIMEOUT_SECS*1000ULL*1000ULL;
    entry->flag_state = FLAG_STATE_RESETED;
    timer_linkheap_modify(&local->timers, &entry->timer);
  }
  else if (res == 0)
  {
    uint16_t proxied_port = 0;
    log_log(LOG_LEVEL_NOTICE, "AIRWALL", "detected protocol and host %s",
            entry->detect->hostctx.hostname);
    if (entry->local_port != 0)
    {
      abort();
    }
    if (entry->detect->hostctx.is_http_connect_num_bytes)
    {
      // FIXME should use a local buffer; this overwrites it!
      strr = strrchr(entry->detect->hostctx.hostname, ':');
      if (strr != NULL)
      {
        unsigned long int portul;
        char *endptr;
        *strr = '\0'; // A bit unsafe: every return path must revert this
        portul = strtoul(strr+1, &endptr, 10);
        if (*endptr != '\0' || portul >= 65536 || portul == 0)
        {
          log_log(LOG_LEVEL_ERR, "AIRWALL", "invalid port %s", strr+1);
          send_rst(orig, local, airwall, port, st, time64, entry);
          entry->timer.time64 = time64 + TCP_RESETED_TIMEOUT_SECS*1000ULL*1000ULL;
          entry->flag_state = FLAG_STATE_RESETED;
          timer_linkheap_modify(&local->timers, &entry->timer);
          *strr = ':';
          return;
        }
        proxied_port = portul;
      }
      else
      {
        proxied_port = 80;
      }
#if 0 // Best not to ACK it now so that client will try re-TX if packets lost
      if (airwall->conf->enable_ack)
      {
        ack_data(orig, local, airwall, port, st, time64, entry,
                 entry->detect->hostctx.is_http_connect_num_bytes);
      }
#endif
    }
    else
    {
      proxied_port = entry->nat_port;
    }
    entry->local_port = proxied_port;
#ifdef ENABLE_ARP
    if (entry->version == 6)
    {
      abort(); // FIXME
    }
    uint32_t loc =
      host_hash_get(&airwall->conf->hosts, entry->detect->hostctx.hostname);
    char ipv4[4];
    if (strr)
    {
      *strr = ':';
    }
    if (loc == 0)
    {
      log_log(LOG_LEVEL_ERR, "AIRWALL", "host %s not found",
              entry->detect->hostctx.hostname);
      send_rst(orig, local, airwall, port, st, time64, entry);
      entry->timer.time64 = time64 + TCP_RESETED_TIMEOUT_SECS*1000ULL*1000ULL;
      entry->flag_state = FLAG_STATE_RESETED;
      timer_linkheap_modify(&local->timers, &entry->timer);
      return;
    }
    hdr_set32n(ipv4, loc);
    memcpy(&entry->local_ip.ipv4, ipv4, sizeof(ipv4));
#else
    memcpy(&entry->local_ip, &entry->nat_ip, sizeof(entry->local_ip));
#endif
    allocate_udp_port(airwall->porter, entry->nat_port, ntohl(entry->local_ip.ipv4), entry->local_port, 0);
    entry->port_alloced = 1;
    hash_table_add_nogrow_already_bucket_locked(
      &local->local_hash, &entry->local_node, airwall_hash_local(entry));
    if (entry->detect->hostctx.is_http_connect_num_bytes)
    {
      entry->revdata = 1;
      entry->remote_isn += entry->detect->hostctx.is_http_connect_num_bytes;
      if (entry->detect)
      {
        local->detect_count--;
        linked_list_delete(&entry->detect_node);
      }
      free(entry->detect);
      entry->detect = NULL;
    }
    send_syn(
      orig, local, port, st, // FIXME verify send_syn doesn't handle orig wrong
      entry->state_data.downlink_half_open.mss,
      entry->state_data.downlink_half_open.wscale,
      entry->state_data.downlink_half_open.sack_permitted, entry, time64, 0,
      airwall);
  }
}

// Caller must hold worker_local mutex lock
static void send_synack(
  void *orig, struct worker_local *local, struct airwall *airwall,
  struct port *port, struct ll_alloc_st *st, uint64_t time64)
{
  char synack[14+40+20+12+12] = {0};
  void *ip, *origip;
  void *tcp, *origtcp;
  unsigned char *tcpopts;
  struct packet *pktstruct;
  uint32_t syn_cookie;
  struct tcp_information tcpinfo;
  //struct sack_hash_data ipentry, ipportentry;
  uint16_t own_mss;
  uint8_t own_sack;
  uint32_t ts;
  const void *local_ip, *remote_ip;
  uint16_t local_port, remote_port;
  uint8_t own_wscale;
  //struct threetuplepayload threetuplepayload;
  int version;
  size_t sz;

  origip = ether_payload(orig);
  version = ip_version(origip);
  sz = ((version == 4) ? (sizeof(synack) - 20) : sizeof(synack));
  origtcp = ip46_payload(origip);
  tcp_parse_options(origtcp, &tcpinfo);
  if (!tcpinfo.options_valid)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "options in TCP SYN invalid");
    return;
  }
  if (version == 4)
  {
    syn_cookie = form_cookie(
      &local->info, airwall, ip_dst(origip), ip_src(origip),
      tcp_dst_port(origtcp), tcp_src_port(origtcp),
      tcpinfo.mss, tcpinfo.wscale, tcpinfo.sack_permitted,
      tcp_seq_number(origtcp));
    ts = form_timestamp(
      &local->info, airwall, ip_dst(origip), ip_src(origip),
      tcp_dst_port(origtcp), tcp_src_port(origtcp),
      tcpinfo.mss, tcpinfo.wscale);
  }
  else
  {
    syn_cookie = form_cookie6(
      &local->info, airwall, ipv6_dst(origip), ipv6_src(origip),
      tcp_dst_port(origtcp), tcp_src_port(origtcp),
      tcpinfo.mss, tcpinfo.wscale, tcpinfo.sack_permitted,
      tcp_seq_number(origtcp));
    ts = form_timestamp6(
      &local->info, airwall, ipv6_dst(origip), ipv6_src(origip),
      tcp_dst_port(origtcp), tcp_src_port(origtcp),
      tcpinfo.mss, tcpinfo.wscale);
  }

#if 0
  if (   airwall->conf->mssmode == HASHMODE_COMMANDED
      || airwall->conf->sackmode == HASHMODE_COMMANDED
      || airwall->conf->wscalemode == HASHMODE_COMMANDED)
  {
    if (version == 4)
    {
      if (threetuplectx_find(&airwall->threetuplectx, ip_dst(origip), tcp_dst_port(origtcp), 6, &threetuplepayload) != 0)
      {
        threetuplepayload.sack_supported = airwall->conf->own_sack;
        threetuplepayload.mss = airwall->conf->own_mss;
        threetuplepayload.wscaleshift = airwall->conf->own_wscale;
      }
    }
    else
    {
      if (threetuplectx_find6(&airwall->threetuplectx, ipv6_dst(origip), tcp_dst_port(origtcp), 6, &threetuplepayload) != 0)
      {
        threetuplepayload.sack_supported = airwall->conf->own_sack;
        threetuplepayload.mss = airwall->conf->own_mss;
        threetuplepayload.wscaleshift = airwall->conf->own_wscale;
      }
    }
  }
  if (   airwall->conf->mssmode == HASHMODE_HASHIPPORT
      || airwall->conf->sackmode == HASHMODE_HASHIPPORT)
  {
    if (version == 4)
    {
      if (sack_ip_port_hash_get4(&airwall->autolearn, ip_dst(origip), tcp_dst_port(origtcp), &ipportentry) == 0)
      {
        ipportentry.sack_supported = airwall->conf->own_sack;
        ipportentry.mss = airwall->conf->own_mss;
      }
    }
    else
    {
      if (sack_ip_port_hash_get6(&airwall->autolearn, ipv6_dst(origip), tcp_dst_port(origtcp), &ipportentry) == 0)
      {
        ipportentry.sack_supported = airwall->conf->own_sack;
        ipportentry.mss = airwall->conf->own_mss;
      }
    }
  }
  if (   airwall->conf->mssmode == HASHMODE_HASHIP
      || airwall->conf->sackmode == HASHMODE_HASHIP)
  {
    if (version == 4)
    {
      if (sack_ip_port_hash_get4(&airwall->autolearn, ip_dst(origip), 0, &ipentry) == 0)
      {
        ipentry.sack_supported = airwall->conf->own_sack;
        ipentry.mss = airwall->conf->own_mss;
      }
    }
    else
    {
      if (sack_ip_port_hash_get6(&airwall->autolearn, ipv6_dst(origip), 0, &ipentry) == 0)
      {
        ipentry.sack_supported = airwall->conf->own_sack;
        ipentry.mss = airwall->conf->own_mss;
      }
    }
  }
  if (airwall->conf->mssmode == HASHMODE_HASHIPPORT)
  {
    own_mss = ipportentry.mss;
  }
  else if (airwall->conf->mssmode == HASHMODE_HASHIP)
  {
    own_mss = ipentry.mss;
  }
  else if (airwall->conf->mssmode == HASHMODE_COMMANDED)
  {
    own_mss = threetuplepayload.mss;
  }
  else
#endif
  {
    own_mss = airwall->conf->own_mss;
  }
#if 0
  if (airwall->conf->sackmode == HASHMODE_HASHIPPORT)
  {
    own_sack = ipportentry.sack_supported;
  }
  else if (airwall->conf->sackmode == HASHMODE_HASHIP)
  {
    own_sack = ipentry.sack_supported;
  }
  else if (airwall->conf->sackmode == HASHMODE_COMMANDED)
  {
    own_sack = threetuplepayload.sack_supported;
  }
  else
#endif
  {
    own_sack = airwall->conf->own_sack;
  }
#if 0
  if (airwall->conf->wscalemode == HASHMODE_COMMANDED)
  {
    own_wscale = threetuplepayload.wscaleshift;
  }
  else
#endif
  {
    own_wscale = airwall->conf->own_wscale;
  }

  local_ip = ip46_dst(origip);
  remote_ip = ip46_src(origip);
  local_port = tcp_dst_port(origtcp);
  remote_port = tcp_src_port(origtcp);

  memcpy(ether_src(synack), ether_dst(orig), 6);
  memcpy(ether_dst(synack), ether_src(orig), 6);
  ether_set_type(synack, version == 4 ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
  ip = ether_payload(synack);
  ip_set_version(ip, version);
  if (version == 6)
  {
    ipv6_set_flow_label(ip, gen_flowlabel(ip46_dst(origip), tcp_dst_port(origtcp), ip46_src(origip), tcp_src_port(origtcp)));
  }
  ip46_set_min_hdr_len(ip);
  ip46_set_payload_len(ip, sizeof(synack) - 14 - 40);
  ip46_set_dont_frag(ip, 1);
  ip46_set_id(ip, 0); // XXX
  ip46_set_ttl(ip, 64);
  ip46_set_proto(ip, 6);
  ip46_set_src(ip, ip46_dst(origip));
  ip46_set_dst(ip, ip46_src(origip));
  ip46_set_hdr_cksum_calc(ip);
  tcp = ip46_payload(ip);
  tcp_set_src_port(tcp, tcp_dst_port(origtcp));
  tcp_set_dst_port(tcp, tcp_src_port(origtcp));
  tcp_set_syn_on(tcp);
  tcp_set_ack_on(tcp);
  tcp_set_data_offset(tcp, sizeof(synack) - 14 - 40);
  tcp_set_seq_number(tcp, syn_cookie);
  tcp_set_ack_number(tcp, tcp_seq_number(origtcp) + 1);
  tcp_set_window(tcp, 0);
  tcpopts = &((unsigned char*)tcp)[20];
  // WS, kind 3 len 3
  // NOP, kind 1 len 1
  // MSS, kind 2 len 4
  // SACK permitted, kind 4 len 2
  // endlist, kind 0 len 1
  // pad, kind 0 len 1
  tcpopts[0] = 3;
  tcpopts[1] = 3;
  tcpopts[2] = own_wscale;
  tcpopts[3] = 1;
  tcpopts[4] = 2;
  tcpopts[5] = 4;
  hdr_set16n(&tcpopts[6], own_mss);
  if (own_sack)
  {
    tcpopts[8] = 4;
    tcpopts[9] = 2;
    if (tcpinfo.options_valid && tcpinfo.ts_present)
    {
      tcpopts[10] = 1;
      tcpopts[11] = 1;
    }
    else
    {
      tcpopts[10] = 0;
      tcpopts[11] = 0;
    }
  }
  else if (tcpinfo.options_valid && tcpinfo.ts_present)
  {
    tcpopts[8] = 1;
    tcpopts[9] = 1;
    tcpopts[10] = 1;
    tcpopts[11] = 1;
  }
  else
  {
    tcpopts[8] = 0;
    tcpopts[9] = 0;
    tcpopts[10] = 0;
    tcpopts[11] = 0;
  }
  if (tcpinfo.options_valid && tcpinfo.ts_present)
  {
    tcpopts[12] = 1;
    tcpopts[13] = 1;
    tcpopts[14] = 8;
    tcpopts[15] = 10;
    hdr_set32n(&tcpopts[16], ts); // ts
    hdr_set32n(&tcpopts[20], tcpinfo.ts); // tsecho
  }
  else
  {
    memset(&tcpopts[12], 0, 12);
  }
  tcp46_set_cksum_calc(ip);
  pktstruct = ll_alloc_st(st, packet_size(sz));
  pktstruct->data = packet_calc_data(pktstruct);
  pktstruct->direction = PACKET_DIRECTION_UPLINK;
  pktstruct->sz = sz;
  memcpy(pktstruct->data, synack, sz);
#ifdef ENABLE_ARP
  if (send_via_arp(pktstruct, local, airwall, st, port, PACKET_DIRECTION_UPLINK, time64))
  {
    ll_free_st(st, pktstruct);
    return;
  }
#endif
  port->portfunc(pktstruct, port->userdata);

  if (airwall->conf->halfopen_cache_max)
  {
    struct airwall_hash_entry *e;
    struct airwall_hash_entry *e2;
    struct airwall_hash_ctx ctx;
    //ctx.locked = 0;
    e2 = airwall_hash_get_nat(local, version,
                              local_ip, local_port, remote_ip, remote_port,
                              &ctx);
    if (e2)
    {
      if (e2->flag_state == FLAG_STATE_RESETED ||
          e2->flag_state == FLAG_STATE_TIME_WAIT ||
          ((e2->flag_state & FLAG_STATE_UPLINK_FIN) &&
           (e2->flag_state & FLAG_STATE_DOWNLINK_FIN)))
      {
        delete_closing_already_bucket_locked(airwall, local, e2);
        e2 = NULL;
      }
      else
      {
        //airwall_hash_unlock(local, &ctx);
        return; // duplicate SYN
      }
    }
    worker_local_wrlock(local);
    if (local->half_open_connections >= airwall->conf->halfopen_cache_max)
    {
      struct linked_list_node *node = local->half_open_list.node.next;
      //uint32_t hashval;
      e = CONTAINER_OF(
            node, struct airwall_hash_entry,
            state_data.downlink_half_open.listnode);
      //hashval = airwall_hash(e);
      linked_list_delete(&e->state_data.downlink_half_open.listnode);
      timer_linkheap_remove(&local->timers, &e->timer);
      if (e->retxtimer_set)
      {
        timer_linkheap_remove(&local->timers, &e->retx_timer);
        e->retxtimer_set = 0;
      }
      if (e->detect)
      {
        local->detect_count--;
        linked_list_delete(&e->detect_node);
      }
      free(e->detect);
      e->detect = NULL;
      if (e->port_alloced)
      {
        deallocate_udp_port(airwall->porter, e->nat_port, !e->was_synproxied);
      }
      //if (ctx.hashval == hashval)
      {
        if (e->local_port != 0)
        {
          hash_table_delete_already_bucket_locked(&local->local_hash, &e->local_node);
        }
        hash_table_delete_already_bucket_locked(&local->nat_hash, &e->nat_node);
      }
#if 0
      else
      {
        // Prevent lock order reversal
        worker_local_wrunlock(local);
        hash_table_delete(&local->hash, &e->node, airwall_hash(e));
        worker_local_wrlock(local);
      }
#endif
    }
    else
    {
      e = alloc_airwall_hash_entry(local);
      if (e == NULL)
      {
        worker_local_wrunlock(local);
        //airwall_hash_unlock(local, &ctx);
        log_log(LOG_LEVEL_ERR, "WORKER", "out of memory");
        return;
      }
      local->half_open_connections++;
      local->synproxied_connections++;
    }
    memset(e, 0, sizeof(*e));
    e->version = version;
    memcpy(&e->nat_ip, local_ip, (version == 6) ? 16 : 4);
    memcpy(&e->remote_ip, remote_ip, (version == 6) ? 16 : 4);
    e->nat_port = local_port;
    e->remote_port = remote_port;
    // Don't allocate the port yet, as local IP is unknown
    //allocate_udp_port(airwall->porter, e->nat_port, 0, 0, 0);
    //e->port_alloced = 1;
    e->was_synproxied = 1;
    e->timer.time64 = time64 + TCP_DOWNLINK_HALF_OPEN_TIMEOUT_SECS*1000ULL*1000ULL;
    e->timer.fn = airwall_expiry_fn;
    e->timer.userdata = local;
    timer_linkheap_add(&local->timers, &e->timer);
    hash_table_add_nogrow(&local->nat_hash, &e->nat_node, airwall_hash_nat(e));
    //hash_table_add_nogrow(&local->local_hash, &e->local_node, airwall_hash_local(e));
    linked_list_add_tail(
      &e->state_data.downlink_half_open.listnode, &local->half_open_list);
    e->flag_state = FLAG_STATE_DOWNLINK_HALF_OPEN;
    e->state_data.downlink_half_open.wscale = tcpinfo.wscale;
    e->state_data.downlink_half_open.mss = tcpinfo.mss;
    e->state_data.downlink_half_open.sack_permitted = tcpinfo.sack_permitted;
    e->remote_isn = tcp_seq_number(origtcp);
    e->local_isn = syn_cookie;
    if (e->version == 6)
    {
      e->ulflowlabel = gen_flowlabel_entry(e);
    }

    worker_local_wrunlock(local);
    //airwall_hash_unlock(local, &ctx);
  }
}

static void send_or_resend_syn(
  void *orig, struct worker_local *local, struct port *port,
  struct ll_alloc_st *st,
  struct airwall_hash_entry *entry,
  struct airwall *airwall,
  uint64_t time64)
{
  char syn[14+20+40+12+12] = {0};
  void *ip, *origip;
  void *tcp, *origtcp;
  unsigned char *tcpopts;
  struct packet *pktstruct;
  int version;
  size_t sz;

  origip = ether_payload(orig);
  version = ip_version(origip);
  sz = ((version == 4) ? (sizeof(syn) - 20) : sizeof(syn));
  origtcp = ip46_payload(origip);

  memcpy(ether_src(syn), ether_src(orig), 6);
  memcpy(ether_dst(syn), ether_dst(orig), 6);
  ether_set_type(syn, version == 4 ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
  ip = ether_payload(syn);
  ip_set_version(ip, version);
  if (version == 6)
  {
    ipv6_set_flow_label(ip, entry->dlflowlabel);
  }
  ip46_set_min_hdr_len(ip);
  ip46_set_payload_len(ip, sizeof(syn) - 14 - 40);
  ip46_set_dont_frag(ip, 1);
  ip46_set_id(ip, 0); // XXX
  ip46_set_ttl(ip, 64);
  ip46_set_proto(ip, 6);
  ip46_set_src(ip, &entry->remote_ip);
  ip46_set_dst(ip, &entry->local_ip);
  ip46_set_hdr_cksum_calc(ip);
  tcp = ip46_payload(ip);
  tcp_set_src_port(tcp, entry->remote_port);
  tcp_set_dst_port(tcp, entry->local_port);
  tcp_set_syn_on(tcp);
  tcp_set_data_offset(tcp, sizeof(syn) - 14 - 40);
  tcp_set_seq_number(tcp, entry->remote_isn);
  tcp_set_ack_number(tcp, 0);
  tcp_set_window(tcp, tcp_window(origtcp));
  tcpopts = &((unsigned char*)tcp)[20];
  // WS, kind 3 len 3
  // NOP, kind 1 len 1
  // MSS, kind 2 len 4
  // SACK permitted, kind 4 len 2
  // endlist, kind 0 len 1
  // pad, kind 0 len 1
  tcpopts[0] = 3;
  tcpopts[1] = 3;
  tcpopts[2] = entry->wan_wscale;
  tcpopts[3] = 1;
  tcpopts[4] = 2;
  tcpopts[5] = 4;
  hdr_set16n(&tcpopts[6], entry->state_data.downlink_syn_sent.mss);
  if (entry->state_data.downlink_syn_sent.sack_permitted)
  {
    tcpopts[8] = 4;
    tcpopts[9] = 2;
    if (entry->state_data.downlink_syn_sent.timestamp_present)
    {
      tcpopts[10] = 1;
      tcpopts[11] = 1;
    }
    else
    {
      tcpopts[10] = 0;
      tcpopts[11] = 0;
    }
  }
  else if (entry->state_data.downlink_syn_sent.timestamp_present)
  {
    tcpopts[8] = 1;
    tcpopts[9] = 1;
    tcpopts[10] = 1;
    tcpopts[11] = 1;
  }
  else
  {
    tcpopts[8] = 0;
    tcpopts[9] = 0;
    tcpopts[10] = 0;
    tcpopts[11] = 0;
  }
  if (entry->state_data.downlink_syn_sent.timestamp_present)
  {
    tcpopts[12] = 1;
    tcpopts[13] = 1;
    tcpopts[14] = 8;
    tcpopts[15] = 10;
    hdr_set32n(&tcpopts[16],
      entry->state_data.downlink_syn_sent.remote_timestamp);
    hdr_set32n(&tcpopts[20], 0); // tsecho
  }
  else
  {
    memset(&tcpopts[12], 0, 12);
  }
  tcp46_set_cksum_calc(ip);

  pktstruct = ll_alloc_st(st, packet_size(sz));
  pktstruct->data = packet_calc_data(pktstruct);
  pktstruct->direction = PACKET_DIRECTION_DOWNLINK;
  pktstruct->sz = sz;
  memcpy(pktstruct->data, syn, sz);
#ifdef ENABLE_ARP
  if (send_via_arp(pktstruct, local, airwall, st, port, PACKET_DIRECTION_DOWNLINK, time64))
  {
    ll_free_st(st, pktstruct);
    return;
  }
#endif
  port->portfunc(pktstruct, port->userdata);
}

static void resend_syn(
  void *orig, struct worker_local *local, struct port *port,
  struct ll_alloc_st *st,
  struct airwall_hash_entry *entry,
  uint64_t time64, struct airwall *airwall)
{
  void *origip;
  void *origtcp;

  if (entry->flag_state != FLAG_STATE_DOWNLINK_SYN_SENT)
  {
    abort();
  }

  origip = ether_payload(orig);
  origtcp = ip46_payload(origip);

  if (seq_cmp(tcp_seq_number(origtcp), entry->wan_sent) >= 0)
  {
    entry->wan_sent = tcp_seq_number(origtcp);
  }
  if (seq_cmp(tcp_ack_number(origtcp), entry->wan_acked) >= 0)
  {
    entry->wan_acked = tcp_ack_number(origtcp);
  }
  if (seq_cmp(
    tcp_ack_number(origtcp) + (tcp_window(origtcp) << entry->wan_wscale),
    entry->wan_max) >= 0)
  {
    entry->wan_max =
      tcp_ack_number(origtcp) + (tcp_window(origtcp) << entry->wan_wscale);
  }

  if (tcp_window(origtcp) > entry->wan_max_window_unscaled)
  {
    entry->wan_max_window_unscaled = tcp_window(origtcp);
  }
  entry->timer.time64 = time64 + TCP_DOWNLINK_SYN_SENT_TIMEOUT_SECS*1000ULL*1000ULL;
  timer_linkheap_modify(&local->timers, &entry->timer);

  send_or_resend_syn(orig, local, port, st, entry, airwall, time64);
}

static void send_syn(
  void *orig, struct worker_local *local, struct port *port,
  struct ll_alloc_st *st,
  uint16_t mss, uint8_t wscale, uint8_t sack_permitted,
  struct airwall_hash_entry *entry,
  uint64_t time64, int was_keepalive, struct airwall *airwall)
{
  //void *origip;
  //void *origtcp;
  //struct tcp_information info;
  char packetbuf[8192];

  if (entry == NULL || entry->flag_state != FLAG_STATE_WINDOW_UPDATE_SENT)
  {
    abort();
  }

  airwall_packet_to_str(packetbuf, sizeof(packetbuf), orig);
  log_log(
    LOG_LEVEL_NOTICE, "WORKERDOWNLINK", "SYN proxy sending SYN, packet: %s",
    packetbuf);

  //origip = ether_payload(orig);
  //origtcp = ip46_payload(origip);
  //tcp_parse_options(origtcp, &info);

  entry->flag_state = FLAG_STATE_DOWNLINK_SYN_SENT;
  entry->timer.time64 = time64 + TCP_DOWNLINK_SYN_SENT_TIMEOUT_SECS*1000ULL*1000ULL;
  timer_linkheap_modify(&local->timers, &entry->timer);

  send_or_resend_syn(orig, local, port, st, entry, airwall, time64);
}

static void send_data_only(
  void *orig, struct airwall_hash_entry *entry, struct port *port,
  struct ll_alloc_st *st, struct worker_local *local, struct airwall *airwall,
  uint64_t time64)
{
  const size_t maxpay = 1208;
  char data[14+40+20+12+1208] = {0};
  char *ip, *origip;
  char *tcp, *origtcp;
  char *tcppay;
  struct packet *pktstruct;
  struct tcp_information tcpinfo;
  unsigned char *tcpopts;
  int version;
  size_t sz;
  size_t curstart = 0;
  size_t curpay = 0;

  origip = ether_payload(orig);
  version = ip_version(origip);
  origtcp = ip46_payload(origip);
  tcp_parse_options(origtcp, &tcpinfo);

  curstart = tcp_ack_number(origtcp) - entry->remote_isn - 1;
  for (;;)
  {
    curpay = maxpay;
    if (curstart >= entry->detect->acked)
    {
      return;
    }
    if (curstart + curpay > entry->detect->acked)
    {
      curpay = entry->detect->acked - curstart;
    }
    if (curpay > ((uint32_t)tcp_window(origtcp)) << entry->lan_wscale)
    {
      curpay = tcp_window(origtcp) << entry->lan_wscale;
    }
  
    memcpy(ether_src(data), ether_dst(orig), 6);
    memcpy(ether_dst(data), ether_src(orig), 6);
    ether_set_type(data, version == 4 ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
    ip = ether_payload(data);
    ip_set_version(ip, version);
    if (version == 6)
    {
      ipv6_set_flow_label(ip, entry->dlflowlabel);
    }
    ip46_set_min_hdr_len(ip);
    ip46_set_payload_len(ip, 20 + 12 + curpay);
    ip46_set_dont_frag(ip, 1);
    ip46_set_id(ip, 0); // XXX
    ip46_set_ttl(ip, 64);
    ip46_set_proto(ip, 6);
    ip46_set_src(ip, ip46_dst(origip));
    ip46_set_dst(ip, ip46_src(origip));
    ip46_set_hdr_cksum_calc(ip);
    tcp = ip46_payload(ip);
    tcp_set_src_port(tcp, tcp_dst_port(origtcp));
    tcp_set_dst_port(tcp, tcp_src_port(origtcp));
    tcp_set_ack_on(tcp);
    tcp_set_data_offset(tcp, 20 + 12);
    tcp_set_seq_number(tcp, curstart + entry->remote_isn + 1);
    tcp_set_ack_number(tcp,
      entry->local_isn+1-entry->seqoffset); // FIXME entry->wan_acked?
    tcp_set_window(tcp, entry->wan_max_window_unscaled);
  
    tcpopts = &((unsigned char*)tcp)[20];
  
    if (tcpinfo.options_valid && tcpinfo.ts_present)
    {
      tcpopts[0] = 1;
      tcpopts[1] = 1;
      tcpopts[2] = 8;
      tcpopts[3] = 10;
      hdr_set32n(&tcpopts[4], tcpinfo.tsecho);
      hdr_set32n(&tcpopts[8], tcpinfo.ts);
    }
    else
    {
      memset(&tcpopts[0], 0, 12);
    }
  
    tcppay = tcp + tcp_data_offset(tcp);
    memcpy(tcppay, &entry->detect->init_data[curstart], curpay);
  
    tcp46_set_cksum_calc(ip);
  
    sz = ((version == 4) ? (14+20+20+12+curpay) : (14+40+20+12+curpay));

    pktstruct = ll_alloc_st(st, packet_size(sz));
    pktstruct->data = packet_calc_data(pktstruct);
    pktstruct->direction = PACKET_DIRECTION_DOWNLINK;
    pktstruct->sz = sz;
    memcpy(pktstruct->data, data, sz);
#ifdef ENABLE_ARP
    if (send_via_arp(pktstruct, local, airwall, st, port, PACKET_DIRECTION_DOWNLINK, time64))
    {
      ll_free_st(st, pktstruct);
      return;
    }
#endif
  
    port->portfunc(pktstruct, port->userdata);
    curstart += curpay;
  }
}

static void send_ack_only(
  void *orig, struct airwall_hash_entry *entry, struct port *port,
  struct ll_alloc_st *st)
{
  char ack[14+40+20+12] = {0};
  void *ip, *origip;
  void *tcp, *origtcp;
  struct packet *pktstruct;
  struct tcp_information tcpinfo;
  unsigned char *tcpopts;
  int version;
  size_t sz;

  origip = ether_payload(orig);
  version = ip_version(origip);
  sz = ((version == 4) ? (sizeof(ack) - 20) : sizeof(ack));
  origtcp = ip46_payload(origip);
  tcp_parse_options(origtcp, &tcpinfo);

  memcpy(ether_src(ack), ether_dst(orig), 6);
  memcpy(ether_dst(ack), ether_src(orig), 6);
  ether_set_type(ack, version == 4 ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
  ip = ether_payload(ack);
  ip_set_version(ip, version);
  if (version == 6)
  {
    ipv6_set_flow_label(ip, entry->dlflowlabel);
  }
  ip46_set_min_hdr_len(ip);
  ip46_set_payload_len(ip, sizeof(ack) - 14 - 40);
  ip46_set_dont_frag(ip, 1);
  ip46_set_id(ip, 0); // XXX
  ip46_set_ttl(ip, 64);
  ip46_set_proto(ip, 6);
  ip46_set_src(ip, ip46_dst(origip));
  ip46_set_dst(ip, ip46_src(origip));
  ip46_set_hdr_cksum_calc(ip);
  tcp = ip46_payload(ip);
  tcp_set_src_port(tcp, tcp_dst_port(origtcp));
  tcp_set_dst_port(tcp, tcp_src_port(origtcp));
  tcp_set_ack_on(tcp);
  tcp_set_data_offset(tcp, sizeof(ack) - 14 - 40);
  tcp_set_seq_number(tcp, tcp_ack_number(origtcp));
  tcp_set_ack_number(tcp, tcp_seq_number(origtcp)+1);
  tcp_set_window(tcp, entry->wan_max_window_unscaled);

  tcpopts = &((unsigned char*)tcp)[20];

  if (tcpinfo.options_valid && tcpinfo.ts_present)
  {
    tcpopts[0] = 1;
    tcpopts[1] = 1;
    tcpopts[2] = 8;
    tcpopts[3] = 10;
    hdr_set32n(&tcpopts[4], tcpinfo.tsecho);
    hdr_set32n(&tcpopts[8], tcpinfo.ts);
  }
  else
  {
    memset(&tcpopts[0], 0, 12);
  }

  tcp46_set_cksum_calc(ip);

  pktstruct = ll_alloc_st(st, packet_size(sz));
  pktstruct->data = packet_calc_data(pktstruct);
  pktstruct->direction = PACKET_DIRECTION_DOWNLINK;
  pktstruct->sz = sz;
  memcpy(pktstruct->data, ack, sz);
  port->portfunc(pktstruct, port->userdata);
}

static void send_window_update(
  void *triggerpkt, struct worker_local *local,
  struct airwall_hash_entry *entry, struct port *port,
  struct airwall *airwall, struct ll_alloc_st *st, uint32_t mss,
  int sack_permitted, uint32_t wscale, int was_keepalive, uint64_t time64)
{
  char windowupdate[14+40+20+12] = {0};
  void *ip, *origip;
  char *tcp, *origtcp;
  struct packet *pktstruct;
  unsigned char *tcpopts;
  int version;
  size_t sz;

  struct tcp_information info;

  origip = ether_payload(triggerpkt);
  version = ip_version(origip);
  origtcp = ip46_payload(origip);
  tcp_parse_options(origtcp, &info);

  if (entry == NULL)
  {
    // Don't allocate the port yet, as local IP is unknown
    //allocate_udp_port(airwall->porter, tcp_dst_port(origtcp), 0, 0, 0);
    entry = airwall_hash_put(
      local, version,
      NULL, 0,
      ip46_dst(origip), tcp_dst_port(origtcp),
      ip46_src(origip), tcp_src_port(origtcp),
      1, time64, 0);
    if (entry == NULL)
    {
      //deallocate_udp_port(airwall->porter, tcp_dst_port(origtcp), 0);
      log_log(LOG_LEVEL_ERR, "WORKER", "not enough memory or already existing");
      return;
    }
    if (entry->version == 6)
    {
      entry->ulflowlabel = gen_flowlabel_entry(entry);
    }
  }
  if (version == 6)
  {
    entry->dlflowlabel = ipv6_flow_label(origip);
  }

  entry->state_data.downlink_syn_sent.mss = mss;
  entry->state_data.downlink_syn_sent.sack_permitted = sack_permitted;
  entry->state_data.downlink_syn_sent.timestamp_present = info.ts_present;
  if (info.ts_present)
  {
    entry->state_data.downlink_syn_sent.local_timestamp = info.tsecho;
    entry->state_data.downlink_syn_sent.remote_timestamp = info.ts;
  }

  entry->wan_wscale = wscale;
  entry->wan_sent = tcp_seq_number(origtcp) + (!!was_keepalive);
  entry->lan_max_window_unscaled = INITIAL_WINDOW >> entry->lan_wscale;
  entry->wan_acked = tcp_ack_number(origtcp);
  entry->wan_max =
    tcp_ack_number(origtcp) + (tcp_window(origtcp) << entry->wan_wscale);
  entry->lan_max = tcp_seq_number(origtcp) + INITIAL_WINDOW;
  entry->lan_sent = tcp_ack_number(origtcp);

  entry->wan_max_window_unscaled = tcp_window(origtcp);
  if (entry->wan_max_window_unscaled == 0)
  {
    entry->wan_max_window_unscaled = 1;
  }

#if 0 // Not yet needed at this stage, only after first data arrives
  entry->detect = malloc(sizeof(*entry->detect));
  proto_detect_ctx_init(entry->detect);
  linked_list_add_tail(
    &entry->detect_node, &local->detect_list);
  local->detect_count++;
#endif

  entry->local_isn = tcp_ack_number(origtcp) - 1;
  entry->remote_isn = tcp_seq_number(origtcp) - 1 + (!!was_keepalive);
  entry->flag_state = FLAG_STATE_WINDOW_UPDATE_SENT;
  entry->timer.time64 = time64 + TCP_WINDOW_UPDATE_SENT_TIMEOUT_SECS*1000ULL*1000ULL;
  timer_linkheap_modify(&local->timers, &entry->timer);

  if (version == 4)
  {
    uint32_t threetuple_ip;
    uint16_t threetuple_port;
    if (threetuple2ctx_consume(&airwall->threetuplectx, &local->timers, ip_dst(origip), tcp_dst_port(origtcp), 6, &threetuple_ip, &threetuple_port) == 0)
    {
      if (threetuple_port != 0)
      {
        entry->local_port = threetuple_port;
      }
      else
      {
        entry->local_port = entry->nat_port;
      }
      entry->local_ip.ipv4 = htonl(threetuple_ip);
      allocate_udp_port(airwall->porter, entry->nat_port, ntohl(entry->local_ip.ipv4), entry->local_port, 0);
      entry->port_alloced = 1;
      hash_table_add_nogrow_already_bucket_locked(
        &local->local_hash, &entry->local_node, airwall_hash_local(entry));
      send_syn(triggerpkt, local, port, st, mss, wscale, sack_permitted, entry, time64, was_keepalive, airwall);
      return;
    }
    else
    {
      struct free_udp_port *freeport = &airwall->porter->udpports[tcp_dst_port(origtcp)];
      if (freeport->lan_ip != 0 && freeport->lan_port != 0 && freeport->count != 0 && freeport->outcount != 0)
      {
        log_log(LOG_LEVEL_ERR, "AIRWALL", "could find free port %d",
                tcp_dst_port(origtcp));
        entry->local_port = freeport->lan_port;
        entry->local_ip.ipv4 = htonl(freeport->lan_ip);
        allocate_udp_port(airwall->porter, entry->nat_port, ntohl(entry->local_ip.ipv4), entry->local_port, 0);
        entry->port_alloced = 1;
        hash_table_add_nogrow_already_bucket_locked(
          &local->local_hash, &entry->local_node, airwall_hash_local(entry));
        send_syn(triggerpkt, local, port, st, mss, wscale, sack_permitted, entry, time64, was_keepalive, airwall);
        return;
      }
      else
      {
        log_log(LOG_LEVEL_ERR, "AIRWALL", "could not find free port %d / "
                "%u %u %u %u",
                tcp_dst_port(origtcp),
                freeport->lan_ip, freeport->lan_port, freeport->count,
                freeport->outcount);
      }
    }
  }
  else
  {
    abort(); // FIXME
  }

  version = entry->version;
  sz = (version == 4) ? (sizeof(windowupdate) - 20) : sizeof(windowupdate);

  memcpy(ether_src(windowupdate), ether_dst(triggerpkt), 6);
  memcpy(ether_dst(windowupdate), ether_src(triggerpkt), 6);
  ether_set_type(windowupdate, (version == 4) ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
  ip = ether_payload(windowupdate);
  ip_set_version(ip, version);
#if 0 // FIXME this needs to be thought carefully
  if (version == 6)
  {
    ipv6_set_flow_label(ip, entry->ulflowlabel);
  }
#endif
  ip46_set_min_hdr_len(ip);
  ip46_set_payload_len(ip, sizeof(windowupdate) - 14 - 40);
  ip46_set_dont_frag(ip, 1);
  ip46_set_id(ip, 0); // XXX
  ip46_set_ttl(ip, 64);
  ip46_set_proto(ip, 6);
  ip46_set_src(ip, ip46_dst(origip));
  ip46_set_dst(ip, ip46_src(origip));
  ip46_set_hdr_cksum_calc(ip);
  tcp = ip46_payload(ip);
  tcp_set_src_port(tcp, tcp_dst_port(origtcp));
  tcp_set_dst_port(tcp, tcp_src_port(origtcp));
  tcp_set_ack_on(tcp);
  tcp_set_data_offset(tcp, sizeof(windowupdate) - 14 - 40);
#if 0
  tcp_set_seq_number(tcp, tcp_ack_number(origtcp)); // FIXME looks suspicious
  tcp_set_ack_number(tcp, tcp_seq_number(origtcp)+1); // FIXME the same
#endif
  tcp_set_seq_number(tcp, tcp_ack_number(origtcp));
  tcp_set_ack_number(tcp, tcp_seq_number(origtcp));
  tcp_set_window(tcp, INITIAL_WINDOW>>airwall->conf->own_wscale);
  tcpopts = &((unsigned char*)tcp)[20];
  if (info.options_valid && info.ts_present)
  {
    tcpopts[0] = 1;
    tcpopts[1] = 1;
    tcpopts[2] = 8;
    tcpopts[3] = 10;
    hdr_set32n(&tcpopts[4], info.tsecho);
    hdr_set32n(&tcpopts[8], info.ts);
  }
  else
  {
    memset(&tcpopts[0], 0, 12);
  }
  tcp46_set_cksum_calc(ip);

  pktstruct = ll_alloc_st(st, packet_size(sz));
  pktstruct->data = packet_calc_data(pktstruct);
  pktstruct->direction = PACKET_DIRECTION_UPLINK;
  pktstruct->sz = sz;
  memcpy(pktstruct->data, windowupdate, sz);
  port->portfunc(pktstruct, port->userdata);
}

static void retx_http_connect_response(
  struct airwall_hash_entry *entry, struct port *port,
  struct ll_alloc_st *st, struct airwall *airwall, struct worker_local *local)
{
  char windowupdate[14+40+20+12+sizeof(http_connect_revdatabuf)] = {0};
  const size_t rsz = sizeof(http_connect_revdatabuf);
  void *ip;//, *origip;
  void *tcp;//, *origtcp;
  struct packet *pktstruct;
  //struct tcp_information tcpinfo;
  unsigned char *tcpopts;
  int version;
  size_t sz;

  //origip = ether_payload(orig);
  version = entry->version;
  sz = (version == 4) ? (sizeof(windowupdate) - 20) : sizeof(windowupdate);
  if (!entry->revdata)
  {
    sz -= rsz;
  }
  //origtcp = ip46_payload(origip);
  //tcp_parse_options(origtcp, &tcpinfo);

  memcpy(ether_src(windowupdate), airwall->ul_mac, 6);
  memset(ether_dst(windowupdate), 0, 6);
  ether_set_type(windowupdate, (version == 4) ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
  ip = ether_payload(windowupdate);
  ip_set_version(ip, version);
  if (version == 6)
  {
    ipv6_set_flow_label(ip, entry->ulflowlabel);
  }
  ip46_set_min_hdr_len(ip);
  ip46_set_payload_len(ip, sizeof(windowupdate) - 14 - 40 -
                           (entry->revdata ? 0 : rsz));
  ip46_set_dont_frag(ip, 1);
  ip46_set_id(ip, 0); // XXX
  ip46_set_ttl(ip, 64);
  ip46_set_proto(ip, 6);
  ip46_set_src(ip, &entry->nat_ip);
  ip46_set_dst(ip, &entry->remote_ip);
  ip46_set_hdr_cksum_calc(ip);
  tcp = ip46_payload(ip);
  tcp_set_src_port(tcp, entry->nat_port);
  tcp_set_dst_port(tcp, entry->remote_port);
  tcp_set_ack_on(tcp);
  tcp_set_data_offset(tcp, sizeof(windowupdate) - 14 - 40 - rsz);
  tcp_set_seq_number(tcp, entry->state_data.established.retx_seq);
  tcp_set_ack_number(tcp, entry->state_data.established.retx_ack);
  tcp_set_window(tcp, entry->state_data.established.retx_win);
  tcpopts = &((unsigned char*)tcp)[20];
  if (entry->state_data.established.retx_ts_present)
  {
    tcpopts[0] = 1;
    tcpopts[1] = 1;
    tcpopts[2] = 8;
    tcpopts[3] = 10;
    hdr_set32n(&tcpopts[4], entry->state_data.established.retx_ts);
    hdr_set32n(&tcpopts[8], entry->state_data.established.retx_tsecho);
  }
  else
  {
    memset(&tcpopts[0], 0, 12);
  }
  if (entry->revdata)
  {
    char *tcppay = ((char*)tcp) + tcp_data_offset(tcp);
    memcpy(tcppay, http_connect_revdatabuf, rsz);
  }
  tcp46_set_cksum_calc(ip);

  pktstruct = ll_alloc_st(st, packet_size(sz));
  pktstruct->data = packet_calc_data(pktstruct);
  pktstruct->direction = PACKET_DIRECTION_UPLINK;
  pktstruct->sz = sz;
  memcpy(pktstruct->data, windowupdate, sz);
#ifdef ENABLE_ARP
  if (send_via_arp(pktstruct, local, airwall, st, port, PACKET_DIRECTION_UPLINK, gettime64()))
  {
    ll_free_st(st, pktstruct);
    return;
  }
#endif
  port->portfunc(pktstruct, port->userdata);
}

static void send_ack_and_window_update(
  void *orig, struct airwall_hash_entry *entry, struct port *port,
  struct ll_alloc_st *st, struct airwall *airwall, struct worker_local *local,
  uint64_t time64)
{
  char windowupdate[14+40+20+12+sizeof(http_connect_revdatabuf)] = {0};
  const size_t rsz = sizeof(http_connect_revdatabuf);
  void *ip, *origip;
  void *tcp, *origtcp;
  struct packet *pktstruct;
  struct tcp_information tcpinfo;
  unsigned char *tcpopts;
  int version;
  size_t sz;
  uint32_t acked_seq;

  origip = ether_payload(orig);
  version = ip_version(origip);
  sz = (version == 4) ? (sizeof(windowupdate) - 20) : sizeof(windowupdate);
  if (!entry->revdata)
  {
    sz -= rsz;
  }
  origtcp = ip46_payload(origip);
  tcp_parse_options(origtcp, &tcpinfo);

  send_ack_only(orig, entry, port, st); // XXX send_ack_only reparses opts

  if (airwall->conf->enable_ack && entry->detect)
  {
    send_data_only(orig, entry, port, st, local, airwall, time64); // XXX send_data_only reparses opts
  }

  memcpy(ether_src(windowupdate), airwall->ul_mac, 6);
  memset(ether_dst(windowupdate), 0, 6);
  ether_set_type(windowupdate, (version == 4) ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
  ip = ether_payload(windowupdate);
  ip_set_version(ip, version);
  if (version == 6)
  {
    ipv6_set_flow_label(ip, entry->ulflowlabel);
  }
  ip46_set_min_hdr_len(ip);
  ip46_set_payload_len(ip, sizeof(windowupdate) - 14 - 40 -
                           (entry->revdata ? 0 : rsz));
  ip46_set_dont_frag(ip, 1);
  ip46_set_id(ip, 0); // XXX
  ip46_set_ttl(ip, 64);
  ip46_set_proto(ip, 6);
  ip46_set_src(ip, &entry->nat_ip);
  ip46_set_dst(ip, ip46_dst(origip));
  ip46_set_hdr_cksum_calc(ip);
  tcp = ip46_payload(ip);
  tcp_set_src_port(tcp, entry->nat_port);
  tcp_set_dst_port(tcp, tcp_dst_port(origtcp));
  tcp_set_ack_on(tcp);
  tcp_set_data_offset(tcp, sizeof(windowupdate) - 14 - 40 - rsz);
#if 0
  tcp_set_seq_number(tcp, tcp_ack_number(origtcp)); // FIXME looks suspicious
  tcp_set_ack_number(tcp, tcp_seq_number(origtcp)+1); // FIXME the same
#endif
  tcp_set_seq_number(tcp, tcp_seq_number(origtcp)+1+entry->seqoffset);
  if (airwall->conf->enable_ack && entry->detect)
  {
    acked_seq = entry->detect->acked + 1 + entry->remote_isn; // FIXME correct?

    if (seq_cmp(tcp_ack_number(origtcp), acked_seq) < 0)
    {
      tcp_set_ack_number(tcp, acked_seq);
    }
    else
    {
      tcp_set_ack_number(tcp, tcp_ack_number(origtcp));
    }
  }
  else
  {
    tcp_set_ack_number(tcp, tcp_ack_number(origtcp));
  }
  entry->state_data.established.retx_seq = tcp_seq_number(tcp);
  entry->state_data.established.retx_ack = tcp_ack_number(tcp);
  if (entry->wscalediff >= 0)
  {
    tcp_set_window(tcp, tcp_window(origtcp)>>entry->wscalediff);
  }
  else
  {
    uint64_t win64 = tcp_window(origtcp)<<entry->wscalediff;
    if (win64 > 0xFFFF)
    {
      win64 = 0xFFFF;
    }
    tcp_set_window(tcp, win64);
  }
  entry->state_data.established.retx_win = tcp_window(tcp);
  tcpopts = &((unsigned char*)tcp)[20];
  if (tcpinfo.options_valid && tcpinfo.ts_present)
  {
    tcpopts[0] = 1;
    tcpopts[1] = 1;
    tcpopts[2] = 8;
    tcpopts[3] = 10;
    hdr_set32n(&tcpopts[4], tcpinfo.ts+entry->tsoffset);
    hdr_set32n(&tcpopts[8], tcpinfo.tsecho);
    entry->state_data.established.retx_ts = tcpinfo.ts+entry->tsoffset;
    entry->state_data.established.retx_tsecho = tcpinfo.tsecho;
    entry->state_data.established.retx_ts_present = 1;
  }
  else
  {
    memset(&tcpopts[0], 0, 12);
    entry->state_data.established.retx_ts_present = 0;
  }
  if (entry->revdata)
  {
    // FIXME we need capability to retransmit!!! Otherwise will work badly!!!
    char *tcppay = ((char*)tcp) + tcp_data_offset(tcp);
    memcpy(tcppay, http_connect_revdatabuf, rsz);
    entry->seqoffset += rsz;

    entry->retx_timer.time64 = time64 + TCP_RETX_TIMEOUT_SECS*1000ULL*1000ULL;
    entry->retx_timer.fn = airwall_retx_fn;
    entry->retx_timer.userdata = local;
    timer_linkheap_add(&local->timers, &entry->retx_timer);
    entry->retxtimer_set = 1;
  }
  tcp46_set_cksum_calc(ip);

  pktstruct = ll_alloc_st(st, packet_size(sz));
  pktstruct->data = packet_calc_data(pktstruct);
  pktstruct->direction = PACKET_DIRECTION_UPLINK;
  pktstruct->sz = sz;
  memcpy(pktstruct->data, windowupdate, sz);
#ifdef ENABLE_ARP
  if (send_via_arp(pktstruct, local, airwall, st, port, PACKET_DIRECTION_UPLINK, time64))
  {
    ll_free_st(st, pktstruct);
    return;
  }
#endif
  port->portfunc(pktstruct, port->userdata);
}

const unsigned char bcast_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};

static int uplink_pcp(
  struct airwall *airwall, struct worker_local *local, struct packet *pkt,
  struct port *port, uint64_t time64, struct ll_alloc_st *st)
{
  void *origether = pkt->data;
  void *origip = ether_payload(origether);
  char *origudp = ip46_payload(origip);
  void *origudppay = origudp + 8;
  char *ip, *udp, *udppay;
  int version = ip_version(origip);
  void *lan_ip, *remote_ip;
  uint16_t lan_port, remote_port;
  uint16_t udp_len = ip46_payload_len(origip);
  char dnspkt[1514] = {0};
  struct packet *pktstruct;
  uint8_t rcode = 0;
  uint8_t outudppay = 0;
  int prefer_failure = 0;

  if (version != 4)
  {
    abort();
  }
  lan_ip = ip_src_ptr(origip);
  remote_ip = ip_dst_ptr(origip);
  lan_port = udp_src_port(origudp);
  remote_port = udp_dst_port(origudp);
  if (remote_ip == 0 || remote_port == 0 || lan_ip == 0 || lan_port == 0)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "some of UDP addresses and ports were zero");
    return 1;
  }

  memcpy(ether_src(dnspkt), ether_dst(origether), 6);
  memcpy(ether_dst(dnspkt), ether_src(origether), 6);
  ether_set_type(dnspkt, (version == 4) ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
  ip = ether_payload(dnspkt);
  ip_set_version(ip, version);
#if 0 // FIXME this needs to be thought carefully
  if (version == 6)
  {
    ipv6_set_flow_label(ip, entry->ulflowlabel);
  }
#endif
  ip46_set_min_hdr_len(ip);
  //ip46_set_payload_len(ip, sizeof(dns) - 14 - 40);
  ip46_set_dont_frag(ip, 1);
  ip46_set_id(ip, 0); // XXX
  ip46_set_ttl(ip, 64);
  ip46_set_proto(ip, 17);
  ip46_set_src(ip, ip46_dst(origip));
  ip46_set_dst(ip, ip46_src(origip));
  udp = ip46_payload(ip);
  udp_set_src_port(udp, udp_dst_port(origudp));
  udp_set_dst_port(udp, udp_src_port(origudp));
  udppay = udp+8;

  if (udp_len < 8 + 24)
  {
    return 1;
  }
  else if (pcp_opcode(origudppay) != PCP_OPCODE_MAP)
  {
    rcode = PCP_RCODE_UNSUPP_OPCODE;
  }
  else if (!pcp_req_is_ipv4(origudppay))
  {
    rcode = PCP_RCODE_UNSUPP_PROTOCOL;
  }

  outudppay = 24;
  pcp_set_version(udppay, 2);
  pcp_set_r(udppay, 1);
  pcp_set_opcode(udppay, pcp_opcode(origudppay));
  pcp_resp_set_reserved(udppay, 0);
  pcp_set_lifetime(udppay, pcp_lifetime(origudppay));
  pcp_resp_set_epoch_time(udppay, epoch_time(airwall));
  pcp_resp_zero_reserved2(udppay);
  if (pcp_opcode(origudppay) == PCP_OPCODE_MAP)
  {
    uint16_t ext_port = 0;
    uint32_t ext_ipv4 = airwall->conf->ul_addr;
    if (udp_len >= 8 + 60)
    {
      const char *opts = pcp_mapreq_options(udppay);
      int curloc = 60;
      while (curloc+4 < udp_len - 8)
      {
        if (pcp_option_code(opts) == PCP_OPTION_PREFER_FAILURE)
        {
          prefer_failure = 1;
        }
        else
        {
          rcode = PCP_RCODE_MALFORMED_REQUEST;
          break;
        }
        if (curloc + 4 + pcp_option_paylength(opts) < udp_len - 8)
        {
          opts += 4 + pcp_option_paylength(opts);
          curloc += 4 + pcp_option_paylength(opts);
        }
        else
        {
          rcode = PCP_RCODE_MALFORMED_REQUEST;
          break;
        }
      }
      if (curloc != udp_len - 8)
      {
        rcode = PCP_RCODE_MALFORMED_REQUEST;
      }
      outudppay = 60;
      if (pcp_mapreq_protocol(origudppay) != 6 &&
          pcp_mapreq_protocol(origudppay) != 17)
      {
        rcode = PCP_RCODE_UNSUPP_PROTOCOL;
      }
      if (pcp_req_get_ipv4(origudppay) != ip_src(origip))
      {
        rcode = PCP_RCODE_UNSUPP_PROTOCOL; // FIXME rethink
      }
      if (rcode == 0 && pcp_lifetime(origudppay) == 0)
      {
        int status;
        uint64_t old_expiry;
        uint16_t old_ext_port;
        uint32_t old_ext_ip;
        status = threetuple2ctx_delete_nonce(
                             &airwall->threetuplectx,
                             &local->timers,
                             pcp_mapreq_protocol(origudppay),
                             ip_src(origip),
                             pcp_mapreq_int_port(origudppay),
                             pcp_mapreq_nonce(origudppay),
                             &old_expiry, &old_ext_port, &old_ext_ip);
        ext_port = old_ext_port;
        if (status != 0)
        {
          uint32_t secdiff;
          if (old_expiry < time64)
          {
            secdiff = 0;
          }
          else
          {
            uint64_t secdiff64 = (old_expiry - time64) / (1000*1000);
            if (secdiff64 > UINT32_MAX)
            {
              secdiff64 = UINT32_MAX;
            }
            secdiff = secdiff64;
          }
          pcp_set_lifetime(udppay, secdiff);
          rcode = PCP_RCODE_NOT_AUTHORIZED;
        }
#if 0
        if (pcp_mapreq_protocol(origudppay) == 6)
        {
          deallocate_udp_port(airwall->porter, // FIXME only if prev ok
                              pcp_mapreq_sugg_ext_port(origudppay), 0);
        }
        else
        {
          deallocate_udp_port(airwall->udp_porter, // FIXME only if prev ok
                              pcp_mapreq_sugg_ext_port(origudppay), 0);
        }
#endif
      }
      else if (rcode == 0 && pcp_lifetime(origudppay) > 0)
      {
        uint64_t old_expiry;
        uint16_t old_ext_port;
        uint32_t old_ext_ip;
        int status;
        ext_port = pcp_mapreq_sugg_ext_port(origudppay);
        status = threetuple2ctx_modify_noadd_nonce(
                     &airwall->threetuplectx,
                     &local->timers, 1,
                     pcp_mapreq_protocol(origudppay),
                     gettime64() + pcp_lifetime(origudppay)*1000ULL*1000ULL,
                     ip_src(origip), pcp_mapreq_int_port(origudppay),
                     pcp_mapreq_nonce(origudppay),
                     &old_expiry, &old_ext_port, &old_ext_ip);
        ext_port = old_ext_port;
        if (status == -ENOENT)
        {
          if (pcp_mapreq_protocol(origudppay) == 6)
          {
            ext_port = get_udp_port_different(airwall->porter,
                                              pcp_req_get_ipv4(origudppay),
                                              pcp_mapreq_sugg_ext_port(origudppay),
                                              pcp_mapreq_int_port(origudppay), 0);
          }
          else
          {
            ext_port = get_udp_port_different(airwall->udp_porter,
                                              pcp_req_get_ipv4(origudppay),
                                              pcp_mapreq_sugg_ext_port(origudppay),
                                              pcp_mapreq_int_port(origudppay), 0);
          }
          // FIXME verify also ext_ip:
          if (ext_port != pcp_mapreq_sugg_ext_port(origudppay) && prefer_failure)
          {
            if (pcp_mapreq_protocol(origudppay) == 6)
            {
              deallocate_udp_port(airwall->porter, ext_port, 0);
            }
            else
            {
              deallocate_udp_port(airwall->udp_porter, ext_port, 0);
            }
            rcode = PCP_RCODE_CANNOT_PROVIDE_EXTERNAL;
          }
          else
          {
            status = threetuple2ctx_add_nonce(
                         &airwall->threetuplectx,
                         &local->timers, 0, 1, ext_ipv4, ext_port,
                         pcp_mapreq_protocol(origudppay),
                         gettime64() + pcp_lifetime(origudppay)*1000ULL*1000ULL,
                         ip_src(origip),
                         pcp_mapreq_int_port(origudppay),
                         pcp_mapreq_nonce(origudppay),
                         &old_expiry, airwall->conf->port_binding_limit);
            if (status != 0)
            {
              uint32_t secdiff;
              if (old_expiry < time64)
              {
                secdiff = 0;
              }
              else
              {
                uint64_t secdiff64 = (old_expiry - time64) / (1000*1000);
                if (secdiff64 > UINT32_MAX)
                {
                  secdiff64 = UINT32_MAX;
                }
                secdiff = secdiff64;
              }
              pcp_set_lifetime(udppay, secdiff);
              rcode = PCP_RCODE_NOT_AUTHORIZED;
            }
          }
        }
        else if (status != 0)
        {
          uint32_t secdiff;
          if (old_expiry < time64)
          {
            secdiff = 0;
          }
          else
          {
            uint64_t secdiff64 = (old_expiry - time64) / (1000*1000);
            if (secdiff64 > UINT32_MAX)
            {
              secdiff64 = UINT32_MAX;
            }
            secdiff = secdiff64;
          }
          pcp_set_lifetime(udppay, secdiff);
          rcode = PCP_RCODE_NOT_AUTHORIZED;
        }
        else if (status == 0)
        {
          rcode = PCP_RCODE_SUCCESS;
        }
      }
      pcp_mapresp_set_nonce(udppay, pcp_mapreq_nonce(origudppay));
      pcp_mapresp_set_protocol(udppay, pcp_mapreq_protocol(origudppay));
      pcp_mapresp_zero_reserved(udppay);
      pcp_mapresp_set_int_port(udppay, pcp_mapreq_int_port(origudppay));
      pcp_mapresp_set_ext_port(udppay, ext_port);
      pcp_mapresp_set_ext_ipv4(udppay, ext_ipv4);
    }
    else
    {
      rcode = PCP_RCODE_MALFORMED_REQUEST;
    }
  }
  pcp_resp_set_rcode(udppay, rcode);

  udp_set_total_len(udp, 8 + outudppay);
  udp_set_cksum(udp, 0); // FIXME
  ip46_set_payload_len(ip, 8 + outudppay);
  ip46_set_hdr_cksum_calc(ip);

  pktstruct = ll_alloc_st(st, packet_size(14+20+8+outudppay));
  pktstruct->data = packet_calc_data(pktstruct);
  pktstruct->direction = PACKET_DIRECTION_DOWNLINK;
  pktstruct->sz = 14+20+8+outudppay;
  memcpy(pktstruct->data, dnspkt, 14+20+8+outudppay);
#ifdef ENABLE_ARP
  if (send_via_arp(pktstruct, local, airwall, st, port, PACKET_DIRECTION_DOWNLINK, time64))
  {
    ll_free_st(st, pktstruct);
    return 1;
  }
#endif
  port->portfunc(pktstruct, port->userdata);

  return 1;
}


static int uplink_udp(
  struct airwall *airwall, struct worker_local *local, struct packet *pkt,
  struct port *port, uint64_t time64, struct ll_alloc_st *st)
{
  void *ether = pkt->data;
  void *ip = ether_payload(ether);
  void *ippay = ip46_payload(ip);
  struct airwall_udp_entry *ue;
  int version = ip_version(ip);
  struct airwall_hash_ctx ctx;
  void *lan_ip, *remote_ip;
  const uint8_t protocol = 17;
  uint16_t lan_port, remote_port;
  size_t ether_len = pkt->sz;
  size_t ip_len = ether_len - ETHER_HDR_LEN;
  uint16_t udp_len = ip46_payload_len(ip);
  uint64_t next64;

  if (version != 4)
  {
    abort();
  }
  remote_ip = ip_dst_ptr(ip);
  lan_ip = ip_src_ptr(ip);
  remote_port = udp_dst_port(ippay);
  lan_port = udp_src_port(ippay);
  if (remote_ip == 0 || remote_port == 0 || lan_ip == 0 || lan_port == 0)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "some of UDP addresses and ports were zero");
    return 1;
  }
  if (remote_port == 5351)
  {
    return uplink_pcp(airwall, local, pkt, port, time64, st);
  }
  ue = airwall_hash_get_local_udp(local, version, lan_ip, lan_port, remote_ip, remote_port, &ctx);
  if (ue == NULL)
  {
    char ipv4[4];
    uint16_t nat_port;
    if (version == 4)
    {
      uint32_t loc = airwall->conf->ul_addr;
      hdr_set32n(ipv4, loc);
      nat_port = get_udp_port(airwall->udp_porter, hdr_get32n(lan_ip), lan_port, 1);
    }
    else
    {
      abort();
    }
    ue = airwall_hash_put_udp(local, version, lan_ip, lan_port, ipv4, nat_port, remote_ip, remote_port, 0, time64);
    if (ue == NULL)
    {
      deallocate_udp_port(airwall->udp_porter, nat_port, 1);
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "No memory for UDP enry");
      return 1;
    }
  }

  udp_set_src_port_cksum_update(ippay, udp_len, ue->nat_port);
  if (version == 4)
  {
    ip_set_src_cksum_update(ip, ip_len, protocol, ippay, udp_len,
                            hdr_get32n(&ue->nat_ip));
  }
  else
  {
    abort();
  }

  next64 = time64 + UDP_TIMEOUT_SECS*1000ULL*1000ULL;
  if (abs(next64 - ue->timer.time64) >= 1000*1000)
  {
    worker_local_wrlock(local);
    ue->timer.time64 = next64;
    timer_linkheap_modify(&local->timers, &ue->timer);
    worker_local_wrunlock(local);
  }

  if (send_via_arp(pkt, local, airwall, st, port, PACKET_DIRECTION_UPLINK, time64))
  {
    return 1;
  }

  return 0;
}

static int downlink_icmp(
  struct airwall *airwall, struct worker_local *local, struct packet *pkt,
  struct port *port, uint64_t time64, struct ll_alloc_st *st)
{
  void *ether = pkt->data;
  void *ip = ether_payload(ether);
  void *ippay = ip46_payload(ip);
  struct airwall_hash_entry *e;
  struct airwall_udp_entry *ue;
  struct airwall_icmp_entry *ie;
  int version = ip_version(ip);
  struct airwall_hash_ctx ctx;
  void *lan_ip, *remote_ip;
  uint16_t lan_port, remote_port;
  //size_t ether_len = pkt->sz;
  //size_t ip_len = ether_len - ETHER_HDR_LEN;
  uint16_t icmp_len = ip46_payload_len(ip);
  uint16_t ipin_len = icmp_len - ICMP_HEADER_MINLEN;
  void *ipin = icmp_payload(ippay);
  void *ipinpay;
  int inprotocol;

  if (version != 4)
  {
    abort();
  }

  if (icmp_len < ICMP_HEADER_MINLEN)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "too short ICMP packet 1");
    return 1;
  }
  if (icmp_type(ippay) == 0)
  {
    lan_ip = ip_dst_ptr(ip);
    remote_ip = ip_src_ptr(ip);
    ie = airwall_hash_get_nat_icmp(local, version, lan_ip, remote_ip, icmp_echo_identifier(ippay), &ctx);
    if (ie == NULL)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "No ICMP entry");
      return 1;
    }
    icmp_set_echo_identifier_cksum_update(ippay, icmp_len, ie->local_identifier);
    ie->timer.time64 = time64 + ICMP_TIMEOUT_SECS*1000ULL*1000ULL;
    timer_linkheap_modify(&local->timers, &ie->timer);
    ip_set_dst_cksum_update(ip, ip46_total_len(ip), 0, NULL, 0, hdr_get32n(&ie->local_ip));
    if (send_via_arp(pkt, local, airwall, st, port, PACKET_DIRECTION_DOWNLINK, time64))
    {
      return 1;
    }
  
    return 0;
  }
  if (icmp_type(ippay) == 5)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "dropping ICMP redirect");
    return 1;
  }
  if (icmp_type(ippay) != 3 && icmp_type(ippay) != 11 &&
      icmp_type(ippay) != 12)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "not a supported ICMP type");
    return 1;
  }
  if (ipin_len < IP_HDR_MINLEN + ICMP_L4_PAYLOAD_PORTS_MINLEN)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "too short ICMP packet 2");
    return 1;
  }
  if (ip_version(ipin) != 4)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "inner packet not IPv4");
    return 1;
  }
  if (ipin_len < ip_hdr_len(ipin) + ICMP_L4_PAYLOAD_PORTS_MINLEN)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "too short ICMP packet 3");
    return 1;
  }
  ipinpay = ip_payload(ipin);
  inprotocol = ip_proto(ipin);
  if (inprotocol != 6 && inprotocol != 17)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "ICMP inprotocol not supported");
    return 1;
  }
  lan_ip = ip_src_ptr(ipin);
  remote_ip = ip_dst_ptr(ipin);
  if (inprotocol == 6)
  {
    lan_port = tcp_src_port(ipinpay);
    remote_port = tcp_dst_port(ipinpay);
  }
  else if (inprotocol == 17)
  {
    lan_port = udp_src_port(ipinpay);
    remote_port = udp_dst_port(ipinpay);
  }
  else
  {
    abort();
  }
  if (remote_ip == 0 || remote_port == 0 || lan_ip == 0 || lan_port == 0)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "some of UDP addresses and ports were zero");
    return 1;
  }
  if (inprotocol == 6)
  {
    e = airwall_hash_get_nat(local, version, lan_ip, lan_port, remote_ip, remote_port, &ctx);
    if (e == NULL)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "TCP entry not found");
      return 1;
    }
    ip_set_dst_cksum_update(ip, ip46_total_len(ip), 1, ipin, ipin_len, hdr_get32n(&e->local_ip));
    if (ipin_len < ip_hdr_len(ipin) + 18)
    {
      ip_set_src_cksum_update(ipin, ipin_len, inprotocol, ipinpay, 8, hdr_get32n(&e->local_ip));
      tcp_set_src_port(ipinpay, e->local_port);
    }
    else
    {
      ip_set_src_cksum_update(ipin, ipin_len, 0, NULL, 0, hdr_get32n(&e->local_ip));
      tcp_set_src_port_cksum_update(ipinpay, 8, e->local_port);
    }
  }
  else if (inprotocol == 17)
  {
    ue = airwall_hash_get_nat_udp(local, version, lan_ip, lan_port, remote_ip, remote_port, &ctx);
    if (ue == NULL)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "UDP entry not found");
      return 1;
    }
    ip_set_dst_cksum_update(ip, ip46_total_len(ip), 1, ipin, ipin_len, hdr_get32n(&ue->local_ip));
    if (ipin_len < ip_hdr_len(ipin) + 8)
    {
      ip_set_src_cksum_update(ipin, ipin_len, inprotocol, ipinpay, 8, hdr_get32n(&ue->local_ip));
      udp_set_src_port(ipinpay, ue->local_port);
    }
    else
    {
      ip_set_src_cksum_update(ipin, ipin_len, 0, NULL, 0, hdr_get32n(&ue->local_ip));
      udp_set_src_port_cksum_update(ipinpay, 8, ue->local_port);
    }
  }

  if (send_via_arp(pkt, local, airwall, st, port, PACKET_DIRECTION_DOWNLINK, time64))
  {
    return 1;
  }

  return 0;
}

static int uplink_icmp(
  struct airwall *airwall, struct worker_local *local, struct packet *pkt,
  struct port *port, uint64_t time64, struct ll_alloc_st *st)
{
  void *ether = pkt->data;
  void *ip = ether_payload(ether);
  void *ippay = ip46_payload(ip);
  struct airwall_hash_entry *e;
  struct airwall_udp_entry *ue;
  struct airwall_icmp_entry *ie;
  int version = ip_version(ip);
  struct airwall_hash_ctx ctx;
  void *lan_ip, *remote_ip;
  uint16_t lan_port, remote_port;
  //size_t ether_len = pkt->sz;
  //size_t ip_len = ether_len - ETHER_HDR_LEN;
  uint16_t icmp_len = ip46_payload_len(ip);
  uint16_t ipin_len = icmp_len - ICMP_HEADER_MINLEN;
  void *ipin = icmp_payload(ippay);
  void *ipinpay;
  int inprotocol;

  if (version != 4)
  {
    abort();
  }

  if (icmp_len < ICMP_HEADER_MINLEN)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "too short ICMP packet 1");
    return 1;
  }
  if (icmp_type(ippay) == 8)
  {
    lan_ip = ip_src_ptr(ip);
    remote_ip = ip_dst_ptr(ip);
    ie = airwall_hash_get_local_icmp(local, version, lan_ip, remote_ip, icmp_echo_identifier(ippay), &ctx);
    if (ie == NULL)
    {
      char ipv4[4];
      uint16_t nat_identifier;
      if (version == 4)
      {
        uint32_t loc = airwall->conf->ul_addr;
        hdr_set32n(ipv4, loc);
        nat_identifier = get_udp_port(airwall->icmp_porter, hdr_get32n(lan_ip), icmp_echo_identifier(ippay), 1);
      }
      else
      {
        abort();
      }
      ie = airwall_hash_put_icmp(local, version, lan_ip, icmp_echo_identifier(ippay), ipv4, nat_identifier, remote_ip, 0, time64);
      if (ie == NULL)
      {
        deallocate_udp_port(airwall->icmp_porter, nat_identifier, 1);
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "No memory for ICMP entry");
        return 1;
      }
    }
    icmp_set_echo_identifier_cksum_update(ippay, icmp_len, ie->nat_identifier);
    ip_set_src_cksum_update(ip, ip46_total_len(ip), 0, NULL, 0, hdr_get32n(&ie->nat_ip));
    ie->timer.time64 = time64 + ICMP_TIMEOUT_SECS*1000ULL*1000ULL;
    timer_linkheap_modify(&local->timers, &ie->timer);
    if (send_via_arp(pkt, local, airwall, st, port, PACKET_DIRECTION_UPLINK, time64))
    {
      return 1;
    }
  
    return 0;
  }
  if (icmp_type(ippay) == 5)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "dropping ICMP redirect");
    return 1;
  }
  if (icmp_type(ippay) != 3 && icmp_type(ippay) != 11 &&
      icmp_type(ippay) != 12)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "not a supported ICMP type");
    return 1;
  }
  if (ipin_len < IP_HDR_MINLEN + ICMP_L4_PAYLOAD_PORTS_MINLEN)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "too short ICMP packet 2");
    return 1;
  }
  if (ip_version(ipin) != 4)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "inner packet not IPv4");
    return 1;
  }
  if (ipin_len < ip_hdr_len(ipin) + ICMP_L4_PAYLOAD_PORTS_MINLEN)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "too short ICMP packet 3");
    return 1;
  }
  ipinpay = ip_payload(ipin);
  inprotocol = ip_proto(ipin);
  if (inprotocol != 6 && inprotocol != 17)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "ICMP inprotocol not supported");
    return 1;
  }
  lan_ip = ip_dst_ptr(ipin);
  remote_ip = ip_src_ptr(ipin);
  if (inprotocol == 6)
  {
    lan_port = tcp_dst_port(ipinpay);
    remote_port = tcp_src_port(ipinpay);
  }
  else if (inprotocol == 17)
  {
    lan_port = udp_dst_port(ipinpay);
    remote_port = udp_src_port(ipinpay);
  }
  else
  {
    abort();
  }
  if (remote_ip == 0 || remote_port == 0 || lan_ip == 0 || lan_port == 0)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "some of UDP addresses and ports were zero");
    return 1;
  }
  if (inprotocol == 6)
  {
    e = airwall_hash_get_local(local, version, lan_ip, lan_port, remote_ip, remote_port, &ctx);
    if (e == NULL)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "TCP entry not found");
      return 1;
    }
    ip_set_src_cksum_update(ip, ip46_total_len(ip), 1, ipin, ipin_len, hdr_get32n(&e->nat_ip));
    if (ipin_len < ip_hdr_len(ipin) + 18)
    {
      ip_set_dst_cksum_update(ipin, ipin_len, inprotocol, ipinpay, 8, hdr_get32n(&e->nat_ip));
      tcp_set_dst_port(ipinpay, e->nat_port);
    }
    else
    {
      ip_set_dst_cksum_update(ipin, ipin_len, 0, NULL, 0, hdr_get32n(&e->nat_ip));
      tcp_set_dst_port_cksum_update(ipinpay, 8, e->nat_port);
    }
  }
  else if (inprotocol == 17)
  {
    ue = airwall_hash_get_local_udp(local, version, lan_ip, lan_port, remote_ip, remote_port, &ctx);
    if (ue == NULL)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "UDP entry not found");
      return 1;
    }
    ip_set_src_cksum_update(ip, ip46_total_len(ip), 1, ipin, ipin_len, hdr_get32n(&ue->nat_ip));
    if (ipin_len < ip_hdr_len(ipin) + 8)
    {
      ip_set_dst_cksum_update(ipin, ipin_len, inprotocol, ipinpay, 8, hdr_get32n(&ue->nat_ip));
      udp_set_dst_port(ipinpay, ue->nat_port);
    }
    else
    {
      ip_set_dst_cksum_update(ipin, ipin_len, 0, NULL, 0, hdr_get32n(&ue->nat_ip));
      udp_set_dst_port_cksum_update(ipinpay, 8, ue->nat_port);
    }
  }

  if (send_via_arp(pkt, local, airwall, st, port, PACKET_DIRECTION_UPLINK, time64))
  {
    return 1;
  }

  return 0;
}

static int downlink_dns(
  struct airwall *airwall, struct worker_local *local, struct packet *pkt,
  struct port *port, uint64_t time64, struct ll_alloc_st *st)
{
  void *origether = pkt->data;
  void *origip = ether_payload(origether);
  char *origudp = ip46_payload(origip);
  void *origudppay = origudp + 8;
  char *ip, *udp, *udppay;
  int version = ip_version(origip);
  void *lan_ip, *remote_ip;
  uint16_t lan_port, remote_port;
  uint16_t udp_len = ip46_payload_len(origip);
  char dnspkt[1514] = {0};
  const size_t udppay_maxlen = sizeof(dnspkt) - 14 - 20 - 8;
  uint16_t off, aoff, qtype, qclass;
  uint16_t remcnt, aremcnt;
  char nambuf[1514-14-20-8] = {0};
  struct packet *pktstruct;
  int has_errs = 0;

  if (version != 4)
  {
    abort();
  }
  lan_ip = ip_dst_ptr(origip);
  remote_ip = ip_src_ptr(origip);
  lan_port = udp_dst_port(origudp);
  remote_port = udp_src_port(origudp);
  if (remote_ip == 0 || remote_port == 0 || lan_ip == 0 || lan_port == 0)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "some of UDP addresses and ports were zero");
    return 1;
  }

  memcpy(ether_src(dnspkt), ether_dst(origether), 6);
  memcpy(ether_dst(dnspkt), ether_src(origether), 6);
  ether_set_type(dnspkt, (version == 4) ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
  ip = ether_payload(dnspkt);
  ip_set_version(ip, version);
#if 0 // FIXME this needs to be thought carefully
  if (version == 6)
  {
    ipv6_set_flow_label(ip, entry->ulflowlabel);
  }
#endif
  ip46_set_min_hdr_len(ip);
  //ip46_set_payload_len(ip, sizeof(dns) - 14 - 40);
  ip46_set_dont_frag(ip, 1);
  ip46_set_id(ip, 0); // XXX
  ip46_set_ttl(ip, 64);
  ip46_set_proto(ip, 17);
  ip46_set_src(ip, ip46_dst(origip));
  ip46_set_dst(ip, ip46_src(origip));
  udp = ip46_payload(ip);
  udp_set_src_port(udp, udp_dst_port(origudp));
  udp_set_dst_port(udp, udp_src_port(origudp));
  udppay = udp+8;

  dns_set_id(udppay, dns_id(origudppay));
  dns_set_qr(udppay, 1);
  dns_set_opcode(udppay, dns_opcode(origudppay));
  dns_set_aa(udppay, 1);
  dns_set_aa(udppay, 1);
  dns_set_tc(udppay, 0);
  dns_set_rd(udppay, 0);
  dns_set_ra(udppay, 0);
  dns_set_z(udppay);
  dns_set_rcode(udppay, 0);
  dns_set_qdcount(udppay, 0);
  dns_set_ancount(udppay, 0);
  dns_set_nscount(udppay, 0);
  dns_set_arcount(udppay, 0);

  dns_next_init_qd(udppay, &aoff, &remcnt, udppay_maxlen);

  dns_next_init_qd(origudppay, &off, &remcnt, udp_len);

  while (dns_next(origudppay, &off, &remcnt, udp_len, nambuf, sizeof(nambuf), &qtype, &qclass) == 0)
  {
    dns_set_qdcount(udppay, dns_qdcount(udppay) + 1);
    dns_put_next_qr(udppay, &aoff, &aremcnt, udppay_maxlen, nambuf, qtype, qclass);
  }

  dns_next_init_qd(origudppay, &off, &remcnt, udp_len);
  while (dns_next(origudppay, &off, &remcnt, udp_len, nambuf, udppay_maxlen, &qtype, &qclass) == 0)
  {
    struct host_hash_entry *host;
    uint32_t addr;
    if (qclass == 1 && qtype == 16 && strncmp(nambuf, "_cgtp.", 6) == 0)
    {
      host = host_hash_get_entry(&airwall->conf->hosts, nambuf+6);
    }
    else
    {
      host = host_hash_get_entry(&airwall->conf->hosts, nambuf);
    }
    if (qclass == 1 && qtype == 16 && host != NULL && strncmp(nambuf, "_cgtp.", 6) == 0)
    {
      char answbuf[1514] = {0};
      char answbuffin[1514] = {0};
      char locipv4[4] = {0};
      char ipv4[4] = {0};
      addr = airwall->conf->ul_addr;
      hdr_set32n(ipv4, addr);
      hdr_set32n(locipv4, host->local_ip);
#if 0
      snprintf(answbuf, sizeof(answbuf), "%d.%d.%d.%d!%d.%d.%d.%d",
               (unsigned char)ipv4[0],
               (unsigned char)ipv4[1],
               (unsigned char)ipv4[2],
               (unsigned char)ipv4[3],
               (unsigned char)locipv4[0],
               (unsigned char)locipv4[1],
               (unsigned char)locipv4[2],
               (unsigned char)locipv4[3]);
#endif
      snprintf(answbuf, sizeof(answbuf), "%d.%d.%d.%d!%s",
               (unsigned char)ipv4[0],
               (unsigned char)ipv4[1],
               (unsigned char)ipv4[2],
               (unsigned char)ipv4[3],
               nambuf+6);
      answbuffin[0] = strlen(answbuf);
      snprintf(&answbuffin[1], sizeof(answbuffin)-1, "%s", answbuf);

      dns_set_ancount(udppay, dns_ancount(udppay) + 1);
      dns_put_next(udppay, &aoff, &aremcnt, udppay_maxlen, nambuf, qtype, qclass, 0,
                   strlen(answbuffin), answbuffin);
    }
    if (qclass == 1 && qtype == 1 && host != NULL)
    {
      char ipv4[4];
      int ret = -1;
      if (host->protocol != 255)
      {
        struct hash_list_node *node;
        unsigned bucket;
        log_log(LOG_LEVEL_NOTICE, "WORKERDOWNLINK", "adding threetuple match");
        HASH_TABLE_FOR_EACH(&airwall->conf->ul_alternatives, bucket, node)
        {
          struct ul_addr *e = CONTAINER_OF(node, struct ul_addr, node);
          addr = e->addr;
          ret = threetuple2ctx_add(&airwall->threetuplectx, &local->timers,
                                   1, 0,
                                   addr, host->port, host->protocol,
                                   host->local_ip, host->port,
                                   time64 + 2ULL*1000ULL*1000ULL);
          if (ret == 0)
          {
            break;
          }
        }
        if (ret != 0 && (host->port != 0 || airwall->conf->allow_anyport_primary))
        {
          int ok = 1;
          addr = airwall->conf->ul_addr;
          if (host->protocol == 0 && host->port != 0)
          {
            int gotten_tcp, gotten_udp = 0;
            gotten_tcp = get_exact_port_in(airwall->porter, host->local_ip, host->port);
            if (gotten_tcp == host->port)
            {
              gotten_udp = get_exact_port_in(airwall->udp_porter, host->local_ip, host->port);
              if (gotten_udp < 0)
              {
                deallocate_udp_port(airwall->porter, gotten_tcp, 0);
              }
            }
            ok = (gotten_udp == host->port) && (gotten_tcp == host->port);
          }
          else if (host->protocol == 6 && host->port != 0)
          {
            int gotten;
            gotten = get_exact_port_in(airwall->porter, host->local_ip, host->port);
            ok = (gotten == host->port);
          }
          else if (host->protocol == 17 && host->port != 0)
          {
            int gotten;
            gotten = get_exact_port_in(airwall->udp_porter, host->local_ip, host->port);
            ok = (gotten == host->port);
          }
          if (ok)
          {
            ret = threetuple2ctx_add(&airwall->threetuplectx, &local->timers,
                                     1, 1,
                                     addr, host->port, host->protocol,
                                     host->local_ip, host->port,
                                     time64 + 2ULL*1000ULL*1000ULL);
          }
        }
      }
      else
      {
        ret = 0;
        addr = airwall->conf->ul_addr;
      }
      if (ret == 0)
      {
        hdr_set32n(ipv4, addr);
        dns_set_ancount(udppay, dns_ancount(udppay) + 1);
        dns_put_next(udppay, &aoff, &aremcnt, udppay_maxlen, nambuf, qtype, qclass, 0,
                     4, ipv4);
      }
      else
      {
        has_errs = 1;
      }
    }
  }
  udp_set_total_len(udp, 8 + aoff);
  udp_set_cksum(udp, 0); // FIXME
  ip46_set_payload_len(ip, 8 + aoff);
  ip46_set_hdr_cksum_calc(ip);

  if (has_errs)
  {
    log_log(LOG_LEVEL_NOTICE, "WORKERDOWNLINK", "not DNS-responding due to addr shorage");
    return 1;
  }

  pktstruct = ll_alloc_st(st, packet_size(14+20+8+aoff));
  pktstruct->data = packet_calc_data(pktstruct);
  pktstruct->direction = PACKET_DIRECTION_UPLINK;
  pktstruct->sz = 14+20+8+aoff;
  memcpy(pktstruct->data, dnspkt, 14+20+8+aoff);
#ifdef ENABLE_ARP
  if (send_via_arp(pktstruct, local, airwall, st, port, PACKET_DIRECTION_UPLINK, time64))
  {
    ll_free_st(st, pktstruct);
    return 1;
  }
#endif
  port->portfunc(pktstruct, port->userdata);

  return 1;
}

static int downlink_udp(
  struct airwall *airwall, struct worker_local *local, struct packet *pkt,
  struct port *port, uint64_t time64, struct ll_alloc_st *st)
{
  void *ether = pkt->data;
  void *ip = ether_payload(ether);
  void *ippay = ip46_payload(ip);
  struct airwall_udp_entry *ue;
  int version = ip_version(ip);
  struct airwall_hash_ctx ctx;
  void *lan_ip, *remote_ip;
  const uint8_t protocol = 17;
  uint16_t lan_port, remote_port;
  size_t ether_len = pkt->sz;
  size_t ip_len = ether_len - ETHER_HDR_LEN;
  uint16_t udp_len = ip46_payload_len(ip);
  uint64_t next64;

  if (version != 4)
  {
    abort();
  }
  lan_ip = ip_dst_ptr(ip);
  remote_ip = ip_src_ptr(ip);
  lan_port = udp_dst_port(ippay);
  remote_port = udp_src_port(ippay);
  if (remote_ip == 0 || remote_port == 0 || lan_ip == 0 || lan_port == 0)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "some of UDP addresses and ports were zero");
    return 1;
  }
  if (lan_port == 53)
  {
    return downlink_dns(airwall, local, pkt, port, time64, st);
  }
  ue = airwall_hash_get_nat_udp(local, version, lan_ip, lan_port, remote_ip, remote_port, &ctx);
  if (ue == NULL)
  {
    uint32_t threetupleip;
    uint16_t threetupleport;
    uint32_t local_ip;
    char local_ipv4[4];
    uint16_t local_port;
    if (threetuple2ctx_consume(&airwall->threetuplectx, &local->timers, ip_dst(ip), udp_dst_port(ippay), 17, &threetupleip, &threetupleport) != 0)
    {
      struct free_udp_port *freeport = &airwall->udp_porter->udpports[udp_dst_port(ippay)];
      if (freeport->lan_ip == 0 || freeport->lan_port == 0 || freeport->count == 0 || freeport->outcount == 0)
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "no UDP entry and no threetupleentry");
        return 1;
      }
      local_port = freeport->lan_port;
      local_ip = freeport->lan_ip;
      hdr_set32n(local_ipv4, local_ip);
      allocate_udp_port(airwall->udp_porter, udp_dst_port(ippay),
                        local_ip, local_port, 0);
      ue = airwall_hash_put_udp(local, version, local_ipv4, local_port, lan_ip, lan_port,
                                remote_ip, remote_port, 1, time64);
      if (ue == NULL)
      {
        deallocate_udp_port(airwall->udp_porter, udp_dst_port(ippay), 0);
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "can't add UDP entry");
        return 1;
      }
    }
    else
    {
      if (threetupleport != 0)
      {
        local_port = threetupleport;
      }
      else
      {
        local_port = lan_port;
      }
      local_ip = threetupleip;
      hdr_set32n(local_ipv4, local_ip);
      allocate_udp_port(airwall->udp_porter, udp_dst_port(ippay),
                        local_ip, local_port, 0);
      ue = airwall_hash_put_udp(local, version, local_ipv4, local_port, lan_ip, lan_port,
                                remote_ip, remote_port, 1, time64);
      if (ue == NULL)
      {
        deallocate_udp_port(airwall->udp_porter, udp_dst_port(ippay), 0);
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "can't add UDP entry");
        return 1;
      }
    }
  }


  udp_set_dst_port_cksum_update(ippay, udp_len, ue->local_port);
  if (version == 4)
  {
    ip_set_dst_cksum_update(ip, ip_len, protocol, ippay, udp_len,
                            hdr_get32n(&ue->local_ip));
  }
  else
  {
    abort();
  }

  next64 = time64 + UDP_TIMEOUT_SECS*1000ULL*1000ULL;
  if (abs(next64 - ue->timer.time64) >= 1000*1000)
  {
    worker_local_wrlock(local);
    ue->timer.time64 = next64;
    timer_linkheap_modify(&local->timers, &ue->timer);
    worker_local_wrunlock(local);
  }

  if (send_via_arp(pkt, local, airwall, st, port, PACKET_DIRECTION_DOWNLINK, time64))
  {
    return 1;
  }

  return 0;
}

int downlink(
  struct airwall *airwall, struct worker_local *local, struct packet *pkt,
  struct port *port, uint64_t time64, struct ll_alloc_st *st)
{
  void *ether = pkt->data;
  void *ip;
  void *ippay;
  size_t ether_len = pkt->sz;
  size_t ip_len;
  uint16_t ihl;
  const void *remote_ip;
  uint16_t remote_port;
  uint8_t protocol;
  const void *lan_ip;
  uint16_t lan_port;
  uint16_t tcp_len;
  struct airwall_hash_entry *entry;
  struct airwall_hash_ctx ctx;
  uint32_t first_seq;
  uint32_t last_seq;
  int32_t data_len;
  int todelete = 0;
  uint32_t wan_min;
  struct sack_ts_headers hdrs;
  char statebuf[8192];
  char packetbuf[8192];
  int version;

  if (ether_len < ETHER_HDR_LEN)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "pkt does not have full Ether hdr");
    return 1;
  }
  if (ether_type(ether) == ETHER_TYPE_IPV6)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "IPv6 not supported yet");
    return 1;
  }
#ifdef ENABLE_ARP
  if (memcmp(ether_dst(ether), airwall->ul_mac, 6) != 0 &&
      memcmp(ether_dst(ether), bcast_mac, 6) != 0)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "MAC not to airwall");
    return 1;
  }
#endif
#ifdef ENABLE_ARP
  if (ether_type(ether) == ETHER_TYPE_ARP)
  {
    const void *arp = ether_payload(ether);
    if (ether_len < ETHER_HDR_LEN + 28 || !arp_is_valid_reqresp(arp))
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "ARP is not valid");
      return 1;
    }
    if (arp_is_req(arp))
    {
      if (arp_cache_get_accept_invalid(&local->ul_arp_cache, arp_spa(arp)))
      {
        uint32_t spa = arp_spa(arp);
        const unsigned char *sha = arp_const_sha(arp);
        log_log(LOG_LEVEL_INFO, "WORKERDOWNLINK",
                "%d.%d.%d.%d is at %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
                (spa>>24)&0xFF, (spa>>16)&0xFF, (spa>>8)&0xFF, (spa>>0)&0xFF,
                sha[0], sha[1], sha[2], sha[3], sha[4], sha[5]);
        arp_cache_put(&local->ul_arp_cache, port, arp_spa(arp), arp_const_sha(arp), &local->timers, time64);
      }
      if (!ul_addr_is_mine(airwall->conf, arp_tpa(arp)))
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "ARP is not to us");
        return 1;
      }
      char etherarp[14+28] = {0};
      char *arp2 = ether_payload(etherarp);
      memcpy(ether_src(etherarp), airwall->ul_mac, 6);
      memcpy(ether_dst(etherarp), arp_const_sha(arp), 6);
      ether_set_type(etherarp, ETHER_TYPE_ARP);
      arp_set_ether(arp2);
      arp_set_resp(arp2);
      memcpy(arp_sha(arp2), airwall->ul_mac, 6);
      memcpy(arp_tha(arp2), arp_const_sha(arp), 6);
      arp_set_spa(arp2, arp_tpa(arp));
      arp_set_tpa(arp2, arp_spa(arp));

      struct packet *pktstruct = ll_alloc_st(st, packet_size(sizeof(etherarp)));
      pktstruct->data = packet_calc_data(pktstruct);
      pktstruct->direction = PACKET_DIRECTION_UPLINK;
      pktstruct->sz = sizeof(etherarp);
      memcpy(pktstruct->data, etherarp, sizeof(etherarp));
      port->portfunc(pktstruct, port->userdata);
      return 1;
    }
    else if (arp_is_resp(arp))
    {
      if (arp_cache_get_accept_invalid(&local->ul_arp_cache, arp_spa(arp)))
      {
        uint32_t spa = arp_spa(arp);
        const unsigned char *sha = arp_const_sha(arp);
        log_log(LOG_LEVEL_INFO, "WORKERDOWNLINK",
                "%d.%d.%d.%d is at %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
                (spa>>24)&0xFF, (spa>>16)&0xFF, (spa>>8)&0xFF, (spa>>0)&0xFF,
                sha[0], sha[1], sha[2], sha[3], sha[4], sha[5]);
        arp_cache_put(&local->ul_arp_cache, port, arp_spa(arp), arp_const_sha(arp), &local->timers, time64);
      }
      else
      {
        uint32_t spa = arp_spa(arp);
        const unsigned char *sha = arp_const_sha(arp);
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK",
                "%d.%d.%d.%d would be at %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
                (spa>>24)&0xFF, (spa>>16)&0xFF, (spa>>8)&0xFF, (spa>>0)&0xFF,
                sha[0], sha[1], sha[2], sha[3], sha[4], sha[5]);
      }
      return 1;
    }
  }
#else
  if (ether_type(ether) == ETHER_TYPE_ARP)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "ARP packet bypass");
    return 0;
  }
#endif
  if (ether_type(ether) != ETHER_TYPE_IP && ether_type(ether) != ETHER_TYPE_IPV6)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "pkt is neither IPv4 nor IPv6");
    return 1;
  }
  ip = ether_payload(ether);
  ip_len = ether_len - ETHER_HDR_LEN;
  if (ip_len < IP_HDR_MINLEN)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "pkt does not have full IP hdr 1");
    return 1;
  }
  version = ip_version(ip);
  if (version != 4 && version != 6)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "IP version mismatch");
    return 1;
  }
  if (version == 4)
  {
    ihl = ip_hdr_len(ip);
    if (ip_len < ihl)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "pkt does not have full IP hdr 2");
      return 1;
    }
    if (ip_frag_off(ip) != 0 || ip_more_frags(ip))
    {
      struct packet *pkt2 = reasshlctx_add(&local->reass_dl, &local->mallocif,
                                           pkt->data, pkt->sz, time64);
      if (pkt2 != NULL)
      {
        pkt2->direction = PACKET_DIRECTION_DOWNLINK;
        if (downlink(airwall, local, pkt2, port, time64, st) == 0)
        {
          struct packet *pktstruct = ll_alloc_st(st, packet_size(pkt2->sz));
          pktstruct->data = packet_calc_data(pktstruct);
          pktstruct->direction = pkt2->direction;
          pktstruct->sz = pkt2->sz;
          memcpy(pktstruct->data, pkt2->data, pkt2->sz);
          port->portfunc(pkt2, port->userdata);
        }
        allocif_free(&local->mallocif, pkt2);
      }
      return 1;
    }
    if (ip_len < ip_total_len(ip))
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "pkt does not have full IP data");
      return 1;
    }
    lan_ip = ip_dst_ptr(ip);
    remote_ip = ip_src_ptr(ip);
    protocol = ip_proto(ip);
    ippay = ip_payload(ip);
#ifdef ENABLE_ARP
    if (!ul_addr_is_mine(airwall->conf, hdr_get32n(lan_ip)))
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "address of packet invalid");
      return 1;
    }
#endif
    if (ip_proto(ip) == 17)
    {
      return downlink_udp(airwall, local, pkt, port, time64, st);
    }
    else if (ip_proto(ip) == 1)
    {
      return downlink_icmp(airwall, local, pkt, port, time64, st);
    }
    else if (ip_proto(ip) != 6)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "non-TCP/UDP");
      return 1;
    }
  }
  else if (version == 6)
  {
    int is_frag = 0;
    uint16_t proto_off_from_frag = 0;
    if (ip_len < 40)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "pkt does not have full IPv6 hdr 1");
      return 1;
    }
    if (ip_len < (size_t)(ipv6_payload_len(ip) + 40))
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "pkt does not have full IPv6 data");
      return 1;
    }
    protocol = 0;
    ippay = ipv6_proto_hdr_2(ip, &protocol, &is_frag, NULL, &proto_off_from_frag);
    if (ippay == NULL)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "pkt without ext hdr chain");
      return 1;
    }
    if (is_frag)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "IPv6 fragment");
      return 1;
    }
    if (protocol != 6)
    {
      //port->portfunc(pkt, port->userdata);
#ifdef ENABLE_ARP
      if (send_via_arp(pkt, local, airwall, st, port, PACKET_DIRECTION_DOWNLINK, time64))
      {
        return 1;
      }
#endif
      return 0;
    }
    ihl = ((char*)ippay) - ((char*)ip);
    lan_ip = ipv6_dst(ip);
    remote_ip = ipv6_src(ip);
#ifdef ENABLE_ARP
    if (1)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "v6 address of packet invalid");
      return 1;
    }
#endif
  }
  else
  {
    abort();
  }
  
  if (protocol == 6)
  {
    tcp_len = ip46_total_len(ip) - ihl;
    if (tcp_len < 20)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "pkt does not have full TCP hdr");
      return 1;
    }
    if (tcp_data_offset(ippay) > tcp_len)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "pkt does not have full TCP opts");
      return 1;
    }
    lan_port = tcp_dst_port(ippay);
    remote_port = tcp_src_port(ippay);
    if (remote_ip == 0 || remote_port == 0 || lan_ip == 0 || lan_port == 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "some of TCP addresses and ports were zero");
      return 1;
    }
  }
  else
  {
    abort();
  }
  if (unlikely(tcp_syn(ippay)))
  {
    if (ip46_hdr_cksum_calc(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid IP hdr cksum");
      return 1;
    }
    if (tcp46_cksum_calc(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid TCP hdr cksum");
      return 1;
    }
    if (tcp_fin(ippay) || tcp_rst(ippay))
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "SYN packet contains FIN or RST");
      return 1;
    }
    if (!tcp_ack(ippay))
    {
      worker_local_wrlock(local);
      if (version == 4)
      {
        if (!ip_permitted(
          ip_src(ip), airwall->conf->ratehash.network_prefix, &local->ratelimit))
        {
          worker_local_wrunlock(local);
          log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "IP ratelimited");
          return 1;
        }
      }
      else
      {
        if (!ipv6_permitted(
          ipv6_src(ip), airwall->conf->ratehash.network_prefix6, &local->ratelimit))
        {
          worker_local_wrunlock(local);
          log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "IPv6 ratelimited");
          return 1;
        }
      }
      send_synack(ether, local, airwall, port, st, time64);
      worker_local_wrunlock(local);
      return 1;
    }
    else
    {
      struct tcp_information tcpinfo;
      //ctx.locked = 0;
      entry = airwall_hash_get_nat(
        local, version, lan_ip, lan_port, remote_ip, remote_port, &ctx);
      if (entry == NULL)
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "SA/SA but entry nonexistent");
        //airwall_hash_unlock(local, &ctx);
        return 1;
      }
      if (entry->flag_state == FLAG_STATE_UPLINK_SYN_RCVD &&
          entry->state_data.uplink_syn_rcvd.isn == tcp_seq_number(ippay))
      {
        // retransmit of SYN+ACK
        if (airwall->conf->mss_clamp_enabled)
        {
          uint16_t mss;
          tcp_parse_options(ippay, &tcpinfo);
          if (tcpinfo.options_valid)
          {
            mss = tcpinfo.mss;
            if (mss > airwall->conf->mss_clamp)
            {
              mss = airwall->conf->mss_clamp;
            }
            if (tcpinfo.mssoff)
            {
              tcp_set_mss_cksum_update(ippay, &tcpinfo, mss);
            }
          }
        }
        //airwall_hash_unlock(local, &ctx);
        //port->portfunc(pkt, port->userdata);
        tcp_set_dst_port_cksum_update(ippay, tcp_len, entry->local_port);
        if (version == 4)
        {
          ip_set_dst_cksum_update(ip, ip_len, protocol, ippay, tcp_len,
                                  hdr_get32n(&entry->local_ip));
        }
        else
        {
          abort();
        }
#ifdef ENABLE_ARP
        if (send_via_arp(pkt, local, airwall, st, port, PACKET_DIRECTION_DOWNLINK, time64))
        {
          return 1;
        }
#endif
        return 0;
      }
      if (entry->flag_state == FLAG_STATE_ESTABLISHED &&
          entry->wan_sent-1 == tcp_seq_number(ippay))
      {
        // retransmit of SYN+ACK
        // FIXME should store the ISN for a longer duration of time...
        if (airwall->conf->mss_clamp_enabled)
        {
          uint16_t mss;
          tcp_parse_options(ippay, &tcpinfo);
          if (tcpinfo.options_valid)
          {
            mss = tcpinfo.mss;
            if (mss > airwall->conf->mss_clamp)
            {
              mss = airwall->conf->mss_clamp;
            }
            if (tcpinfo.mssoff)
            {
              tcp_set_mss_cksum_update(ippay, &tcpinfo, mss);
            }
          }
        }
        //airwall_hash_unlock(local, &ctx);
        //port->portfunc(pkt, port->userdata);
        tcp_set_dst_port_cksum_update(ippay, tcp_len, entry->local_port);
        if (version == 4)
        {
          ip_set_dst_cksum_update(ip, ip_len, protocol, ippay, tcp_len,
                                  hdr_get32n(&entry->local_ip));
        }
        else
        {
          abort();
        }
#ifdef ENABLE_ARP
        if (send_via_arp(pkt, local, airwall, st, port, PACKET_DIRECTION_DOWNLINK, time64))
        {
          return 1;
        }
#endif
        return 0;
      }
      if (entry->flag_state != FLAG_STATE_UPLINK_SYN_SENT)
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "SA/SA, entry != UL_SYN_SENT");
        //airwall_hash_unlock(local, &ctx);
        return 1;
      }
      if (tcp_ack_number(ippay) != entry->state_data.uplink_syn_sent.isn + 1)
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "SA/SA, invalid ACK num");
        //airwall_hash_unlock(local, &ctx);
        return 1;
      }
      tcp_parse_options(ippay, &tcpinfo);
      if (!tcpinfo.options_valid)
      {
        tcpinfo.wscale = 0;
        tcpinfo.mssoff = 0;
        tcpinfo.mss = 1460;
      }
      entry->wan_wscale = tcpinfo.wscale;
      entry->wan_max_window_unscaled = tcp_window(ippay);
      if (entry->wan_max_window_unscaled == 0)
      {
        entry->wan_max_window_unscaled = 1;
      }
      entry->state_data.uplink_syn_rcvd.isn = tcp_seq_number(ippay);
      entry->wan_sent = tcp_seq_number(ippay) + 1;
      entry->wan_acked = tcp_ack_number(ippay);
      entry->wan_max =
        entry->wan_acked + (tcp_window(ippay) << entry->wan_wscale);
      entry->flag_state = FLAG_STATE_UPLINK_SYN_RCVD;
      worker_local_wrlock(local);
      entry->timer.time64 = time64 + TCP_UPLINK_SYN_RCVD_TIMEOUT_SECS*1000ULL*1000ULL;
      timer_linkheap_modify(&local->timers, &entry->timer);
      worker_local_wrunlock(local);
      if (airwall->conf->mss_clamp_enabled)
      {
        uint16_t mss;
        mss = tcpinfo.mss;
        if (mss > airwall->conf->mss_clamp)
        {
          mss = airwall->conf->mss_clamp;
        }
        if (tcpinfo.mssoff)
        {
          tcp_set_mss_cksum_update(ippay, &tcpinfo, mss);
        }
      }
      //airwall_hash_unlock(local, &ctx);
      //port->portfunc(pkt, port->userdata);
      tcp_set_dst_port_cksum_update(ippay, tcp_len, entry->local_port);
      if (version == 4)
      {
        ip_set_dst_cksum_update(ip, ip_len, protocol, ippay, tcp_len,
                                hdr_get32n(&entry->local_ip));
      }
      else
      {
        abort();
      }
#ifdef ENABLE_ARP
      if (send_via_arp(pkt, local, airwall, st, port, PACKET_DIRECTION_DOWNLINK, time64))
      {
        return 1;
      }
#endif
      return 0;
    }
  }
  //ctx.locked = 0;
  entry = airwall_hash_get_nat(
    local, version, lan_ip, lan_port, remote_ip, remote_port, &ctx);
  if (entry != NULL && entry->flag_state == FLAG_STATE_DOWNLINK_HALF_OPEN)
  {
    if (tcp_rst(ippay))
    {
      /*
       * Ok, here we could verify that the RST is valid and drop the half-open
       * state. But it's extremely unlikely that someone opens a connection
       * with SYN and then to the SYN+ACK responds with RST. Also, the timeout
       * for downlink half-open connections is 64 seconds, and the timeout for
       * connections in the RST state is 45 seconds. So, the additional benefit
       * for moving the connection to RST state is minimal. Also, by maintaining
       * the connection in DOWNLINK_HALF_OPEN state, we can use the linked list
       * to remove old expired connections. In reseted connections, there is no
       * such list. So, the short summary is that moving the connection to the
       * RST state is not worth it.
       */
    }
    if (tcp_ack(ippay) && !tcp_fin(ippay) && !tcp_rst(ippay) && !tcp_syn(ippay))
    {
      uint32_t ack_num = tcp_ack_number(ippay);
      if (ip46_hdr_cksum_calc(ip) != 0)
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid IP hdr cksum");
        //airwall_hash_unlock(local, &ctx);
        return 1;
      }
      if (tcp46_cksum_calc(ip) != 0)
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid TCP hdr cksum");
        //airwall_hash_unlock(local, &ctx);
        return 1;
      }
      if (((uint32_t)(entry->state_data.downlink_half_open.local_isn + 1)) != ack_num)
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid TCP ACK number");
        //airwall_hash_unlock(local, &ctx);
        return 1;
      }
      if (((uint32_t)(entry->remote_isn + 1)) != tcp_seq_number(ippay))
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid TCP SEQ number");
        //airwall_hash_unlock(local, &ctx);
        return 1;
      }
      worker_local_wrlock(local);
      if (version == 4)
      {
        ip_increment_one(
          ip_src(ip), airwall->conf->ratehash.network_prefix, &local->ratelimit);
      }
      else
      {
        ipv6_increment_one(
          ipv6_src(ip), airwall->conf->ratehash.network_prefix6, &local->ratelimit);
      }
      log_log(
        LOG_LEVEL_NOTICE, "WORKERDOWNLINK", "SYN proxy sending WINUPD, found");
      linked_list_delete(&entry->state_data.downlink_half_open.listnode);
      if (local->half_open_connections <= 0)
      {
        abort();
      }
      local->half_open_connections--;
      worker_local_wrunlock(local);
      send_window_update(
        ether, local, entry, port, airwall, st,
        entry->state_data.downlink_half_open.mss,
        entry->state_data.downlink_half_open.sack_permitted,
        entry->state_data.downlink_half_open.wscale, 0, time64);
      //airwall_hash_unlock(local, &ctx);
      return 1;
    }
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "entry is HALF_OPEN");
    //airwall_hash_unlock(local, &ctx);
    return 1;
  }
  if (entry == NULL || entry->flag_state == FLAG_STATE_RESETED ||
      entry->flag_state == FLAG_STATE_TIME_WAIT ||
      ((entry->flag_state & FLAG_STATE_UPLINK_FIN) &&
       (entry->flag_state & FLAG_STATE_DOWNLINK_FIN)))
  {
    first_seq = tcp_seq_number(ippay);
    data_len =
      ((int32_t)ip_len) - ((int32_t)ihl) - ((int32_t)tcp_data_offset(ippay));
    if (data_len < 0)
    {
      // This can occur in fragmented packets. We don't then know the true
      // data length, and can therefore drop packets that would otherwise be
      // valid.
      data_len = 0;
    }
    last_seq = first_seq + data_len - 1;
    if (entry != NULL)
    {
      wan_min =
        entry->wan_sent - (entry->lan_max_window_unscaled<<entry->lan_wscale);
    }

    /*
     * If entry is NULL, it can only be ACK of a SYN+ACK so we verify cookie
     * If entry is non-NULL, it can be ACK of FIN or ACK of SYN+ACK
     * In the latter case, we verify whether the SEQ/ACK numbers look fine.
     * If either SEQ or ACK number is invalid, it has to be ACK of SYN+ACK
     */
    if (tcp_ack(ippay) && !tcp_fin(ippay) && !tcp_rst(ippay) && !tcp_syn(ippay)
        && (entry == NULL ||
            !between(
              entry->wan_acked - (entry->wan_max_window_unscaled<<entry->wan_wscale),
              tcp_ack_number(ippay),
              entry->lan_sent + 1 + MAX_FRAG) ||
            (!between(
               wan_min, first_seq, entry->lan_max+1)
             &&
             !between(
               wan_min, last_seq, entry->lan_max+1))))
    {
      uint32_t ack_num = tcp_ack_number(ippay);
      uint32_t other_seq = tcp_seq_number(ippay);
      uint16_t mss;
      uint16_t tsmss;
      uint8_t tswscale;
      uint8_t wscale, sack_permitted;
      int ok;
      int was_keepalive = 0;
      struct tcp_information tcpinfo;
      if (ip46_hdr_cksum_calc(ip) != 0)
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid IP hdr cksum");
        //airwall_hash_unlock(local, &ctx);
        return 1;
      }
      if (tcp46_cksum_calc(ip) != 0)
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid TCP hdr cksum");
        //airwall_hash_unlock(local, &ctx);
        return 1;
      }
      if (version == 4)
      {
        ok = verify_cookie(
          &local->info, airwall, ip_dst(ip), ip_src(ip),
          tcp_dst_port(ippay), tcp_src_port(ippay), ack_num - 1,
          &mss, &wscale, &sack_permitted, other_seq - 1);
        if (!ok)
        {
          other_seq++;
          ok = verify_cookie(
            &local->info, airwall, ip_dst(ip), ip_src(ip),
            tcp_dst_port(ippay), tcp_src_port(ippay), ack_num - 1,
            &mss, &wscale, &sack_permitted, other_seq - 1);
          if (ok)
          {
            airwall_packet_to_str(packetbuf, sizeof(packetbuf), ether);
            log_log(
              LOG_LEVEL_NOTICE, "WORKERDOWNLINK",
              "SYN proxy detected keepalive packet opening connection: %s",
              packetbuf);
            was_keepalive = 1;
          }
        }
      }
      else
      {
        ok = verify_cookie6(
          &local->info, airwall, ipv6_dst(ip), ipv6_src(ip),
          tcp_dst_port(ippay), tcp_src_port(ippay), ack_num - 1,
          &mss, &wscale, &sack_permitted, other_seq - 1);
        if (!ok)
        {
          other_seq++;
          ok = verify_cookie6(
            &local->info, airwall, ipv6_dst(ip), ipv6_src(ip),
            tcp_dst_port(ippay), tcp_src_port(ippay), ack_num - 1,
            &mss, &wscale, &sack_permitted, other_seq - 1);
          if (ok)
          {
            airwall_packet_to_str(packetbuf, sizeof(packetbuf), ether);
            log_log(
              LOG_LEVEL_NOTICE, "WORKERDOWNLINK",
              "SYN proxy detected keepalive packet opening connection6: %s",
              packetbuf);
            was_keepalive = 1;
          }
        }
      }
      if (ok)
      {
        tcp_parse_options(ippay, &tcpinfo); // XXX send_syn reparses
        if (tcpinfo.options_valid && tcpinfo.ts_present)
        {
          if (version == 4)
          {
            if (verify_timestamp(
              &local->info, airwall, ip_dst(ip), ip_src(ip),
              tcp_dst_port(ippay), tcp_src_port(ippay), tcpinfo.tsecho,
              &tsmss, &tswscale))
            {
              if (tsmss > mss)
              {
                mss = tsmss;
              }
              if (tswscale > wscale)
              {
                wscale = tswscale;
              }
            }
          }
          else
          {
            if (verify_timestamp6(
              &local->info, airwall, ipv6_dst(ip), ipv6_src(ip),
              tcp_dst_port(ippay), tcp_src_port(ippay), tcpinfo.tsecho,
              &tsmss, &tswscale))
            {
              if (tsmss > mss)
              {
                mss = tsmss;
              }
              if (tswscale > wscale)
              {
                wscale = tswscale;
              }
            }
          }
        }
      }
      if (!ok)
      {
        if (entry != NULL)
        {
          airwall_entry_to_str(statebuf, sizeof(statebuf), entry);
          airwall_packet_to_str(packetbuf, sizeof(packetbuf), ether);
          log_log(
            LOG_LEVEL_ERR, "WORKERDOWNLINK",
            "entry found, A/SAFR set, SYN cookie invalid, state: %s, packet: %s", statebuf, packetbuf);
        }
        else
        {
          airwall_packet_to_str(packetbuf, sizeof(packetbuf), ether);
          log_log(
            LOG_LEVEL_ERR, "WORKERDOWNLINK",
            "entry not found but A/SAFR set, SYN cookie invalid, packet: %s", packetbuf);
        }
        //airwall_hash_unlock(local, &ctx);
        return 1;
      }
      worker_local_wrlock(local);
      if (version == 4)
      {
        ip_increment_one(
          ip_src(ip), airwall->conf->ratehash.network_prefix, &local->ratelimit);
      }
      else
      {
        ipv6_increment_one(
          ipv6_src(ip), airwall->conf->ratehash.network_prefix6, &local->ratelimit);
      }
      worker_local_wrunlock(local);
      airwall_packet_to_str(packetbuf, sizeof(packetbuf), ether);
      log_log(
        LOG_LEVEL_NOTICE, "WORKERDOWNLINK", "SYN proxy sending WINUPD, packet: %s",
        packetbuf);
      if (entry != NULL)
      {
        delete_closing_already_bucket_locked(airwall, local, entry);
        entry = NULL;
      }
      send_window_update(ether, local, entry, port, airwall, st, mss,
                         !!sack_permitted, wscale, was_keepalive, time64);
      //airwall_hash_unlock(local, &ctx);
      return 1;
    }
    if (entry == NULL)
    {
      airwall_packet_to_str(packetbuf, sizeof(packetbuf), ether);
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "entry not found, packet: %s", packetbuf);
      //airwall_hash_unlock(local, &ctx);
      return 1;
    }
  }
  if (unlikely(tcp_rst(ippay)))
  {
    if (ip46_hdr_cksum_calc(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid IP hdr cksum");
      //airwall_hash_unlock(local, &ctx);
      return 1;
    }
    if (tcp46_cksum_calc(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid TCP hdr cksum");
      //airwall_hash_unlock(local, &ctx);
      return 1;
    }
    if (entry->flag_state == FLAG_STATE_UPLINK_SYN_SENT)
    {
      if (!tcp_ack(ippay))
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "R/RA in UPLINK_SYN_SENT");
        //airwall_hash_unlock(local, &ctx);
        return 1;
      }
      if (tcp_ack_number(ippay) != entry->state_data.uplink_syn_sent.isn + 1)
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "RA/RA in UL_SYN_SENT, bad seq");
        //airwall_hash_unlock(local, &ctx);
        return 1;
      }
    }
    else if (entry->flag_state == FLAG_STATE_DOWNLINK_SYN_SENT)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "dropping RST in DOWNLINK_SYN_SENT");
      //airwall_hash_unlock(local, &ctx);
      return 1;
    }
    else
    {
      uint32_t seq = tcp_seq_number(ippay);
      if (tcp_ack(ippay) && entry->flag_state == FLAG_STATE_RESETED)
      {
        // Don't spam the log in this common case
        //airwall_hash_unlock(local, &ctx);
        return 1;
      }
      if (!rst_is_valid(seq, entry->wan_sent) &&
          !rst_is_valid(seq, entry->lan_acked))
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK",
                "RST has invalid SEQ number, %u/%u/%u",
                seq, entry->wan_sent, entry->lan_acked);
        //airwall_hash_unlock(local, &ctx);
        return 1;
      }
    }
    if (tcp_ack(ippay))
    {
      tcp_set_ack_number_cksum_update(
        ippay, tcp_len, tcp_ack_number(ippay)-entry->seqoffset);
    }
    entry->flag_state = FLAG_STATE_RESETED;
    worker_local_wrlock(local);
    entry->timer.time64 = time64 + TCP_RESETED_TIMEOUT_SECS*1000ULL*1000ULL;
    timer_linkheap_modify(&local->timers, &entry->timer);
    worker_local_wrunlock(local);
    //airwall_hash_unlock(local, &ctx);
    //port->portfunc(pkt, port->userdata);
    tcp_set_dst_port_cksum_update(ippay, tcp_len, entry->local_port);
    if (version == 4)
    {
      ip_set_dst_cksum_update(ip, ip_len, protocol, ippay, tcp_len,
                              hdr_get32n(&entry->local_ip));
    }
    else
    {
      abort();
    }
#ifdef ENABLE_ARP
    if (send_via_arp(pkt, local, airwall, st, port, PACKET_DIRECTION_DOWNLINK, time64))
    {
      return 1;
    }
#endif
    return 0;
  }
  if (   tcp_ack(ippay)
      && entry->flag_state == FLAG_STATE_DOWNLINK_SYN_SENT
      && resend_request_is_valid_win(tcp_seq_number(ippay), entry->wan_sent,
                                     INITIAL_WINDOW)
      && resend_request_is_valid(tcp_ack_number(ippay), entry->wan_acked))
  {
    log_log(LOG_LEVEL_NOTICE, "WORKERDOWNLINK", "resending SYN");
    worker_local_wrlock(local);
    resend_syn(ether, local, port, st, entry, time64, airwall);
    worker_local_wrunlock(local);
    //airwall_hash_unlock(local, &ctx);
    return 1;
  }
  if (!airwall_is_connected(entry) && entry->flag_state != FLAG_STATE_RESETED && entry->flag_state != FLAG_STATE_WINDOW_UPDATE_SENT)
  {
    airwall_entry_to_str(statebuf, sizeof(statebuf), entry);
    airwall_packet_to_str(packetbuf, sizeof(packetbuf), ether);
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "not CONNECTED/RESETED, dropping, state: %s, packet: %s", statebuf, packetbuf);
    //airwall_hash_unlock(local, &ctx);
    return 1;
  }
  if (!tcp_ack(ippay))
  {
    airwall_entry_to_str(statebuf, sizeof(statebuf), entry);
    airwall_packet_to_str(packetbuf, sizeof(packetbuf), ether);
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "no TCP ACK, dropping pkt, state: %s, packet: %s", statebuf, packetbuf);
    //airwall_hash_unlock(local, &ctx);
    return 1;
  }
  if (entry->retxtimer_set && entry->flag_state == FLAG_STATE_ESTABLISHED &&
      seq_cmp(tcp_ack_number(ippay),
              entry->state_data.established.retx_seq +
              sizeof(http_connect_revdatabuf)) >= 0)
  {
    log_log(LOG_LEVEL_NOTICE, "WORKERDOWNLINK", "removing retx timer");
    retx_timer_del(entry, local);
  }
  if (!between(
    entry->wan_acked - (entry->wan_max_window_unscaled<<entry->wan_wscale),
    tcp_ack_number(ippay),
    entry->lan_sent + 1 + MAX_FRAG))
  {
    airwall_entry_to_str(statebuf, sizeof(statebuf), entry);
    airwall_packet_to_str(packetbuf, sizeof(packetbuf), ether);
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "packet has invalid ACK number, state: %s, packet: %s", statebuf, packetbuf);
    //airwall_hash_unlock(local, &ctx);
    return 1;
  }
  first_seq = tcp_seq_number(ippay);
  data_len =
    ((int32_t)ip_len) - ((int32_t)ihl) - ((int32_t)tcp_data_offset(ippay));
  if (data_len < 0)
  {
    // This can occur in fragmented packets. We don't then know the true
    // data length, and can therefore drop packets that would otherwise be
    // valid.
    data_len = 0;
  }
  last_seq = first_seq + data_len - 1;
  if (unlikely(tcp_fin(ippay)))
  {
    if (ip46_hdr_cksum_calc(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid IP hdr cksum");
      //airwall_hash_unlock(local, &ctx);
      return 1;
    }
    if (tcp46_cksum_calc(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid TCP hdr cksum");
      //airwall_hash_unlock(local, &ctx);
      return 1;
    }
    last_seq += 1;
  }
  wan_min =
    entry->wan_sent - (entry->lan_max_window_unscaled<<entry->lan_wscale);
  if (
    !between(
      wan_min, first_seq, entry->lan_max+1)
    &&
    !between(
      wan_min, last_seq, entry->lan_max+1)
    )
  {
    airwall_entry_to_str(statebuf, sizeof(statebuf), entry);
    airwall_packet_to_str(packetbuf, sizeof(packetbuf), ether);
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "packet has invalid SEQ number, state: %s, packet: %s", statebuf, packetbuf);
    //airwall_hash_unlock(local, &ctx);
    return 1;
  }
  if (unlikely(tcp_fin(ippay)) && entry->flag_state != FLAG_STATE_RESETED)
  {
    if (version == 4 && ip_more_frags(ip)) // FIXME for IPv6 also
    {
      log_log(LOG_LEVEL_WARNING, "WORKERDOWNLINK", "FIN with more frags");
    }
    if (entry->flag_state & FLAG_STATE_DOWNLINK_FIN)
    {
      if (entry->state_data.established.downfin != last_seq)
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "FIN seq changed");
        //airwall_hash_unlock(local, &ctx);
        return 1;
      }
    }
    entry->state_data.established.downfin = last_seq;
    // We may receive downlink SYN on WINDOW_UPDATE_SENT state, move directly
    // to ESTABLISHED and then add the DOWNLINK_FIN specifier.
    if (entry->flag_state & FLAG_STATE_WINDOW_UPDATE_SENT)
    {
      entry->flag_state &= ~FLAG_STATE_WINDOW_UPDATE_SENT;
      entry->flag_state |= FLAG_STATE_ESTABLISHED;
    }
    entry->flag_state |= FLAG_STATE_DOWNLINK_FIN;
  }
  if (unlikely(entry->flag_state & FLAG_STATE_UPLINK_FIN))
  {
    uint32_t fin = entry->state_data.established.upfin;
    if (tcp_ack(ippay) && tcp_ack_number(ippay) == fin + 1)
    {
      if (ip46_hdr_cksum_calc(ip) != 0)
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid IP hdr cksum");
        //airwall_hash_unlock(local, &ctx);
        return 1;
      }
      if (tcp46_cksum_calc(ip) != 0)
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid TCP hdr cksum");
        //airwall_hash_unlock(local, &ctx);
        return 1;
      }
      entry->flag_state |= FLAG_STATE_UPLINK_FIN_ACK;
      if (entry->flag_state & FLAG_STATE_DOWNLINK_FIN_ACK)
      {
        todelete = 1;
      }
    }
  }
  if (tcp_window(ippay) > entry->wan_max_window_unscaled)
  {
    entry->wan_max_window_unscaled = tcp_window(ippay);
    if (entry->wan_max_window_unscaled == 0)
    {
      entry->wan_max_window_unscaled = 1;
    }
  }
  if (seq_cmp(last_seq, entry->wan_sent) >= 0)
  {
    entry->wan_sent = last_seq + 1;
  }
  if (likely(tcp_ack(ippay)))
  {
    uint32_t ack = tcp_ack_number(ippay);
    uint16_t window = tcp_window(ippay);
    if (seq_cmp(ack, entry->wan_acked) >= 0)
    {
      entry->wan_acked = ack;
    }
    if (seq_cmp(ack + (window << entry->wan_wscale), entry->wan_max) >= 0)
    {
      entry->wan_max = ack + (window << entry->wan_wscale);
    }
  }
  uint64_t next64;
  int omit = 0;
  if (entry->flag_state == FLAG_STATE_WINDOW_UPDATE_SENT)
  {
    omit = 1;
  }
  else if (entry->flag_state == FLAG_STATE_RESETED)
  {
    next64 = time64 + TCP_RESETED_TIMEOUT_SECS*1000ULL*1000ULL;
  }
  else if ((entry->flag_state & FLAG_STATE_UPLINK_FIN) &&
           (entry->flag_state & FLAG_STATE_DOWNLINK_FIN))
  {
    next64 = time64 + TCP_BOTH_FIN_TIMEOUT_SECS*1000ULL*1000ULL;
  }
  else if (entry->flag_state & (FLAG_STATE_UPLINK_FIN|FLAG_STATE_DOWNLINK_FIN))
  {
    next64 = time64 + TCP_ONE_FIN_TIMEOUT_SECS*1000ULL*1000ULL;
  }
  else
  {
    next64 = time64 + TCP_CONNECTED_TIMEOUT_SECS*1000ULL*1000ULL;
  }
  if (!omit && abs(next64 - entry->timer.time64) >= 1000*1000)
  {
    worker_local_wrlock(local);
    entry->timer.time64 = next64;
    timer_linkheap_modify(&local->timers, &entry->timer);
    worker_local_wrunlock(local);
  }
  if (entry->flag_state == FLAG_STATE_WINDOW_UPDATE_SENT)
  {
    log_log(LOG_LEVEL_NOTICE, "WORKERDOWNLINK", "processing protodetect data");
    process_data(ether, local, airwall, port, st, time64, entry);
    return 1;
  }
  tcp_find_sack_ts_headers(ippay, &hdrs);
  if (tcp_ack(ippay))
  {
    tcp_set_ack_number_cksum_update(
      ippay, tcp_len, tcp_ack_number(ippay)-entry->seqoffset);
    if (hdrs.sackoff)
    {
      if (   !entry->lan_sack_was_supported
          && airwall->conf->sackconflict == SACKCONFLICT_REMOVE)
      {
        char *cippay = ippay;
        tcp_disable_sack_cksum_update(
          ippay, &cippay[hdrs.sackoff], hdrs.sacklen, !(hdrs.sackoff%2));
      }
      else
      {
        tcp_adjust_sack_cksum_update_2(
          ippay, &hdrs, -entry->seqoffset);
      }
    }
  }
  tcp_adjust_tsecho_cksum_update(ippay, &hdrs, -entry->tsoffset);
  tcp_set_dst_port_cksum_update(ippay, tcp_len, entry->local_port);
  if (version == 4)
  {
    ip_set_dst_cksum_update(ip, ip_len, protocol, ippay, tcp_len,
                            hdr_get32n(&entry->local_ip));
  }
  else
  {
    abort();
  }
#ifdef ENABLE_ARP
  if (send_via_arp(pkt, local, airwall, st, port, PACKET_DIRECTION_DOWNLINK, time64))
  {
    return 1;
  }
#endif
  //port->portfunc(pkt, port->userdata);
  if (todelete)
  {
    worker_local_wrlock(local);
    entry->timer.time64 = time64 + TCP_TIME_WAIT_TIMEOUT_SECS*1000ULL*1000ULL;
    entry->flag_state = FLAG_STATE_TIME_WAIT;
    timer_linkheap_modify(&local->timers, &entry->timer);
    worker_local_wrunlock(local);
  }
  //airwall_hash_unlock(local, &ctx);
  return 0;
}

/*
  Uplink packet arrives. It has lan_ip:lan_port remote_ip:remote_port
  - Lookup by lan_ip:lan_port, verify remote_ip:remote_port
  Downlink packet arrives. It has wan_ip:wan_port remote_ip:remote_port
  - Lookup by wan_port, verify remote_ip:remote_port
 */

// return: whether to free (1) or not (0)
int uplink(
  struct airwall *airwall, struct worker_local *local, struct packet *pkt,
  struct port *port, uint64_t time64, struct ll_alloc_st *st)
{
  void *ether = pkt->data;
  void *ip;
  void *ippay;
  size_t ether_len = pkt->sz;
  size_t ip_len;
  uint16_t ihl;
  const void *remote_ip;
  uint16_t remote_port;
  uint8_t protocol;
  const void *lan_ip;
  uint16_t lan_port;
  uint16_t tcp_len;
  struct airwall_hash_entry *entry;
  struct airwall_hash_ctx ctx;
  int8_t wscalediff;
  uint32_t first_seq;
  uint32_t last_seq;
  int32_t data_len;
  int todelete = 0;
  uint32_t lan_min;
  struct sack_ts_headers hdrs;
  char statebuf[8192];
  char packetbuf[8192];
  int version;

  if (ether_len < ETHER_HDR_LEN)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "pkt does not have full Ether hdr");
    return 1;
  }
  if (ether_type(ether) == ETHER_TYPE_IPV6)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "IPv6 not supported yet");
    return 1;
  }
#ifdef ENABLE_ARP
  if (memcmp(ether_dst(ether), airwall->dl_mac, 6) != 0 &&
      memcmp(ether_dst(ether), bcast_mac, 6) != 0)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "MAC not to airwall");
    return 1;
  }
#endif
#ifdef ENABLE_ARP
  if (ether_type(ether) == ETHER_TYPE_ARP)
  {
    const void *arp = ether_payload(ether);
    if (ether_len < ETHER_HDR_LEN + 28 || !arp_is_valid_reqresp(arp))
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "ARP is not valid");
      return 1;
    }
    log_log(LOG_LEVEL_NOTICE, "WORKERUPLINK", "ARP packet");
    if (arp_is_req(arp))
    {
      log_log(LOG_LEVEL_NOTICE, "WORKERUPLINK", "ARP req");
      if (arp_cache_get_accept_invalid(&local->dl_arp_cache, arp_spa(arp)))
      {
        uint32_t spa = arp_spa(arp);
        const unsigned char *sha = arp_const_sha(arp);
        log_log(LOG_LEVEL_INFO, "WORKERDOWNLINK",
                "%d.%d.%d.%d is at %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
                (spa>>24)&0xFF, (spa>>16)&0xFF, (spa>>8)&0xFF, (spa>>0)&0xFF,
                sha[0], sha[1], sha[2], sha[3], sha[4], sha[5]);
        arp_cache_put(&local->dl_arp_cache, port, arp_spa(arp), arp_const_sha(arp), &local->timers, time64);
      }
      if (arp_tpa(arp) != airwall->conf->dl_addr)
      {
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "ARP is not to us");
        return 1;
      }
      char etherarp[14+28] = {0};
      char *arp2 = ether_payload(etherarp);
      memcpy(ether_src(etherarp), airwall->dl_mac, 6);
      memcpy(ether_dst(etherarp), arp_const_sha(arp), 6);
      ether_set_type(etherarp, ETHER_TYPE_ARP);
      arp_set_ether(arp2);
      arp_set_resp(arp2);
      memcpy(arp_sha(arp2), airwall->dl_mac, 6);
      memcpy(arp_tha(arp2), arp_const_sha(arp), 6);
      arp_set_spa(arp2, airwall->conf->dl_addr);
      arp_set_tpa(arp2, arp_spa(arp));

      struct packet *pktstruct = ll_alloc_st(st, packet_size(sizeof(etherarp)));
      pktstruct->data = packet_calc_data(pktstruct);
      pktstruct->direction = PACKET_DIRECTION_DOWNLINK;
      pktstruct->sz = sizeof(etherarp);
      memcpy(pktstruct->data, etherarp, sizeof(etherarp));
      port->portfunc(pktstruct, port->userdata);
      return 1;
    }
    else if (arp_is_resp(arp))
    {
      if (arp_cache_get_accept_invalid(&local->dl_arp_cache, arp_spa(arp)))
      {
        uint32_t spa = arp_spa(arp);
        const unsigned char *sha = arp_const_sha(arp);
        log_log(LOG_LEVEL_INFO, "WORKERUPLINK",
                "%d.%d.%d.%d is at %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
                (spa>>24)&0xFF, (spa>>16)&0xFF, (spa>>8)&0xFF, (spa>>0)&0xFF,
                sha[0], sha[1], sha[2], sha[3], sha[4], sha[5]);
        arp_cache_put(&local->dl_arp_cache, port, arp_spa(arp), arp_const_sha(arp), &local->timers, time64);
      }
      return 1;
    }
  }
#else
  if (ether_type(ether) == ETHER_TYPE_ARP)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "ARP packet bypass");
    return 0;
  }
#endif
  if (ether_type(ether) != ETHER_TYPE_IP && ether_type(ether) != ETHER_TYPE_IPV6)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "pkt is neither IPv4 nor IPv6");
    return 1;
  }
  ip = ether_payload(ether);
  ip_len = ether_len - ETHER_HDR_LEN;
  if (ip_len < IP_HDR_MINLEN)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "pkt does not have full IP hdr 1");
    return 1;
  }
  version = ip_version(ip);
  if (version != 4 && version != 6)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "IP version mismatch");
    return 1;
  }
  if (version == 4)
  {
    ihl = ip_hdr_len(ip);
    if (ip_len < ihl)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "pkt does not have full IP hdr 2");
      return 1;
    }
    if (ip_frag_off(ip) != 0 || ip_more_frags(ip))
    {
      struct packet *pkt2 = reasshlctx_add(&local->reass_ul, &local->mallocif,
                                           pkt->data, pkt->sz, time64);
      if (pkt2 != NULL)
      {
        pkt2->direction = PACKET_DIRECTION_UPLINK;
        if (uplink(airwall, local, pkt2, port, time64, st) == 0)
        {
          struct packet *pktstruct = ll_alloc_st(st, packet_size(pkt2->sz));
          pktstruct->data = packet_calc_data(pktstruct);
          pktstruct->direction = pkt2->direction;
          pktstruct->sz = pkt2->sz;
          memcpy(pktstruct->data, pkt2->data, pkt2->sz);
          port->portfunc(pkt2, port->userdata);
        }
        allocif_free(&local->mallocif, pkt2);
      }
      return 1;
    }
    if (ip_len < ip_total_len(ip))
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "pkt does not have full IP data");
      return 1;
    }
    
    protocol = ip_proto(ip);
    ippay = ip_payload(ip);
    lan_ip = ip_src_ptr(ip);
    remote_ip = ip_dst_ptr(ip);
#ifdef ENABLE_ARP
    if ((hdr_get32n(remote_ip) & airwall->conf->dl_mask) ==
        (airwall->conf->dl_addr & airwall->conf->dl_mask) &&
        hdr_get32n(remote_ip) != airwall->conf->dl_addr)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "address of packet internal");
      return 1;
    }
#endif
    if (ip_proto(ip) == 17)
    {
      return uplink_udp(airwall, local, pkt, port, time64, st);
    }
    else if (ip_proto(ip) == 1)
    {
      return uplink_icmp(airwall, local, pkt, port, time64, st);
    }
    else if (ip_proto(ip) != 6)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "non-TCP/UDP");
      return 1;
    }
  }
  else
  {
    int is_frag = 0;
    uint16_t proto_off_from_frag = 0;
    if (ip_len < 40)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "pkt does not have full IPv6 hdr 1");
      return 1;
    }
    if (ip_len < (size_t)(ipv6_payload_len(ip) + 40))
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "pkt does not have full IPv6 data");
      return 1;
    }
    protocol = 0;
    ippay = ipv6_proto_hdr_2(ip, &protocol, &is_frag, NULL, &proto_off_from_frag);
    if (ippay == NULL)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "pkt without ext hdr chain");
      return 1;
    }
    if (is_frag)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "IPv6 fragment");
      return 1;
    }
    if (protocol != 6)
    {
      //port->portfunc(pkt, port->userdata);
#ifdef ENABLE_ARP
      if (send_via_arp(pkt, local, airwall, st, port, PACKET_DIRECTION_UPLINK, time64))
      {
        return 1;
      }
#endif
      return 0;
    }
    ihl = ((char*)ippay) - ((char*)ip);
    lan_ip = ipv6_src(ip);
    remote_ip = ipv6_dst(ip);
#ifdef ENABLE_ARP
    if (1)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "v6 address of packet internal");
      return 1;
    }
#endif
  }
  if (protocol == 6)
  {
    tcp_len = ip46_total_len(ip) - ihl;
    if (tcp_len < 20)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "pkt does not have full TCP hdr");
      return 1;
    }
    if (tcp_data_offset(ippay) > tcp_len)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "pkt does not have full TCP opts");
      return 1;
    }
    lan_port = tcp_src_port(ippay);
    remote_port = tcp_dst_port(ippay);
    if (remote_ip == 0 || remote_port == 0 || lan_ip == 0 || lan_port == 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "some of TCP addresses and ports were zero");
      return 1;
    }
  }
  else
  {
    abort();
  }
  if (unlikely(tcp_syn(ippay)))
  {
    if (ip46_hdr_cksum_calc(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid IP hdr cksum");
      return 1;
    }
    if (tcp46_cksum_calc(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid TCP hdr cksum");
      return 1;
    }
    if (tcp_fin(ippay) || tcp_rst(ippay))
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "SYN packet contains FIN or RST");
      return 1;
    }
    if (!tcp_ack(ippay))
    {
      struct tcp_information tcpinfo;
      //ctx.locked = 0;
      entry = airwall_hash_get_local(
        local, version, lan_ip, lan_port, remote_ip, remote_port, &ctx);
      if (entry != NULL && entry->flag_state == FLAG_STATE_UPLINK_SYN_SENT &&
          entry->state_data.uplink_syn_sent.isn == tcp_seq_number(ippay))
      {
        // retransmit of SYN
        //airwall_hash_unlock(local, &ctx);
        //port->portfunc(pkt, port->userdata);
        tcp_set_src_port_cksum_update(ippay, tcp_len, entry->nat_port);
        if (version == 4)
        {
          ip_set_src_cksum_update(ip, ip_len, protocol, ippay, tcp_len,
                                  hdr_get32n(&entry->nat_ip));
        }
        else
        {
          abort();
        }
#ifdef ENABLE_ARP
        if (send_via_arp(pkt, local, airwall, st, port, PACKET_DIRECTION_UPLINK, time64))
        {
          return 1;
        }
#endif
        return 0;
      }
      if (entry != NULL)
      {
        if (entry->flag_state == FLAG_STATE_RESETED ||
            entry->flag_state == FLAG_STATE_TIME_WAIT ||
            ((entry->flag_state & FLAG_STATE_UPLINK_FIN) &&
             (entry->flag_state & FLAG_STATE_DOWNLINK_FIN)))
        {
          delete_closing_already_bucket_locked(airwall, local, entry);
          entry = NULL;
        }
        else
        {
          airwall_entry_to_str(statebuf, sizeof(statebuf), entry);
          airwall_packet_to_str(packetbuf, sizeof(packetbuf), ether);
          log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "S/SA but entry exists, state: %s, packet: %s", statebuf, packetbuf);
          //airwall_hash_unlock(local, &ctx);
          return 1;
        }
      }
#ifdef ENABLE_ARP
      char ipv4[4];
      uint16_t tcp_port;
      if (version == 4)
      {
        uint32_t loc = airwall->conf->ul_addr;
        hdr_set32n(ipv4, loc);
        tcp_port = get_udp_port(airwall->porter, hdr_get32n(lan_ip), lan_port, 1);
      }
      else
      {
        abort();
      }
      entry = airwall_hash_put(
        local, version, lan_ip, lan_port, ipv4, tcp_port, remote_ip, remote_port, 0, time64, 1);
#else
      allocate_port(lan_port);
      entry = airwall_hash_put(
        local, version, lan_ip, lan_port, lan_ip, lan_port, remote_ip, remote_port, 0, time64, 1);
#endif
      if (entry == NULL)
      {
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "out of memory or already exists");
#ifdef ENABLE_ARP
        deallocate_udp_port(airwall->porter, tcp_port, 1);
#else
        deallocate_udp_port(airwall->porter, lan_port, 1);
#endif
        //airwall_hash_unlock(local, &ctx);
        return 1;
      }
      if (version == 6)
      {
        entry->ulflowlabel = ipv6_flow_label(ip);
      }
      tcp_parse_options(ippay, &tcpinfo);
      if (!tcpinfo.options_valid)
      {
        tcpinfo.wscale = 0;
        tcpinfo.mssoff = 0;
        tcpinfo.mss = 1460;
        tcpinfo.sack_permitted = 0;
      }
      entry->flag_state = FLAG_STATE_UPLINK_SYN_SENT;
      entry->state_data.uplink_syn_sent.isn = tcp_seq_number(ippay);
      entry->lan_wscale = tcpinfo.wscale;
      entry->lan_max_window_unscaled = tcp_window(ippay);
      entry->lan_sack_was_supported = tcpinfo.sack_permitted;
      if (entry->lan_max_window_unscaled == 0)
      {
        entry->lan_max_window_unscaled = 1;
      }
      entry->lan_sent = tcp_seq_number(ippay) + 1;
      if (airwall->conf->mss_clamp_enabled)
      {
        uint16_t mss;
        mss = tcpinfo.mss;
        if (mss > airwall->conf->mss_clamp)
        {
          mss = airwall->conf->mss_clamp;
        }
        if (tcpinfo.mssoff)
        {
          tcp_set_mss_cksum_update(ippay, &tcpinfo, mss);
        }
      }
      tcp_set_src_port_cksum_update(ippay, tcp_len, entry->nat_port);
      if (version == 4)
      {
        ip_set_src_cksum_update(ip, ip_len, protocol, ippay, tcp_len,
                                hdr_get32n(&entry->nat_ip));
      }
      else
      {
        abort();
      }
      //port->portfunc(pkt, port->userdata);
      worker_local_wrlock(local);
      entry->timer.time64 = time64 + TCP_UPLINK_SYN_SENT_TIMEOUT_USEC*1000ULL*1000ULL;
      timer_linkheap_modify(&local->timers, &entry->timer);
      worker_local_wrunlock(local);
      //airwall_hash_unlock(local, &ctx);
#ifdef ENABLE_ARP
      if (send_via_arp(pkt, local, airwall, st, port, PACKET_DIRECTION_UPLINK, time64))
      {
        return 1;
      }
#endif
      return 0;
    }
    else
    {
      struct tcp_information tcpinfo;
      //struct sack_hash_data sackdata;
      //struct threetuplepayload threetuplepayload;
      uint8_t own_wscale;
      //ctx.locked = 0;
      entry = airwall_hash_get_local(
        local, version, lan_ip, lan_port, remote_ip, remote_port, &ctx);
      if (entry == NULL)
      {
        airwall_packet_to_str(packetbuf, sizeof(packetbuf), ether);
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "SA/SA but entry nonexistent, packet: %s", packetbuf);
        //airwall_hash_unlock(local, &ctx);
        return 1;
      }
      if (entry->flag_state == FLAG_STATE_ESTABLISHED)
      {
        // FIXME we should store the ISN permanently...
        if (tcp_ack_number(ippay) == entry->lan_acked &&
            tcp_seq_number(ippay) + 1 + entry->seqoffset == entry->lan_sent)
        {
          airwall_entry_to_str(statebuf, sizeof(statebuf), entry);
          airwall_packet_to_str(packetbuf, sizeof(packetbuf), ether);
          log_log(LOG_LEVEL_NOTICE, "WORKERUPLINK", "resending ACK, state: %s, packet: %s", statebuf, packetbuf);
          send_ack_only(ether, entry, port, st);
          //airwall_hash_unlock(local, &ctx);
          return 1;
        }
      }
      if (entry->flag_state != FLAG_STATE_DOWNLINK_SYN_SENT)
      {
        airwall_entry_to_str(statebuf, sizeof(statebuf), entry);
        airwall_packet_to_str(packetbuf, sizeof(packetbuf), ether);
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "SA/SA, entry != DL_SYN_SENT, state: %s, packet: %s", statebuf, packetbuf);
        //airwall_hash_unlock(local, &ctx);
        return 1;
      }
      if (tcp_ack_number(ippay) != entry->remote_isn + 1)
      {
        airwall_entry_to_str(statebuf, sizeof(statebuf), entry);
        airwall_packet_to_str(packetbuf, sizeof(packetbuf), ether);
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "SA/SA, invalid ACK num, state: %s, packet: %s", statebuf, packetbuf);
        //airwall_hash_unlock(local, &ctx);
        return 1;
      }
      tcp_parse_options(ippay, &tcpinfo);
      if (!tcpinfo.options_valid)
      {
        tcpinfo.mss = airwall->conf->own_mss;
        tcpinfo.wscale = 0;
        tcpinfo.sack_permitted = 0;
      }
#if 0
      sackdata.sack_supported = tcpinfo.sack_permitted;
      sackdata.mss = tcpinfo.mss;
      if (sackdata.mss == 0)
      {
        sackdata.mss = airwall->conf->own_mss;
      }
      if (   airwall->conf->sackmode == HASHMODE_HASHIPPORT
          || airwall->conf->mssmode == HASHMODE_HASHIPPORT)
      {
        if (version == 4)
        {
          sack_ip_port_hash_add4(
            &airwall->autolearn, ip_src(ip), tcp_src_port(ippay), &sackdata);
        }
        else
        {
          sack_ip_port_hash_add6(
            &airwall->autolearn, ipv6_src(ip), tcp_src_port(ippay), &sackdata);
        }
      }
      if (   airwall->conf->sackmode == HASHMODE_HASHIP
          || airwall->conf->mssmode == HASHMODE_HASHIP)
      {
        if (version == 4)
        {
          sack_ip_port_hash_add4(
            &airwall->autolearn, ip_src(ip), 0, &sackdata);
        }
        else
        {
          sack_ip_port_hash_add6(
            &airwall->autolearn, ipv6_src(ip), 0, &sackdata);
        }
      }
      if (airwall->conf->wscalemode == HASHMODE_COMMANDED)
      {
        if (version == 4)
        {
          if (threetuplectx_find(&airwall->threetuplectx, ip_src(ip), tcp_src_port(ippay), 6, &threetuplepayload) != 0)
          {
            threetuplepayload.wscaleshift = airwall->conf->own_wscale;
          }
        }
        else
        {
          if (threetuplectx_find6(&airwall->threetuplectx, ipv6_src(ip), tcp_src_port(ippay), 6, &threetuplepayload) != 0)
          {
            threetuplepayload.wscaleshift = airwall->conf->own_wscale;
          }
        }
      }
      if (airwall->conf->wscalemode == HASHMODE_COMMANDED)
      {
        own_wscale = threetuplepayload.wscaleshift;
      }
      else
#endif
      {
        own_wscale = airwall->conf->own_wscale;
      }
      entry->wscalediff =
        ((int)own_wscale) - ((int)tcpinfo.wscale);
      entry->seqoffset =
        entry->local_isn - tcp_seq_number(ippay);
      if (tcpinfo.ts_present)
      {
        entry->tsoffset =
          entry->state_data.downlink_syn_sent.local_timestamp - tcpinfo.ts;
      }
      else
      {
        entry->tsoffset = 0;
      }
      entry->lan_wscale = tcpinfo.wscale;
      entry->lan_sent = tcp_seq_number(ippay) + 1 + entry->seqoffset;
      entry->lan_acked = tcp_ack_number(ippay);
      entry->lan_max = tcp_ack_number(ippay) + (tcp_window(ippay) << entry->lan_wscale);
      entry->lan_max_window_unscaled = tcp_window(ippay);
      entry->lan_sack_was_supported = tcpinfo.sack_permitted;
      if (entry->lan_max_window_unscaled == 0)
      {
        entry->lan_max_window_unscaled = 1;
      }
      entry->flag_state = FLAG_STATE_ESTABLISHED;
      worker_local_wrlock(local);
      entry->timer.time64 = time64 + TCP_CONNECTED_TIMEOUT_SECS*1000ULL*1000ULL;
      timer_linkheap_modify(&local->timers, &entry->timer);
      worker_local_wrunlock(local);
      send_ack_and_window_update(ether, entry, port, st, airwall, local, time64);
      //airwall_hash_unlock(local, &ctx);
      return 1;
    }
  }
  entry = airwall_hash_get_local(
    local, version, lan_ip, lan_port, remote_ip, remote_port, &ctx);
  if (entry == NULL)
  {
    airwall_packet_to_str(packetbuf, sizeof(packetbuf), ether);
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "entry not found, packet: %s", packetbuf);
    //airwall_hash_unlock(local, &ctx);
    return 1;
  }
  if (unlikely(entry->flag_state == FLAG_STATE_UPLINK_SYN_RCVD))
  {
    if (ip46_hdr_cksum_calc(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid IP hdr cksum");
      //airwall_hash_unlock(local, &ctx);
      return 1;
    }
    if (tcp46_cksum_calc(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid TCP hdr cksum");
      //airwall_hash_unlock(local, &ctx);
      return 1;
    }
    if (tcp_rst(ippay))
    {
      uint32_t seq = tcp_seq_number(ippay) + entry->seqoffset;
      if (!rst_is_valid(seq, entry->lan_sent) &&
          !rst_is_valid(seq, entry->wan_acked))
      {
        airwall_entry_to_str(statebuf, sizeof(statebuf), entry);
        airwall_packet_to_str(packetbuf, sizeof(packetbuf), ether);
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK",
                "invalid SEQ num in RST, %u/%u/%u, state: %s, packet: %s",
                seq, entry->lan_sent, entry->wan_acked,
                statebuf, packetbuf);
        //airwall_hash_unlock(local, &ctx);
        return 1;
      }
      entry->flag_state = FLAG_STATE_RESETED;
      worker_local_wrlock(local);
      entry->timer.time64 = time64 + TCP_RESETED_TIMEOUT_SECS*1000ULL*1000ULL;
      timer_linkheap_modify(&local->timers, &entry->timer);
      worker_local_wrunlock(local);
      tcp_set_src_port_cksum_update(ippay, tcp_len, entry->nat_port);
      if (version == 4)
      {
        ip_set_src_cksum_update(ip, ip_len, protocol, ippay, tcp_len,
                                hdr_get32n(&entry->nat_ip));
      }
      else
      {
        abort();
      }
      //port->portfunc(pkt, port->userdata);
      //airwall_hash_unlock(local, &ctx);
#ifdef ENABLE_ARP
      if (send_via_arp(pkt, local, airwall, st, port, PACKET_DIRECTION_UPLINK, time64))
      {
        return 1;
      }
#endif
      return 0;
    }
    if (tcp_ack(ippay))
    {
      uint32_t ack = tcp_ack_number(ippay);
      uint16_t window = tcp_window(ippay);
      if (tcp_ack_number(ippay) != entry->state_data.uplink_syn_rcvd.isn + 1)
      {
        airwall_entry_to_str(statebuf, sizeof(statebuf), entry);
        airwall_packet_to_str(packetbuf, sizeof(packetbuf), ether);
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid ACK number, state: %s, packet: %s", statebuf, packetbuf);
        //airwall_hash_unlock(local, &ctx);
        return 1;
      }
      first_seq = tcp_seq_number(ippay);
      data_len =
        ((int32_t)ip_len) - ((int32_t)ihl) - ((int32_t)tcp_data_offset(ippay));
      if (data_len < 0)
      {
        // This can occur in fragmented packets. We don't then know the true
        // data length, and can therefore drop packets that would otherwise be
        // valid.
        data_len = 0;
      }
      last_seq = first_seq + data_len - 1;
      if (seq_cmp(last_seq, entry->lan_sent) >= 0)
      {
        entry->lan_sent = last_seq + 1;
      }
      entry->lan_acked = ack;
      entry->lan_max = ack + (window << entry->lan_wscale);
      entry->flag_state = FLAG_STATE_ESTABLISHED;
      worker_local_wrlock(local);
      entry->timer.time64 = time64 + TCP_CONNECTED_TIMEOUT_SECS*1000ULL*1000ULL;
      timer_linkheap_modify(&local->timers, &entry->timer);
      worker_local_wrunlock(local);
      tcp_set_src_port_cksum_update(ippay, tcp_len, entry->nat_port);
      if (version == 4)
      {
        ip_set_src_cksum_update(ip, ip_len, protocol, ippay, tcp_len,
                                hdr_get32n(&entry->nat_ip));
      }
      else
      {
        abort();
      }
      //port->portfunc(pkt, port->userdata);
      //airwall_hash_unlock(local, &ctx);
#ifdef ENABLE_ARP
      if (send_via_arp(pkt, local, airwall, st, port, PACKET_DIRECTION_UPLINK, time64))
      {
        return 1;
      }
#endif
      return 0;
    }
    airwall_entry_to_str(statebuf, sizeof(statebuf), entry);
    airwall_packet_to_str(packetbuf, sizeof(packetbuf), ether);
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "UPLINK_SYN_RECEIVED w/o ACK, state: %s, packet: %s", statebuf, packetbuf);
    //airwall_hash_unlock(local, &ctx);
    return 1;
  }
  if (unlikely(tcp_rst(ippay)))
  {
    if (ip46_hdr_cksum_calc(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid IP hdr cksum");
      //airwall_hash_unlock(local, &ctx);
      return 1;
    }
    if (tcp46_cksum_calc(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid TCP hdr cksum");
      //airwall_hash_unlock(local, &ctx);
      return 1;
    }
    if (entry->flag_state == FLAG_STATE_UPLINK_SYN_SENT)
    {
      airwall_entry_to_str(statebuf, sizeof(statebuf), entry);
      airwall_packet_to_str(packetbuf, sizeof(packetbuf), ether);
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "dropping RST in UPLINK_SYN_SENT, state: %s, packet: %s", statebuf, packetbuf);
      //airwall_hash_unlock(local, &ctx);
      return 1;
    }
    else if (entry->flag_state == FLAG_STATE_DOWNLINK_SYN_SENT)
    {
      if (!tcp_ack(ippay))
      {
        airwall_entry_to_str(statebuf, sizeof(statebuf), entry);
        airwall_packet_to_str(packetbuf, sizeof(packetbuf), ether);
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "R/RA in DOWNLINK_SYN_SENT, state: %s, packet: %s", statebuf, packetbuf);
        //airwall_hash_unlock(local, &ctx);
        return 1;
      }
      if (tcp_ack_number(ippay) != entry->remote_isn + 1)
      {
        airwall_entry_to_str(statebuf, sizeof(statebuf), entry);
        airwall_packet_to_str(packetbuf, sizeof(packetbuf), ether);
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "RA/RA in DL_SYN_SENT, bad seq, state: %s, packet: %s", statebuf, packetbuf);
        //airwall_hash_unlock(local, &ctx);
        return 1;
      }
      tcp_set_seq_number_cksum_update(
        ippay, tcp_len, entry->local_isn + 1);
      tcp_set_ack_off_cksum_update(ippay);
      tcp_set_ack_number_cksum_update(
        ippay, tcp_len, 0);
      entry->flag_state = FLAG_STATE_RESETED;
      worker_local_wrlock(local);
      entry->timer.time64 = time64 + TCP_RESETED_TIMEOUT_SECS*1000ULL*1000ULL;
      timer_linkheap_modify(&local->timers, &entry->timer);
      worker_local_wrunlock(local);
      tcp_set_src_port_cksum_update(ippay, tcp_len, entry->nat_port);
      if (version == 4)
      {
        ip_set_src_cksum_update(ip, ip_len, protocol, ippay, tcp_len,
                                hdr_get32n(&entry->nat_ip));
      }
      else
      {
        abort();
      }
      //port->portfunc(pkt, port->userdata);
      //airwall_hash_unlock(local, &ctx);
#ifdef ENABLE_ARP
      if (send_via_arp(pkt, local, airwall, st, port, PACKET_DIRECTION_UPLINK, time64))
      {
        return 1;
      }
#endif
      return 0;
    }
    else
    {
      uint32_t seq = tcp_seq_number(ippay) + entry->seqoffset;
      if (!rst_is_valid(seq, entry->lan_sent) &&
          !rst_is_valid(seq, entry->wan_acked))
      {
        airwall_entry_to_str(statebuf, sizeof(statebuf), entry);
        airwall_packet_to_str(packetbuf, sizeof(packetbuf), ether);
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK",
                "invalid SEQ num in RST, %u/%u/%u, state: %s, packet: %s",
                seq, entry->lan_sent, entry->wan_acked, statebuf, packetbuf);
        //airwall_hash_unlock(local, &ctx);
        return 1;
      }
    }
    tcp_set_seq_number_cksum_update(
      ippay, tcp_len, tcp_seq_number(ippay)+entry->seqoffset);
    entry->flag_state = FLAG_STATE_RESETED;
    worker_local_wrlock(local);
    entry->timer.time64 = time64 + TCP_RESETED_TIMEOUT_SECS*1000ULL*1000ULL;
    timer_linkheap_modify(&local->timers, &entry->timer);
    worker_local_wrunlock(local);
    tcp_set_src_port_cksum_update(ippay, tcp_len, entry->nat_port);
    if (version == 4)
    {
      ip_set_src_cksum_update(ip, ip_len, protocol, ippay, tcp_len,
                              hdr_get32n(&entry->nat_ip));
    }
    else
    {
      abort();
    }
    //port->portfunc(pkt, port->userdata);
    //airwall_hash_unlock(local, &ctx);
#ifdef ENABLE_ARP
    if (send_via_arp(pkt, local, airwall, st, port, PACKET_DIRECTION_UPLINK, time64))
    {
      return 1;
    }
#endif
    return 0;
  }
  if (!airwall_is_connected(entry) && entry->flag_state != FLAG_STATE_RESETED)
  {
    airwall_entry_to_str(statebuf, sizeof(statebuf), entry);
    airwall_packet_to_str(packetbuf, sizeof(packetbuf), ether);
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "not CONNECTED/RESETED, dropping, state: %s, packet: %s", statebuf, packetbuf);
    //airwall_hash_unlock(local, &ctx);
    return 1;
  }
  if (!tcp_ack(ippay))
  {
    airwall_entry_to_str(statebuf, sizeof(statebuf), entry);
    airwall_packet_to_str(packetbuf, sizeof(packetbuf), ether);
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "no TCP ACK, dropping pkt, state: %s, packet: %s", statebuf, packetbuf);
    //airwall_hash_unlock(local, &ctx);
    return 1;
  }
  if (!between(
    entry->lan_acked - (entry->lan_max_window_unscaled<<entry->lan_wscale),
    tcp_ack_number(ippay),
    entry->wan_sent + 1 + MAX_FRAG))
  {
    airwall_entry_to_str(statebuf, sizeof(statebuf), entry);
    airwall_packet_to_str(packetbuf, sizeof(packetbuf), ether);
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "packet has invalid ACK number, state: %s, packet: %s", statebuf, packetbuf);
    //airwall_hash_unlock(local, &ctx);
    return 1;
  }
  first_seq = tcp_seq_number(ippay);
  data_len =
    ((int32_t)ip_len) - ((int32_t)ihl) - ((int32_t)tcp_data_offset(ippay));
  if (data_len < 0)
  {
    // This can occur in fragmented packets. We don't then know the true
    // data length, and can therefore drop packets that would otherwise be
    // valid.
    data_len = 0;
  }
  last_seq = first_seq + data_len - 1;
  if (unlikely(tcp_fin(ippay)))
  {
    if (ip46_hdr_cksum_calc(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid IP hdr cksum");
      //airwall_hash_unlock(local, &ctx);
      return 1;
    }
    if (tcp46_cksum_calc(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid TCP hdr cksum");
      //airwall_hash_unlock(local, &ctx);
      return 1;
    }
    last_seq += 1;
  }
  lan_min =
    entry->lan_sent - (entry->wan_max_window_unscaled<<entry->wan_wscale);
  first_seq += entry->seqoffset;
  last_seq += entry->seqoffset;
  if (
    !between(
      lan_min, first_seq, entry->wan_max+1)
    &&
    !between(
      lan_min, last_seq, entry->wan_max+1)
    )
  {
    airwall_entry_to_str(statebuf, sizeof(statebuf), entry);
    airwall_packet_to_str(packetbuf, sizeof(packetbuf), ether);
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "packet has invalid SEQ number, state: %s, packet: %s", statebuf, packetbuf);
    //airwall_hash_unlock(local, &ctx);
    return 1;
  }
  if (tcp_window(ippay) > entry->lan_max_window_unscaled)
  {
    entry->lan_max_window_unscaled = tcp_window(ippay);
    if (entry->lan_max_window_unscaled == 0)
    {
      entry->lan_max_window_unscaled = 1;
    }
  }
  if (unlikely(tcp_fin(ippay)) && entry->flag_state != FLAG_STATE_RESETED)
  {
    if (version == 4 && ip_more_frags(ip)) // FIXME for IPv6
    {
      log_log(LOG_LEVEL_WARNING, "WORKERUPLINK", "FIN with more frags");
    }
    if (entry->flag_state & FLAG_STATE_UPLINK_FIN)
    {
      if (entry->state_data.established.upfin != last_seq)
      {
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "FIN seq changed");
        //airwall_hash_unlock(local, &ctx);
        return 1;
      }
    }
    entry->state_data.established.upfin = last_seq;
    entry->flag_state |= FLAG_STATE_UPLINK_FIN;
  }
  if (unlikely(entry->flag_state & FLAG_STATE_DOWNLINK_FIN))
  {
    uint32_t fin = entry->state_data.established.downfin;
    if (tcp_ack(ippay) && tcp_ack_number(ippay) == fin + 1)
    {
      if (ip46_hdr_cksum_calc(ip) != 0)
      {
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid IP hdr cksum");
        //airwall_hash_unlock(local, &ctx);
        return 1;
      }
      if (tcp46_cksum_calc(ip) != 0)
      {
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid TCP hdr cksum");
        //airwall_hash_unlock(local, &ctx);
        return 1;
      }
      entry->flag_state |= FLAG_STATE_DOWNLINK_FIN_ACK;
      if (entry->flag_state & FLAG_STATE_UPLINK_FIN_ACK)
      {
        todelete = 1;
      }
    }
  }
  if (seq_cmp(last_seq, entry->lan_sent) >= 0)
  {
    entry->lan_sent = last_seq + 1;
  }
  if (likely(tcp_ack(ippay)))
  {
    uint32_t ack = tcp_ack_number(ippay);
    uint16_t window = tcp_window(ippay);
    if (seq_cmp(ack, entry->lan_acked) >= 0)
    {
      entry->lan_acked = ack;
    }
    if (seq_cmp(ack + (window << entry->lan_wscale), entry->lan_max) >= 0)
    {
      entry->lan_max = ack + (window << entry->lan_wscale);
    }
    if (entry->detect) 
    {
      uint32_t acked_seq = entry->detect->acked + 1 + entry->remote_isn;
      int cmp;
      cmp = seq_cmp(tcp_ack_number(ippay), acked_seq);
      if (cmp >= 0)
      {
        local->detect_count--;
        linked_list_delete(&entry->detect_node);
        free(entry->detect);
        entry->detect = NULL;
      }
      else
      {
        if (airwall->conf->enable_ack)
        {
          send_data_only(ether, entry, port, st, local, airwall, time64);
          tcp_set_ack_number_cksum_update(ippay, tcp_len, acked_seq);
        }
      }
    }
  }
  uint64_t next64;
  if (entry->flag_state == FLAG_STATE_RESETED)
  {
    next64 = time64 + TCP_RESETED_TIMEOUT_SECS*1000ULL*1000ULL;
  }
  else if ((entry->flag_state & FLAG_STATE_UPLINK_FIN) &&
           (entry->flag_state & FLAG_STATE_DOWNLINK_FIN))
  {
    next64 = time64 + TCP_BOTH_FIN_TIMEOUT_SECS*1000ULL*1000ULL;
  }
  else if (entry->flag_state & (FLAG_STATE_UPLINK_FIN|FLAG_STATE_DOWNLINK_FIN))
  {
    next64 = time64 + TCP_ONE_FIN_TIMEOUT_SECS*1000ULL*1000ULL;
  }
  else
  {
    next64 = time64 + TCP_CONNECTED_TIMEOUT_SECS*1000ULL*1000ULL;
  }
  if (abs(next64 - entry->timer.time64) >= 1000*1000)
  {
    worker_local_wrlock(local);
    entry->timer.time64 = next64;
    timer_linkheap_modify(&local->timers, &entry->timer);
    worker_local_wrunlock(local);
  }
  tcp_set_seq_number_cksum_update(
    ippay, tcp_len, tcp_seq_number(ippay)+entry->seqoffset);
  if (version == 6)
  {
    ipv6_set_flow_label(ip, entry->ulflowlabel);
  }
  wscalediff = entry->wscalediff;
  if (wscalediff > 0)
  {
    tcp_set_window_cksum_update(
      ippay, tcp_len, tcp_window(ippay) >> entry->wscalediff);
  }
  else
  {
    uint64_t win64 = ((uint64_t)tcp_window(ippay)) << (-(entry->wscalediff));
    if (win64 > 65535 || win64 < tcp_window(ippay))
    {
      win64 = 65535;
    }
    tcp_set_window_cksum_update(ippay, tcp_len, win64);
  }
  tcp_find_sack_ts_headers(ippay, &hdrs);
  tcp_adjust_tsval_cksum_update(ippay, &hdrs, entry->tsoffset);
  tcp_set_src_port_cksum_update(ippay, tcp_len, entry->nat_port);
  if (version == 4)
  {
    ip_set_src_cksum_update(ip, ip_len, protocol, ippay, tcp_len,
                            hdr_get32n(&entry->nat_ip));
  }
  else
  {
    abort();
  }
#ifdef ENABLE_ARP
  if (send_via_arp(pkt, local, airwall, st, port, PACKET_DIRECTION_UPLINK, time64))
  {
    return 1;
  }
#endif
  //port->portfunc(pkt, port->userdata);
  if (todelete)
  {
    worker_local_wrlock(local);
    entry->timer.time64 = time64 + TCP_TIME_WAIT_TIMEOUT_SECS*1000ULL*1000ULL;
    entry->flag_state = FLAG_STATE_TIME_WAIT;
    timer_linkheap_modify(&local->timers, &entry->timer);
    worker_local_wrunlock(local);
  }
  //airwall_hash_unlock(local, &ctx);
  return 0;
}

void send_announce(struct worker_local *local, struct port *port,
                   struct ll_alloc_st *st)
{
  char pcppkt[14+20+8+24] = {0};
  char *ip, *udp, *udppay;
  uint16_t outudppay;
  struct packet *pktstruct;

  memcpy(ether_src(pcppkt), local->airwall->dl_mac, 6);
  memset(ether_dst(pcppkt), 0xff, 6);
  ether_set_type(pcppkt, ETHER_TYPE_IP);
  ip = ether_payload(pcppkt);
  ip_set_version(ip, 4);
#if 0 // FIXME this needs to be thought carefully
  if (version == 6)
  {
    ipv6_set_flow_label(ip, entry->ulflowlabel);
  }
#endif
  ip46_set_min_hdr_len(ip);
  ip46_set_payload_len(ip, 24);
  ip46_set_dont_frag(ip, 1);
  ip46_set_id(ip, 0); // XXX
  ip46_set_ttl(ip, 1);
  ip46_set_proto(ip, 17);
  ip_set_src(ip, local->airwall->conf->dl_addr);
  ip_set_dst(ip, (224<<24)|1);
  udp = ip46_payload(ip);
  udp_set_src_port(udp, 5351);
  udp_set_dst_port(udp, 5350);
  udppay = udp+8;

  outudppay = 24;
  pcp_set_version(udppay, 2);
  pcp_set_r(udppay, 1);
  pcp_set_opcode(udppay, PCP_OPCODE_ANNOUNCE);
  pcp_resp_set_reserved(udppay, 0);
  pcp_resp_set_rcode(udppay, PCP_RCODE_SUCCESS);
  pcp_set_lifetime(udppay, 0);
  pcp_resp_set_epoch_time(udppay, epoch_time(local->airwall));
  pcp_resp_zero_reserved2(udppay);

  udp_set_total_len(udp, 8 + outudppay);
  udp_set_cksum(udp, 0); // FIXME
  ip46_set_payload_len(ip, 8 + outudppay);
  ip46_set_hdr_cksum_calc(ip);

  pktstruct = ll_alloc_st(st, packet_size(sizeof(pcppkt)));
  pktstruct->data = packet_calc_data(pktstruct);
  pktstruct->direction = PACKET_DIRECTION_DOWNLINK;
  pktstruct->sz = sizeof(pcppkt);
  memcpy(pktstruct->data, pcppkt, sizeof(pcppkt));
  port->portfunc(pktstruct, port->userdata);
}

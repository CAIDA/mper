#ifdef _WIN32
#include <winsock2.h>
#define STDIN_FILENO 0
#endif

#if defined(_MSC_VER)
typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
#endif

#if defined(__APPLE__)
#include <stdint.h>
#endif

#include <sys/types.h>

#ifndef _WIN32
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#include <stdio.h>
#include <string.h>
#include <time.h>

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_tlv.h"
#include "scamper_icmpext.h"
#include "scamper_trace.h"
#include "scamper_ping.h"
#include "scamper_tracelb.h"
#include "scamper_dealias.h"
#include "scamper_file.h"
#include "utils.h"

static void usage()
{
  fprintf(stderr, "usage: warts-dump <file>\n");
  return;
}

static void dump_list_summary(scamper_list_t *list)
{
  if(list != NULL)
    {
      fprintf(stdout, " list id: %d", list->id);
      if(list->name != NULL)
	fprintf(stdout, ", name: %s", list->name);
      if(list->monitor != NULL)
	fprintf(stdout, ", monitor: %s", list->monitor);
      fprintf(stdout, "\n");
    }
  return;
}

static void dump_cycle_summary(scamper_cycle_t *cycle)
{
  if(cycle != NULL)
    {
      fprintf(stdout, " cycle id: %d\n", cycle->id);
    }
  return;
}

static void dump_tcp_flags(uint8_t flags)
{
  if(flags != 0)
    {
      fprintf(stdout, " (%s%s%s%s%s%s%s%s )",
	      (flags & 0x01) ? " fin" : "",
	      (flags & 0x02) ? " syn" : "",
	      (flags & 0x04) ? " rst" : "",
	      (flags & 0x08) ? " psh" : "",
	      (flags & 0x10) ? " ack" : "",
	      (flags & 0x20) ? " urg" : "",
	      (flags & 0x40) ? " ece" : "",
	      (flags & 0x80) ? " cwr" : "");
    }
  return;
}

static void dump_start(struct timeval *start)
{
  time_t tt = start->tv_sec;
  char buf[32];
  memcpy(buf, ctime(&tt), 24); buf[24] = '\0';
  fprintf(stdout, " start: %s %06d\n", buf, (int)start->tv_usec);
  return;
}

static void dump_trace_hop(scamper_trace_hop_t *hop)
{
  scamper_icmpext_t *ie;
  scamper_tlv_t *tlv;
  uint32_t u32;
  char addr[256];
  int i;

  fprintf(stdout, "hop %2d  %s\n",
	  hop->hop_probe_ttl,
	  scamper_addr_tostr(hop->hop_addr, addr, sizeof(addr)));

  fprintf(stdout, " attempt: %d, rtt: %d.%06ds\n",
	  hop->hop_probe_id,
	  (int)hop->hop_rtt.tv_sec, (int)hop->hop_rtt.tv_usec);

  fprintf(stdout, " probe_size: %d", hop->hop_probe_size);
  if(hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_REPLY_TTL)
    {
      fprintf(stdout, ", reply_ttl: %d", hop->hop_reply_ttl);
    }
  fprintf(stdout, "\n");

  if((hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_TCP) == 0)
    {
      fprintf(stdout, " icmp type: %d, code: %d\n",
	      hop->hop_icmp_type, hop->hop_icmp_code);
    }
  else
    {
      fprintf(stdout, " tcp flags: 0x%02x", hop->hop_tcp_flags);
      dump_tcp_flags(hop->hop_tcp_flags);
      fprintf(stdout, "\n");
    }

  fprintf(stdout, " flags: 0x%02x", hop->hop_flags);
  if(hop->hop_flags != 0)
    {
      fprintf(stdout, " (");
      if(hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_TS_SOCK_RX)
	fprintf(stdout, " sockrxts");
      if(hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_TS_DL_TX)
	fprintf(stdout, " dltxts");
      if(hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_TS_DL_RX)
	fprintf(stdout, " dlrxts");
      if(hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_TS_TSC)
	fprintf(stdout, " tscrtt");
      if(hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_REPLY_TTL)
	fprintf(stdout, " replyttl");
      fprintf(stdout, " )");
    }
  fprintf(stdout, "\n");

  if(hop->hop_tlvs != NULL)
    {
      for(tlv = hop->hop_tlvs; tlv != NULL; tlv = tlv->tlv_next)
	{
	  switch(tlv->tlv_type)
	    {
	    case SCAMPER_TRACE_HOP_TLV_REPLY_IPID:
	      fprintf(stdout, " ipid outer 0x%04x", tlv->tlv_val_16);
	      break;

	    case SCAMPER_TRACE_HOP_TLV_REPLY_IPTOS:
	      fprintf(stdout, " iptos outer 0x%02x", tlv->tlv_val_8);
	      break;

	    case SCAMPER_TRACE_HOP_TLV_NHMTU:
	      fprintf(stdout, " nhmtu %d", tlv->tlv_val_16);
	      break;

	    case SCAMPER_TRACE_HOP_TLV_INNER_IPTTL:
	      fprintf(stdout, " turn ttl %d", tlv->tlv_val_8);
	      break;

	    case SCAMPER_TRACE_HOP_TLV_INNER_IPLEN:
	      fprintf(stdout, " iplen inner %d", tlv->tlv_val_16);
	      break;

	    case SCAMPER_TRACE_HOP_TLV_INNER_IPTOS:
	      fprintf(stdout, " iptos inner 0x%02x", tlv->tlv_val_8);
	      break;
	    }
	}
      fprintf(stdout, "\n");
    }

  for(ie = hop->hop_icmpext; ie != NULL; ie = ie->ie_next)
    {
      if(SCAMPER_ICMPEXT_IS_MPLS(ie))
	{
	  for(i=0; i<SCAMPER_ICMPEXT_MPLS_COUNT(ie); i++)
	    {
	      u32 = SCAMPER_ICMPEXT_MPLS_LABEL(ie, i);
	      fprintf(stdout, "%9s: label %d exp %d s %d ttl %d\n",
		      (i == 0) ? "mpls ext" : "", u32,		      
		      SCAMPER_ICMPEXT_MPLS_EXP(ie, i),
		      SCAMPER_ICMPEXT_MPLS_S(ie, i),
		      SCAMPER_ICMPEXT_MPLS_TTL(ie, i));
	    }
	}
    }

  return;
}

static void dump_trace(scamper_trace_t *trace)
{
  scamper_trace_hop_t *hop;
  uint16_t i;
  char buf[256];

  if(trace->src != NULL)
    {
      scamper_addr_tostr(trace->src, buf, sizeof(buf));
      fprintf(stdout, "traceroute from %s to ", buf);
      scamper_addr_tostr(trace->dst, buf, sizeof(buf));
      fprintf(stdout, "%s\n", buf);
    }
  else
    {
      fprintf(stdout, "traceroute to %s\n",
	      scamper_addr_tostr(trace->dst, buf, sizeof(buf)));
    }

  dump_list_summary(trace->list);
  dump_cycle_summary(trace->cycle);
  dump_start(&trace->start);

  fprintf(stdout, " type: ");
  switch(trace->type)
    {
    case SCAMPER_TRACE_TYPE_ICMP_ECHO:
      fprintf(stdout, "icmp, echo id: %d", trace->sport);
      break;

    case SCAMPER_TRACE_TYPE_ICMP_ECHO_PARIS:
      /*
       * if the byte ordering of the trace->sport used in the icmp csum
       * is unknown -- that is, not known to be correct, print that detail
       */
      fprintf(stdout, "icmp paris, echo id: %d", trace->sport);
      if(SCAMPER_TRACE_IS_ICMPCSUMDP(trace))
	fprintf(stdout, ", csum: 0x%04x", trace->dport);
      break;

    case SCAMPER_TRACE_TYPE_UDP:
      fprintf(stdout, "udp, sport: %d, base dport: %d",
	      trace->sport, trace->dport);
      break;

    case SCAMPER_TRACE_TYPE_UDP_PARIS:
      fprintf(stdout, "udp paris, sport: %d, dport: %d",
	      trace->sport, trace->dport);
      break;

    case SCAMPER_TRACE_TYPE_TCP:
      fprintf(stdout, "tcp, sport: %d, dport: %d", trace->sport, trace->dport);
      break;

    case SCAMPER_TRACE_TYPE_TCP_ACK:
      fprintf(stdout, "tcp-ack, sport: %d, dport: %d",
	      trace->sport, trace->dport);
      break;

    default:
      fprintf(stdout, "%d", trace->type);
      break;
    }
  fprintf(stdout, "\n");

  if(trace->dtree != NULL)
    {
      fprintf(stdout, " doubletree firsthop: %d", trace->dtree->firsthop);
      if(trace->dtree->lss_stop != NULL)
	fprintf(stdout, ", lss: %s",
		scamper_addr_tostr(trace->dtree->lss_stop, buf, sizeof(buf)));
      if(trace->dtree->gss_stop != NULL)
	fprintf(stdout, ", gss: %s",
		scamper_addr_tostr(trace->dtree->gss_stop, buf, sizeof(buf)));
      fprintf(stdout, "\n");
    }

  fprintf(stdout, " attempts: %d, hoplimit: %d, loops: %d, probec: %d\n",
	  trace->attempts, trace->hoplimit, trace->loops, trace->probec);
  fprintf(stdout, " gaplimit: %d, gapaction: ", trace->gaplimit);
  if(trace->gapaction == SCAMPER_TRACE_GAPACTION_STOP)
    fprintf(stdout, "stop");
  else if(trace->gapaction == SCAMPER_TRACE_GAPACTION_LASTDITCH)
    fprintf(stdout, "lastditch");
  else
    fprintf(stdout, "0x%02x", trace->gapaction);
  fprintf(stdout, "\n");

  fprintf(stdout, " wait-timeout: %ds", trace->wait);
  if(trace->wait_probe != 0)
    fprintf(stdout, ", wait-probe: %dms", trace->wait_probe * 10);
  if(trace->confidence != 0)
    fprintf(stdout, ", confidence: %d%%", trace->confidence);
  fprintf(stdout, "\n");

  fprintf(stdout, " flags: 0x%02x", trace->flags);
  if(trace->flags != 0)
    {
      fprintf(stdout, " (");
      if(trace->flags & SCAMPER_TRACE_FLAG_ALLATTEMPTS)
	fprintf(stdout, " all-attempts");
      if(trace->flags & SCAMPER_TRACE_FLAG_PMTUD)
	fprintf(stdout, " pmtud");
      if(trace->flags & SCAMPER_TRACE_FLAG_DL)
	fprintf(stdout, " dltxts");
      if(trace->flags & SCAMPER_TRACE_FLAG_IGNORETTLDST)
	fprintf(stdout, " ignorettldst");
      if(trace->flags & SCAMPER_TRACE_FLAG_DTREE)
	fprintf(stdout, " doubletree");
      if(trace->flags & SCAMPER_TRACE_FLAG_ICMPCSUMDP)
	fprintf(stdout, " icmp-csum-dport");
      fprintf(stdout, " )");
    }
  fprintf(stdout, "\n");

  fprintf(stdout, " stop reason: ");
  switch(trace->stop_reason)
    {
    case SCAMPER_TRACE_STOP_NONE:
      fprintf(stdout, "none");
      break;

    case SCAMPER_TRACE_STOP_COMPLETED:
      fprintf(stdout, "done");
      break;

    case SCAMPER_TRACE_STOP_UNREACH:
      fprintf(stdout, "icmp unreach %d", trace->stop_data);
      break;

    case SCAMPER_TRACE_STOP_ICMP:
      fprintf(stdout, "icmp type %d", trace->stop_data);
      break;

    case SCAMPER_TRACE_STOP_LOOP:
      fprintf(stdout, "loop");
      break;

    case SCAMPER_TRACE_STOP_GAPLIMIT:
      fprintf(stdout, "gaplimit");
      break;

    case SCAMPER_TRACE_STOP_ERROR:
      fprintf(stdout, "errno %d", trace->stop_data);
      break;

    case SCAMPER_TRACE_STOP_HOPLIMIT:
      fprintf(stdout, "hoplimit");
      break;

    case SCAMPER_TRACE_STOP_GSS:
      fprintf(stdout, "dtree-gss");
      break;

    default:
      fprintf(stdout, "reason 0x%02x data 0x%02x",
	      trace->stop_reason, trace->stop_data);
      break;
    }
  fprintf(stdout, "\n");

  for(i=0; i<trace->hop_count; i++)
    {
      for(hop = trace->hops[i]; hop != NULL; hop = hop->hop_next)
	{
	  dump_trace_hop(hop);
	}
    }

  /* dump any last-ditch probing hops */
  for(hop = trace->lastditch; hop != NULL; hop = hop->hop_next)
    {
      dump_trace_hop(hop);
    }

  if(trace->pmtud != NULL)
    {
      fprintf(stdout, "pmtud: ifmtu %d, pmtu %d\n",
	     trace->pmtud->ifmtu, trace->pmtud->pmtu);
      for(hop = trace->pmtud->hops; hop != NULL; hop = hop->hop_next)
	{
	  dump_trace_hop(hop);
	}
    }

  fprintf(stdout, "\n");

  scamper_trace_free(trace);

  return;
}

static void dump_tracelb_reply(scamper_tracelb_probe_t *probe,
			       scamper_tracelb_reply_t *reply)
{
  scamper_icmpext_t *ie;
  struct timeval rtt;
  char from[32];
  uint32_t u32;
  uint16_t m;

  timeval_diff_tv(&rtt, &probe->tx, &reply->reply_rx);
  scamper_addr_tostr(reply->reply_from, from, sizeof(from));

  fprintf(stdout, "   reply from: %s, rtt: %d.%06d, ttl: %d",
	  from, (int)rtt.tv_sec, (int)rtt.tv_usec, reply->reply_ttl);

  if(reply->reply_from->type == SCAMPER_ADDR_TYPE_IPV4)
    fprintf(stdout, ", ipid: 0x%04x", reply->reply_ipid);
  fprintf(stdout, "\n     ");

  if(reply->reply_flags & SCAMPER_TRACELB_REPLY_FLAG_TCP)
    {
      fprintf(stdout,"tcp flags 0x%02x",reply->reply_tcp_flags);
      dump_tcp_flags(reply->reply_tcp_flags);
      fprintf(stdout, "\n");
    }
  else
    {
      fprintf(stdout, "icmp: %d/%d, q-tos: 0x%02x",
	      reply->reply_icmp_type, reply->reply_icmp_code,
	      reply->reply_icmp_q_tos);
      if(SCAMPER_TRACELB_REPLY_IS_ICMP_UNREACH(reply) ||
	 SCAMPER_TRACELB_REPLY_IS_ICMP_TTL_EXP(reply))
	{
	  fprintf(stdout, ", q-ttl: %d", reply->reply_icmp_q_ttl);
	}
      fprintf(stdout, "\n");

      for(ie = reply->reply_icmp_ext; ie != NULL; ie = ie->ie_next)
	{
	  if(SCAMPER_ICMPEXT_IS_MPLS(ie))
	    {
	      for(m=0; m<SCAMPER_ICMPEXT_MPLS_COUNT(ie); m++)
		{
		  u32 = SCAMPER_ICMPEXT_MPLS_LABEL(ie, m);
		  fprintf(stdout,
			  "   %9s: label %d exp %d s %d ttl %d\n",
			  (m == 0) ? "  icmp-ext mpls" : "", u32,
			  SCAMPER_ICMPEXT_MPLS_EXP(ie, m),
			  SCAMPER_ICMPEXT_MPLS_S(ie, m),
			  SCAMPER_ICMPEXT_MPLS_TTL(ie, m));
		}
	    }
	}
    }

  return;
}

static void dump_tracelb_probe(scamper_tracelb_t *trace,
			       scamper_tracelb_probe_t *probe)
{
  uint32_t i;

  fprintf(stdout,
	  "  probe flowid: %d, ttl: %d, attempt: %d, tx: %d.%06d\n",
	  probe->flowid, probe->ttl, probe->attempt,
	  (int)probe->tx.tv_sec, (int)probe->tx.tv_usec);

  for(i=0; i<probe->rxc; i++)
    {
      dump_tracelb_reply(probe, probe->rxs[i]);
    }

  return;
}

static void dump_tracelb(scamper_tracelb_t *trace)
{
  scamper_tracelb_link_t *link;
  scamper_tracelb_node_t *node;
  scamper_tracelb_probeset_t *set;
  char src[256], dst[256];
  uint16_t i, j, k, l;

  if(trace->src != NULL)
    {
      fprintf(stdout, "tracelb from %s to %s\n",
	      scamper_addr_tostr(trace->src, src, sizeof(src)),
	      scamper_addr_tostr(trace->dst, dst, sizeof(dst)));
    }
  else
    {
      fprintf(stdout, "tracelb to %s\n",
	      scamper_addr_tostr(trace->dst, dst, sizeof(dst)));
    }

  dump_list_summary(trace->list);
  dump_cycle_summary(trace->cycle);
  dump_start(&trace->start);

  fprintf(stdout, " type: ");
  switch(trace->type)
    {
    case SCAMPER_TRACELB_TYPE_ICMP_ECHO:
      fprintf(stdout, "icmp-echo id: %d", trace->sport);
      break;

    case SCAMPER_TRACELB_TYPE_UDP_DPORT:
      fprintf(stdout, "udp-dport %d:%d", trace->sport, trace->dport);
      break;

    case SCAMPER_TRACELB_TYPE_UDP_SPORT:
      fprintf(stdout, "udp-sport %d:%d", trace->sport, trace->dport);
      break;

    case SCAMPER_TRACELB_TYPE_TCP_SPORT:
      fprintf(stdout, "tcp-sport %d:%d", trace->sport, trace->dport);
      break;

    default:
      fprintf(stdout, "%d", trace->type);
      break;
    }
  fprintf(stdout, ", tos: 0x%02x\n", trace->tos);

  fprintf(stdout, " firsthop: %d, attempts: %d, confidence: %d\n",
	  trace->firsthop, trace->attempts, trace->confidence);
  fprintf(stdout, " probe-size: %d, wait-probe: %dms, wait-timeout %ds\n",
	  trace->probe_size, trace->wait_probe * 10, trace->wait_timeout);
  fprintf(stdout, " nodec: %d, linkc: %d, probec: %d, probec_max: %d\n",
	  trace->nodec, trace->linkc, trace->probec, trace->probec_max);

  for(i=0; i<trace->nodec; i++)
    {
      node = trace->nodes[i];

      fprintf(stdout, "node %d %s", i,
	      scamper_addr_tostr(node->addr, src, sizeof(src)));
      if(SCAMPER_TRACELB_NODE_QTTL(node) != 0)
	fprintf(stdout, ", qttl %d", node->q_ttl);
      fprintf(stdout, "\n");

      for(j=0; j<node->linkc; j++)
	{
	  link = node->links[j];
	  scamper_addr_tostr(link->from->addr, src, sizeof(src));
	  if(link->to != NULL)
	    scamper_addr_tostr(link->to->addr, dst, sizeof(dst));
	  else
	    snprintf(dst, sizeof(dst), "*");
	  fprintf(stdout, " link %s -> %s hopc %d\n", src, dst, link->hopc);

	  for(k=0; k<link->hopc; k++)
	    {
	      set = link->sets[k];
	      for(l=0; l<set->probec; l++)
		dump_tracelb_probe(trace, set->probes[l]);
	    }
	}
    }

  scamper_tracelb_free(trace);
  return;
}

static void dump_ping_reply(scamper_ping_reply_t *reply)
{
  char addr[256];

  fprintf(stdout, "reply from %s, attempt: %d, rtt: %d.%06ds\n",
	  scamper_addr_tostr(reply->addr, addr, sizeof(addr)),
	  reply->probe_id+1, (int)reply->rtt.tv_sec, (int)reply->rtt.tv_usec);

  fprintf(stdout, " size: %d", reply->reply_size);
  if(reply->flags & SCAMPER_PING_REPLY_FLAG_REPLY_TTL)
    {
      fprintf(stdout, ", ttl: %d", reply->reply_ttl);
    }
  if(reply->flags & SCAMPER_PING_REPLY_FLAG_PROBE_IPID)
    {
      fprintf(stdout, ", probe-ipid: 0x%04x", reply->probe_ipid);
    }
  if(reply->flags & SCAMPER_PING_REPLY_FLAG_REPLY_IPID)
    {
      fprintf(stdout, ", reply-ipid: 0x%04x", reply->reply_ipid);
    }
  fprintf(stdout, "\n");

  if(SCAMPER_PING_REPLY_IS_ICMP(reply))
    {
      fprintf(stdout, " icmp type: %d, code: %d\n",
	      reply->icmp_type, reply->icmp_code);
    }
  else if(SCAMPER_PING_REPLY_IS_TCP(reply))
    {
      fprintf(stdout, " tcp flags: %02x", reply->tcp_flags);
      dump_tcp_flags(reply->tcp_flags);
      fprintf(stdout, "\n");
    }

  return;
}

static void dump_ping(scamper_ping_t *ping)
{
  scamper_ping_reply_t *reply;
  char buf[256];
  int i;

  scamper_addr_tostr(ping->src, buf, sizeof(buf));
  fprintf(stdout, "ping from %s to ", buf);
  scamper_addr_tostr(ping->dst, buf, sizeof(buf));
  fprintf(stdout, "%s\n", buf);

  dump_list_summary(ping->list);
  dump_cycle_summary(ping->cycle);
  fprintf(stdout, " user-id: %d\n", ping->userid);
  dump_start(&ping->start);

  fprintf(stdout, " probe count: %d, size: %d, wait: %d, ttl %d\n",
	  ping->probe_count,ping->probe_size,ping->probe_wait,ping->probe_ttl);

  switch(ping->probe_method)
    {
    case SCAMPER_PING_METHOD_ICMP_ECHO:
      fprintf(stdout, " method: icmp-echo\n");
      break;

    case SCAMPER_PING_METHOD_TCP_ACK:
      fprintf(stdout, " method: tcp-ack, sport: %d, dport: %d\n",
	      ping->probe_sport, ping->probe_dport);
      break;

    case SCAMPER_PING_METHOD_TCP_ACK_SPORT:
      fprintf(stdout, " method: tcp-ack-sport, base-sport: %d, dport: %d\n",
	      ping->probe_sport, ping->probe_dport);
      break;

    case SCAMPER_PING_METHOD_UDP:
      fprintf(stdout, " method: udp, sport: %d, dport %d\n",
	      ping->probe_sport, ping->probe_dport);
      break;

    case SCAMPER_PING_METHOD_UDP_DPORT:
      fprintf(stdout, " method: udp-dport, sport: %d, base-dport %d\n",
	      ping->probe_sport, ping->probe_dport);
      break;

    default:
      fprintf(stdout, " method: %d\n", ping->probe_method);
      break;
    }

  fprintf(stdout, " probes sent: %d", ping->ping_sent);
  if(ping->reply_count > 0)
    {
      fprintf(stdout, ", replies requested: %d", ping->reply_count);
    }
  fprintf(stdout, "\n");

  /* dump pad bytes, if used */
  if(ping->pattern_len > 0 && ping->pattern_bytes != NULL)
    {
      fprintf(stdout, " pattern bytes (%d): ", ping->pattern_len);
      for(i=0; i<ping->pattern_len; i++)
	{
	  fprintf(stdout, "%02x", ping->pattern_bytes[i]);
	}
      fprintf(stdout, "\n");
    }

  fprintf(stdout, " stop reason: ");
  switch(ping->stop_reason)
    {
    case SCAMPER_PING_STOP_NONE:
      fprintf(stdout, "none"); break;

    case SCAMPER_PING_STOP_COMPLETED:
      fprintf(stdout, "done"); break;

    case SCAMPER_PING_STOP_ERROR:
      fprintf(stdout, "sendto errno %d", ping->stop_data); break;

    default:
      fprintf(stdout, "reason 0x%02x data 0x%02x",
	      ping->stop_reason, ping->stop_data);
      break;
    }
  fprintf(stdout, "\n");

  for(i=0; i<ping->ping_sent; i++)
    {
      for(reply = ping->ping_replies[i]; reply != NULL; reply = reply->next)
	{
	  dump_ping_reply(reply);
	}
    }

  fprintf(stdout, "\n");

  scamper_ping_free(ping);

  return;
}

static void dump_dealias_probedef(scamper_dealias_probedef_t *def)
{
  scamper_dealias_probedef_icmp_t *icmp;
  char dst[128], src[128];

  fprintf(stdout, " probedef %d: dst: %s, src: %s, ttl: %d, tos: 0x%02x\n",
	  def->id,
	  scamper_addr_tostr(def->dst, dst, sizeof(dst)),
	  scamper_addr_tostr(def->src, src, sizeof(src)),
	  def->ttl, def->tos);
  if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP(def))
    {
      icmp = &def->un.icmp;
      fprintf(stdout,
	      "  icmp type: %d, code: %d, csum: %04x, id: %04x\n",
	      icmp->type, icmp->code, icmp->csum, icmp->id);
    }
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(def))
    {
      if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP)
	fprintf(stdout, "  udp");
      else if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP_DPORT)
	fprintf(stdout, "  udp-dport");
      else
	fprintf(stdout, "  udp-%d", def->method);
      fprintf(stdout, " %d:%d\n", def->un.udp.sport, def->un.udp.dport);
    }
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(def))
    {
      if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK)
	fprintf(stdout, "  tcp-ack");
      else if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK_SPORT)
	fprintf(stdout, "  tcp-ack-sport");
      else
	fprintf(stdout, "  tcp-%d", def->method);
      fprintf(stdout, " %d:%d ", def->un.tcp.sport, def->un.tcp.dport);
      dump_tcp_flags(def->un.tcp.flags);
      fprintf(stdout, "\n");
    }
  else
    {
      fprintf(stdout, "%d\n", def->method);
    }
  return;
}

static void dump_dealias(scamper_dealias_t *dealias)
{
  scamper_dealias_prefixscan_t *prefixscan = dealias->data;
  scamper_dealias_mercator_t *mercator = dealias->data;
  scamper_dealias_radargun_t *radargun = dealias->data;
  scamper_dealias_ally_t *ally = dealias->data;
  scamper_dealias_probe_t *probe;
  scamper_dealias_reply_t *reply;
  struct timeval rtt;
  uint16_t u16;
  char buf[256];
  int i, j;

  /* first line: dealias */
  fprintf(stdout, "dealias");
  if(dealias->method == SCAMPER_DEALIAS_METHOD_MERCATOR)
    {
      scamper_addr_tostr(mercator->probedef.src, buf, sizeof(buf));
      fprintf(stdout, " from %s", buf);
      scamper_addr_tostr(mercator->probedef.dst, buf, sizeof(buf));
      fprintf(stdout, " to %s", buf);
    }
  fprintf(stdout, "\n");

  /* dump list, cycle, start time */
  dump_list_summary(dealias->list);
  dump_cycle_summary(dealias->cycle);
  fprintf(stdout, " user-id: %d\n", dealias->userid);
  dump_start(&dealias->start);

  fprintf(stdout, " probes: %d, result: ", dealias->probec);
  switch(dealias->result)
    {
    case SCAMPER_DEALIAS_RESULT_NONE:
      fprintf(stdout, "none");
      break;

    case SCAMPER_DEALIAS_RESULT_ALIASES:
      fprintf(stdout, "aliases");
      break;

    case SCAMPER_DEALIAS_RESULT_NOTALIASES:
      fprintf(stdout, "not aliases");
      break;
    }
  fprintf(stdout, "\n");

  /* method headers */
  fprintf(stdout, " method: ");
  if(dealias->method == SCAMPER_DEALIAS_METHOD_MERCATOR)
    {
      fprintf(stdout, "mercator, attempts: %d, timeout: %ds\n",
	      mercator->attempts, mercator->wait_timeout);
      dump_dealias_probedef(&mercator->probedef);
    }
  else if(dealias->method == SCAMPER_DEALIAS_METHOD_ALLY)
    {
      fprintf(stdout, "ally, attempts: %d, fudge: %d, "
	      "wait-probe: %dms, wait-timeout: %ds",
	      ally->attempts, ally->fudge, ally->wait_probe,
	      ally->wait_timeout);
      if(SCAMPER_DEALIAS_ALLY_IS_NOBS(dealias))
	fprintf(stdout, ", nobs");
      fprintf(stdout, "\n");

      dump_dealias_probedef(&ally->probedefs[0]);
      dump_dealias_probedef(&ally->probedefs[1]);
    }
  else if(dealias->method == SCAMPER_DEALIAS_METHOD_RADARGUN)
    {
      fprintf(stdout, "radargun, wait-probe: %dms, wait-round: %dms\n"
	      "  wait-timeout: %ds, attempts: %d, probedefc: %d\n",
	      radargun->wait_probe, radargun->wait_round,
	      radargun->wait_timeout, radargun->attempts, radargun->probedefc);
      for(i=0; i<radargun->probedefc; i++)
	dump_dealias_probedef(&radargun->probedefs[i]);
    }
  else if(dealias->method == SCAMPER_DEALIAS_METHOD_PREFIXSCAN)
    {
      fprintf(stdout, "prefixscan, %s:",
	      scamper_addr_tostr(prefixscan->a, buf, sizeof(buf)));
      fprintf(stdout, "%s/%d",
	      scamper_addr_tostr(prefixscan->b,buf,sizeof(buf)),
	      prefixscan->prefix);
      if(prefixscan->ab != NULL)
	fprintf(stdout, ", alias: %s/%d",
		scamper_addr_tostr(prefixscan->ab, buf, sizeof(buf)),
		scamper_addr_prefixhosts(prefixscan->b, prefixscan->ab));
      fprintf(stdout, "\n");

      fprintf(stdout, "  attempts: %d, replyc: %d, fudge: %d,"
	      " wait-probe: %dms, wait-timeout: %ds",
	      prefixscan->attempts, prefixscan->replyc, prefixscan->fudge,
	      prefixscan->wait_probe, prefixscan->wait_timeout);
      if(SCAMPER_DEALIAS_PREFIXSCAN_IS_NOBS(dealias))
	fprintf(stdout, ", nobs");
      fprintf(stdout, "\n");
      if(prefixscan->xc > 0)
	{
	  fprintf(stdout, "  exclude:");
	  for(u16=0; u16<prefixscan->xc; u16++)
	    fprintf(stdout, " %s",
		    scamper_addr_tostr(prefixscan->xs[u16], buf, sizeof(buf)));
	  fprintf(stdout, "\n");
	}
      for(i=0; i<prefixscan->probedefc; i++)
	dump_dealias_probedef(&prefixscan->probedefs[i]);
    }
  else
    {
      fprintf(stdout, "%d\n", dealias->method);
    }

  for(i=0; i<dealias->probec; i++)
    {
      probe = dealias->probes[i];
      fprintf(stdout,
	      " probe: %d, def: %d, seq: %d, ipid: %04x, tx: %d.%06d\n",
	      i, probe->probedef->id, probe->seq, probe->ipid,
	      (int)probe->tx.tv_sec, (int)probe->tx.tv_usec);
      for(j=0; j<probe->replyc; j++)
	{
	  reply = probe->replies[j];
	  timeval_diff_tv(&rtt, &probe->tx, &reply->rx);
	  fprintf(stdout, "  reply: %d, src: %s",
		  j, scamper_addr_tostr(reply->src, buf, sizeof(buf)));
	  fprintf(stdout, " ipid: %04x, ttl: %d, rtt: %d.%06d\n",
		  reply->ipid, reply->ttl,
		  (int)rtt.tv_sec, (int)rtt.tv_usec);

	  if(SCAMPER_DEALIAS_REPLY_IS_ICMP(reply))
	    {
	      fprintf(stdout, "  icmp-type: %d, icmp-code: %d",
		      reply->icmp_type, reply->icmp_code);

	      if(SCAMPER_DEALIAS_REPLY_IS_ICMP_UNREACH(reply) ||
		 SCAMPER_DEALIAS_REPLY_IS_ICMP_TTL_EXP(reply))
		{
		  fprintf(stdout, ", icmp-q-ttl: %d", reply->icmp_q_ip_ttl);
		}
	      fprintf(stdout, "\n");
	    }
	  else if(SCAMPER_DEALIAS_REPLY_IS_TCP(reply))
	    {
	      fprintf(stdout, "   tcp flags:");
	      dump_tcp_flags(reply->tcp_flags);
	      fprintf(stdout, "\n");
	    }
	  else
	    {
	      fprintf(stdout, "  reply proto %d\n", reply->proto);
	    }
	}
    }

  scamper_dealias_free(dealias);
  return;
}

static void dump_cycle(scamper_cycle_t *cycle, const char *type)
{
  time_t tt;
  char buf[32];

  if(strcmp(type, "start") == 0 || strcmp(type, "def") == 0)
    {
      tt = cycle->start_time;
    }
  else
    {
      tt = cycle->stop_time;
    }
  memcpy(buf, ctime(&tt), 24); buf[24] = '\0';

  printf("cycle %s, list %s %d, cycle %d, time %s\n",
	 type, cycle->list->name, cycle->list->id, cycle->id, buf);
  scamper_cycle_free(cycle);
  return;
}

static void dump_list(scamper_list_t *list)
{
  printf("list id %d, name %s", list->id, list->name);
  if(list->descr != NULL) printf(", descr \"%s\"", list->descr);
  printf("\n");
  scamper_list_free(list);
  return;
}

static void dump_addr(scamper_addr_t *addr)
{
  char buf[128];
  printf("addr %s\n", scamper_addr_tostr(addr, buf, sizeof(buf)));
  scamper_addr_free(addr);
  return;
}

int main(int argc, char *argv[])
{
  scamper_file_t        *file;
  scamper_file_filter_t *filter;
  uint16_t filter_types[] = {
    SCAMPER_FILE_OBJ_LIST,
    SCAMPER_FILE_OBJ_CYCLE_START,
    SCAMPER_FILE_OBJ_CYCLE_DEF,
    SCAMPER_FILE_OBJ_CYCLE_STOP,
    SCAMPER_FILE_OBJ_TRACE,
    SCAMPER_FILE_OBJ_PING,
    SCAMPER_FILE_OBJ_TRACELB,
    SCAMPER_FILE_OBJ_DEALIAS,
  };
  uint16_t filter_cnt = sizeof(filter_types)/sizeof(uint16_t);
  void     *data;
  uint16_t  type;

#ifdef _WIN32
  WSADATA wsaData;
  WSAStartup(MAKEWORD(2,2), &wsaData);
#endif

#if defined(DMALLOC)
  free(malloc(1));
#endif

  if(argc == 1)
    {
      if((file = scamper_file_openfd(STDIN_FILENO, "-", 'r', "warts")) == NULL)
	{
	  usage();
	  fprintf(stderr, "could not use stdin\n");
	  return -1;
	}
    }
  else if(argc == 2)
    {
      if((file = scamper_file_open(argv[1], 'r', NULL)) == NULL)
	{
	  usage();
	  fprintf(stderr, "could not open %s\n", argv[1]);
	  return -1;
	}
    }
  else
    {
      usage();
      return -1;
    }

  if((filter = scamper_file_filter_alloc(filter_types, filter_cnt)) == NULL)
    {
      usage();
      fprintf(stderr, "could not alloc fitler\n");
      return -1;
    }

  while(scamper_file_read(file, filter, &type, &data) == 0)
    {
      /* hit eof */
      if(data == NULL)
	{
	  goto done;
	}

      switch(type)
	{
	case SCAMPER_FILE_OBJ_ADDR:
	  dump_addr(data);
	  break;

	case SCAMPER_FILE_OBJ_TRACE:
	  dump_trace(data);
	  break;

	case SCAMPER_FILE_OBJ_PING:
	  dump_ping(data);
	  break;

	case SCAMPER_FILE_OBJ_TRACELB:
	  dump_tracelb(data);
	  break;

	case SCAMPER_FILE_OBJ_DEALIAS:
	  dump_dealias(data);
	  break;

	case SCAMPER_FILE_OBJ_LIST:
	  dump_list(data);
	  break;

	case SCAMPER_FILE_OBJ_CYCLE_START:
	  dump_cycle(data, "start");
	  break;

	case SCAMPER_FILE_OBJ_CYCLE_STOP:
	  dump_cycle(data, "stop");
	  break;

	case SCAMPER_FILE_OBJ_CYCLE_DEF:
	  dump_cycle(data, "def");
	  break;
	}
    }

  scamper_file_filter_free(filter);
  scamper_file_close(file);
  fprintf(stderr, "error encountered\n");
  return -1;

 done:
  scamper_file_filter_free(filter);
  scamper_file_close(file);
  return 0;
}

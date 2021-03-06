/*
 * scamper
 *
 * $Id: scamper.c,v 1.183 2009/04/18 03:58:37 mjl Exp $
 *
 *        Matthew Luckie, WAND Group, Computer Science, University of Waikato
 *        mjl@wand.net.nz
 *
 * Copyright (C) 2003-2009 The University of Waikato
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "mper_keywords.h"
#include "mper_msg.h"
#include "mper_msg_reader.h"
#include "mper_msg_writer.h"

#include "scamper.h"
#include "scamper_debug.h"
#include "scamper_addr.h"
#include "scamper_fds.h"
#include "scamper_writebuf.h"
#include "scamper_task.h"
#include "scamper_target.h"
#include "scamper_queue.h"
#include "scamper_getsrc.h"
#include "scamper_addr2mac.h"
#include "scamper_icmp4.h"
#include "scamper_icmp6.h"
#include "scamper_udp4.h"
#include "scamper_udp6.h"
#include "scamper_tcp4.h"
#include "scamper_rtsock.h"
#include "scamper_dl.h"
#include "scamper_firewall.h"
#include "scamper_probe.h"
#include "scamper_privsep.h"
#include "scamper_control.h"
#include "scamper_ping.h"
#include "scamper_do_ping.h"

#include "utils.h"

static uint32_t options = 0;
#define OPT_PPS         0x00000001 /* p: */
#define OPT_VERSION     0x00000020 /* v: */
#define OPT_HOLDTIME    0x00000100 /* H: */
#define OPT_DAEMON      0x00000200 /* D: */
#define OPT_DL          0x00001000 /* P: */
#define OPT_MONITORNAME 0x00002000 /* M: */
#define OPT_HELP        0x00008000 /* ?: */
#define OPT_WINDOW      0x00010000 /* w: */
#define OPT_DEBUGFILE   0x00020000 /* d: */
#define OPT_MATCHFILE   0x00040000 /* Z: */
#define OPT_FIREWALL    0x00200000 /* F: */
#define OPT_GATEWAY     0x00400000 /* G: */
#define OPT_INTERFACE   0x00800000 /* I: */
#define OPT_USE_TCP     0x01000000 /* T */
#define OPT_SIMULATE    0x02000000 /* S */
#define OPT_PARIS       0x04000000 /* K */
#define OPT_CHECKSUM    0x10000000 /* k */
#define OPT_WEAK_MATCH  0x80000000 /* Y */

/*
 * parameters configurable by the command line:
 *
 * command:     default command to use with scamper
 * pps:         how many probe packets to send per second
 * holdtime:    how long to hold tasks for late replies after completion
 * daemon_port: port to use when operating as a daemon
 * monitorname: canonical name of monitor assigned by human
 * arglist:     whatever is left over after getopt processing
 * arglist_len: number of arguments left over after getopt processing
 * window:      maximum number of concurrent tasks to actively probe
 * debugfile:   place to write debugging output
 * matchfile:   place to write probe-response matching information
 * firewall:    scamper should use the system firewall when needed
 * gateway:     IP address of the gateway to use
 * interface:   datalink interface name to use if manually specifying gateway
 * use_tcp:     use a TCP server socket instead of a Unix domain socket
 * simulate:    don't actually probe--simulate a non-response for each probe
 * use_paris:   use 'paris ping' to avoid per-flow load balancing
 * weak_match:  don't consider IP ID's when matching ICMP responses to probes
 */
static char  *command      = NULL;
static int    pps          = SCAMPER_PPS_DEF;
static int    holdtime     = SCAMPER_HOLDTIME_DEF;
static int    daemon_port  = 0;
static char  *monitorname  = NULL;
static char **arglist      = NULL;
static int    arglist_len  = 0;
static int    window       = SCAMPER_WINDOW_DEF;
static char  *debugfile    = NULL;
static char  *matchfile    = NULL;
static char  *firewall     = NULL;
static int   use_tcp       = 0;
static int   checksum      = SCAMPER_CHECKSUM_DEF;

/* don't make these static: need in scamper_do_ping.c */
scamper_addr_t *g_gateway_sa = NULL;
int g_interface   = -1;
int g_debug_match = 0;  /* whether to write out probe-response info */
int g_simulate    = 0;
int g_use_paris   = 1;
int g_weak_match  = 0;

/*
 * parameters calculated by scamper at run time:
 *
 * wait_between:   calculated wait between probes to reach pps, in microseconds
 * probe_window:   maximum extension of probing window before truncation
 * exit_when_done: exit scamper when current window of tasks is completed
 */
static int    wait_between   = 1000000 / SCAMPER_PPS_DEF;
static int    probe_window   = 250000;
static int    exit_when_done = 1;

/* central cache of addresses that scamper is dealing with */
scamper_addrcache_t *addrcache = NULL;

static void usage_str(char c, char *str)
{
  fprintf(stderr, "            -%c %s\n", c, str);
  return;
}

static void version(void)
{
  fprintf(stderr, "mper version %s; client protocol version %d.%d\n",
          MPER_VERSION, CLIENT_PROTOCOL_MAJOR, CLIENT_PROTOCOL_MINOR);
  return;
}

static void usage(uint32_t opt_mask)
{
  char buf[256];

  fprintf(stderr,
    "usage: mper    [-?Pv] [-p pps] [-w window]\n"
    "               [-M monitorname] [-H holdtime]\n"
    "               [-F firewall] [-d debugfile] [-Z matchfile]\n"
    "               [-G gateway-address] [-I interface-name]\n"
    "               [-D port] [-T] [-S] [-K] [-k default-checksum] [-Y]\n");

  if(opt_mask == 0) return;

  fprintf(stderr, "\n");

  if((opt_mask & OPT_HELP) != 0)
    usage_str('?', "give an overview of the usage of mper");

  if((opt_mask & OPT_DEBUGFILE) != 0)
    usage_str('d', "write debugging information to the specified file");

  if((opt_mask & OPT_DAEMON) != 0)
    usage_str('D', "start as a daemon listening for commands on a port");

  if((opt_mask & OPT_FIREWALL) != 0)
    usage_str('F', "use the system firewall to install rules as necessary");

  if((opt_mask & OPT_GATEWAY) != 0)
    usage_str('G', "use a given gateway address rather than querying system");

  if((opt_mask & OPT_HOLDTIME) != 0)
    {
      (void)snprintf(buf, sizeof(buf),
		     "time to hold for delayed responses (%d < holdtime %d)",
		     SCAMPER_HOLDTIME_MIN, SCAMPER_HOLDTIME_MAX);

      usage_str('H', buf);
    }

  if((opt_mask & OPT_INTERFACE) != 0)
    usage_str('I', "use a given interface when manually setting gateway");

  if((opt_mask & OPT_PARIS) != 0)
    usage_str('K', "disable paris-ping mode");

  if((opt_mask & OPT_CHECKSUM) != 0)
    usage_str('k', "use given value for default probe checksum value");

  if((opt_mask & OPT_MONITORNAME) != 0)
    usage_str('M', "specify the canonical name of the monitor");

  if((opt_mask & OPT_PPS) != 0)
    {
      (void)snprintf(buf, sizeof(buf),
		     "number of packets per second to send (%d <= pps <= %d)",
		     SCAMPER_PPS_MIN, SCAMPER_PPS_MAX);

      usage_str('p', buf);
    }

  if((opt_mask & OPT_DL) != 0)
    usage_str('P', "use a datalink to get tx timestamps for outgoing probes");

  if((opt_mask & OPT_SIMULATE) != 0)
    usage_str('S', "don't actually probe--simulate a non-response for each probe");

  if((opt_mask & OPT_VERSION) != 0)
    usage_str('v', "output the version of mper this binary is");

  if((opt_mask & OPT_WINDOW) != 0)
    usage_str('w', "limit the window of actively probing tasks");

  if((opt_mask & OPT_WEAK_MATCH) != 0)
    usage_str('Y', "don't consider IP ID's when matching ICMP responses to probes");

  if((opt_mask & OPT_MATCHFILE) != 0)
    usage_str('Z', "write probe-response matching info to the specified file");

  return;
}

static int set_opt(uint32_t opt, char *str, int (*setfunc)(int))
{
  long l = 0;

  if(string_isnumber(str) == 0 || string_tolong(str, &l) == -1)
    {
      usage(opt);
      return -1;
    }

  return setfunc(l);
}

static int check_options(int argc, char *argv[])
{
  int   i;
  long  lo;
  char *opts = "d:D:F:G:H:I:Kk:M:p:PSTvw:YZ:?";
  char *opt_daemon = NULL, *opt_holdtime = NULL, *opt_monitorname = NULL;
  char *opt_checksum = NULL, *opt_pps = NULL, *opt_window = NULL;
  char *opt_debugfile = NULL, *opt_matchfile = NULL, *opt_firewall = NULL;
  char *opt_gateway = NULL, *opt_interface = NULL;

  while((i = getopt(argc, argv, opts)) != -1)
    {
      switch(i)
	{
	case 'd':
	  options |= OPT_DEBUGFILE;
	  opt_debugfile = optarg;
	  break;

	case 'D':
	  options |= OPT_DAEMON;
	  opt_daemon = optarg;
	  break;

	case 'F':
	  options |= OPT_FIREWALL;
	  opt_firewall = optarg;
	  break;

       case 'G':
          options |= OPT_GATEWAY;
          opt_gateway = optarg;
          break;

	case 'H':
	  options |= OPT_HOLDTIME;
	  opt_holdtime = optarg;
	  break;

       case 'I':
          options |= OPT_INTERFACE;
          opt_interface = optarg;
          break;

	case 'K':
	  options |= OPT_PARIS;
	  g_use_paris = 0;
	  break;

	case 'k':
	  options |= OPT_CHECKSUM;
	  opt_checksum = optarg;
	  break;

	case 'M':
	  options |= OPT_MONITORNAME;
	  opt_monitorname = optarg;
	  break;

	case 'p':
	  options |= OPT_PPS;
	  opt_pps = optarg;
	  break;

	case 'P':
	  options |= OPT_DL;
	  break;

	case 'S':
	  options |= OPT_SIMULATE;
	  g_simulate = 1;
	  break;

	case 'T':
	  options |= OPT_USE_TCP;
	  use_tcp = 1;
	  break;

	case 'v':
	  options |= OPT_VERSION;
	  break;

	case 'w':
	  options |= OPT_WINDOW;
	  opt_window = optarg;
	  break;

	case 'Y':
	  options |= OPT_WEAK_MATCH;
	  g_weak_match = 1;
	  break;

	case 'Z':
	  options |= OPT_MATCHFILE;
	  opt_matchfile = optarg;
	  g_debug_match = 1;
	  break;

	case '?':
	  options |= OPT_HELP;
	  usage(0xffffffff);
	  return -1;

	default:
	  printerror(errno, strerror, __func__,
		     "could not parse command line options");
	  return -1;
	}
    }

  if(options & OPT_VERSION)
    {
      version();
      return -1;
    }

  if(options & OPT_PPS && set_opt(OPT_PPS, opt_pps, scamper_pps_set) == -1)
    {
      usage(OPT_PPS);
      return -1;
    }

  if(options & OPT_WINDOW &&
     set_opt(OPT_WINDOW, opt_window, scamper_window_set) == -1)
    {
      usage(OPT_WINDOW);
      return -1;
    }

  if(options & OPT_FIREWALL && (firewall = strdup(opt_firewall)) == NULL)
    {
      printerror(errno, strerror, __func__, "could not strdup firewall");
      return -1;
    }


  if(options & OPT_GATEWAY)
    {
      if ((g_gateway_sa = scamper_addr_resolve(PF_INET, opt_gateway)) == NULL)
        {
	  fprintf(stderr, "invalid -G gateway value '%s'\n", opt_gateway);
	  return -1;
	}
    }
#if 0
  else
    {
      fprintf(stderr, "missing -G gateway option\n");
      return -1;
    }
#endif

  if(options & OPT_HOLDTIME &&
     set_opt(OPT_HOLDTIME, opt_holdtime, scamper_holdtime_set) == -1)
    {
      usage(OPT_HOLDTIME);
      return -1;
    }

  if(options & OPT_INTERFACE &&
     scamper_interface_set(opt_interface) == -1)
    {
      fprintf(stderr, "invalid -I interface value '%s'\n", opt_interface);
      usage(OPT_INTERFACE);
      return -1;
    }

  if(options & OPT_CHECKSUM &&
     set_opt(OPT_CHECKSUM, opt_checksum, scamper_checksum_set) == -1)
    {
      usage(OPT_CHECKSUM);
      return -1;
    }

  if(options & OPT_MONITORNAME &&
     (monitorname = strdup(opt_monitorname)) == NULL)
    {
      printerror(errno, strerror, __func__, "could not strdup monitorname");
      return -1;
    }

  if(options & OPT_DEBUGFILE && (debugfile = strdup(opt_debugfile)) == NULL)
    {
      printerror(errno, strerror, __func__, "could not strdup debugfile");
      return -1;
    }

  if(options & OPT_MATCHFILE && (matchfile = strdup(opt_matchfile)) == NULL)
    {
      printerror(errno, strerror, __func__, "could not strdup matchfile");
      return -1;
    }

  /* these are the left-over arguments */
  arglist     = argv + optind;
  arglist_len = argc - optind;

  if(options & OPT_DAEMON)
    {
      /* if started as daemon, there should be no leftover arguments */
      if(arglist_len != 0)
	{
	  usage(OPT_DAEMON);
	  return -1;
	}

      /* port on which to run the daemon */
      if(string_isnumber(opt_daemon) == 0 ||
	 string_tolong(opt_daemon, &lo) == -1 ||
	 lo < 1 || lo > 65535)
	{
	  usage(OPT_DAEMON);
	  return -1;
	}

      daemon_port = lo;
    }
  else
    {
      fprintf(stderr, "missing -D daemon port\n");
      usage(OPT_DAEMON);
      return -1;
    }

#ifdef _WIN32
  use_tcp = 1;  /* unix domain sockets not supported */
#endif

  return 0;
}

const char *scamper_command_get(void)
{
  assert(command != NULL);
  return command;
}

int scamper_command_set(const char *command_in)
{
  char *d;

  if(command_in == NULL)
    {
      return -1;
    }

  if((d = strdup(command_in)) == NULL)
    {
      printerror(errno, strerror, __func__, "could not strdup command");
      return -1;
    }

  if(command != NULL)
    free(command);

  command = d;
  return 0;
}

void scamper_exitwhendone(int on)
{
  if(on == 1 || on == 0)
    {
      exit_when_done = on;
    }
  return;
}

int scamper_holdtime_get()
{
  return holdtime;
}

int scamper_holdtime_set(const int ht)
{
  if(ht >= SCAMPER_HOLDTIME_MIN && ht <= SCAMPER_HOLDTIME_MAX)
    {
      holdtime = ht;
      return 0;
    }

  return -1;
}

int scamper_interface_set(const char *interface)
{
  /* attempt to resolve the interface index from the name */
  if((g_interface = if_nametoindex(interface)) == 0)
    {
      scamper_debug(__func__, 
		    "could not resolve index for %s", interface);
      return -1;
    }
  return 0;
}

int scamper_checksum_get()
{
  return checksum;
}

int scamper_checksum_set(const int c)
{
  if(c >= SCAMPER_CHECKSUM_MIN && c <= SCAMPER_CHECKSUM_MAX)
    {
      checksum = c;
      return 0;
    }

  return -1;
}

int scamper_pps_get()
{
  return pps;
}

int scamper_pps_set(const int p)
{
  if(p >= SCAMPER_PPS_MIN && p <= SCAMPER_PPS_MAX)
    {
      /*
       * reset the pps scamper is operating at.  re-calculate the inter-probe
       * delay, and the maximum size of the probe window.
       */

      pps = p;
      wait_between = 1000000 / pps;
      probe_window = (wait_between < 250000 ? 250000 : wait_between + 250000);

      return 0;
    }

  return -1;
}

int scamper_window_get()
{
  return window;
}

int scamper_window_set(const int w)
{
  if(w >= SCAMPER_WINDOW_MIN && w <= SCAMPER_WINDOW_MAX)
    {
      window = w;
      return 0;
    }

  return -1;
}

const char *scamper_monitorname_get()
{
  return monitorname;
}

int scamper_monitorname_set(const char *mn)
{
  char *tmp;

  /*
   * before removing the old monitor name, get a copy of the monitor name
   * since that's what we'll be using to store afterward
   */
  if(mn != NULL)
    {
      if((tmp = strdup(mn)) == NULL)
	{
	  return -1;
	}
    }
  else
    {
      tmp = NULL;
    }

  if(monitorname != NULL)
    {
      free(monitorname);
    }

  monitorname = tmp;
  return 0;
}

int scamper_option_dl()
{
  if(options & OPT_DL) return 1;
  return 0;
}

#ifndef _WIN32
static void scamper_hup(int sig)
{
  if(sig != SIGHUP)
    return;

  return;
}

static void scamper_chld(int sig)
{
  int status;

  if(sig != SIGCHLD)
    return;

  for(;;)
    {
      if(waitpid(-1, &status, WNOHANG) == -1)
	{
	  break;
	}
    }

  return;
}
#endif

/*
 * scamper:
 * this bit of code contains most of the logic for driving the parallel
 * traceroute process.
 */
static int scamper(int argc, char *argv[])
{
  struct timeval           tv;
  struct timeval           lastprobe;
  struct timeval           nextprobe;
  struct timeval          *timeout;
  scamper_task_t          *task;

  gettimeofday_wrap(&lastprobe);

#ifndef _WIN32
  srandom(lastprobe.tv_usec);
#endif

  if(check_options(argc, argv) == -1)
    {
      return -1;
    }

  /*
   * this has to be done before priviledge separation, as if scamper is
   * running on a BPF system it has to open a BPF fd to establish
   * version compatibility
   */
  if(scamper_dl_init() == -1)
    {
      return -1;
    }

#ifndef WITHOUT_PRIVSEP
  /* revoke the root priviledges we started with */
  if(scamper_privsep_init() == -1)
    {
      return -1;
    }
#endif

  if(scamper_firewall_init(firewall) != 0)
    {
      return -1;
    }

#ifndef WITHOUT_DEBUGFILE
  /*
   * open the debug file immediately so initialisation debugging information
   * makes it to the file
   */
  if(debugfile != NULL && scamper_debug_open(debugfile) != 0)
    {
      return -1;
    }
#endif

  if(matchfile != NULL && scamper_debug_match_open(matchfile) != 0)
    {
      return -1;
    }

  /* allocate the cache of addresses for scamper to keep track of */
  if((addrcache = scamper_addrcache_alloc()) == NULL)
    {
      return -1;
    }

  /* setup the file descriptor monitoring code */
  if(scamper_fds_init() == -1)
    {
      return -1;
    }

  /*
   * if we have been told to open a control socket and daemonise, then do
   * that now.
   */
  if(options & OPT_DAEMON)
    {
      if(scamper_control_init(daemon_port, use_tcp) == -1)
	{
	  return -1;
	}

      /*
       * scamper should wait for more tasks when it has finished with the
       * active window
       */
      exit_when_done = 0;
    }

  /* initialise the subsystem responsible for obtaining source addresses */
  if(scamper_getsrc_init() == -1)
    {
      return -1;
    }

  /* initialise the subsystem responsible for recording mac addresses */
  if(scamper_addr2mac_init() == -1)
    {
      return -1;
    }

  if(scamper_rtsock_init() == -1)
    {
      return -1;
    }

  /* initialise the structures necessary to keep track of addresses to probe */
  if(scamper_sources_init() == -1)
    {
      return -1;
    }

  /*
   * initialise the data structures necessary to keep track of target
   * addresses currently being probed
   */
  if(scamper_targets_init() == -1)
    {
      return -1;
    }

  /* initialise the queues that hold the current tasks */
  if(scamper_queue_init() == -1)
    {
      return -1;
    }

  /* initialise scamper so it is ready to traceroute and ping */
  if(scamper_do_ping_init() != 0)
    {
      return -1;
    }

  for(;;)
    {
      if(scamper_queue_readycount() > 0 || scamper_sources_isready() == 1)
	{
	  /*
	   * if there is something ready to be probed right now, then set the
	   * timeout to go off when it is time to send the next probe
	   */
	  timeval_add_us(&nextprobe, &lastprobe, wait_between);
	  timeout = &tv;
	}
      else if(scamper_queue_count() > 0)
	{
	  /*
	   * if there isn't anything ready to go right now, but we are
	   * waiting on a response from an earlier probe, then set the timer
	   * to go off when that probe expires.
	   */
	  scamper_queue_waittime(&nextprobe);
	  timeout = &tv;
	}
      else
	{
	  /*
	   * there is nothing to do, so block in select until a file
	   * descriptor supplies an address to probe.
	   */
	  timeout = NULL;
	}

      if(timeout != NULL)
	{
	  /*
	   * we've been told to calculate a timeout value.  figure out what
	   * it should be.
	   */
	  gettimeofday_wrap(&tv);
	  if(timeval_cmp(&nextprobe, &tv) <= 0)
	    memset(&tv, 0, sizeof(tv));
	  else
	    timeval_diff_tv(&tv, &tv, &nextprobe);
	}
      else
	{
	  if(exit_when_done != 0 && scamper_sources_isempty() == 1)
	    {
	      break;
	    }
	  timeout = NULL;
	}

      /* listen until it is time to send the next probe */
      if(scamper_fds_poll(timeout) == -1)
	{
	  return -1;
	}

      /* get the current time */
      gettimeofday_wrap(&tv);

      /* take any 'done' traces and output them now */
      while((task = scamper_queue_getdone(&tv)) != NULL)
	{
	  /* write the trace out */
	  task->funcs->write(task);

	  /* cleanup the task */
	  scamper_task_free(task);
	}

      /*
       * if there is something waiting to be probed, then find out if it is
       * time to probe yet
       */
      if(scamper_queue_readycount() > 0 || scamper_sources_isready() == 1)
	{
	  /*
	   * check for large differences between the time the last probe
	   * was sent and the current time.  don't allow the difference to
	   * be larger than a particular amount, since that could result in
	   * either a large flutter of probes to be sent, or a large time
	   * before the next probe is sent
	   */
	  if(timeval_inrange_us(&tv, &lastprobe, probe_window) == 0)
	    {
	      timeval_sub_us(&lastprobe, &tv, wait_between);
	    }

	  /*
	   * when probing at > HZ, scamper might find that select blocks it
	   * from achieving the specified packets per second rate if it sends
	   * one probe per select.  Based on the time spent in the last call
	   * to select, send the necessary number of packets to fill that
	   * window where we sent no packets.
	   */
	  for(;;)
	    {
	      timeval_add_us(&nextprobe, &lastprobe, wait_between);

	      /* if the next probe is not due to be sent, don't send one */
	      if(timeval_cmp(&nextprobe, &tv) > 0)
		{
		  break;
		}

	      /*
	       * look for an address that we can send a probe to.  if
	       * scamper doesn't have a task on the probe queue waiting
	       * to be probed, then get a fresh task. if there's absolutely
	       * nothing that scamper can probe, then break.
	       */
	      if((task = scamper_queue_select()) == NULL)
		{
		  /*
		   * if we are already probing to the window limit, don't
		   * add any new tasks
		   */
		  if(window != 0 && scamper_queue_windowcount() >= window)
		    {
		      break;
		    }

		  /*
		   * if there are no more tasks ready to be added yet, there's
		   * nothing more to be done in the loop
		   */
		  if(scamper_sources_gettask(&task) != 0 || task == NULL)
		    {
		      break;
		    }
		}

	      task->funcs->probe(task);
	      timeval_cpy(&lastprobe, &nextprobe);
	    }
	}
    }
  
  return 0; 
}

/*
 * cleanup:
 *
 * be nice to the system and clean up all our mallocs
 */
static void cleanup(void)
{
#ifndef WITHOUT_PRIVSEP
  scamper_privsep_cleanup();
#endif
  scamper_getsrc_cleanup();
  scamper_rtsock_cleanup();

  scamper_icmp4_cleanup();
  scamper_icmp6_cleanup();
  scamper_udp4_cleanup();

  scamper_addr2mac_cleanup();

  scamper_do_ping_cleanup();

  scamper_sources_cleanup();

  scamper_dl_cleanup();

  scamper_firewall_cleanup();

  if(options & OPT_DAEMON)
    {
      scamper_control_cleanup();
    }

  scamper_fds_cleanup();

  /* free the address cache, if one was used */
  if(addrcache != NULL)
    {
      scamper_addrcache_free(addrcache);
      addrcache = NULL;
    }

  if(monitorname != NULL)
    {
      free(monitorname);
      monitorname = NULL;
    }

  if(command != NULL)
    {
      free(command);
      command = NULL;
    }
  scamper_queue_cleanup();
  scamper_targets_cleanup();
  scamper_probe_cleanup();

#ifndef WITHOUT_DEBUGFILE
  if(options & OPT_DEBUGFILE)
    {
      scamper_debug_close();
    }
#endif

  if(debugfile != NULL)
    {
      free(debugfile);
      debugfile = NULL;
    }

  if(options & OPT_MATCHFILE)
    {
      scamper_debug_match_close();
    }

  if(matchfile != NULL)
    {
      free(matchfile);
      matchfile = NULL;
    }

  return;
}


int main(int argc, char *argv[])
{
  int i;

#ifndef _WIN32
  struct sigaction si_sa;
#endif

#ifdef _WIN32
  WSADATA wsaData;
#endif

  /*
   * if we are using dmalloc, then we want to get it to register its
   * logdump function to occur after we have used cleanup to free up
   * scamper's core data structures.  this is a dirty hack.
   */
#if defined(DMALLOC)
  free(malloc(1));
#endif

#ifdef _WIN32
  WSAStartup(MAKEWORD(2,2), &wsaData);
#endif

#ifndef _WIN32
  sigemptyset(&si_sa.sa_mask);
  si_sa.sa_flags   = 0;
  si_sa.sa_handler = scamper_hup;
  if(sigaction(SIGHUP, &si_sa, 0) == -1)
    {
      printerror(errno, strerror, __func__,
		 "could not set sigaction for SIGHUP");
      return -1;
    }

  sigemptyset(&si_sa.sa_mask);
  si_sa.sa_flags   = 0;
  si_sa.sa_handler = scamper_chld;
  if(sigaction(SIGCHLD, &si_sa, 0) == -1)
    {
      printerror(errno, strerror, __func__,
		 "could not set sigaction for SIGCHLD");
      return -1;
    }
#endif

  i = scamper(argc, argv);

  cleanup();

#ifdef _WIN32
  WSACleanup();
#endif

  return i;
}

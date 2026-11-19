/*
 * fuzz_vrrp_packet — VRRP advertisement receive path.
 *
 * Entry: vrrp_dispatcher_read(sock_t *), the daemon's own receive routine (recvmsg loop ->
 * vrrp_get_header -> VRID lookup -> vrrp_state_backup -> vrrp_check_packet: VRRPv2/v3, IPv4/IPv6,
 * PASS and IPSEC-AH authentication, unicast peers, checksum and VIP checks).  It is static in
 * vrrp_scheduler.c, so that file is compiled into this harness (the archive copy is then not
 * linked).
 *
 * Setup (once): the fixed configuration below is parsed by keepalived's parser; the socket pool is
 * built by vrrp_dispatcher_init() exactly as at daemon start, and each pool socket's receive fd is
 * replaced by one end of an AF_UNIX datagram socketpair.  All instances are BACKUP + nopreempt, so
 * receiving an advert never makes the instance take over (no addresses/ARP are touched).
 *
 * Input: byte 0 selects the socket (instance group); the rest is one datagram exactly as the raw
 * socket would deliver it (IPv4: IP header + [AH] + VRRP; IPv6: VRRP only).  The IPv6 instance is
 * unicast: an AF_UNIX socket cannot carry the IPV6_PKTINFO control message that marks multicast.
 *
 * Per-input state: every vrrp_t, its stats and every pool sock_t (whose timer tree links the
 * vrrp_t's) are restored from a snapshot taken after setup, so an input's result depends only on
 * that input.  The parsed configuration, interface list and global_data are read-only here.
 */
#include "vrrp_scheduler.c"

#include <sys/socket.h>
#include <fcntl.h>
#include "fuzz_common.h"

static const char config[] =
"global_defs {\n"
"  dynamic_interfaces\n"
"  log_unknown_vrids\n"
"}\n"
"vrrp_instance V2_PASS {\n"
"  state BACKUP\n  interface fz0\n  virtual_router_id 51\n  priority 100\n  nopreempt\n"
"  advert_int 1\n  version 2\n"
"  authentication {\n    auth_type PASS\n    auth_pass s3cr3tpw\n  }\n"
"  virtual_ipaddress {\n    192.168.200.16\n    192.168.200.17/24\n  }\n"
"}\n"
"vrrp_instance V3_v4 {\n"
"  state BACKUP\n  interface fz0\n  virtual_router_id 52\n  priority 100\n  nopreempt\n"
"  advert_int 1\n  version 3\n"
"  virtual_ipaddress {\n    192.168.201.1\n    192.168.201.2\n    192.168.201.3\n  }\n"
"}\n"
"vrrp_instance V2_NOAUTH {\n"
"  state BACKUP\n  interface fz0\n  virtual_router_id 50\n  priority 100\n  nopreempt\n"
"  advert_int 2\n  version 2\n"
"  virtual_ipaddress {\n    192.168.199.1\n  }\n"
"}\n"
"vrrp_instance V2_AH {\n"
"  state BACKUP\n  interface fz0\n  virtual_router_id 53\n  priority 100\n  nopreempt\n"
"  advert_int 1\n  version 2\n"
"  authentication {\n    auth_type AH\n    auth_pass ahsecret\n  }\n"
"  virtual_ipaddress {\n    192.168.202.1\n  }\n"
"}\n"
"vrrp_instance V3_UNICAST {\n"
"  state BACKUP\n  interface fz0\n  virtual_router_id 54\n  priority 100\n  nopreempt\n"
"  advert_int 1\n  version 3\n"
"  unicast_src_ip 10.0.0.1\n"
"  unicast_peer {\n    10.0.0.2\n    10.0.0.3\n  }\n"
"  virtual_ipaddress {\n    192.168.203.1\n  }\n"
"}\n"
"vrrp_instance V3_v6 {\n"
"  state BACKUP\n  interface fz0\n  virtual_router_id 55\n  priority 100\n  nopreempt\n"
"  advert_int 1\n  version 3\n"
"  unicast_src_ip 2001:db8::1\n"
"  unicast_peer {\n    2001:db8::2\n  }\n"
"  virtual_ipaddress {\n    fe80::55\n    2001:db8::55\n  }\n"
"}\n";

#define MAX_SOCKS 16
#define MAX_VRRP 32

static sock_t *socks[MAX_SOCKS];
static sock_t sock_snap[MAX_SOCKS];
static int peer_fd[MAX_SOCKS];
static unsigned n_socks;

static vrrp_t *vrrps[MAX_VRRP];
static vrrp_t vrrp_snap[MAX_VRRP];
static vrrp_stats vrrp_stats_snap[MAX_VRRP];
static unsigned n_vrrp;

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int
LLVMFuzzerInitialize(__attribute__((unused)) int *argc, __attribute__((unused)) char ***argv)
{
	char *conf;
	sock_t *sock;
	vrrp_t *vrrp;
	int sv[2];

	prog_type = PROG_TYPE_VRRP;
	fuzz_setup_logging();
	conf = fuzz_write_tmp("ka_vrrp_conf", config, sizeof(config) - 1);

	master = thread_make_master();
	fuzz_parse_vrrp_config(conf);
	unlink(conf);
	free(conf);
	set_time_now();

	if (!vrrp_complete_init()) {
		fprintf(stderr, "fuzz_vrrp_packet: vrrp_complete_init failed\n");
		abort();
	}

	vrrp_dispatcher_init(NULL);

	list_for_each_entry(sock, &vrrp_data->vrrp_socket_pool, e_list) {
		if (n_socks == MAX_SOCKS)
			break;
		if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv))
			abort();
		fcntl(sv[0], F_SETFL, O_NONBLOCK);
		if (sock->fd_in >= 0)
			close(sock->fd_in);
		sock->fd_in = sv[0];
		peer_fd[n_socks] = sv[1];
		socks[n_socks++] = sock;
	}

	list_for_each_entry(vrrp, &vrrp_data->vrrp, e_list) {
		if (n_vrrp == MAX_VRRP)
			break;
		/* what vrrp_state_become_backup() leaves behind, without touching addresses */
		vrrp->state = VRRP_STATE_BACK;
		vrrp->wantstate = VRRP_STATE_BACK;
		vrrp->ms_down_timer = VRRP_MS_DOWN_TIMER(vrrp);
		vrrp_init_instance_sands(vrrp);
		vrrps[n_vrrp] = vrrp;
		vrrp_snap[n_vrrp] = *vrrp;
		vrrp_stats_snap[n_vrrp] = *vrrp->stats;
		n_vrrp++;
	}

	for (unsigned i = 0; i < n_socks; i++)
		sock_snap[i] = *socks[i];

	if (!n_socks || !n_vrrp) {
		fprintf(stderr, "fuzz_vrrp_packet: no sockets/instances configured\n");
		abort();
	}

	return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	unsigned i, s;
	char drain[1];

	if (size < 1)
		return -1;

	for (i = 0; i < n_vrrp; i++) {
		*vrrps[i] = vrrp_snap[i];
		*vrrps[i]->stats = vrrp_stats_snap[i];
	}
	/* the per-socket timer tree links nodes inside the vrrp_t's restored above */
	for (i = 0; i < n_socks; i++)
		*socks[i] = sock_snap[i];
	set_time_now();

	s = data[0] % n_socks;
	if (send(peer_fd[s], data + 1, size - 1, MSG_DONTWAIT) < 0)
		return -1;	/* larger than an AF_UNIX datagram can carry */

	vrrp_dispatcher_read(socks[s]);

	/* never leave a datagram behind for the next input */
	while (recv(socks[s]->fd_in, drain, sizeof(drain), MSG_DONTWAIT | MSG_TRUNC) >= 0)
		;

	return 0;
}

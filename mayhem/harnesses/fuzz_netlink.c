/*
 * fuzz_netlink — rtnetlink messages received from the kernel by the VRRP process.
 *
 * Entry: kernel_netlink_poll(), the public routine that drains the kernel reflection channel
 * (nl_kernel) through netlink_parse_info() + netlink_broadcast_filter(): RTM_NEWLINK/DELLINK
 * (netlink_link_filter, IFLA_* incl. IFLA_AF_SPEC/IFLA_INET_CONF, IFLA_BROADCAST, VMAC/linkinfo),
 * RTM_NEWADDR/DELADDR (netlink_if_address_filter), RTM_NEWROUTE/DELROUTE (netlink_route_filter) and
 * RTM_NEWRULE/DELRULE (netlink_rule_filter), plus the resulting interface/VRRP state updates.
 *
 * nl_kernel is static in keepalived_netlink.c, so that file is compiled into this harness (the
 * archive copy is then not linked) and nl_kernel.fd is pointed at one end of an AF_UNIX datagram
 * socketpair.  recvmsg() is wrapped (libc only, -Wl,--wrap=recvmsg) to report the sender as the
 * kernel (a sockaddr_nl with nl_pid 0), which is what a real NETLINK_ROUTE socket reports.
 *
 * Input: a stream of datagrams, each `u16 little-endian length` + that many bytes of nlmsghdr
 * stream, delivered on the socket in order before kernel_netlink_poll() runs.
 *
 * Per-input state: the daemon is rebuilt from the fixed configuration for every input (config
 * parse, vrrp_complete_init, socket pool) and torn down afterwards, so the interface list and the
 * VRRP instances an input mutates never leak into the next input.
 */
#include "keepalived_netlink.c"

#include <sys/socket.h>
#include <fcntl.h>
#include "vrrp_scheduler.h"
#include "fuzz_common.h"

static const char config[] =
"global_defs {\n"
"  dynamic_interfaces allow_if_changes\n"
"}\n"
"static_ipaddress {\n"
"  10.1.1.1/24 dev fz0\n"
"}\n"
"static_routes {\n"
"  10.30.0.0/16 via 10.1.1.254 dev fz0\n"
"}\n"
"static_rules {\n"
"  from 10.1.1.0/24 table 200\n"
"}\n"
"vrrp_instance VI_4 {\n"
"  state BACKUP\n  interface fz0\n  virtual_router_id 61\n  priority 100\n  advert_int 1\n"
"  track_interface {\n    fz1 weight 10\n  }\n"
"  virtual_ipaddress {\n    192.168.210.1/24 dev fz0\n    192.168.211.1/24 dev fz1\n  }\n"
"  virtual_routes {\n    10.20.0.0/16 via 192.168.210.254 dev fz0\n  }\n"
"  virtual_rules {\n    from 192.168.210.0/24 table 100\n  }\n"
"}\n"
"vrrp_instance VI_6 {\n"
"  state BACKUP\n  interface fz1\n  virtual_router_id 62\n  priority 100\n  advert_int 1\n"
"  virtual_ipaddress {\n    2001:db8:1::1/64\n  }\n"
"  virtual_routes {\n    2001:db8:2::/64 via 2001:db8:1::fe dev fz1\n  }\n"
"}\n";

static char *conf;
static int fuzz_fd = -1, peer_fd = -1;

ssize_t __real_recvmsg(int fd, struct msghdr *msg, int flags);
ssize_t __wrap_recvmsg(int fd, struct msghdr *msg, int flags);

ssize_t
__wrap_recvmsg(int fd, struct msghdr *msg, int flags)
{
	socklen_t namelen = msg->msg_namelen;	/* the caller's buffer size; recvmsg() overwrites it */
	ssize_t ret = __real_recvmsg(fd, msg, flags);

	if (ret >= 0 && fd == fuzz_fd && msg->msg_name && namelen >= sizeof(struct sockaddr_nl)) {
		struct sockaddr_nl *snl = msg->msg_name;

		memset(snl, 0, sizeof(*snl));
		snl->nl_family = AF_NETLINK;
		snl->nl_pid = 0;
		msg->msg_namelen = sizeof(*snl);
	}
	return ret;
}

/*
 * Input precondition, from the sender's contract: every RTM_NEWLINK/RTM_DELLINK the kernel sends is
 * built by rtnl_fill_ifinfo() (net/core/rtnetlink.c), which always emits IFLA_MTU and IFLA_GROUP,
 * and netlink_if_link_populate() relies on that (it dereferences both unconditionally).  The
 * nl_pid == 0 check in netlink_parse_info() is what makes the kernel the only sender, so a link
 * message without them is not a message keepalived can receive.  Such inputs are rejected (-1);
 * attribute *lengths* and every other attribute stay fuzzer-controlled.
 */
static bool
link_msgs_have_kernel_attrs(const uint8_t *buf, size_t len)
{
	const struct nlmsghdr *h;
	size_t rem = len;

	for (h = (const struct nlmsghdr *)buf; NLMSG_OK(h, rem); h = NLMSG_NEXT(h, rem)) {
		const struct rtattr *rta;
		size_t alen;
		bool mtu = false, group = false;

		if (h->nlmsg_type == NLMSG_DONE)
			break;
		if (h->nlmsg_type != RTM_NEWLINK && h->nlmsg_type != RTM_DELLINK)
			continue;
		if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct ifinfomsg)))
			continue;
		alen = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg));
		for (rta = IFLA_RTA((const struct ifinfomsg *)NLMSG_DATA(h)); RTA_OK(rta, alen); rta = RTA_NEXT(rta, alen)) {
			if (rta->rta_type == IFLA_MTU)
				mtu = true;
			else if (rta->rta_type == IFLA_GROUP)
				group = true;
		}
		if (!mtu || !group)
			return false;
	}
	return true;
}

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int
LLVMFuzzerInitialize(__attribute__((unused)) int *argc, __attribute__((unused)) char ***argv)
{
	int sv[2];

	prog_type = PROG_TYPE_VRRP;
	fuzz_setup_logging();
	conf = fuzz_write_conf("ka_netlink_conf", config, sizeof(config) - 1);

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv))
		abort();
	fcntl(sv[0], F_SETFL, O_NONBLOCK);
	fcntl(sv[1], F_SETFL, O_NONBLOCK);
	fuzz_fd = sv[0];
	peer_fd = sv[1];
	return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char drain[1];
	size_t off = 0;
	uint8_t *dgram = NULL;

	/* validate the precondition on each datagram before building any state */
	while (off + 2 <= size) {
		size_t len = data[off] | (size_t)data[off + 1] << 8;

		off += 2;
		if (len > size - off)
			len = size - off;
		/* aligned copy, as the kernel's receive buffer would be */
		free(dgram);
		dgram = malloc(len + 1);
		memcpy(dgram, data + off, len);
		if (!link_msgs_have_kernel_attrs(dgram, len)) {
			free(dgram);
			return -1;
		}
		off += len;
	}
	free(dgram);
	off = 0;

	master = thread_make_master();
	fuzz_parse_vrrp_config(conf);
	set_time_now();
	if (!vrrp_complete_init()) {
		fprintf(stderr, "fuzz_netlink: vrrp_complete_init failed\n");
		abort();
	}
	vrrp_dispatcher_init(NULL);

	/* queue the datagrams, in order */
	while (off + 2 <= size) {
		size_t len = data[off] | (size_t)data[off + 1] << 8;

		off += 2;
		if (len > size - off)
			len = size - off;
		if (len && send(peer_fd, data + off, len, MSG_DONTWAIT) < 0)
			break;
		off += len;
	}

	nl_kernel.fd = fuzz_fd;
	kernel_netlink_poll();
	nl_kernel.fd = -1;

	while (recv(fuzz_fd, drain, sizeof(drain), MSG_DONTWAIT | MSG_TRUNC) >= 0)
		;

	/* tear down as vrrp_terminate_phase2() / a reload does */
	vrrp_dispatcher_release(vrrp_data);
	thread_destroy_master(master);
	master = NULL;
	free_vrrp_data(&vrrp_data);
	free_interface_queue();
	INIT_LIST_HEAD(get_interface_queue());	/* free_interface_queue() is exit-time: it leaves the head dangling */
	free_global_data(&global_data);

	return 0;
}

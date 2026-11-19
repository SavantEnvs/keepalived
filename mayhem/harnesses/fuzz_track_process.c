/*
 * fuzz_track_process — the /proc scan behind vrrp_track_process.
 *
 * Entry: reload_track_processes(), the public routine the VRRP process runs to (re)build its view
 * of running processes: read_procs() walks /proc, reads each /proc/<pid>/cmdline and
 * /proc/<pid>/stat (any local user controls a process's comm and argv, so these contents are
 * untrusted), parses the "(comm) state" fields, matches names/parameters against the configured
 * vrrp_track_process entries (exact / initial / partial param_match) and updates quorum, weights
 * and the tracking VRRP instances.
 *
 * read_procs() hard-codes "/proc", so libc opendir()/open() are wrapped (-Wl,--wrap=opendir,
 * --wrap=open; environment mocking only) to send "/proc" and "/proc/..." to a private scratch
 * directory the harness fills from the input.  free_process_tree() is static, so
 * track_process.c is compiled into this harness (the archive copy is then not linked).
 *
 * Input: up to 64 records, each `u8 pid, u8 stat_len, stat bytes, u8 cmdline_len, cmdline bytes`,
 * written as <scratch>/<pid>/stat and <scratch>/<pid>/cmdline (pid 0 is mapped to 1).
 *
 * Per-input state: the fake /proc is emptied, and the daemon is rebuilt from the fixed
 * configuration and torn down (process tree included) for every input.
 */
#include "track_process.c"

#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include "vrrp_scheduler.h"
#include "fuzz_common.h"

static const char config[] =
"global_defs {\n"
"  dynamic_interfaces\n"
"}\n"
"vrrp_track_process TP_COMM {\n"
"  process nginx\n  weight 10\n  quorum 1\n"
"}\n"
"vrrp_track_process TP_TWO {\n"
"  process sshd\n  quorum 2\n  weight 5 reverse\n"
"}\n"
"vrrp_track_process TP_EXACT {\n"
"  process /usr/sbin/httpd -k start\n  weight 20\n"
"}\n"
"vrrp_track_process TP_PARTIAL {\n"
"  process /usr/bin/python3 -m server\n  param_match partial\n"
"}\n"
"vrrp_track_process TP_INITIAL {\n"
"  process /opt/app/bin/worker --id\n  param_match initial\n"
"}\n"
"vrrp_instance VI_1 {\n"
"  state BACKUP\n  interface fz0\n  virtual_router_id 71\n  priority 100\n  advert_int 1\n"
"  track_process {\n    TP_COMM\n    TP_TWO\n    TP_EXACT\n    TP_PARTIAL weight 30\n    TP_INITIAL\n  }\n"
"  virtual_ipaddress {\n    192.168.220.1\n  }\n"
"}\n";

static char *conf;
static char proc_root[PATH_MAX];
static size_t proc_root_len;

DIR *__real_opendir(const char *name);
DIR *__wrap_opendir(const char *name);
int __real_open(const char *path, int flags, ...);
int __wrap_open(const char *path, int flags, ...);

DIR *
__wrap_opendir(const char *name)
{
	if (proc_root_len && !strcmp(name, "/proc"))
		return __real_opendir(proc_root);
	return __real_opendir(name);
}

int
__wrap_open(const char *path, int flags, ...)
{
	char buf[PATH_MAX];
	mode_t mode = 0;

	if (flags & (O_CREAT | O_TMPFILE)) {
		va_list ap;

		va_start(ap, flags);
		mode = (mode_t)va_arg(ap, int);
		va_end(ap);
	}
	if (proc_root_len && !strncmp(path, "/proc/", 6) &&
	    snprintf(buf, sizeof(buf), "%s/%s", proc_root, path + 6) < (int)sizeof(buf))
		return __real_open(buf, flags, mode);
	return __real_open(path, flags, mode);
}

static void
put_file(unsigned pid, const char *name, const uint8_t *data, size_t len)
{
	char path[PATH_MAX];
	int fd;

	snprintf(path, sizeof(path), "%s/%u", proc_root, pid);
	mkdir(path, 0700);
	snprintf(path, sizeof(path), "%s/%u/%s", proc_root, pid, name);
	fd = __real_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		abort();
	if (len && write(fd, data, len) != (ssize_t)len)
		abort();
	close(fd);
}

static void
clear_proc_root(void)
{
	char path[PATH_MAX];
	struct dirent *ent;
	DIR *d = __real_opendir(proc_root);

	if (!d)
		abort();
	while ((ent = readdir(d))) {
		if (ent->d_name[0] == '.')
			continue;
		snprintf(path, sizeof(path), "%s/%s/stat", proc_root, ent->d_name);
		unlink(path);
		snprintf(path, sizeof(path), "%s/%s/cmdline", proc_root, ent->d_name);
		unlink(path);
		snprintf(path, sizeof(path), "%s/%s", proc_root, ent->d_name);
		rmdir(path);
	}
	closedir(d);
}

static void
remove_proc_root(void)
{
	clear_proc_root();
	rmdir(proc_root);
}

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int
LLVMFuzzerInitialize(__attribute__((unused)) int *argc, __attribute__((unused)) char ***argv)
{
	const char *dir = getenv("TMPDIR");

	prog_type = PROG_TYPE_VRRP;
	fuzz_setup_logging();
	conf = fuzz_write_conf("ka_track_process_conf", config, sizeof(config) - 1);

	if (!dir || !*dir)
		dir = "/tmp";
	snprintf(proc_root, sizeof(proc_root), "%s/ka_fake_procXXXXXX", dir);
	if (!mkdtemp(proc_root))
		abort();
	proc_root_len = strlen(proc_root);
	atexit(remove_proc_root);
	return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	size_t off = 0;
	unsigned n;

	clear_proc_root();
	for (n = 0; n < 64 && off + 3 <= size; n++) {
		unsigned pid = data[off] ? data[off] : 1;
		size_t slen = data[off + 1], clen;

		off += 2;
		if (slen > size - off)
			slen = size - off;
		put_file(pid, "stat", data + off, slen);
		off += slen;
		if (off >= size)
			break;
		clen = data[off++];
		if (clen > size - off)
			clen = size - off;
		put_file(pid, "cmdline", data + off, clen);
		off += clen;
	}

	master = thread_make_master();
	fuzz_parse_vrrp_config(conf);
	set_time_now();
	if (!vrrp_complete_init()) {
		fprintf(stderr, "fuzz_track_process: vrrp_complete_init failed\n");
		abort();
	}
	vrrp_dispatcher_init(NULL);

	reload_track_processes();

	/* tear down: the process tree refers to the tracked processes in vrrp_data */
	free_process_tree();
	vrrp_dispatcher_release(vrrp_data);
	thread_destroy_master(master);
	master = NULL;
	read_thread = NULL;
	free_vrrp_data(&vrrp_data);
	free_interface_queue();
	INIT_LIST_HEAD(get_interface_queue());	/* free_interface_queue() is exit-time: it leaves the head dangling */
	free_global_data(&global_data);

	return 0;
}

/*
 * Shared helpers for the keepalived in-process harnesses.
 *
 * The daemon is configured exactly as it is at startup: a fixed configuration file is written to
 * a private scratch file and parsed by keepalived's own config parser (init_data() with the VRRP
 * keyword tables), then completed with vrrp_complete_init().  Interfaces are "dynamic"
 * (global_defs dynamic_interfaces) so no real NIC is needed.
 */
#ifndef KA_FUZZ_COMMON_H
#define KA_FUZZ_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char *fuzz_tmp_conf;

static void
fuzz_remove_tmp_conf(void)
{
	if (fuzz_tmp_conf)
		unlink(fuzz_tmp_conf);
}

/* Write the harness's fixed configuration to a private scratch file, removed at exit. */
static char *
fuzz_write_conf(const char *prefix, const char *text, size_t len);

static char *
fuzz_write_tmp(const char *prefix, const void *data, size_t len)
{
	const char *dir = getenv("TMPDIR");
	char *path;
	int fd;

	if (!dir || !*dir)
		dir = "/tmp";
	if (asprintf(&path, "%s/%sXXXXXX", dir, prefix) < 0)
		abort();
	fd = mkstemp(path);
	if (fd < 0)
		abort();
	if (len && write(fd, data, len) != (ssize_t)len)
		abort();
	close(fd);
	return path;
}

static char *
fuzz_write_conf(const char *prefix, const char *text, size_t len)
{
	fuzz_tmp_conf = fuzz_write_tmp(prefix, text, len);
	atexit(fuzz_remove_tmp_conf);
	return fuzz_tmp_conf;
}

#include "bitops.h"
#include "logger.h"
#include "main.h"

/* KA_FUZZ_LOG=1 sends keepalived's log_message() output to stderr (debugging only). */
static void
fuzz_setup_logging(void)
{
	if (getenv("KA_FUZZ_LOG")) {
		__set_bit(DONT_FORK_BIT, &debug);
		__set_bit(LOG_CONSOLE_BIT, &debug);
		__set_bit(LOG_DETAIL_BIT, &debug);
		enable_console_log();
	}
}

#include "parser.h"
#include "global_parser.h"
#include "global_data.h"
#include "vrrp_parser.h"
#include "vrrp_data.h"
#include "check_parser.h"
#include "bfd_parser.h"
#include "track_file.h"

/* The parent process's keyword table (keepalived/core/main.c global_init_keywords(), static there):
 * global_defs active, every other section parsed but inactive. */
static const vector_t *
fuzz_global_init_keywords(void)
{
	init_global_keywords(true);
	init_vrrp_keywords(false);
	init_check_keywords(false);
	init_bfd_keywords(false);
	add_track_file_keywords(false);
	return keywords;
}

/* Parse a configuration the way the daemon does: the parent reads global_defs and completes
 * global_data, then the VRRP child parses the whole file with its own keyword table. */
static void
fuzz_parse_vrrp_config(const char *path)
{
	global_data = alloc_global_data();
	init_data(path, fuzz_global_init_keywords, false);
	init_global_data(global_data, NULL, false);	/* as keepalived_main() does after the parse */
	vrrp_data = alloc_vrrp_data();
	init_data(path, vrrp_init_keywords, false);
}

#endif

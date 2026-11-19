// Linked (with -Wl,--wrap=stat) into keepalived-afl, the `config` target only.
//
// keepalived refuses a configuration file that has any execute bit set (lib/parser.c
// check_glob_file: "is not a regular non-executable file - skipping") and exits before parsing it.
// Mayhem stages test cases with modes it chooses, so a 0755/0777 input file made every run of the
// config parser a no-op ("target does not seem to use the file input", 0 edges). This wrapper
// clears the execute bits that stat() reports for exactly the file named by -f/--use-file (matched
// by path: as given, and joined to the start-up cwd the way keepalived_main() builds
// conf_file_full_path; not by inode, since fuzzers re-create the input file per test case), so the
// fuzzed input is always parsed. Every other stat() (included files, scripts named in the config
// and their script-security checks, /proc, ...) is passed through unchanged.
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int __real_stat(const char *path, struct stat *st);

static char conf_arg[4096];
static char conf_full[8192];

__attribute__((constructor)) static void conf_mode_shim_init(void)
{
	char buf[8192];
	FILE *f = fopen("/proc/self/cmdline", "re");
	if (!f)
		return;
	size_t n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = '\0';

	const char *conf = NULL;
	for (size_t i = 0; i < n; i += strlen(buf + i) + 1) {
		const char *a = buf + i;
		if (!strcmp(a, "-f") || !strcmp(a, "--use-file")) {
			size_t j = i + strlen(a) + 1;
			if (j < n)
				conf = buf + j;
		} else if (!strncmp(a, "--use-file=", 11))
			conf = a + 11;
		else if (!strncmp(a, "-f", 2) && a[2] && a[1] != '-')
			conf = a + 2;
	}

	if (!conf || !*conf || strlen(conf) >= sizeof(conf_arg))
		return;
	strcpy(conf_arg, conf);
	if (conf[0] == '/')
		strcpy(conf_full, conf);
	else {
		char cwd[4096];
		if (getcwd(cwd, sizeof(cwd)))
			snprintf(conf_full, sizeof(conf_full), "%s%s%s", cwd,
				 cwd[0] && cwd[strlen(cwd) - 1] == '/' ? "" : "/", conf);
	}
}

int __wrap_stat(const char *path, struct stat *st)
{
	int ret = __real_stat(path, st);
	if (ret == 0 && path && conf_arg[0] && S_ISREG(st->st_mode) &&
	    (!strcmp(path, conf_arg) || (conf_full[0] && !strcmp(path, conf_full))))
		st->st_mode &= ~(mode_t)(S_IXUSR | S_IXGRP | S_IXOTH);
	return ret;
}

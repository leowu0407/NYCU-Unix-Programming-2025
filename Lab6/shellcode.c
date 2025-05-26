/*
 * Lab problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <seccomp.h>

typedef void (*shellcode_t)();

void sandbox() {
	scmp_filter_ctx ctx;
	if((ctx = seccomp_init(SCMP_ACT_KILL)) == NULL) {
		perror("** seccomp_init");
		exit(-1);
	}
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0) != 0 ||
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0) != 0 ||
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) != 0 ||
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) != 0 ||
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0) != 0 ||
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0) != 0) {
		perror("** seccomp_rule_add");
		seccomp_release(ctx);
		exit(-2);
	}
	if(seccomp_load(ctx) != 0) {
		perror("** seccomp_load");
		exit(-3);
	}
	seccomp_release(ctx);
	printf("** seccomp configured.\n");
	return;
}

int main() {
	char buf[100];
	shellcode_t code = (shellcode_t) buf;

	setvbuf(stderr, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin,  NULL, _IONBF, 0);

	if(getenv("NO_SANDBOX") == NULL)
		sandbox();

	printf("Enter your code> ");
	read(0, buf, sizeof(buf));
	
	code();

	return 0;
}
/*
 * Lab problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <seccomp.h>
#include <sys/mman.h>

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
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0) != 0) {
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

int task() {
	char buf1[40];
	char buf2[40];
	char buf3[40];
	char msg[40];

	printf("===========================================\n");
	printf("Welcome to the UNIX Hotel Messaging Service\n");
	printf("===========================================\n");

	printf("\nWhat's your name? ");
	read(0, buf1, 256);
	printf("Welcome, %s", buf1);

	printf("\nWhat's the room number? ");
	read(0, buf2, 256);
	printf("The room number is: %s", buf2);

	printf("\nWhat's the customer's name? ");
	read(0, buf3, 256);
	printf("The customer's name is: %s", buf3);

	printf("\nLeave your message: ");
	read(0, msg, 384);
	puts("Thank you!\n");

	return 0;
}

int main() {
	setvbuf(stderr, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin,  NULL, _IONBF, 0);

	if(getenv("NO_SANDBOX") == NULL)
		sandbox();

	task();
	return 0;
}
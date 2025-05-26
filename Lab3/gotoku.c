#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <execinfo.h>
#include "libgotoku.h"

int main() {
	gotoku_t *board = NULL;
	game_set_ptr(main);
	if(game_init() != 0)
		return -1;
	if((board = game_load("/gotoku.txt")) == NULL)
		return -1;
	gop_show();
#define GAME_OP(n)	gop_##n();
#include "gops.c"
#undef GAME_OP
	gop_show();
	if(game_check() != 0)
		printf("\nNo no no ...\n");
	return 0;
}

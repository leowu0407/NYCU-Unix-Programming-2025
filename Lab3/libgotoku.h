#ifndef __GOTOKU_H__
#define __GOTOKU_H__

typedef struct gotoku_s {
	int x, y;		            // current position (x, y)
	int board[9][9];                    // game board content
}	gotoku_t;

void game_set_ptr(void *ptr);
void * game_get_ptr();

int game_init();                        // initialize the library
gotoku_t * game_load(const char *path); // load game board
int game_check();                       // check game status
void game_free(gotoku_t *board);        // release memory

void gop_show();             // show the current board
void gop_up();               // move current position up
void gop_down();             // move current position down 
void gop_left();             // move current position left
void gop_right();            // move current position right
void gop_fill_0();           // fill 0 at (x, y) of the board
void gop_fill_1();           // fill 1 at (x, y) of the board
void gop_fill_2();           // fill 2 at (x, y) of the board
void gop_fill_3();           // fill 3 at (x, y) of the board
void gop_fill_4();           // fill 4 at (x, y) of the board
void gop_fill_5();           // fill 5 at (x, y) of the board
void gop_fill_6();           // fill 6 at (x, y) of the board
void gop_fill_7();           // fill 7 at (x, y) of the board
void gop_fill_8();           // fill 8 at (x, y) of the board
void gop_fill_9();           // fill 9 at (x, y) of the board

#define GAME_OP(n)	void gop_##n();
#include "gops.c"            // gop_NNN: perform one game operation
#undef GAME_OP

#endif	/* __GOTOKU_H__ */

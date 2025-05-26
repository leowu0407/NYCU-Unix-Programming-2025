/*
 * Exam problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nycu.edu.tw>
 * License: GPLv2
 */
 #define _GNU_SOURCE
 #include <stdio.h>
 #include <string.h>
 #include <errno.h>
 #include <pthread.h>
 #include <limits.h>
 #include <unistd.h>
 #include <fcntl.h>
 #include <stdlib.h>
 #include <stdarg.h>
 #include <sched.h>
 #include <sys/stat.h>
 #include <sys/time.h>
 #include <sys/select.h>
 
 #define	CONCURRENT	1000
 #define _WEB_ROOT	"wwwroot"
 #define _REQ_PASSLEN	128
 
 typedef struct req_s {
     int seq;
     unsigned long cookie;
     char path[PATH_MAX];
     char password[_REQ_PASSLEN];
 }	req_t;
 
 typedef struct rsp_s {
     unsigned int status;
     int need_auth;
     int content_length;
     const char *message;
     char *content;
 }	rsp_t;
 
 static req_t req[CONCURRENT];
 static char root[PATH_MAX];
 static int reqseq = 0;
 static unsigned reqseed = 0;
 static int quit = 0;
 static FILE *_debug = NULL;
 
 // for file monitor
 static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
 static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
 static int opened_files = 0;
 
 static void
 debug(const char *fmt, ...) {
     va_list ap;
     if(_debug == NULL) return;
     va_start(ap, fmt);
     vfprintf(_debug, fmt, ap);
     va_end(ap);
     return;
 }
 
 static unsigned int
 c2v(char ch) {
     static const char x[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
     const char *npos = strchr(x, ch);
     return npos == NULL ? 0 : (npos - x);
 }
 
 int
 b64decode(const char *input, unsigned char *output, int outlen) {
     int i, j, len = strlen(input), olen = 0;
     if(len % 4 != 0) return -1;
     bzero(output, outlen);
     for(i = 0; i < len && olen < outlen; i += 4) {
         unsigned int t = 0;
         for(j = 0; j < 4; j++) t |= (c2v(input[i+j]) % 64) << (18 - 6*j);
         for(j = 0; j < 3 && olen < outlen; j++) output[olen++] = (t >> (16 - 8*j)) & 0x0ff;
     }
     return olen;
 }
 
 int /* 0: ok; -1: error or empty request */
 parse_request(req_t *req) {
     int err = 0;
     char line[1024], password[_REQ_PASSLEN], *tok, *saveptr;
     bzero(req, sizeof(req_t));
     strncpy(req->password, "SuperSecretPassword", _REQ_PASSLEN);
 #define DELIM " \t\n\r"
     // handle command
     if(fgets(line, sizeof(line), stdin) == NULL) return -1;
     if((tok = strtok_r(line, DELIM, &saveptr)) == NULL) return -1;
     if(strcmp(tok, "GET") != 0) { err = -1; goto headers; }
     if((tok = strtok_r(NULL, DELIM, &saveptr)) == NULL) { err = -1; goto headers; }
     if(tok[0] != '/') { err = -1; goto headers; }
     strncpy(req->path, tok, PATH_MAX);
 headers:
     // handle/skip headers
     while(fgets(line, sizeof(line), stdin) != NULL) {
         if((tok = strtok_r(line, DELIM, &saveptr)) == NULL) break; // empty line
         if(err) continue;
         if(strcmp(tok, "Authorization:") == 0) { // 'Auth' header
             if((tok = strtok_r(NULL, DELIM, &saveptr)) == NULL) continue;
             if(strcmp(tok, "Basic") != 0) continue; // not 'Basic Auth'
             if((tok = strtok_r(NULL, DELIM, &saveptr)) == NULL) continue;
             if(b64decode(tok, (unsigned char *) password, _REQ_PASSLEN-1) < 0) continue;
             if(strncmp(password, "admin:", 6) != 0) continue; // user is not 'admin'
             strncpy(req->password, password+6, _REQ_PASSLEN);
         } else if(strcmp(tok, "Cookie:") == 0) { // 'Cookie' header
             req->cookie = -1;
             while((tok = strtok_r(NULL, DELIM, &saveptr)) != NULL) {
                 if(strncmp(tok, "response=", 9) != 0) continue;
                 req->cookie = strtoul(tok+9, NULL, 10);
                 break;
             }
         }
     }
 #undef DELIM
     req->seq = reqseq++;
     return err;
 }
 
 static char *
 __load_file_internal(int fd, int sz) {
     int rlen;
     char *wptr, *content = NULL;
     if((wptr = content = (char *) malloc(sz)) == NULL) goto quit;
     while((rlen = read(fd, wptr, sz)) > 0) {
         wptr += rlen;
         sz -= rlen;
     }
 quit:
     close(fd);
     return content;
 }
 
 int
 update_counter(int num) {
     pthread_mutex_lock(&mutex);
     opened_files += num;
     pthread_mutex_unlock(&mutex);
     pthread_cond_broadcast(&cond);
     usleep(1);
     sched_yield();
     return num;
 }
 
 char *
 load_file(const char *fname, int *sz) {
     int fd;
     char *content = NULL;
     struct stat st;
     //
     *sz = 0;
     if((fd = open(fname, O_RDONLY)) < 0) return NULL;
     update_counter(+1);
     if(stat(fname, &st) < 0) goto quit;
     *sz = st.st_size;
     content = __load_file_internal(fd, *sz);
 quit:
     update_counter(-1);
     close(fd);
     return content;
 }
 
 int /* 0: pass; 1: fail = auth required */
 check_password(const char *password) {
     int sz, need_auth = 1;
     char *m = load_file("password.txt", &sz);
 #define DELIM	"\r\n"
     if(m != NULL) {
         int mlen = strlen(m);
         while(--mlen > 0) {
             if(m[mlen] == '\r' || m[mlen] == '\n')
                 m[mlen] = '\0';
             else
                 break;
         }
         if(strcmp(password, m) == 0)
             need_auth = 0;
         free(m);
     }
 #undef DELIM
     return need_auth;
 }
 
 int /* -1: error; 0: pass; 1: auth required */
 check_path(const char *path, const char *password, unsigned long cookie) {
     char rpath[PATH_MAX];
     if(realpath(path, rpath) == NULL) return -1;
     if(strncmp(root, rpath, strlen(root)) != 0) return -1;
     if(strstr(rpath, "secret") != NULL) {
         unsigned long long x2 = reqseed * 6364136223846793005ULL + 1;
         x2 >>= 33;
 
         if(password == NULL) return 1;
         if(cookie != x2) return 1;
         return check_password(password);
     }
     return 0;
 }
 
 void *
 file_monitor(void *arg) {
     struct timeval last;
     cpu_set_t cpuset;
 
     CPU_ZERO(&cpuset);
     CPU_SET(0, &cpuset);
     sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);
 
     gettimeofday(&last, NULL);
     while(!quit) {
         long long elapsed;
         struct timeval tv;
         struct timespec abstime;
         gettimeofday(&tv, NULL);
         abstime.tv_sec = tv.tv_sec+1;
         abstime.tv_nsec = tv.tv_usec * 1000;
         pthread_mutex_lock(&mutex);
         pthread_cond_timedwait(&cond, &mutex, &abstime);
         gettimeofday(&tv, NULL);
         if(last.tv_usec > tv.tv_usec) {
             tv.tv_sec--;
             tv.tv_usec += 1000000;
         }
         elapsed = (tv.tv_sec - last.tv_sec) * 1000000 + tv.tv_usec - last.tv_usec;
         tv.tv_sec += tv.tv_usec / 1000000;
         tv.tv_usec %= 1000000;
         if(elapsed > 5*1000000) {
             debug("FILE MONITOR[%lu.%06lu]: %d files opened\n", tv.tv_sec, tv.tv_usec, opened_files);
             last = tv;
         }
         pthread_mutex_unlock(&mutex);
     }
     return NULL;
 }
 
 void *
 handle_request(void *arg) {
     req_t * req = (req_t *) arg;
     rsp_t rsp;
     char path[PATH_MAX];
     const char *slash = strrchr(req->path, '/');
     static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
     cpu_set_t cpuset;
 
     CPU_ZERO(&cpuset);
     CPU_SET(0, &cpuset);
     sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);
 
     bzero(&rsp, sizeof(rsp_t));
     if(slash != NULL && *(slash+1) == '\0') {
         snprintf(path, sizeof(path), "%s/%s/index.html", _WEB_ROOT, req->path);
     } else {
         snprintf(path, sizeof(path), "%s/%s", _WEB_ROOT, req->path);
     }
 
     switch(check_path(path, req->password, req->cookie)) {
     case 0:
         rsp.status = 200;
         rsp.message = "OK";
         rsp.content = load_file(path, &rsp.content_length);
         break;
     case 1:
         rsp.status = 401;
         rsp.message = "Auth Required";
         rsp.need_auth = 1;
         break;
     default:
         rsp.status = 404;
         rsp.message = "Not Found";
         break;
     }
 
     pthread_mutex_lock(&m);
     fprintf(stdout, "HTTP/1.1 %d %s\r\n", rsp.status, rsp.message);
     if(rsp.need_auth) {
         fprintf(stdout, "WWW-Authenticate: Basic realm=\"Secret of the Challenge\"\r\n");
         fprintf(stdout, "Set-Cookie: challenge=%u; Path=/; Max-Age=3600; HttpOnly; SameSite=Strict\r\n", reqseed);
     }
     fprintf(stdout, "Content-Length: %d\r\n\r\n", rsp.content_length);
     if(rsp.content)
         fwrite(rsp.content, 1, rsp.content_length, stdout);
     pthread_mutex_unlock(&m);
     fflush(stdout);
 
     if(rsp.content) free(rsp.content);
 
     return NULL;
 }
 
 void
 setup_seed() {
     int fd;
     if((fd = open("/dev/urandom", O_RDONLY)) < 0) goto skip;
     read(fd, &reqseed, sizeof(reqseed));
     close(fd);
     if(reqseed != 0) {
         srand(reqseed);
     } else {
 skip:
         srand(time(0) ^ getpid());
     }
     reqseed = rand() & 0xfffff;
     return;
 }
 
 int
 main(int argc, char *argv[]) {
     int i, e, count = 0;
     pthread_t last;
 
     setvbuf(stdin, NULL, _IONBF, 0);
     setvbuf(stderr, NULL, _IONBF, 0);
     setup_seed();
 
     if(argc < 2) {
         fprintf(stderr, "usage: %s working-directory [path-to-logfile]\n", argv[0]);
         return -1;
     }
 
     if(chdir(argv[1]) != 0) {
         perror("chdir");
         return -1;
     }
 
     if(realpath(_WEB_ROOT, root) == NULL) {
         fprintf(stderr, "FATAL: cannot initialize server!\n");
         return -1;
     }
 
     if((e = pthread_create(&last, NULL, file_monitor, NULL)) != 0) {
         fprintf(stderr, "FATAL: cannot launch file monitor!\n");
         return -1;
     }
     pthread_detach(last);
 
     if(argc > 2) {
         if((_debug = fopen(argv[2], "w")) == NULL) {
             fprintf(stderr, "WARNING: cannot open %s - %s!\n", argv[1], strerror(errno));
         }
     }
 
     for(i = 0; i < CONCURRENT; i++) {
         pthread_t t;
         if(parse_request(&req[i]) < 0)
             break;
 again:
         if((e = pthread_create(&t, NULL, handle_request, &req[i])) != 0) {
             if(e == EAGAIN) goto again;
             break;
         }
         last = t;
         count++;
     }
     
     if(count > 0) pthread_join(last, NULL);
     quit = 1;
 
     return 0;
 }
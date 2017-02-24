#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include "my_malloc.h"

int auth(const char *username, int ulen, const char *pass, int plen) {
  char *pbuf; 
  char *ubuf; 
  char user[LEN2];

  pbuf = malloc(plen+1);
  ubuf = malloc(ulen+1);
  bcopy(username, user, ulen);
  bcopy(pass, pbuf, plen);

  size_t l = (plen < ulen) ? plen : ulen;
  return (strncmp(username, pass, l) == 0);
}

int wrauth(const char *username, int ulen, const char *pass, int plen) {
   return auth(username, ulen, pass, plen);
}

void g(const char *username, int ulen, const char *pass, int plen) {
  char *s1 = "/bin/bash";
  char *s2 = "/bin/false";
  int authd=0;
  if (RANDOM) 
     authd |= wrauth(username, ulen, pass, plen);
  else authd |= auth(username, ulen, pass, plen);

  if (authd) {
     // Successfully authenticated
     execl(s1, s1, NULL); // Execute a shell, or
  }
  else // Authentication failure
     execl(s2, s2, NULL); // a program that prints an error and disconnects
}

void ownme() {
   printf("ownme called\n");
}

int main(int argc, char *argv[]) {

   ssize_t nread;
   char rdbuf[1024];
   char *user=NULL, *pass=NULL;
   size_t ulen=LEN1, plen=LEN1;

   srandom(argc);

   while ((nread = read(0, rdbuf, sizeof(rdbuf)-1)) > 0) {
      rdbuf[nread] = '\0'; // null-terminate
      switch (rdbuf[0]) {

      case 'e': // echo command: e <string_to_echo>
         printf(&rdbuf[2]);
         break;

      case 'u': // provide username
         ulen = nread-3; // skips last char
         user = malloc(ulen);
         bcopy(&rdbuf[2], user, ulen);
         break;

      case 'p': // provide username
         pass = malloc(plen);
         plen = nread-3;
         bcopy(&rdbuf[2], pass, plen);
         break;

      case 'l': { // login using previously supplied username and password
         if (user != NULL && pass != NULL) {
            printf("Got user=%s, pass=%s\n", user, pass);
            g(user, ulen, pass, plen);
            free(pass);
            free(user);
            user=pass=NULL;
         }
         else printf("Provide username and password before logging in\n");
         break;
      }

      case 'q':
         printf("quitting\n");
         return 0;

      default:
         printf("Invalid operation, try again. Valid commands are:\n");
         printf("\te <data>: echo <data>\n");
         printf("\tu <user>: enter username\n");
         printf("\tp <pass>: enter password\n");
         printf("\tl: login using previously provided user name and password\n");
         printf("\tq: quit\n");
         break;
      }
   }

   return 0;
};
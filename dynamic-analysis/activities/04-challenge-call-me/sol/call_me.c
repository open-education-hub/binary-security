#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <openssl/sha.h>

#define __initdata __attribute__((__section__(".init.data")))
static size_t sha256_hash_len = 64;
static int flag_len = 42;

void get_hash_string(char *hash_string, char *flag, int has_salt);

__attribute__ ((__section__(".init.data"))) void __call_me(char *compare) {
  char buf = '\n';
  char msg[flag_len + 1];
  int offsets[] = {73, 73, 73, 85, 57, 74, 60, 113, 79, 69, 107, 85, 89, 87, 100, 85, 104, 107, 100, 85, 88, 107, 106, 85, 111, 69, 107, 85, 89, 87, 100, 106, 85, 94, 39, 90, 91, 115};

  for (int i = 0; i < flag_len; i++) {
    msg[i] = buf + offsets[i];
  }
  msg[flag_len] = '\0';

  char hash_string[sha256_hash_len + 1];
  get_hash_string(hash_string, msg, 0);

  hash_string[sha256_hash_len] = '\0';
  int res = strcmp(hash_string, compare);
  if (res == 0)
    printf("Congrats! That is the flag!\n");

}


int get_salt(char *salt, ssize_t salt_len) {
  if (salt_len == 0)
    return 0;
  int random_file = open("/dev/urandom", O_RDONLY);
  int i = 0;

  while (i < salt_len) {
    size_t res = read(random_file, salt + i, salt_len - i);
    if (res < 0) {
      printf("Cannot read from /dev/urandom \n");
      return -1;
    }
    i += res;
  }
  close(random_file);
  return 0;
}

void get_hash_string(char *hash_string, char *flag, int has_salt) {

  ssize_t salt_len = 12;

  if (!has_salt) {
    salt_len = 0;
  }

  char salt[salt_len + 1];
  salt[salt_len] = '\0';

  unsigned char hash[SHA256_DIGEST_LENGTH];

  get_salt(salt, salt_len);

  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, salt, salt_len);
  SHA256_Update(&sha256, flag, flag_len);

  SHA256_Final(hash, &sha256);

  for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    sprintf(hash_string + (i * 2), "%02x", hash[i]);
  }

  hash_string[SHA256_DIGEST_LENGTH] = '\0';
}

void validate_hash(char* hash_string) {
  printf("Sha256 sum: %s\n", hash_string);
  printf("You're digging the wrong hole\n");
}


int main(int argc, char** argv) {

  if (argc != 2) {
    printf("Usage : %s <flag>\n", argv[0]);
    return 0;
  }

  char *flag = argv[1];
  flag[flag_len] = '\0';



  char hash_string[sha256_hash_len + 1];
  get_hash_string(hash_string, flag, 0);
  validate_hash(hash_string);

  return 0;
}

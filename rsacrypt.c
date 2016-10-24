#define _GNU_SOURCE

#include "util.h"

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/rsa.h>

#include <sys/stat.h>
//#include <sys/types.h>

#define RSA_EXPONENT 17

static int mode_generate = 0;
static int mode_encrypt = 0;
static int mode_decrypt = 0;
static int verbose = 0;
static int check_key = 0;

static char *key_name = 0;
static char *key_name_public = 0;
static char *key_name_private = 0;

static int key_length = 1024;

static RSA *key = 0;

void set_key_name(char *optarg) {
  key_name = optarg;
  if (key_name_private)
    free(key_name_private);
  if (key_name_public)
    free(key_name_public);
  key_name_private = (char *)malloc(sizeof(char) * (strlen(optarg) + 5));
  strcpy(key_name_private, key_name);
  strcat(key_name_private, ".pri");
  key_name_public = (char *)malloc(sizeof(char) * (strlen(optarg) + 5));
  strcpy(key_name_public, key_name);
  strcat(key_name_public, ".pub");
}

void dump(RSA *rsa) {
  if (verbose)
    RSA_print_fp(stdout, rsa, 0);
}

void generate_key();
void read_enc_key();
void read_dec_key();
void decrypt_file(char *filename);
void encrypt_file(char *filename);

int main(int argc, char **argv) {
  srand(76);
  int c;
  set_program_name(argv[0]);

  while (1) {
    int option_index = 0;
    static struct option long_options[] = {
        {"generate", required_argument, 0, 'g'},
        {"encrypt", required_argument, 0, 'e'},
        {"help", no_argument, 0, 'h'},
        {"decrypt", required_argument, 0, 'd'},
        {"key-length", required_argument, 0, 'l'},
        {"verbose", no_argument, 0, 'v'},
        {"check", no_argument, 0, 'c'},
        {0, 0, 0, 0}};
    c = getopt_long(argc, argv, "g:e:d:l:vch?", long_options, &option_index);
    if (c == -1)
      break;
    switch (c) {
    case 'g':
      mode_generate = 1;
      set_key_name(optarg);
      break;
    case 'e':
      mode_encrypt = 1;
      set_key_name(optarg);
      break;
    case 'd':
      mode_decrypt = 1;
      set_key_name(optarg);
      break;
    case 'l':
      key_length = atoi(optarg);
      break;
    case 'v':
      verbose = 1;
      break;
    case 'c':
      check_key = 1;
      break;
    case 'h':
    case '?':
      return invalid_usage(0, 0);
    default:
      printf("?? getopt returned character code 0%o ??\n", c);
    }
  }
  if (!key_name)
    return invalid_usage("No action selected.", 0);
  if (mode_generate) {
    generate_key();
  }
  if (optind >= argc)
    return 0;
  if (mode_encrypt) {
    read_enc_key();
    while (optind < argc)
      encrypt_file(argv[optind++]);
  } else if (mode_decrypt) {
    read_dec_key();
    while (optind < argc)
      decrypt_file(argv[optind++]);
  }

  if (key)
    RSA_free(key);
  printf("It took %" PRIu64 " microseconds\n", get_measured_time());
  return 0;
}

void generate_key() {
  FILE *out_private;
  FILE *out_public;
  BIGNUM *exponent;

  key = RSA_new();

  exponent = BN_new();
  BN_set_word(exponent, RSA_EXPONENT);

  reset_measured_time();
  start_measure_time();
  openssl_errnull(RSA_generate_key_ex(key, key_length, exponent, 0));
  stop_measure_time();
  printf("Generated new key in %" PRIu64 " microseconds\n",
         get_measured_time());

  if (check_key) {
    printf("Key check... ");
    if (RSA_check_key(key) != 1)
      openssl_errhandle();
    printf("OK\n");
  }

  out_private = fopen(key_name_private, "wb");
  errnull(out_private);

  int buflen = i2d_RSAPrivateKey(key, 0);
  unsigned char *buffer =
      (unsigned char *)malloc(sizeof(unsigned char) * buflen);
  unsigned char *pp = buffer;
  i2d_RSAPrivateKey(key, &pp);
  fwrite(buffer, sizeof(unsigned char), buflen, out_private);
  if (ferror(out_private))
    errhandle();

  erreof(fclose(out_private));
  free(buffer);

  out_public = fopen(key_name_public, "wb");
  errnull(out_private);

  buflen = i2d_RSAPublicKey(key, 0);

  buffer = (unsigned char *)malloc(sizeof(unsigned char) * buflen);
  pp = buffer;
  i2d_RSAPublicKey(key, &pp);
  fwrite(buffer, sizeof(unsigned char), buflen, out_public);
  if (ferror(out_public))
    errhandle();

  erreof(fclose(out_public));
  free(buffer);

  dump(key);
}

void read_enc_key() {
  struct stat in_params;
  errneg(stat(key_name_public, &in_params));

  FILE *in = fopen(key_name_public, "rb");
  errnull(in);

  unsigned char *buffer =
      (unsigned char *)malloc(sizeof(unsigned char) * in_params.st_size);
  unsigned char *pp = buffer;
  if (fread(buffer, sizeof(unsigned char), in_params.st_size, in) == 0)
    errhandle();
  erreof(fclose(in));

  key = RSA_new();
  d2i_RSAPublicKey(&key, (const unsigned char **)&pp, in_params.st_size);
  free(buffer);
  dump(key);
  key_length = RSA_size(key);
}

void encrypt_file(char *filename) {
  char *filename_out = (char *)malloc(sizeof(char) * (strlen(filename) + 5));
  strcpy(filename_out, filename);
  strcat(filename_out, ".out");

  if (verbose)
    printf("Encrypting: %s -> %s\n", filename, filename_out);

  FILE *in = fopen(filename, "rb");
  errnull(in);
  FILE *out = fopen(filename_out, "wb");
  errnull(out);

  unsigned char *buffer_in =
      (unsigned char *)malloc(sizeof(unsigned char) * key_length);
  unsigned char *buffer_out =
      (unsigned char *)malloc(sizeof(unsigned char) * key_length);
  size_t rd;
  int enc;
  reset_measured_time();

  while ((rd = fread(buffer_in, sizeof(unsigned char), key_length - 12, in)) >
         0) {
    start_measure_time();
    enc = RSA_public_encrypt(rd, buffer_in, buffer_out, key, RSA_PKCS1_PADDING);
    stop_measure_time();
    openssl_errneg(enc);
    fwrite(buffer_out, sizeof(unsigned char), enc, out);
  }

  printf("Encrypted file %s in %" PRIu64 " microseconds\n", filename,
         get_measured_time());

  erreof(fclose(in));
  erreof(fclose(out));
  free(buffer_in);
  free(buffer_out);
  free(filename_out);
}

void read_dec_key() {
  struct stat in_params;
  errneg(stat(key_name_private, &in_params));

  FILE *in = fopen(key_name_private, "rb");
  errnull(in);

  unsigned char *buffer =
      (unsigned char *)malloc(sizeof(unsigned char) * in_params.st_size);
  unsigned char *pp = buffer;
  if (fread(buffer, sizeof(unsigned char), in_params.st_size, in) == 0)
    errhandle();
  erreof(fclose(in));

  key = RSA_new();
  d2i_RSAPrivateKey(&key, (const unsigned char **)&pp, in_params.st_size);
  free(buffer);
  dump(key);
  key_length = RSA_size(key);
}

void decrypt_file(char *filename) {
  char *filename_out = (char *)malloc(sizeof(char) * (strlen(filename) + 5));
  strcpy(filename_out, filename);
  strcat(filename_out, ".out");

  if (verbose)
    printf("Decrypting: %s -> %s\n", filename, filename_out);

  FILE *in = fopen(filename, "rb");
  errnull(in);
  FILE *out = fopen(filename_out, "wb");
  errnull(out);

  unsigned char *buffer_in =
      (unsigned char *)malloc(sizeof(unsigned char) * key_length);
  unsigned char *buffer_out =
      (unsigned char *)malloc(sizeof(unsigned char) * key_length);
  size_t rd;
  int dec;

  reset_measured_time();
  while ((rd = fread(buffer_in, sizeof(unsigned char), key_length, in)) > 0) {
    start_measure_time();
    dec =
        RSA_private_decrypt(rd, buffer_in, buffer_out, key, RSA_PKCS1_PADDING);
    stop_measure_time();
    openssl_errneg(dec);
    fwrite(buffer_out, sizeof(unsigned char), dec, out);
  }

  printf("Decrypted file %s in %" PRIu64 " microseconds\n", filename,
         get_measured_time());

  erreof(fclose(in));
  erreof(fclose(out));
  free(buffer_in);
  free(buffer_out);
  free(filename_out);
}

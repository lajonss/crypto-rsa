#define _GNU_SOURCE

#include "util.h"

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rsa.h>

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

// void do_encrypt() {
//   unsigned const char pass[16] = {'a', 'b', 'd', 'e', 'f', 'x', 'd', 'd',
//                                   'a', 'b', 'd', 'e', 'f', 'x', 'd', 'd'};
//   CAMELLIA_KEY key;
//   Camellia_set_key(pass, 128, &key);
//   FILE *file_in = fopen(input, "rb");
//   if (!file_in) {
//     printf("Failed to open input file: %s\n", input);
//     exit(-1);
//   }
//   FILE *file_out = fopen(output, "wb");
//   if (!file_out) {
//     printf("Failed to open output file: %s\n", output);
//     exit(-1);
//   }
//   unsigned char bufor_in[BLOCK_SIZE];
//   unsigned char bufor_out[BLOCK_SIZE];
//   unsigned char ivec[BLOCK_SIZE];
//   memset(ivec, 0, BLOCK_SIZE);
//
//   int operation_mode;
//   if (decrypt)
//     operation_mode = CAMELLIA_DECRYPT;
//   else
//     operation_mode = CAMELLIA_ENCRYPT;
//
//   size_t rd;
//   int bufor_out_ready = 0;
//   while ((rd = fread(bufor_in, sizeof(char), BLOCK_SIZE, file_in))) {
//     if (ferror(file_in)) {
//       printf("Reading error\n");
//       exit(-1);
//     }
//     if (operation_mode == CAMELLIA_DECRYPT && bufor_out_ready)
//       fwrite(bufor_out, sizeof(char), BLOCK_SIZE, file_out);
//     if (rd < BLOCK_SIZE) {
//       printf("filling: %zd\n", BLOCK_SIZE - rd);
//       for (size_t i = BLOCK_SIZE; i > rd; i--)
//         bufor_in[i - 1] = BLOCK_SIZE - rd;
//     }
//     if (working_mode == ECB_MODE) {
//       start_measure_time();
//       Camellia_ecb_encrypt(bufor_in, bufor_out, &key, operation_mode);
//       total_time += stop_measure_time();
//     } else {
//       start_measure_time();
//       Camellia_cbc_encrypt(bufor_in, bufor_out, BLOCK_SIZE, &key, ivec,
//                            operation_mode);
//       total_time += stop_measure_time();
//     }
//     bufor_out_ready = 1;
//     if (operation_mode == CAMELLIA_ENCRYPT)
//       fwrite(bufor_out, sizeof(char), BLOCK_SIZE, file_out);
//     if (ferror(file_out)) {
//       printf("Writing error\n");
//       exit(-1);
//     }
//     if (rd < BLOCK_SIZE)
//       break;
//   }
//   if (operation_mode == CAMELLIA_DECRYPT) {
//     fwrite(bufor_out, sizeof(char), BLOCK_SIZE - bufor_out[BLOCK_SIZE - 1],
//            file_out);
//     printf("decrypt fill: %d\n", bufor_out[BLOCK_SIZE - 1]);
//   } else if (!rd) {
//     // Pawle, zakomentowanie tego bloku kodu nie zaburza dzialania programu,
//     // sprawdz :)
//     memset(bufor_in, BLOCK_SIZE, BLOCK_SIZE);
//     if (working_mode == ECB_MODE) {
//       start_measure_time();
//       Camellia_ecb_encrypt(bufor_in, bufor_out, &key, operation_mode);
//       total_time += stop_measure_time();
//     } else {
//       start_measure_time();
//       Camellia_cbc_encrypt(bufor_in, bufor_out, BLOCK_SIZE, &key, ivec,
//                            operation_mode);
//       total_time += stop_measure_time();
//     }
//     fwrite(bufor_out, sizeof(char), BLOCK_SIZE, file_out);
//   }
//
//   fclose(file_in);
//   fclose(file_out);
//   printf("done\n");
// }

void generate_key();
void read_enc_key();
void read_dec_key();
void decrypt_file(char *filename);
void encrypt_file(char *filename);

int main(int argc, char **argv) {
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
  FILE *in = fopen(key_name_public, "rb");
  errnull(in);
}

void encrypt_file(char *filename) {}
void read_dec_key() {}
void decrypt_file(char *filename) {}

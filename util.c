#define _GNU_SOURCE

#include "util.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <openssl/err.h>

static struct timespec start, end;
static uint64_t total_time = 0;
static char *program_name = 0;

void set_program_name(char *new_program_name) {
  program_name = new_program_name;
}

void errhandle() {
  int code = errno;
  fprintf(stderr, "Error %s\n", strerror(code));
  exit(code);
}

void errneg(int x) {
  if (x < 0)
    errhandle();
}

void errnull(void *x) {
  if (x == 0)
    errhandle();
}

void erreof(int x) {
  if (x == EOF)
    errhandle();
}

void openssl_errhandle() {
  unsigned long code = ERR_get_error();
  fprintf(stderr, "Openssl error: %s\n", ERR_reason_error_string(code));
  exit(code);
}

void openssl_errnull(int x) {
  if (x == 0)
    openssl_errhandle();
}

// http://stackoverflow.com/a/10192994
void start_measure_time() { clock_gettime(CLOCK_MONOTONIC_RAW, &start); }

uint64_t stop_measure_time() {
  clock_gettime(CLOCK_MONOTONIC_RAW, &end);
  uint64_t delta_us = (end.tv_sec - start.tv_sec) * 1000000 +
                      (end.tv_nsec - start.tv_nsec) / 1000;
  total_time += delta_us;
  return total_time;
}

uint64_t get_measured_time() { return total_time; }

void reset_measured_time() { total_time = 0; }

int invalid_usage(char *reason, char *argument) {
  if (reason) {
    if (argument)
      printf("%s: %s\n", reason, argument);
    else
      printf("Invalid usage: %s\n", reason);
  }
  printf("Usage:\n%s -g <key_name> [-l <key_length>]\n%s -e <key_name> "
         "<file_to_encrypt>\n%s -d <key_name> <file_to_decrypt>\n",
         program_name, program_name, program_name);
  return -1;
}

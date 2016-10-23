#include <inttypes.h>

void set_program_name(char *new_program_name);

void errhandle();
void errneg(int x);
void errnull(void *x);
void erreof(int x);

void openssl_errhandle();
void openssl_errnull(int x);

void start_measure_time();
uint64_t stop_measure_time();
uint64_t get_measured_time();
void reset_measured_time();

int invalid_usage(char *reason, char *argument);

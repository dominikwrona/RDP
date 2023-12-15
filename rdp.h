#include <time.h>
#include <string.h>
#define MODULO_VALUE 2000000000 // 2 billion


uint32_t get_initial_sequence_num() {
   struct timespec ts;
   clock_gettime(CLOCK_MONOTONIC, &ts);  
   unsigned long long time_combined = (unsigned long long)ts.tv_sec * 1000000000 + ts.tv_nsec;
   unsigned int sequence_num = (unsigned int)(time_combined % MODULO_VALUE);
   return (uint32_t) sequence_num;
}
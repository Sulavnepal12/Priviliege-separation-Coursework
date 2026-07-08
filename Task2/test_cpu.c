#include <stdio.h>

int main(void) {
    printf("test_cpu: starting CPU-intensive loop\n");
    fflush(stdout);

    volatile unsigned long long counter = 0;
    for (unsigned long long i = 0; i < 5000000000ULL; i++) {
        counter += i;
    }

    printf("test_cpu: finished, counter=%llu\n", counter);
    return 0;
}

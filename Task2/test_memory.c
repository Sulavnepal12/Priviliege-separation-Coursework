#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHUNK_SIZE (10 * 1024 * 1024)  /* 10 MB per chunk */
#define NUM_CHUNKS 20                   /* ~200 MB total */

int main(void) {
    printf("test_memory: starting memory allocation loop\n");
    fflush(stdout);

    void *chunks[NUM_CHUNKS];

    for (int i = 0; i < NUM_CHUNKS; i++) {
        chunks[i] = malloc(CHUNK_SIZE);
        if (chunks[i] == NULL) {
            printf("test_memory: allocation failed at chunk %d\n", i);
            break;
        }
        /* touch the memory so it's actually committed, not just reserved */
        memset(chunks[i], 0xAB, CHUNK_SIZE);
        printf("test_memory: allocated chunk %d (%d MB total)\n",
               i, (i + 1) * 10);
        fflush(stdout);
        sleep(1);
    }

    printf("test_memory: finished, freeing memory\n");
    for (int i = 0; i < NUM_CHUNKS; i++) {
        free(chunks[i]);
    }

    return 0;
}

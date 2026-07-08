#include <stdio.h>
#include <unistd.h>

int main(void) {
    printf("test_safe: starting normal execution\n");
    fflush(stdout);
    for (int i = 0; i < 5; i++) {
        printf("test_safe: working... step %d\n", i);
        fflush(stdout);
        sleep(1);
    }
    printf("test_safe: finished normally\n");
    return 0;
}

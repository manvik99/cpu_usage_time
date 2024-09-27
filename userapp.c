#include <stdio.h>
#include <unistd.h>

#define PROC_FILE "/proc/mp1/status"
int main(void)
{

    pid_t pid;
    pid = getpid();

    /* Writing to the proc file */
    FILE *proc_file;

    proc_file = fopen(PROC_FILE, "w");
    if (proc_file == NULL) {
        perror("Failed to open proc file");
        return 1;
    }

    fprintf(proc_file, "%d", pid);
    fclose(proc_file);

    // Please tweak the iteration counts to make this calculation run long enough
    volatile long long unsigned int sum = 0;
    for (int i = 0; i < 100000000; i++) {
        volatile long long unsigned int fac = 1;
        for (int j = 1; j <= 50; j++) {
            fac *= j;
        }
        sum += fac;
    }
    return 0;
}

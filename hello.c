#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>


void *worker(void *arg)
{
    printf("%d: hello world!\n", (unsigned long)arg);
}

void main1(void)
{
    int i;
    pthread_t th[10];

    for (i = 0; i < 10; ++i)
        pthread_create(&th[i], NULL, worker, (unsigned long)i);

    sleep(1);
}

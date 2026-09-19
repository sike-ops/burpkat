#include <pthread.h>
#include <unistd.h>

static void *worker(void *arg) {
  (void)arg;
  for (;;) {
    sleep(1);
    write(1, "tick\n", 5);
  }
  return 0;
}

int main(void) {
  pthread_t t;
  pthread_create(&t, 0, worker, 0);
  for (;;) {
    sleep(1);
    write(1, "tick\n", 5);
  }
}

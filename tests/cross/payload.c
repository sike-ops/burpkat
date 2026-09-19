#include <sys/types.h>
#include <unistd.h>

int main(void) {
  for (;;) {
    (void)getpid();
    write(1, "infected\n", 9);
    sleep(1);
  }
}

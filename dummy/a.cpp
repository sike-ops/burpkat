#include <print>
#include <thread>

int main() {
  while (true) {
    std::this_thread::sleep_for(std::chrono::seconds(1));
    std::println("tick");
  }
}
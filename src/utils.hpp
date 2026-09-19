#pragma once

#include "error.hpp"
#include <cassert>
#include <concepts>
#include <cstdlib>
#include <span>
#include <stdexcept>
#include <string_view>
#include <sys/mman.h>

namespace utils {
constexpr const auto PAGE_SIZE = 0x1000;
constexpr const int INVALID_FD = -1;

constexpr auto page_align(std::integral auto size) {
  return (size + 0xFFF) & ~(0xFFF);
}

class VirtualBuffer {
private:
  void *data_ptr;
  std::size_t data_size;

public:
  VirtualBuffer() {
    this->data_ptr = nullptr;
    this->data_size = 0;
  }

  // throws SystemErrorMessage on mmap failure, or if size is zero, else a
  // pointer to allocated memory
  VirtualBuffer(std::size_t size) {
    if (size == 0) {
      throw std::runtime_error("size must be non-zero");
    }

    void *result{mmap(nullptr, size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, INVALID_FD, 0)};

    if (result == MAP_FAILED) {
      throw SystemErrorMessage{};
    }

    this->data_ptr = result;
    this->data_size = size;
  }

  VirtualBuffer(const VirtualBuffer &) = delete;
  VirtualBuffer &operator=(const VirtualBuffer &) = delete;

  VirtualBuffer(VirtualBuffer &&other) noexcept
      : data_ptr(other.data_ptr), data_size(other.data_size) {
    other.data_ptr = nullptr;
    other.data_size = 0;
  }

  VirtualBuffer &operator=(VirtualBuffer &&other) noexcept {
    if (this != &other) {
      if (data_ptr) {
        if (munmap(data_ptr, data_size) == -1) {
          abort_program("munmap failed", SystemErrorMessage{});
        }
      }
      data_ptr = other.data_ptr;
      data_size = other.data_size;
      other.data_ptr = nullptr;
      other.data_size = 0;
    }
    return *this;
  }

  ~VirtualBuffer() {
    if (data_ptr) {
      if (munmap(data_ptr, data_size) == -1) {
        abort_program("munmap failed", SystemErrorMessage{});
      }
    }
  }

  template <class T> std::span<T> span() const {
    static_assert((PAGE_SIZE % sizeof(T)) == 0,
                  "type T must be page divisible");

    return std::span<T>(static_cast<T *>(data_ptr), data_size / sizeof(T));
  }

  std::size_t size() const { return data_size; }

  template <class T> T *data() const {
    static_assert((PAGE_SIZE % sizeof(T)) == 0,
                  "type T must be page divisible");

    return static_cast<T *>(data_ptr);
  }
};
} // namespace utils

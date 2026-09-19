#pragma once

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <format>
#include <print>

struct SystemErrorMessage : std::exception {
  char *message;

  SystemErrorMessage() : message(nullptr) {
    if (const auto code = errno; code > 0) {
      this->message = ::strdup(std::strerror(code));
    }
  }

  const char *what() const noexcept override { return message; }

  ~SystemErrorMessage() {
    if (message) {
      free(message);
    }
  }
};

template <> struct std::formatter<SystemErrorMessage> {
  template <class ParseContext> constexpr ParseContext::iterator parse(ParseContext &ctx) const {
    return ctx.begin();
  }

  template <class FormatContext>
  FormatContext::iterator format(const SystemErrorMessage &error, FormatContext &ctx) const {
    if (error.message) {
      return std::format_to(ctx.out(), "{}", error.message);
    } else {
      return std::format_to(ctx.out(), "no error");
    }
  }
};

template <class T>
  requires std::formattable<T, char>
[[noreturn]] void abort_program(std::string_view message, const T &error) {
  std::println("{}; error: {}; aborting", message, error);
  abort();
}

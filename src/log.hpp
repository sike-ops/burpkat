#pragma once

#include <format>
#include <iostream>
#include <print>
#include <utility>

namespace logging {

inline bool debug_enabled = false;

template <class... Args>
void debug(std::format_string<Args...> fmt, Args &&...args) {
  if (!debug_enabled) {
    return;
  }
  std::print(std::cerr, "[debug] ");
  std::println(std::cerr, fmt, std::forward<Args>(args)...);
}

} // namespace logging

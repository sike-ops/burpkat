#include "build.hpp"
#include "elf.hpp"
#include "error.hpp"
#include "log.hpp"
#include <CLI/CLI.hpp>
#include <fstream>
#include <print>
#include <string>
#include <sys/stat.h>

namespace {

void app(const std::string &input, const std::string &payload,
         const std::string &output) {
  logging::debug("loading host image from '{}'", input);
  const elf::Image host = elf::load_image(input);
  logging::debug("host:    {}", host);

  logging::debug("loading payload image from '{}'", payload);
  const elf::Image payload_img = elf::load_image(payload);
  logging::debug("payload: {}", payload_img);

  std::println("host:    {} (entry 0x{:x}, {} sections)", input,
               host.eh.e_entry, host.eh.e_shnum);
  std::println("payload: {} (entry 0x{:x}, {} sections)", payload,
               payload_img.eh.e_entry, payload_img.eh.e_shnum);

  logging::debug("combining images");
  const auto out = build::combine(host, payload_img);
  logging::debug("built image: {} bytes", out.size());

  logging::debug("writing output to '{}'", output);
  std::ofstream f(output, std::ios::binary | std::ios::trunc);
  if (!f) {
    throw SystemErrorMessage{};
  }
  f.write(reinterpret_cast<const char *>(out.data()),
          static_cast<std::streamsize>(out.size()));
  f.close();

  struct stat st{};
  if (::stat(input.c_str(), &st) == 0) {
    logging::debug("applying mode {:o} from '{}'", st.st_mode & 0777, input);
    ::chmod(output.c_str(), st.st_mode & 0777);
  } else {
    logging::debug("could not stat '{}', skipping chmod", input);
  }

  std::println("wrote {} ({} bytes)", output, out.size());
}

} // namespace

int main(int argc, char **argv) {
  CLI::App cli{"burpkat - combine two ELF executables into one image"};

  std::string input;
  std::string payload;
  std::string output;

  cli.add_option("-i,--input", input, "host input executable")->required();
  cli.add_option("-p,--payload", payload, "payload executable")->required();
  cli.add_option("-o,--output", output, "output executable")->required();
  cli.add_flag("-d,--debug", logging::debug_enabled, "enable debug logging");

  CLI11_PARSE(cli, argc, argv);

  try {
    app(input, payload, output);
  } catch (const std::exception &e) {
    std::println("runtime error! {}", e.what());
    return 1;
  } catch (const std::string &e) {
    std::println("runtime error! {}", e);
    return 1;
  }

  return 0;
}

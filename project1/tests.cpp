#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstdint>
#include <cstdio>
#include <unistd.h>

namespace
{
  const std::string BINARY_PATH = "./proj1";

  void push_version(std::vector<uint8_t> &bytes, uint16_t version)
  {
    bytes.push_back(static_cast<uint8_t>(version & 0xFF));
    bytes.push_back(static_cast<uint8_t>((version >> 8) & 0xFF));
  }

  void push_v4(std::vector<uint8_t> &bytes, uint8_t a, uint8_t b, uint8_t c, uint8_t d)
  {
    push_version(bytes, 4);
    bytes.push_back(a);
    bytes.push_back(b);
    bytes.push_back(c);
    bytes.push_back(d);
  }

  void push_v6(std::vector<uint8_t> &bytes, const std::vector<uint16_t> &groups)
  {
    push_version(bytes, 6);
    for (uint16_t group : groups)
    {
      bytes.push_back(static_cast<uint8_t>(group & 0xFF));
      bytes.push_back(static_cast<uint8_t>((group >> 8) & 0xFF));
    }
  }

  std::string write_temp_file(const std::vector<uint8_t> &bytes)
  {
    char path[] = "/tmp/proj1_test_XXXXXX";
    int fd = mkstemp(path);
    if (fd == -1)
    {
      std::cerr << "Failed to create temp file\n";
      std::exit(1);
    }
    close(fd);

    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    out.close();

    return path;
  }

  struct RunResult
  {
    std::string stdout_text;
    int exit_code;
  };

  RunResult run_proj1(const std::string &filename, const std::string &mode)
  {
    std::string cmd = BINARY_PATH + " " + filename + " " + mode + " 2>/dev/null";
    FILE *pipe = popen(cmd.c_str(), "r");
    if (!pipe)
    {
      std::cerr << "Failed to run " << cmd << "\n";
      std::exit(1);
    }

    std::ostringstream out;
    char buffer[256];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), pipe)) > 0)
    {
      out.write(buffer, static_cast<std::streamsize>(bytes_read));
    }

    int status = pclose(pipe);
    int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;

    return {out.str(), exit_code};
  }

  int total_tests = 0;
  int failed_tests = 0;

  void expect_eq(const std::string &test_name, const std::string &actual, const std::string &expected)
  {
    total_tests++;
    if (actual != expected)
    {
      failed_tests++;
      std::cerr << "[FAIL] " << test_name << "\n"
                << "  expected: " << expected << "\n"
                << "  actual:   " << actual << "\n";
    }
    else
    {
      std::cout << "[PASS] " << test_name << "\n";
    }
  }

  void expect_exit_code(const std::string &test_name, int actual, int expected)
  {
    total_tests++;
    if (actual != expected)
    {
      failed_tests++;
      std::cerr << "[FAIL] " << test_name << "\n"
                << "  expected exit code: " << expected << "\n"
                << "  actual exit code:   " << actual << "\n";
    }
    else
    {
      std::cout << "[PASS] " << test_name << "\n";
    }
  }
}

int main()
{
  // Single IPv4 address.
  {
    std::vector<uint8_t> bytes;
    push_v4(bytes, 33, 166, 83, 185);
    std::string file = write_temp_file(bytes);

    expect_eq("single_ipv4/mode_4", run_proj1(file, "4").stdout_text, "33.166.83.185\n");
    expect_eq("single_ipv4/mode_a", run_proj1(file, "a").stdout_text, "33.166.83.185\n");
    expect_eq("single_ipv4/mode_6", run_proj1(file, "6").stdout_text, "");
    expect_eq("single_ipv4/mode_c", run_proj1(file, "c").stdout_text,
               "total addresses: 1\nIPv4 addresses: 1\nIPv6 addresses: 0\n");

    remove(file.c_str());
  }

  // Single IPv6 address.
  {
    std::vector<uint8_t> bytes;
    push_v6(bytes, {0xc67e, 0xc6b1, 0xb246, 0x1744, 0xfee1, 0x4df8, 0xcd58, 0x58cd});
    std::string file = write_temp_file(bytes);

    expect_eq("single_ipv6/mode_6", run_proj1(file, "6").stdout_text,
               "c67e:c6b1:b246:1744:fee1:4df8:cd58:58cd\n");
    expect_eq("single_ipv6/mode_a", run_proj1(file, "a").stdout_text,
               "c67e:c6b1:b246:1744:fee1:4df8:cd58:58cd\n");
    expect_eq("single_ipv6/mode_4", run_proj1(file, "4").stdout_text, "");
    expect_eq("single_ipv6/mode_c", run_proj1(file, "c").stdout_text,
               "total addresses: 1\nIPv4 addresses: 0\nIPv6 addresses: 1\n");

    remove(file.c_str());
  }

  // Mixed IPv4/IPv6, order preserved.
  {
    std::vector<uint8_t> bytes;
    push_v4(bytes, 10, 0, 0, 1);
    push_v6(bytes, {0x0001, 0x0db8, 0, 0, 0, 0, 0, 0x0001});
    push_v4(bytes, 192, 168, 1, 1);
    std::string file = write_temp_file(bytes);

    expect_eq("mixed/mode_a", run_proj1(file, "a").stdout_text,
               "10.0.0.1\n0001:0db8:0000:0000:0000:0000:0000:0001\n192.168.1.1\n");
    expect_eq("mixed/mode_4", run_proj1(file, "4").stdout_text, "10.0.0.1\n192.168.1.1\n");
    expect_eq("mixed/mode_6", run_proj1(file, "6").stdout_text,
               "0001:0db8:0000:0000:0000:0000:0000:0001\n");
    expect_eq("mixed/mode_c", run_proj1(file, "c").stdout_text,
               "total addresses: 3\nIPv4 addresses: 2\nIPv6 addresses: 1\n");

    remove(file.c_str());
  }

  // Empty file: zero addresses, not an error.
  {
    std::vector<uint8_t> bytes;
    std::string file = write_temp_file(bytes);

    RunResult result = run_proj1(file, "c");
    expect_exit_code("empty_file/exit_code", result.exit_code, 0);
    expect_eq("empty_file/mode_c", result.stdout_text,
               "total addresses: 0\nIPv4 addresses: 0\nIPv6 addresses: 0\n");

    remove(file.c_str());
  }

  // Invalid version: must error out, not crash.
  {
    std::vector<uint8_t> bytes;
    push_version(bytes, 262);
    bytes.insert(bytes.end(), {0, 0, 0, 0});
    std::string file = write_temp_file(bytes);

    RunResult result = run_proj1(file, "a");
    expect_exit_code("invalid_version/exit_code", result.exit_code, 1);
    expect_eq("invalid_version/stdout_empty", result.stdout_text, "");

    remove(file.c_str());
  }

  // Nonexistent file.
  {
    RunResult result = run_proj1("/tmp/proj1_test_does_not_exist", "a");
    expect_exit_code("missing_file/exit_code", result.exit_code, 1);
  }

  std::cout << "\n"
            << (total_tests - failed_tests) << "/" << total_tests << " tests passed\n";

  return failed_tests == 0 ? 0 : 1;
}

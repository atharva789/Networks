#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <string>
#include <memory>
#include <sstream>
#include <iomanip>

struct IPAddress
{
  std::vector<uint8_t> address;

  IPAddress() {};
  IPAddress(std::vector<uint8_t> bytes) { address = bytes; };

  virtual std::string to_string() const = 0;
  virtual bool is_v4() const = 0;

  virtual ~IPAddress() = default;
};

struct IPV4Address : IPAddress
{
  explicit IPV4Address(std::vector<uint8_t> bytes) : IPAddress(std::move(bytes)) {};

  std::string to_string() const override
  {
    return std::to_string(address[0]) + "." +
           std::to_string(address[1]) + "." +
           std::to_string(address[2]) + "." +
           std::to_string(address[3]);
  };
  bool is_v4() const override
  {
    return true;
  };
};

struct IPV6Address : IPAddress
{
  explicit IPV6Address(std::vector<uint8_t> bytes) : IPAddress(std::move(bytes)) {};

  std::string to_string() const override
  {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < address.size(); i += 2)
    {
      uint16_t group = static_cast<uint16_t>(address[i]) | (static_cast<uint16_t>(address[i + 1]) << 8);
      if (i > 0)
      {
        oss << ":";
      }
      oss << std::setw(4) << group;
    }
    return oss.str();
  };

  bool is_v4() const override
  {
    return false;
  };
};

struct FileInformation
{
  std::string filename;
  std::vector<std::unique_ptr<IPAddress> > ip_addresses;

  void add(std::unique_ptr<IPAddress> ip)
  {
    ip_addresses.push_back(std::move(ip));
  }

  bool parse_file()
  {
    std::ifstream file(filename, std::ios::binary);
    if (!file)
    {
      std::cerr << "Error: could not open file '" << filename << "'\n";
      return false;
    }

    const int VERSION_BYTES = 2;
    const int IPv4_BYTES = 4;
    const int IPv6_BYTES = 16;

    std::vector<uint8_t> version_bytes(VERSION_BYTES);
    while (file.read(reinterpret_cast<char *>(version_bytes.data()), VERSION_BYTES))
    {
      uint16_t version = static_cast<uint16_t>(version_bytes[0]) |
                          (static_cast<uint16_t>(version_bytes[1]) << 8);

      if (version == 4)
      {
        std::vector<uint8_t> address_bytes(IPv4_BYTES);
        if (!file.read(reinterpret_cast<char *>(address_bytes.data()), IPv4_BYTES))
        {
          std::cerr << "Error: unexpected end of file while reading IPv4 address\n";
          return false;
        }
        add(std::make_unique<IPV4Address>(address_bytes));
      }
      else if (version == 6)
      {
        std::vector<uint8_t> address_bytes(IPv6_BYTES);
        if (!file.read(reinterpret_cast<char *>(address_bytes.data()), IPv6_BYTES))
        {
          std::cerr << "Error: unexpected end of file while reading IPv6 address\n";
          return false;
        }
        add(std::make_unique<IPV6Address>(address_bytes));
      }
      else
      {
        std::cerr << "Error: invalid IP version '" << version << "' in file '" << filename << "'\n";
        return false;
      }
    };

    return true;
  };

  int get_ip_v4_count() const
  {
    int count = 0;
    for (const auto &ip : ip_addresses)
    {
      if (ip->is_v4())
      {
        count++;
      }
    }
    return count;
  };

  int get_ip_v6_count() const
  {
    int count = 0;
    for (const auto &ip : ip_addresses)
    {
      if (!ip->is_v4())
      {
        count++;
      }
    }
    return count;
  };

  int get_total_count() const
  {
    return static_cast<int>(ip_addresses.size());
  };

  std::string count_mode() const
  {
    std::string out_str = "total addresses: " + std::to_string(get_total_count()) + "\nIPv4 addresses: " + std::to_string(get_ip_v4_count()) + "\nIPv6 addresses: " + std::to_string(get_ip_v6_count());

    return out_str;
  }

  std::string print_ip_addresses() const
  {
    std::string out_str = "";
    for (const auto &ip : ip_addresses)
    {
      out_str = out_str + ip->to_string() + "\n";
    }
    return out_str;
  };

  std::string print_ipv4_mode() const
  {
    std::string out_str = "";
    for (const auto &ip : ip_addresses)
    {
      if (ip->is_v4())
      {
        out_str = out_str + ip->to_string() + "\n";
      }
    }
    return out_str;
  };

  std::string print_ipv6_mode() const
  {
    std::string out_str = "";
    for (const auto &ip : ip_addresses)
    {
      if (!ip->is_v4())
      {
        out_str = out_str + ip->to_string() + "\n";
      }
    }
    return out_str;
  };
};

int main(int argc, char *argv[])
{
  if (argc != 3)
  {
    std::cerr << "Usage: " << argv[0] << " <filename> <mode: 4|6|a|c>\n";
    return 1;
  }

  FileInformation file_info;
  file_info.filename = argv[1];
  std::string mode = argv[2];

  if (!file_info.parse_file())
  {
    return 1;
  }

  if (mode == "4")
  {
    std::cout << file_info.print_ipv4_mode();
  }
  else if (mode == "6")
  {
    std::cout << file_info.print_ipv6_mode();
  }
  else if (mode == "a")
  {
    std::cout << file_info.print_ip_addresses();
  }
  else if (mode == "c")
  {
    std::cout << file_info.count_mode() << "\n";
  }
  else
  {
    std::cerr << "Error: unknown mode '" << mode << "'. Expected 4, 6, a, or c.\n";
    return 1;
  }

  return 0;
};

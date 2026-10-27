// Name: Atharva Gupta
// Case Network ID: axg1395
// date created: 10/02/2026
// date updated: 10/05/2026
// filename: proj2.cpp
// description: file contains all essentials structs, functions, methods. includes code for Forwarding Table print mode, packet dumping mode,
// router simulation mode. Argument parsing

// notes:
// proj2: a small IPv4 router simulator for binary forwarding tables and packet traces.
//
//   ./proj2 [-d] [-f] [-r] [-t forwarding_table] [-p trace_file]
//
// All file fields are big-endian and are decoded byte by byte, so nothing here
// depends on native struct layout or byte order. Both input files are streamed one
// record at a time; only the forwarding rules themselves are kept in memory.
// Only /8 rules are supported: a rule matches on the destination's first octet.

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>

namespace
{

  // command-line flags (one bit per option, as in the course sample)
  const unsigned kArgDump = 0x1;
  const unsigned kArgForwardTable = 0x2;
  const unsigned kArgRoute = 0x4;
  const unsigned kArgTableFile = 0x8;
  const unsigned kArgTraceFile = 0x10;
  const unsigned kModeFlags = kArgDump | kArgForwardTable | kArgRoute;
  // Leading ':' makes getopt report a missing value as ':' and stay quiet itself.
  const char *const kOptString = ":dfrt:p:";
  const char *const kOptionLetters = "dfrtp";

  // forwarding-table record layout (8 bytes)
  const size_t kTableRecordSize = 8;
  const size_t kTablePrefixLenOffset = 0;
  const size_t kTableIfaceOffset = 2;
  const size_t kTableAddrOffset = 4;

  // packet-trace record layout (32 bytes: 12 metadata + 20 IPv4 header)
  const size_t kPacketRecordSize = 32;
  const size_t kPacketIncomingOffset = 0;
  const size_t kPacketSecondsOffset = 4;
  const size_t kPacketMicrosOffset = 8;
  const size_t kPacketTtlOffset = 20;
  const size_t kPacketProtocolOffset = 21;
  const size_t kPacketChecksumOffset = 22;
  const size_t kPacketSrcOffset = 24;
  const size_t kPacketDstOffset = 28;

  // field sizes and address arithmetic
  const size_t kUint16Bytes = 2;
  const size_t kUint32Bytes = 4;
  const unsigned kBitsPerByte = 8;
  const unsigned kOctetMask = 0xFF;
  const uint32_t kDefaultRouteAddress = 0; // 0.0.0.0 marks the default rule

  // routing rules
  const uint16_t kGoodChecksum = 54321;
  const uint8_t kExpiredTtl = 1;
  const uint16_t kPolicyDropIface = 0;
  const uint32_t kMaxMicroseconds = 999999;
  const uint16_t kSupportedPrefixLen = 8;
  const size_t kFirstOctet = 0;
  const size_t kPrefixSpace = 256; // number of distinct /8 prefixes (first octets)

  struct Options
  {
    unsigned flags = 0;
    std::string tablePath;
    std::string tracePath;
  };

  struct TableRecord
  {
    uint16_t prefixLen;
    uint16_t iface;
    uint32_t addr;
  };

  struct Packet
  {
    uint16_t incoming;
    uint32_t seconds;
    uint32_t micros;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src;
    uint32_t dst;
  };

  // Forwarding information indexed by the first address octet. The default rule is
  // kept apart from the normal rules so it is only used when nothing else matches.
  struct RoutingTable
  {
    bool hasRule[kPrefixSpace] = {};
    uint16_t ruleIface[kPrefixSpace] = {};
    bool hasDefault = false;
    uint16_t defaultIface = 0;
  };

  // Result of a route lookup.
  struct RouteChoice
  {
    bool found;
    bool isDefault;
    uint16_t iface;
  };

  // small helpers

  // Decodes `numBytes` big-endian bytes into an unsigned integer.
  uint32_t decodeBigEndian(const uint8_t *bytes, size_t numBytes)
  {
    uint32_t value = 0;
    for (size_t i = 0; i < numBytes; i++)
    {
      value = (value << kBitsPerByte) | bytes[i];
    }
    return value;
  }

  // Returns octet `index` (0 = leftmost) of a host-order IPv4 address.
  unsigned octet(uint32_t addr, size_t index)
  {
    unsigned shift = static_cast<unsigned>((kUint32Bytes - 1 - index) * kBitsPerByte);
    return (addr >> shift) & kOctetMask;
  }

  void printAddress(uint32_t addr)
  {
    printf("%u.%u.%u.%u", octet(addr, 0), octet(addr, 1), octet(addr, 2), octet(addr, 3));
  }

  // argument parsing

  void usage(const char *progname)
  {
    fprintf(stderr, "usage: %s [-d] [-f] [-r] [-t forwarding_table] [-p trace_file]\n", progname);
    fprintf(stderr, "   -f    print the forwarding table (needs -t)\n");
    fprintf(stderr, "   -d    dump packet metadata (needs -p)\n");
    fprintf(stderr, "   -r    simulate routing (needs -t and -p)\n");
    exit(EXIT_FAILURE);
  }

  void argError(const char *progname, const std::string &msg)
  {
    fprintf(stderr, "proj2: %s\n", msg.c_str());
    usage(progname);
  }

  // getopt would happily take "-d" as the value of "-t"; treat that as a missing filename.
  bool looksLikeOption(const char *arg)
  {
    return arg[0] == '-' && arg[1] != '\0' && strchr(kOptionLetters, arg[1]) != nullptr && arg[2] == '\0';
  }

  void setFlag(Options &opts, unsigned flag, int opt, const char *progname)
  {
    if (opts.flags & flag)
      argError(progname, std::string("option '-") + static_cast<char>(opt) + "' given more than once");
    opts.flags |= flag;
  }

  void setFileOption(Options &opts, unsigned flag, int opt, std::string &path, const char *progname)
  {
    setFlag(opts, flag, opt, progname);
    if (looksLikeOption(optarg))
      argError(progname, std::string("option '-") + static_cast<char>(opt) + "' requires a filename");
    path = optarg;
  }

  void checkModeRequirements(const Options &opts, const char *progname)
  {
    unsigned modes = opts.flags & kModeFlags;
    if (modes == 0)
      argError(progname, "no mode given (use exactly one of -f, -d, -r)");
    if (modes != kArgDump && modes != kArgForwardTable && modes != kArgRoute)
      argError(progname, "multiple modes given (use exactly one of -f, -d, -r)");
    bool needTable = (modes & (kArgForwardTable | kArgRoute)) != 0;
    bool needTrace = (modes & (kArgDump | kArgRoute)) != 0;
    if (needTable && !(opts.flags & kArgTableFile))
      argError(progname, "this mode requires -t forwarding_table");
    if (needTrace && !(opts.flags & kArgTraceFile))
      argError(progname, "this mode requires -p trace_file");
  }

  Options parseArgs(int argc, char *argv[])
  {
    Options opts;
    int opt;
    while ((opt = getopt(argc, argv, kOptString)) != -1)
    {
      switch (opt)
      {
      case 'd':
        setFlag(opts, kArgDump, opt, argv[0]);
        break;
      case 'f':
        setFlag(opts, kArgForwardTable, opt, argv[0]);
        break;
      case 'r':
        setFlag(opts, kArgRoute, opt, argv[0]);
        break;
      case 't':
        setFileOption(opts, kArgTableFile, opt, opts.tablePath, argv[0]);
        break;
      case 'p':
        setFileOption(opts, kArgTraceFile, opt, opts.tracePath, argv[0]);
        break;
      case ':':
        argError(argv[0], std::string("option '-") + static_cast<char>(optopt) + "' requires a filename");
        break;
      case '?':
      default:
        argError(argv[0], std::string("unknown option '-") + static_cast<char>(optopt) + "'");
      }
    }
    if (optind < argc)
      argError(argv[0], std::string("unexpected argument '") + argv[optind] + "'");
    checkModeRequirements(opts, argv[0]);
    return opts;
  }

  // record reading

  FILE *openInput(const std::string &path, std::string &err)
  {
    FILE *fp = fopen(path.c_str(), "rb");
    if (fp == nullptr)
      err = "cannot open '" + path + "': " + strerror(errno);
    return fp;
  }

  // Reads exactly `size` bytes. Returns 1 on success, 0 on clean EOF, -1 on a
  // partial record or read error (with `err` filled in).
  int readRecord(FILE *fp, uint8_t *buf, size_t size, const std::string &path, std::string &err)
  {
    size_t got = fread(buf, 1, size, fp);
    if (got == size)
      return 1;
    if (ferror(fp))
    {
      err = "read error on '" + path + "': " + strerror(errno);
      return -1;
    }
    if (got == 0)
      return 0;
    err = "'" + path + "' ends with a partial record (" + std::to_string(got) + " of " +
          std::to_string(size) + " bytes)";
    return -1;
  }

  // Reads and validates the next table record. Same return convention as readRecord.
  int readTableRecord(FILE *fp, const std::string &path, size_t recordNumber, TableRecord &rec,
                      std::string &err)
  {
    uint8_t buf[kTableRecordSize];
    int status = readRecord(fp, buf, sizeof buf, path, err);
    if (status != 1)
      return status;
    rec.prefixLen = static_cast<uint16_t>(decodeBigEndian(buf + kTablePrefixLenOffset, kUint16Bytes));
    rec.iface = static_cast<uint16_t>(decodeBigEndian(buf + kTableIfaceOffset, kUint16Bytes));
    rec.addr = decodeBigEndian(buf + kTableAddrOffset, kUint32Bytes);
    if (rec.prefixLen != kSupportedPrefixLen)
    {
      err = "'" + path + "' record " + std::to_string(recordNumber) + ": unsupported prefix length " +
            std::to_string(rec.prefixLen) + " (only 8 is supported)";
      return -1;
    }
    return 1;
  }

  Packet decodePacket(const uint8_t *buf)
  {
    Packet p;
    p.incoming = static_cast<uint16_t>(decodeBigEndian(buf + kPacketIncomingOffset, kUint16Bytes));
    p.seconds = decodeBigEndian(buf + kPacketSecondsOffset, kUint32Bytes);
    p.micros = decodeBigEndian(buf + kPacketMicrosOffset, kUint32Bytes);
    p.ttl = buf[kPacketTtlOffset];
    p.protocol = buf[kPacketProtocolOffset];
    p.checksum = static_cast<uint16_t>(decodeBigEndian(buf + kPacketChecksumOffset, kUint16Bytes));
    p.src = decodeBigEndian(buf + kPacketSrcOffset, kUint32Bytes);
    p.dst = decodeBigEndian(buf + kPacketDstOffset, kUint32Bytes);
    return p;
  }

  // -f: table printing

  bool printTable(const std::string &path, std::string &err)
  {
    FILE *fp = openInput(path, err);
    if (fp == nullptr)
      return false;
    TableRecord rec;
    size_t recordNumber = 1;
    int status;
    while ((status = readTableRecord(fp, path, recordNumber, rec, err)) == 1 && !ferror(stdout))
    {
      printAddress(rec.addr);
      printf(" %u %u\n", rec.prefixLen, rec.iface);
      recordNumber++;
    }
    fclose(fp);
    return status == 0;
  }

  // -r: routing table

  // Adds one rule, rejecting a duplicate /8 prefix. 10.0.0.0, 10.1.1.1 and 10.0.0.2 are
  // all the same prefix. The default 0.0.0.0 counts as prefix 0, so it conflicts with
  // e.g. 0.1.2.3/8.
  bool addRoute(RoutingTable &table, const TableRecord &rec, size_t recordNumber, std::string &err)
  {
    unsigned prefix = octet(rec.addr, kFirstOctet);
    bool isDefault = rec.addr == kDefaultRouteAddress;
    bool prefixTaken = table.hasRule[prefix] || (prefix == octet(kDefaultRouteAddress, kFirstOctet) &&
                                                 table.hasDefault);
    if (prefixTaken)
    {
      err = "forwarding table record " + std::to_string(recordNumber) + ": duplicate prefix " +
            std::to_string(prefix) + ".0.0.0/8";
      return false;
    }
    if (isDefault)
    {
      table.hasDefault = true;
      table.defaultIface = rec.iface;
    }
    else
    {
      table.hasRule[prefix] = true;
      table.ruleIface[prefix] = rec.iface;
    }
    return true;
  }

  bool loadRoutingTable(const std::string &path, RoutingTable &table, std::string &err)
  {
    FILE *fp = openInput(path, err);
    if (fp == nullptr)
      return false;
    TableRecord rec;
    size_t recordNumber = 1;
    int status;
    while ((status = readTableRecord(fp, path, recordNumber, rec, err)) == 1)
    {
      if (!addRoute(table, rec, recordNumber, err))
      {
        status = -1;
        break;
      }
      recordNumber++;
    }
    fclose(fp);
    return status == 0;
  }

  // Matches on the destination's first octet; falls back to the default rule.
  RouteChoice lookupRoute(const RoutingTable &table, uint32_t dst)
  {
    unsigned prefix = octet(dst, kFirstOctet);
    if (table.hasRule[prefix])
      return RouteChoice{true, false, table.ruleIface[prefix]};
    return RouteChoice{table.hasDefault, true, table.defaultIface};
  }

  // per-packet output

  void printTimestamp(const Packet &p)
  {
    printf("%u.%06u", p.seconds, p.micros);
  }

  void printDump(const Packet &p)
  {
    printTimestamp(p);
    printf(" %u ", p.incoming);
    printAddress(p.src);
    putchar(' ');
    printAddress(p.dst);
    printf(" %u %u %c\n", p.ttl, p.protocol, p.checksum == kGoodChecksum ? 'C' : 'I');
  }

  // Applies the routing rules in their required order; the first match wins.
  void printRoute(const Packet &p, const RoutingTable &table)
  {
    printTimestamp(p);
    if (p.checksum != kGoodChecksum)
    {
      printf(" drop checksum\n");
      return;
    }
    if (p.ttl == kExpiredTtl)
    {
      printf(" drop expired\n");
      return;
    }
    RouteChoice choice = lookupRoute(table, p.dst);
    if (!choice.found)
      printf(" drop unknown\n");
    else if (choice.iface == p.incoming)
      printf(" drop loop %u\n", choice.iface);
    else if (choice.iface == kPolicyDropIface)
      printf(" drop policy\n");
    else if (choice.isDefault)
      printf(" default %u\n", choice.iface);
    else
      printf(" send %u\n", choice.iface);
  }

  // Streams the trace one record at a time. `table == nullptr` means dump mode (-d).
  bool processTrace(const std::string &path, const RoutingTable *table, std::string &err)
  {
    FILE *fp = openInput(path, err);
    if (fp == nullptr)
      return false;
    uint8_t buf[kPacketRecordSize];
    size_t recordNumber = 1;
    int status;
    while ((status = readRecord(fp, buf, sizeof buf, path, err)) == 1 && !ferror(stdout))
    {
      Packet p = decodePacket(buf);
      if (p.micros > kMaxMicroseconds)
      {
        err = "'" + path + "' record " + std::to_string(recordNumber) + ": microseconds " +
              std::to_string(p.micros) + " out of range (0..999999)";
        status = -1;
        break;
      }
      if (table == nullptr)
        printDump(p);
      else
        printRoute(p, *table);
      recordNumber++;
    }
    fclose(fp);
    return status == 0;
  }

  bool runMode(const Options &opts, std::string &err)
  {
    if (opts.flags & kArgForwardTable)
      return printTable(opts.tablePath, err);
    if (opts.flags & kArgDump)
      return processTrace(opts.tracePath, nullptr, err);
    // The table is fully validated before the first packet is read.
    RoutingTable table;
    return loadRoutingTable(opts.tablePath, table, err) && processTrace(opts.tracePath, &table, err);
  }

} // namespace

int main(int argc, char *argv[])
{
  Options opts = parseArgs(argc, argv);
  std::string err;
  bool ok = runMode(opts, err);
  if (fflush(stdout) != 0 || ferror(stdout))
  {
    if (ok)
      err = "write error on standard output";
    ok = false;
  }
  if (!ok)
  {
    fprintf(stderr, "proj2: %s\n", err.c_str());
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

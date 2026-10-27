// Name: Atharva Gupta
// Case Network ID: axg1395
// date created: 10/02/2026
// date updated: 10/05/2026
// filename: tests.cpp
// description: automated tests for proj2. Builds binary forwarding tables and packet
// traces, runs ./proj2, and compares standard output byte-for-byte. Also checks exit
// status and standard error for error cases, and runs the course sample files.

// notes:
//   ./tests [samples_dir]      (default samples_dir: "samples")
//
// Generated fixtures are named test_tmp_* in the current directory and are removed
// at the end. Sample cases whose files are missing are reported as skipped.

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace
{

  const char *const kProgram = "./proj2";
  const char *const kTmpPrefix = "test_tmp_";
  const char *const kDefaultSamplesDir = "samples";
  const char *const kMissingFile = "test_tmp_does_not_exist.bin";

  const unsigned kBitsPerByte = 8;
  const unsigned kBitsPerUint16 = 16;
  const size_t kTableRecordSize = 8;
  const size_t kPacketRecordSize = 32;
  const char *const kDefaultTimestamp = "100.000001 "; // timestamp of the default packet P()
  const unsigned kByteMask = 0xFF;
  const size_t kIpv4Bytes = 4;
  const uint16_t kDefaultPrefixLen = 8;
  const unsigned kMaxOctet = 255;
  const unsigned long kMaxUint16 = 0xFFFF;
  const unsigned long kMaxUint32 = 0xFFFFFFFFUL;

  // Fixed part of the 20-byte IPv4 header before TTL: version 4/IHL 5, total length 20.
  const uint8_t kHeaderPrefix[] = {0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00};

  // Large-trace pattern: every Nth packet has a bad checksum / TTL of 1.
  const unsigned long kBigTraceCount = 100000;
  const unsigned long kBadChecksumEvery = 7;
  const unsigned long kExpiredEvery = 10;
  const unsigned long kMicrosPerSecond = 1000000;
  const size_t kLineBufferSize = 64;

  struct PacketSpec
  {
    uint32_t seconds = 100;
    uint32_t micros = 1;
    uint16_t incoming = 7;
    uint16_t padding = 0;
    uint8_t src[kIpv4Bytes] = {192, 168, 1, 2};
    uint8_t dst[kIpv4Bytes] = {10, 9, 8, 7};
    uint8_t ttl = 64;
    uint8_t protocol = 6;
    uint16_t checksum = 54321;
  };

  struct RunResult
  {
    bool success; // exit status zero
    std::string out;
    std::string err;
  };

  struct Stats
  {
    int passed = 0;
    int failed = 0;
    int skipped = 0;
  };

  Stats stats;
  std::vector<std::string> createdFiles;

  // reporting

  void pass() { stats.passed++; }

  void failTest(const std::string &name, const std::string &why)
  {
    stats.failed++;
    printf("FAIL: %s (%s)\n", name.c_str(), why.c_str());
  }

  void skipTest(const std::string &name, const std::string &why)
  {
    stats.skipped++;
    printf("SKIP: %s (%s)\n", name.c_str(), why.c_str());
  }

  // file helpers

  std::string tmpPath(const std::string &name)
  {
    std::string path = kTmpPrefix + name;
    createdFiles.push_back(path);
    return path;
  }

  bool fileExists(const std::string &path)
  {
    std::ifstream in(path, std::ios::binary);
    return in.good();
  }

  std::string readFile(const std::string &path)
  {
    std::ifstream in(path, std::ios::binary);
    std::ostringstream contents;
    contents << in.rdbuf();
    return contents.str();
  }

  void writeFile(const std::string &path, const std::string &data)
  {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(data.data(), static_cast<std::streamsize>(data.size()));
    if (!out)
    {
      fprintf(stderr, "tests: cannot write %s\n", path.c_str());
      exit(EXIT_FAILURE);
    }
  }

  void removeCreatedFiles()
  {
    for (const std::string &path : createdFiles)
      std::remove(path.c_str());
  }

  // fixture bytes

  void put16(std::string &out, uint16_t value)
  {
    out.push_back(static_cast<char>((value >> kBitsPerByte) & kByteMask));
    out.push_back(static_cast<char>(value & kByteMask));
  }

  void put32(std::string &out, uint32_t value)
  {
    put16(out, static_cast<uint16_t>(value >> kBitsPerUint16));
    put16(out, static_cast<uint16_t>(value & kMaxUint16));
  }

  void putAddress(std::string &out, const uint8_t addr[kIpv4Bytes])
  {
    out.append(reinterpret_cast<const char *>(addr), kIpv4Bytes);
  }

  void parseAddress(const std::string &text, uint8_t out[kIpv4Bytes])
  {
    unsigned octets[kIpv4Bytes];
    char extra;
    int matched = sscanf(text.c_str(), "%u.%u.%u.%u%c", &octets[0], &octets[1], &octets[2], &octets[3], &extra);
    if (matched != static_cast<int>(kIpv4Bytes))
    {
      fprintf(stderr, "tests: bad address '%s'\n", text.c_str());
      exit(EXIT_FAILURE);
    }
    for (size_t i = 0; i < kIpv4Bytes; i++)
    {
      if (octets[i] > kMaxOctet)
      {
        fprintf(stderr, "tests: bad address '%s'\n", text.c_str());
        exit(EXIT_FAILURE);
      }
      out[i] = static_cast<uint8_t>(octets[i]);
    }
  }

  // R(address, interface[, prefix]) from the spec.
  std::string tableRecord(const std::string &addr, uint16_t iface, uint16_t prefixLen = kDefaultPrefixLen)
  {
    uint8_t bytes[kIpv4Bytes];
    parseAddress(addr, bytes);
    std::string out;
    put16(out, prefixLen);
    put16(out, iface);
    putAddress(out, bytes);
    return out;
  }

  uint32_t parseNumber(const std::string &text, unsigned long max)
  {
    char *end = nullptr;
    unsigned long value = strtoul(text.c_str(), &end, 0);
    if (text.empty() || *end != '\0' || value > max)
    {
      fprintf(stderr, "tests: bad number '%s'\n", text.c_str());
      exit(EXIT_FAILURE);
    }
    return static_cast<uint32_t>(value);
  }

  void applyPacketField(PacketSpec &p, const std::string &key, const std::string &val)
  {
    if (key == "seconds")
      p.seconds = parseNumber(val, kMaxUint32);
    else if (key == "microseconds")
      p.micros = parseNumber(val, kMaxUint32);
    else if (key == "incoming")
      p.incoming = static_cast<uint16_t>(parseNumber(val, kMaxUint16));
    else if (key == "padding")
      p.padding = static_cast<uint16_t>(parseNumber(val, kMaxUint16));
    else if (key == "source")
      parseAddress(val, p.src);
    else if (key == "destination")
      parseAddress(val, p.dst);
    else if (key == "ttl")
      p.ttl = static_cast<uint8_t>(parseNumber(val, kMaxOctet));
    else if (key == "protocol")
      p.protocol = static_cast<uint8_t>(parseNumber(val, kMaxOctet));
    else if (key == "checksum")
      p.checksum = static_cast<uint16_t>(parseNumber(val, kMaxUint16));
    else
    {
      fprintf(stderr, "tests: unknown packet field '%s'\n", key.c_str());
      exit(EXIT_FAILURE);
    }
  }

  // Parses "key=value,key=value" overrides of the default packet; "" means P().
  PacketSpec parsePacketSpec(const std::string &spec)
  {
    PacketSpec p;
    std::istringstream fields(spec);
    std::string field;
    while (std::getline(fields, field, ','))
    {
      size_t eq = field.find('=');
      if (eq == std::string::npos)
      {
        fprintf(stderr, "tests: bad packet field '%s'\n", field.c_str());
        exit(EXIT_FAILURE);
      }
      applyPacketField(p, field.substr(0, eq), field.substr(eq + 1));
    }
    return p;
  }

  std::string packetRecord(const PacketSpec &p)
  {
    std::string out;
    put16(out, p.incoming);
    put16(out, p.padding);
    put32(out, p.seconds);
    put32(out, p.micros);
    out.append(reinterpret_cast<const char *>(kHeaderPrefix), sizeof kHeaderPrefix);
    out.push_back(static_cast<char>(p.ttl));
    out.push_back(static_cast<char>(p.protocol));
    put16(out, p.checksum);
    putAddress(out, p.src);
    putAddress(out, p.dst);
    return out;
  }

  // P(spec) for each spec, concatenated.
  std::string trace(const std::vector<std::string> &specs)
  {
    std::string out;
    for (const std::string &spec : specs)
      out += packetRecord(parsePacketSpec(spec));
    return out;
  }

  std::string writeTmp(const std::string &name, const std::string &data)
  {
    std::string path = tmpPath(name);
    writeFile(path, data);
    return path;
  }

  // running proj2

  RunResult runProgram(const std::string &args)
  {
    static const std::string outPath = tmpPath("stdout.txt");
    static const std::string errPath = tmpPath("stderr.txt");
    std::string command = std::string(kProgram) + " " + args + " >" + outPath + " 2>" + errPath;
    int status = std::system(command.c_str());
    return RunResult{status == 0, readFile(outPath), readFile(errPath)};
  }

  std::string toLower(std::string text)
  {
    for (char &c : text)
      c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    return text;
  }

  // Exit 0, empty stderr, stdout exactly `expected`.
  void expectOutput(const std::string &name, const std::string &args, const std::string &expected)
  {
    RunResult r = runProgram(args);
    if (!r.success)
      failTest(name, "nonzero exit: " + r.err);
    else if (!r.err.empty())
      failTest(name, "unexpected stderr: " + r.err);
    else if (r.out != expected)
      failTest(name, "stdout differs");
    else
      pass();
  }

  // Nonzero exit and a diagnostic containing `pattern`. Unless `allowOutput`, stdout must be empty.
  void expectError(const std::string &name, const std::string &args, const std::string &pattern,
                   bool allowOutput = false)
  {
    RunResult r = runProgram(args);
    if (r.success)
      failTest(name, "exit status 0");
    else if (!allowOutput && !r.out.empty())
      failTest(name, "stdout not empty");
    else if (toLower(r.err).find(toLower(pattern)) == std::string::npos)
      failTest(name, "stderr lacks '" + pattern + "': " + r.err);
    else
      pass();
  }

  std::string lines(const std::vector<std::string> &items)
  {
    std::string out;
    for (const std::string &item : items)
      out += item + "\n";
    return out;
  }

  // One packet through -r; expects "100.000001 <action>".
  void expectRoute(const std::string &name, const std::string &table, const std::string &spec,
                   const std::string &action)
  {
    std::string tracePath = writeTmp("one.bin", trace({spec}));
    expectOutput(name, "-r -t " + table + " -p " + tracePath, kDefaultTimestamp + action + "\n");
  }

  // test groups

  void testFixtureBytes()
  {
    const std::string expectedRule("\x00\x08\x00\x04\x0A\x01\x02\x03", kTableRecordSize);
    const std::string expectedPacket("\x00\x07\x00\x00\x00\x00\x00\x64\x00\x00\x00\x01"
                                     "\x45\x00\x00\x14\x00\x00\x00\x00\x40\x06\xD4\x31"
                                     "\xC0\xA8\x01\x02\x0A\x09\x08\x07",
                                     kPacketRecordSize);
    tableRecord("10.1.2.3", 4) == expectedRule ? pass() : failTest("R(10.1.2.3, 4) bytes", "mismatch");
    trace({""}) == expectedPacket ? pass() : failTest("P() bytes", "mismatch");
  }

  void testTablePrinting()
  {
    std::string table = writeTmp("t51.bin", tableRecord("189.1.1.1", 40) + tableRecord("0.0.0.0", 3) +
                                                tableRecord("10.1.2.3", 4) + tableRecord("128.1.0.0", 100) +
                                                tableRecord("255.254.253.252", 65535));
    std::string expected = lines({"189.1.1.1 8 40", "0.0.0.0 8 3", "10.1.2.3 8 4", "128.1.0.0 8 100",
                                  "255.254.253.252 8 65535"});
    expectOutput("-f table", "-f -t " + table, expected);
    expectOutput("-t before -f", "-t " + table + " -f", expected);
    expectOutput("-f ignores unused -p", "-f -t " + table + " -p " + kMissingFile, expected);

    std::string dup = writeTmp("dup.bin", tableRecord("10.0.0.0", 4) + tableRecord("10.1.1.1", 5) +
                                              tableRecord("10.0.0.0", 4));
    expectOutput("-f allows duplicates", "-f -t " + dup, lines({"10.0.0.0 8 4", "10.1.1.1 8 5", "10.0.0.0 8 4"}));
    expectOutput("-f empty table", "-f -t " + writeTmp("empty_t.bin", ""), "");
  }

  void testPacketDump()
  {
    std::string t52 = writeTmp("t52.bin", trace({"", "seconds=4294967295,microseconds=999999,incoming=65535,"
                                                     "padding=0xABCD,source=0.0.0.0,destination=255.255.255.255,"
                                                     "ttl=255,protocol=255,checksum=54320"}));
    expectOutput("-d dump", "-d -p " + t52,
                 lines({"100.000001 7 192.168.1.2 10.9.8.7 64 6 C",
                        "4294967295.999999 65535 0.0.0.0 255.255.255.255 255 255 I"}));
    std::string micros = writeTmp("us.bin", trace({"microseconds=0", "microseconds=100000"}));
    expectOutput("-d microsecond padding", "-d -p " + micros,
                 lines({"100.000000 7 192.168.1.2 10.9.8.7 64 6 C", "100.100000 7 192.168.1.2 10.9.8.7 64 6 C"}));
    expectOutput("-d empty trace", "-d -p " + writeTmp("empty_p.bin", ""), "");
    std::string dropped = writeTmp("ttl.bin", trace({"ttl=1,checksum=0"}));
    std::string droppedLine = lines({"100.000001 7 192.168.1.2 10.9.8.7 1 6 I"});
    expectOutput("-d shows dropped packets with original TTL", "-d -p " + dropped, droppedLine);
    expectOutput("-d ignores unused -t", std::string("-d -t ") + kMissingFile + " -p " + dropped, droppedLine);
  }

  // Section 5.3: each row alone, then all rows as one trace, then with a reordered table.
  void testDefaultRouteTable()
  {
    const std::vector<std::pair<std::string, std::string>> rows = {
        {"", "send 4"},
        {"destination=10.255.255.255", "send 4"},
        {"destination=30.1.2.3", "default 9"},
        {"destination=0.1.2.3", "default 9"},
        {"incoming=4", "drop loop 4"},
        {"destination=20.1.2.3", "drop policy"},
        {"destination=20.1.2.3,incoming=0", "drop loop 0"},
        {"destination=30.1.2.3,incoming=9", "drop loop 9"},
        {"ttl=1", "drop expired"},
        {"ttl=1,incoming=4", "drop expired"},
        {"ttl=1,destination=20.1.2.3", "drop expired"},
        {"checksum=0,ttl=1,incoming=4", "drop checksum"},
        {"checksum=54320,destination=20.1.2.3", "drop checksum"},
        {"ttl=0", "send 4"},
    };
    std::string table = writeTmp("tdef.bin", tableRecord("10.1.2.3", 4) + tableRecord("20.0.0.0", 0) +
                                                 tableRecord("0.0.0.0", 9));
    std::vector<std::string> specs;
    std::string expected;
    for (const auto &row : rows)
    {
      expectRoute("route [" + row.first + "]", table, row.first, row.second);
      specs.push_back(row.first);
      expected += kDefaultTimestamp + row.second + "\n";
    }
    std::string combined = writeTmp("comb.bin", trace(specs));
    expectOutput("combined trace", "-r -t " + table + " -p " + combined, expected);
    expectOutput("-p -r -t order", "-p " + combined + " -r -t " + table, expected);
    std::string reordered = writeTmp("tdef2.bin", tableRecord("0.0.0.0", 9) + tableRecord("20.0.0.0", 0) +
                                                      tableRecord("10.1.2.3", 4));
    expectOutput("reordered table", "-r -t " + reordered + " -p " + combined, expected);
    expectOutput("empty trace with valid table", "-r -t " + table + " -p " + writeTmp("empty_p.bin", ""), "");
  }

  void testOtherRouting()
  {
    std::string empty = writeTmp("empty_t.bin", "");
    expectRoute("no match, no default", writeTmp("t10.bin", tableRecord("10.0.0.0", 4)), "destination=30.1.2.3",
                "drop unknown");
    expectRoute("empty table", empty, "", "drop unknown");
    expectRoute("empty table, TTL 1", empty, "ttl=1", "drop expired");
    expectRoute("empty table, bad checksum", empty, "checksum=0,ttl=1", "drop checksum");
    std::string nullDefault = writeTmp("tdef0.bin", tableRecord("0.0.0.0", 0));
    expectRoute("default to interface 0", nullDefault, "", "drop policy");
    expectRoute("default 0, incoming 0", nullDefault, "incoming=0", "drop loop 0");
    expectRoute("0/8 without default is normal", writeTmp("t0.bin", tableRecord("0.1.2.3", 12)),
                "destination=0.9.8.7", "send 12");
    expectRoute("max interface", writeTmp("t255.bin", tableRecord("255.0.0.0", 65535)), "destination=255.1.2.3",
                "send 65535");
  }

  void testDuplicates()
  {
    const std::vector<std::string> tables = {
        tableRecord("10.0.0.0", 4) + tableRecord("10.1.1.1", 5),
        tableRecord("10.0.0.0", 4) + tableRecord("10.0.0.0", 4),
        tableRecord("0.0.0.0", 1) + tableRecord("0.0.0.0", 2),
        tableRecord("0.0.0.0", 9) + tableRecord("0.1.2.3", 12),
    };
    std::string oneTrace = writeTmp("one.bin", trace({""}));
    std::string emptyTrace = writeTmp("empty_p.bin", "");
    for (size_t i = 0; i < tables.size(); i++)
    {
      std::string name = "duplicate table " + std::to_string(i + 1);
      std::string path = writeTmp("dup" + std::to_string(i + 1) + ".bin", tables[i]);
      expectError(name, "-r -t " + path + " -p " + oneTrace, "duplicate");
      expectError(name + ", empty trace", "-r -t " + path + " -p " + emptyTrace, "duplicate");
    }
  }

  void testCommandLineErrors()
  {
    std::string table = writeTmp("t10.bin", tableRecord("10.0.0.0", 4));
    std::string packets = writeTmp("one.bin", trace({""}));
    expectError("no arguments", "", "usage");
    expectError("no mode", "-t " + table, "no mode");
    expectError("multiple modes", "-f -d -t " + table + " -p " + packets, "multiple");
    expectError("repeated mode", "-f -f -t " + table, "more than once");
    expectError("repeated -t", "-f -t " + table + " -t " + table, "more than once");
    expectError("repeated -p", "-d -p " + packets + " -p " + packets, "more than once");
    expectError("-f without -t", "-f", "requires -t");
    expectError("-d without -p", "-d", "requires -p");
    expectError("-r without -t", "-r -p " + packets, "requires -t");
    expectError("-r without -p", "-r -t " + table, "requires -p");
    expectError("-t without filename", "-f -t", "requires a filename");
    expectError("-p without filename", "-d -p", "requires a filename");
    expectError("-t followed by an option", "-f -t -d", "requires a filename");
    expectError("unknown option", "-x", "unknown option");
    expectError("positional argument", "-f -t " + table + " stray", "unexpected argument");
    expectError("missing table file", std::string("-f -t ") + kMissingFile, "cannot open");
    expectError("missing trace file", std::string("-d -p ") + kMissingFile, "cannot open");
    expectError("missing table file in -r", std::string("-r -t ") + kMissingFile + " -p " + packets, "cannot open");
    expectError("missing trace file in -r", "-r -t " + table + " -p " + kMissingFile, "cannot open");
  }

  void testMalformedInput()
  {
    std::string table = tableRecord("10.0.0.0", 4) + tableRecord("20.0.0.0", 5);
    std::string packet = trace({""});
    std::string partialTable = writeTmp("partial_t.bin", table.substr(0, table.size() - 1));
    std::string emptyTrace = writeTmp("empty_p.bin", "");
    expectError("partial table record", "-f -t " + partialTable, "partial", true);
    expectError("partial table record in -r", "-r -t " + partialTable + " -p " + emptyTrace, "partial");
    std::string partialOnly = writeTmp("partial_p.bin", packet.substr(0, packet.size() - 1));
    expectError("partial trace record", "-d -p " + partialOnly, "partial");
    std::string partialAfter = writeTmp("partial_p2.bin", packet + packet.substr(0, packet.size() - 1));
    expectError("partial final trace record (-d)", "-d -p " + partialAfter, "partial", true);
    std::string goodTable = writeTmp("t10.bin", tableRecord("10.0.0.0", 4));
    expectError("partial final trace record (-r)", "-r -t " + goodTable + " -p " + partialAfter, "partial", true);
    std::string wideTable = writeTmp("p16.bin", tableRecord("10.0.0.0", 4, 16));
    expectError("prefix length 16 (-f)", "-f -t " + wideTable, "prefix");
    expectError("prefix length 16 (-r)", "-r -t " + wideTable + " -p " + emptyTrace, "prefix");
    std::string badMicros = writeTmp("badus.bin", trace({"microseconds=1000000"}));
    expectError("microseconds 1000000 (-d)", "-d -p " + badMicros, "microseconds");
    expectError("microseconds 1000000 (-r)", "-r -t " + goodTable + " -p " + badMicros, "microseconds");
  }

  // Packet i has seconds = i, microseconds = i; some have bad checksums or TTL 1.
  void testLargeTrace()
  {
    std::string data;
    std::string expected;
    char line[kLineBufferSize];
    for (unsigned long i = 0; i < kBigTraceCount; i++)
    {
      PacketSpec p;
      p.seconds = static_cast<uint32_t>(i);
      p.micros = static_cast<uint32_t>(i % kMicrosPerSecond);
      bool badChecksum = i % kBadChecksumEvery == 0;
      bool expired = i % kExpiredEvery == 0;
      if (badChecksum)
        p.checksum = 0;
      if (expired)
        p.ttl = 1;
      data += packetRecord(p);
      const char *action = badChecksum ? "drop checksum" : (expired ? "drop expired" : "send 4");
      snprintf(line, sizeof line, "%u.%06u %s\n", p.seconds, p.micros, action);
      expected += line;
    }
    std::string table = writeTmp("t10.bin", tableRecord("10.0.0.0", 4));
    expectOutput("100000-record trace", "-r -t " + table + " -p " + writeTmp("big.bin", data), expected);
  }

  // course sample files

  struct SampleCase
  {
    int number;
    char mode; // 'f', 'd' or 'r'
    bool variablePrefix; // uses /16, /24 or /32 rules: outside this project's /8 scope
  };

  const SampleCase kSamples[] = {
      {1, 'f', false}, {2, 'f', false}, {5, 'd', false}, {6, 'd', false}, {7, 'd', false},
      {8, 'd', false}, {8, 'f', false}, {8, 'r', false}, {9, 'f', false}, {10, 'f', true},
      {11, 'd', false}, {12, 'd', false}, {13, 'd', false}, {14, 'd', false}, {14, 'f', false},
      {15, 'd', false}, {15, 'f', false}, {16, 'd', false}, {16, 'f', true}, {16, 'r', true},
      {17, 'd', false}, {17, 'f', false}, {17, 'r', false}, {18, 'd', false}, {18, 'f', true},
      {18, 'r', true},
  };

  void runSample(const std::string &dir, const SampleCase &sample)
  {
    std::string base = dir + "/samp-" + std::to_string(sample.number);
    std::string expectedPath = base + "-" + sample.mode + ".out";
    std::string name = "sample " + std::to_string(sample.number) + " -" + sample.mode;
    if (sample.variablePrefix)
    {
      skipTest(name, "variable-length prefixes; only /8 is supported");
      return;
    }
    if (!fileExists(expectedPath))
    {
      skipTest(name, expectedPath + " not found");
      return;
    }
    std::string args = std::string("-") + sample.mode;
    if (sample.mode != 'd')
      args += " -t " + base + ".tbl";
    if (sample.mode != 'f')
      args += " -p " + base + ".trace";
    expectOutput(name, args, readFile(expectedPath));
  }

  void testSamples(const std::string &dir)
  {
    for (const SampleCase &sample : kSamples)
      runSample(dir, sample);
  }

} // namespace

int main(int argc, char *argv[])
{
  std::string samplesDir = argc > 1 ? argv[1] : kDefaultSamplesDir;
  if (!fileExists(kProgram))
  {
    fprintf(stderr, "tests: %s not found; build it first\n", kProgram);
    return EXIT_FAILURE;
  }
  testFixtureBytes();
  testTablePrinting();
  testPacketDump();
  testDefaultRouteTable();
  testOtherRouting();
  testDuplicates();
  testCommandLineErrors();
  testMalformedInput();
  testLargeTrace();
  testSamples(samplesDir);
  removeCreatedFiles();
  printf("passed: %d, failed: %d, skipped: %d\n", stats.passed, stats.failed, stats.skipped);
  return stats.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

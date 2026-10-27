// Name: Atharva Gupta
// Case Network ID: axg1395
// date created: 10/25/2026
// date updated: 10/27/2026
// filename: gen_traces.cpp
// description: writes small binary packet traces and their expected proj3 output for the test
// suite. Each case NAME produces NAME.trace and one NAME-MODE.out file per mode checked (p, c, n).

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

static const uint8_t IP_VERSION_IHL = 0x45; // IPv4, 5-word header
static const uint8_t DEFAULT_TTL = 64;
static const uint16_t IP_HDR_LEN = 20;
static const uint16_t TCP_MIN_HDR_LEN = 20;
static const uint8_t TCP_OFFSET_UNIT = 4;
static const int TCP_OFFSET_SHIFT = 4; // data offset sits in the upper nibble of its byte
static const uint16_t TCP_WINDOW = 65535;
static const uint8_t TCP_OPTION_NOP = 1;
static const uint16_t INTERFACE_ID = 1;
static const uint8_t PROTO_ICMP = 1;
static const uint8_t PROTO_GRE = 47;
static const int BITS_PER_BYTE = 8;
static const int BYTES_PER_U32 = 4;
static const uint8_t BYTE_MASK = 0xff;

struct Timestamp
{
    uint32_t sec;
    uint32_t usec;
};

struct Expected
{
    char mode;
    std::string output;
};

struct TestCase
{
    std::string name;
    std::string trace;
    std::vector<Expected> expected;
};

static void append_u8(std::string &buf, uint8_t value)
{
    buf.push_back((char)value);
}

static void append_u16(std::string &buf, uint16_t value)
{
    append_u8(buf, (uint8_t)(value >> BITS_PER_BYTE));
    append_u8(buf, (uint8_t)(value & BYTE_MASK));
}

static void append_u32(std::string &buf, uint32_t value)
{
    for (int i = BYTES_PER_U32 - 1; i >= 0; i--)
    {
        append_u8(buf, (uint8_t)((value >> (i * BITS_PER_BYTE)) & BYTE_MASK));
    }
}

static void append_ip_addr(std::string &buf, const char *addr)
{
    struct in_addr parsed;
    if (inet_pton(AF_INET, addr, &parsed) != 1)
    {
        fprintf(stderr, "error: bad address '%s' in test case\n", addr);
        exit(EXIT_FAILURE);
    }
    append_u32(buf, ntohl(parsed.s_addr));
}

static void append_record_start(std::string &buf, Timestamp ts, const char *src,
                                const char *dst, uint8_t proto, uint16_t ip_len)
{
    append_u16(buf, INTERFACE_ID);
    append_u16(buf, 0); // padding
    append_u32(buf, ts.sec);
    append_u32(buf, ts.usec);

    append_u8(buf, IP_VERSION_IHL);
    append_u8(buf, 0); // type of service
    append_u16(buf, ip_len);
    append_u16(buf, 0); // identification
    append_u16(buf, 0); // flags and fragment offset
    append_u8(buf, DEFAULT_TTL);
    append_u8(buf, proto);
    append_u16(buf, 0); // checksum
    append_ip_addr(buf, src);
    append_ip_addr(buf, dst);
}

static void add_udp(std::string &buf, Timestamp ts, const char *src, uint16_t sport,
                    const char *dst, uint16_t dport, uint16_t ip_len)
{
    append_record_start(buf, ts, src, dst, IPPROTO_UDP, ip_len);
    append_u16(buf, sport);
    append_u16(buf, dport);
    append_u16(buf, ip_len - IP_HDR_LEN);
    append_u16(buf, 0); // checksum
}

// Adds a TCP record. The ACK flag is set when has_ack is true; otherwise SYN is set.
static void add_tcp(std::string &buf, Timestamp ts, const char *src, uint16_t sport,
                    const char *dst, uint16_t dport, uint16_t ip_len, uint32_t seq,
                    bool has_ack, uint32_t ack, uint16_t hdr_len)
{
    append_record_start(buf, ts, src, dst, IPPROTO_TCP, ip_len);
    append_u16(buf, sport);
    append_u16(buf, dport);
    append_u32(buf, seq);
    append_u32(buf, has_ack ? ack : 0);
    append_u8(buf, (uint8_t)((hdr_len / TCP_OFFSET_UNIT) << TCP_OFFSET_SHIFT));
    append_u8(buf, has_ack ? TH_ACK : TH_SYN);
    append_u16(buf, TCP_WINDOW);
    append_u16(buf, 0); // checksum
    append_u16(buf, 0); // urgent pointer
    buf.append(hdr_len - TCP_MIN_HDR_LEN, (char)TCP_OPTION_NOP);
}

static void add_other(std::string &buf, Timestamp ts, const char *src, const char *dst,
                      uint8_t proto, uint16_t ip_len)
{
    append_record_start(buf, ts, src, dst, proto, ip_len);
}

static void add_case(std::vector<TestCase> &cases, const char *name, const std::string &trace,
                     const std::vector<Expected> &expected)
{
    TestCase tc;
    tc.name = name;
    tc.trace = trace;
    tc.expected = expected;
    cases.push_back(tc);
}

static void add_single_packet_cases(std::vector<TestCase> &cases)
{
    std::string t;

    add_udp(t, {100, 250000}, "10.0.0.1", 1234, "10.0.0.2", 5678, 128);
    add_case(cases, "udp_single", t,
             {{'p', "100.250000 10.0.0.1 10.0.0.2 128 U 1234 5678 100\n"}});

    t.clear();
    add_tcp(t, {200, 500000}, "192.168.1.10", 40000, "8.8.8.8", 443, 120, 123456, true,
            654321, 20);
    add_case(cases, "tcp_single", t,
             {{'p', "200.500000 192.168.1.10 8.8.8.8 120 T 40000 443 20 80 123456 654321\n"}});

    t.clear();
    add_tcp(t, {201, 1}, "10.1.1.1", 5000, "10.2.2.2", 80, 40, 777, false, 0, 20);
    add_case(cases, "tcp_no_ack", t,
             {{'p', "201.000001 10.1.1.1 10.2.2.2 40 T 5000 80 20 0 777 -\n"}});

    t.clear();
    add_other(t, {300, 100000}, "1.2.3.4", "5.6.7.8", PROTO_ICMP, 60);
    add_case(cases, "icmp_single", t, {{'p', "300.100000 1.2.3.4 5.6.7.8 60 1\n"}});
}

static void add_parsing_cases(std::vector<TestCase> &cases)
{
    std::string t;

    // TCP options must be consumed so the following record is decoded correctly.
    add_tcp(t, {210, 0}, "10.0.0.5", 6000, "10.0.0.6", 22, 100, 42, true, 43, 32);
    add_udp(t, {211, 0}, "10.0.0.7", 53, "10.0.0.8", 5353, 60);
    add_case(cases, "tcp_options", t,
             {{'p', "210.000000 10.0.0.5 10.0.0.6 100 T 6000 22 32 48 42 43\n"
                    "211.000000 10.0.0.7 10.0.0.8 60 U 53 5353 32\n"}});

    t.clear();
    add_udp(t, {900, 1}, "10.0.0.1", 111, "10.0.0.2", 222, 100);
    add_tcp(t, {900, 2}, "10.0.0.3", 333, "10.0.0.4", 444, 200, 1000, true, 2000, 20);
    add_other(t, {900, 3}, "10.0.0.5", "10.0.0.6", PROTO_ICMP, 64);
    add_tcp(t, {900, 4}, "10.0.0.7", 555, "10.0.0.8", 666, 300, 3000, false, 0, 32);
    add_udp(t, {900, 5}, "10.0.0.9", 777, "10.0.0.10", 888, 400);
    add_case(cases, "sequential_types", t,
             {{'p', "900.000001 10.0.0.1 10.0.0.2 100 U 111 222 72\n"
                    "900.000002 10.0.0.3 10.0.0.4 200 T 333 444 20 160 1000 2000\n"
                    "900.000003 10.0.0.5 10.0.0.6 64 1\n"
                    "900.000004 10.0.0.7 10.0.0.8 300 T 555 666 32 248 3000 -\n"
                    "900.000005 10.0.0.9 10.0.0.10 400 U 777 888 372\n"},
              {'c', "1 1\n6 2\n17 2\n"},
              {'n', "10.0.0.1 111 10.0.0.2 222 U 900.000001 0.000000 1 0 72 0\n"
                    "10.0.0.3 333 10.0.0.4 444 T 900.000002 0.000000 1 0 160 0\n"
                    "10.0.0.7 555 10.0.0.8 666 T 900.000004 0.000000 1 0 248 0\n"
                    "10.0.0.9 777 10.0.0.10 888 U 900.000005 0.000000 1 0 372 0\n"}});

    t.clear();
    for (uint32_t i = 0; i < 3; i++)
    {
        add_tcp(t, {400 + i, 0}, "10.0.0.1", 1000 + i, "10.0.0.2", 80, 60, i, false, 0, 20);
    }
    for (uint32_t i = 0; i < 4; i++)
    {
        add_udp(t, {410 + i, 0}, "10.0.0.3", 2000 + i, "10.0.0.4", 53, 70);
    }
    for (uint32_t i = 0; i < 2; i++)
    {
        add_other(t, {420 + i, 0}, "10.0.0.5", "10.0.0.6", PROTO_ICMP, 84);
    }
    add_other(t, {430, 0}, "10.0.0.7", "10.0.0.8", PROTO_GRE, 100);
    add_case(cases, "mixed_counts", t, {{'c', "1 2\n6 3\n17 4\n47 1\n"}});
}

static void add_timestamp_cases(std::vector<TestCase> &cases)
{
    std::string t;
    Timestamp same = {1234, 567890};

    add_udp(t, same, "1.1.1.1", 1, "2.2.2.2", 2, 30);
    add_other(t, same, "1.1.1.1", "2.2.2.2", PROTO_ICMP, 30);
    add_tcp(t, same, "1.1.1.1", 3, "2.2.2.2", 4, 40, 9, false, 0, 20);
    add_case(cases, "same_timestamp", t,
             {{'p', "1234.567890 1.1.1.1 2.2.2.2 30 U 1 2 2\n"
                    "1234.567890 1.1.1.1 2.2.2.2 30 1\n"
                    "1234.567890 1.1.1.1 2.2.2.2 40 T 3 4 20 0 9 -\n"}});

    t.clear();
    const uint32_t usecs[] = {1, 10, 100, 1000, 10000, 100000};
    for (uint32_t usec : usecs)
    {
        add_other(t, {50, usec}, "9.9.9.9", "8.8.8.8", PROTO_ICMP, 28);
    }
    add_case(cases, "usec_padding", t,
             {{'p', "50.000001 9.9.9.9 8.8.8.8 28 1\n"
                    "50.000010 9.9.9.9 8.8.8.8 28 1\n"
                    "50.000100 9.9.9.9 8.8.8.8 28 1\n"
                    "50.001000 9.9.9.9 8.8.8.8 28 1\n"
                    "50.010000 9.9.9.9 8.8.8.8 28 1\n"
                    "50.100000 9.9.9.9 8.8.8.8 28 1\n"}});
}

static void add_flow_identity_cases(std::vector<TestCase> &cases)
{
    std::string t;

    add_udp(t, {1000, 0}, "10.0.0.1", 1000, "20.0.0.1", 2000, 128);
    add_case(cases, "flow_udp_single", t,
             {{'n', "10.0.0.1 1000 20.0.0.1 2000 U 1000.000000 0.000000 1 0 100 0\n"}});

    t.clear();
    add_udp(t, {1000, 0}, "10.0.0.1", 1000, "20.0.0.1", 2000, 128);
    add_udp(t, {1001, 500000}, "20.0.0.1", 2000, "10.0.0.1", 1000, 78);
    add_udp(t, {1002, 250000}, "10.0.0.1", 1000, "20.0.0.1", 2000, 228);
    add_case(cases, "flow_udp_bidir", t,
             {{'n', "10.0.0.1 1000 20.0.0.1 2000 U 1000.000000 2.250000 2 1 300 50\n"}});

    // The first packet defines A even though its address sorts higher than B's.
    t.clear();
    add_udp(t, {500, 0}, "5.5.5.5", 5000, "4.4.4.4", 4000, 50);
    add_udp(t, {501, 0}, "4.4.4.4", 4000, "5.5.5.5", 5000, 40);
    add_case(cases, "flow_reverse_first", t,
             {{'n', "5.5.5.5 5000 4.4.4.4 4000 U 500.000000 1.000000 1 1 22 12\n"}});

    t.clear();
    add_udp(t, {600, 0}, "10.0.0.1", 1000, "20.0.0.1", 2000, 128);
    add_tcp(t, {601, 0}, "10.0.0.1", 1000, "20.0.0.1", 2000, 140, 1, true, 2, 20);
    add_case(cases, "flow_diff_proto", t,
             {{'n', "10.0.0.1 1000 20.0.0.1 2000 U 600.000000 0.000000 1 0 100 0\n"
                    "10.0.0.1 1000 20.0.0.1 2000 T 601.000000 0.000000 1 0 100 0\n"}});

    t.clear();
    add_tcp(t, {700, 0}, "10.0.0.1", 1000, "20.0.0.1", 80, 60, 0, false, 0, 20);
    add_tcp(t, {701, 0}, "10.0.0.1", 1001, "20.0.0.1", 80, 70, 0, false, 0, 20);
    add_case(cases, "flow_diff_ports", t,
             {{'n', "10.0.0.1 1000 20.0.0.1 80 T 700.000000 0.000000 1 0 20 0\n"
                    "10.0.0.1 1001 20.0.0.1 80 T 701.000000 0.000000 1 0 30 0\n"}});

    t.clear();
    add_udp(t, {800, 0}, "10.0.0.1", 1000, "20.0.0.1", 2000, 128);
    add_other(t, {801, 0}, "10.0.0.1", "20.0.0.1", PROTO_ICMP, 84);
    add_tcp(t, {802, 0}, "10.0.0.1", 3000, "20.0.0.1", 443, 140, 5, true, 6, 20);
    add_other(t, {803, 0}, "20.0.0.1", "10.0.0.1", PROTO_ICMP, 84);
    add_case(cases, "flow_ignore_icmp", t,
             {{'n', "10.0.0.1 1000 20.0.0.1 2000 U 800.000000 0.000000 1 0 100 0\n"
                    "10.0.0.1 3000 20.0.0.1 443 T 802.000000 0.000000 1 0 100 0\n"}});
}

static void add_flow_total_cases(std::vector<TestCase> &cases)
{
    std::string t;

    add_tcp(t, {1100, 0}, "10.0.0.1", 4000, "10.0.0.2", 80, 100, 1, true, 1, 20);
    add_tcp(t, {1100, 500000}, "10.0.0.1", 4000, "10.0.0.2", 80, 100, 61, true, 1, 32);
    add_case(cases, "tcp_options_payload", t,
             {{'n', "10.0.0.1 4000 10.0.0.2 80 T 1100.000000 0.500000 2 0 108 0\n"}});

    // 100 packets A to B (1472 payload bytes each) and 50 B to A (1000 each), so the byte
    // totals exceed what a 16-bit counter can hold.
    t.clear();
    const uint32_t forward_packets = 100;
    for (uint32_t i = 0; i < forward_packets; i++)
    {
        add_udp(t, {2000 + i, 0}, "10.0.0.1", 9000, "10.0.0.2", 9001, 1500);
        if (i % 2 == 0)
        {
            add_udp(t, {2000 + i, 500000}, "10.0.0.2", 9001, "10.0.0.1", 9000, 1028);
        }
    }
    add_case(cases, "large_counters", t,
             {{'n', "10.0.0.1 9000 10.0.0.2 9001 U 2000.000000 99.000000 100 50 147200 50000\n"},
              {'c', "17 150\n"}});
}

static void write_file(const std::string &path, const std::string &contents)
{
    FILE *fp = fopen(path.c_str(), "wb");
    if (fp == NULL)
    {
        fprintf(stderr, "error: cannot create '%s': %s\n", path.c_str(), strerror(errno));
        exit(EXIT_FAILURE);
    }
    size_t written = fwrite(contents.data(), 1, contents.size(), fp);
    if (written != contents.size() || fclose(fp) != 0)
    {
        fprintf(stderr, "error: cannot write '%s'\n", path.c_str());
        exit(EXIT_FAILURE);
    }
}

// A TCP record cut off partway through its header, used to test error handling.
static void write_truncated_trace(const std::string &dir)
{
    const size_t bytes_removed = 5;
    std::string t;
    add_tcp(t, {1, 0}, "1.1.1.1", 1, "2.2.2.2", 2, 40, 0, false, 0, 20);
    t.resize(t.size() - bytes_removed);
    write_file(dir + "/truncated.trace", t);
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "usage: %s output_dir\n", argv[0]);
        return EXIT_FAILURE;
    }
    std::string dir = argv[1];

    std::vector<TestCase> cases;
    add_single_packet_cases(cases);
    add_parsing_cases(cases);
    add_timestamp_cases(cases);
    add_flow_identity_cases(cases);
    add_flow_total_cases(cases);

    for (const TestCase &tc : cases)
    {
        write_file(dir + "/" + tc.name + ".trace", tc.trace);
        for (const Expected &exp : tc.expected)
        {
            write_file(dir + "/" + tc.name + "-" + exp.mode + ".out", exp.output);
        }
    }
    write_truncated_trace(dir);
    return EXIT_SUCCESS;
}

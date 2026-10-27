// Name: Atharva Gupta
// Case Network ID: axg1395
// date created: 10/21/2026
// date updated: 10/27/2026
// filename: proj3.cpp
// description: reads a binary IPv4 packet trace and supports three modes: packet printing (-p),
// protocol counting (-c) and bidirectional NetFlow-like flow aggregation (-n). Argument parsing

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unistd.h>

#include <cerrno>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <unordered_map>

// Command-line flags.
static const unsigned short ARG_PRINT = 0x1;
static const unsigned short ARG_COUNT = 0x2;
static const unsigned short ARG_NETFLOW = 0x4;
static const unsigned short ARG_TRACE = 0x8;
static const unsigned short MODE_FLAGS = ARG_PRINT | ARG_COUNT | ARG_NETFLOW;
static const char OPTSTRING[] = "pcnr:";

// Trace record layout. Each record begins with 12 bytes of metadata:
// interface (2), padding (2), timestamp seconds (4), timestamp microseconds (4).
static const size_t META_LEN = 12;
static const size_t META_SEC_OFFSET = 4;
static const size_t META_USEC_OFFSET = 8;

static const size_t IP_HDR_LEN = 20;
static const size_t UDP_HDR_LEN = 8;
static const size_t TCP_MIN_HDR_LEN = 20;
static const size_t TCP_MAX_HDR_LEN = 60;
static const size_t TCP_OFFSET_UNIT = 4; // the data offset field counts 32-bit words

static const uint64_t USEC_PER_SEC = 1000000;
static const uint32_t MAX_USEC = 999999;
static const size_t NUM_PROTOCOLS = 256;

static const char PROTO_CHAR_TCP = 'T';
static const char PROTO_CHAR_UDP = 'U';
static const char NO_ACK_MARKER[] = "-";

// Constant from the golden ratio, used to spread bits when combining hash values.
static const size_t HASH_MIX = 0x9e3779b9;
static const int HASH_SHIFT_LEFT = 6;
static const int HASH_SHIFT_RIGHT = 2;

struct Options
{
    unsigned short flags;
    const char *trace_file;
};

enum ReadResult
{
    READ_OK,
    READ_EOF,
    READ_ERROR
};

struct Packet
{
    uint64_t ts_usec; // timestamp as total microseconds
    uint32_t src_ip; // network byte order
    uint32_t dst_ip; // network byte order
    uint16_t ip_len;
    uint8_t protocol;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t tcp_hdr_len;
    uint32_t seq;
    uint32_t ack;
    bool ack_set;
    int64_t payload;
};

struct Endpoint
{
    uint32_t ip;
    uint16_t port;
};

struct FlowStats
{
    Endpoint a;
    Endpoint b;
    uint8_t protocol;
    uint64_t first_usec;
    uint64_t last_usec;
    uint64_t a_to_b_packets;
    uint64_t b_to_a_packets;
    uint64_t a_to_b_bytes;
    uint64_t b_to_a_bytes;
};

// Direction-independent flow identity: the lower endpoint is always stored first, so
// packets travelling in either direction produce the same key.
struct FlowKey
{
    uint32_t low_ip;
    uint32_t high_ip;
    uint16_t low_port;
    uint16_t high_port;
    uint8_t protocol;

    bool operator==(const FlowKey &other) const
    {
        return low_ip == other.low_ip && high_ip == other.high_ip &&
               low_port == other.low_port && high_port == other.high_port &&
               protocol == other.protocol;
    }
};

struct FlowKeyHash
{
    size_t operator()(const FlowKey &key) const
    {
        size_t seed = 0;
        combine(seed, key.low_ip);
        combine(seed, key.high_ip);
        combine(seed, key.low_port);
        combine(seed, key.high_port);
        combine(seed, key.protocol);
        return seed;
    }

    static void combine(size_t &seed, uint32_t value)
    {
        seed ^= std::hash<uint32_t>()(value) + HASH_MIX + (seed << HASH_SHIFT_LEFT) +
                (seed >> HASH_SHIFT_RIGHT);
    }
};

typedef std::unordered_map<FlowKey, FlowStats, FlowKeyHash> FlowTable;

static void usage(const char *progname)
{
    fprintf(stderr, "usage: %s [-p | -c | -n] -r trace_file\n", progname);
    fprintf(stderr, "   -p    print decoded packet information\n");
    fprintf(stderr, "   -c    count packets by IP protocol\n");
    fprintf(stderr, "   -n    aggregate TCP/UDP packets into flows\n");
    fprintf(stderr, "   -r X  read packets from trace file 'X'\n");
    exit(EXIT_FAILURE);
}

static void parse_args(int argc, char *argv[], Options &opts)
{
    int opt;

    opts.flags = 0;
    opts.trace_file = NULL;
    while ((opt = getopt(argc, argv, OPTSTRING)) != -1)
    {
        switch (opt)
        {
            case 'p':
                opts.flags |= ARG_PRINT;
                break;
            case 'c':
                opts.flags |= ARG_COUNT;
                break;
            case 'n':
                opts.flags |= ARG_NETFLOW;
                break;
            case 'r':
                if (opts.flags & ARG_TRACE)
                {
                    fprintf(stderr, "error: -r given more than once\n");
                    usage(argv[0]);
                }
                opts.flags |= ARG_TRACE;
                opts.trace_file = optarg;
                break;
            case '?':
            default:
                usage(argv[0]);
        }
    }

    if (optind < argc)
    {
        fprintf(stderr, "error: unexpected argument '%s'\n", argv[optind]);
        usage(argv[0]);
    }

    unsigned short mode = opts.flags & MODE_FLAGS;
    if (mode == 0)
    {
        fprintf(stderr, "error: one of -p, -c, -n is required\n");
        usage(argv[0]);
    }
    if (mode != ARG_PRINT && mode != ARG_COUNT && mode != ARG_NETFLOW)
    {
        fprintf(stderr, "error: only one of -p, -c, -n may be given\n");
        usage(argv[0]);
    }
    if (!(opts.flags & ARG_TRACE))
    {
        fprintf(stderr, "error: -r trace_file is required\n");
        usage(argv[0]);
    }
}

static ReadResult trace_error(const char *what)
{
    fprintf(stderr, "error: malformed trace: %s\n", what);
    return READ_ERROR;
}

// Reads exactly len bytes. Returns READ_EOF only if the file ended before any byte was read.
static ReadResult read_exact(FILE *trace, void *buf, size_t len)
{
    size_t got = fread(buf, 1, len, trace);
    if (got == len)
    {
        return READ_OK;
    }
    if (ferror(trace))
    {
        fprintf(stderr, "error: cannot read trace file: %s\n", strerror(errno));
        return READ_ERROR;
    }
    if (got == 0)
    {
        return READ_EOF;
    }
    return READ_ERROR;
}

static ReadResult read_metadata(FILE *trace, Packet &pkt)
{
    unsigned char meta[META_LEN];
    ReadResult result = read_exact(trace, meta, META_LEN);
    if (result == READ_EOF)
    {
        return READ_EOF;
    }
    if (result != READ_OK)
    {
        return trace_error("truncated packet metadata");
    }

    // The interface and padding bytes are consumed but not used by any mode.
    uint32_t sec;
    uint32_t usec;
    memcpy(&sec, meta + META_SEC_OFFSET, sizeof(sec));
    memcpy(&usec, meta + META_USEC_OFFSET, sizeof(usec));
    sec = ntohl(sec);
    usec = ntohl(usec);
    if (usec > MAX_USEC)
    {
        return trace_error("timestamp microseconds out of range");
    }
    pkt.ts_usec = sec * USEC_PER_SEC + usec;
    return READ_OK;
}

static ReadResult read_ip_header(FILE *trace, Packet &pkt)
{
    struct ip iph;
    if (read_exact(trace, &iph, IP_HDR_LEN) != READ_OK)
    {
        return trace_error("truncated IPv4 header");
    }
    pkt.src_ip = iph.ip_src.s_addr;
    pkt.dst_ip = iph.ip_dst.s_addr;
    pkt.ip_len = ntohs(iph.ip_len);
    pkt.protocol = iph.ip_p;
    return READ_OK;
}

static ReadResult read_udp_header(FILE *trace, Packet &pkt)
{
    struct udphdr udph;
    if (read_exact(trace, &udph, UDP_HDR_LEN) != READ_OK)
    {
        return trace_error("truncated UDP header");
    }
    pkt.src_port = ntohs(udph.uh_sport);
    pkt.dst_port = ntohs(udph.uh_dport);
    pkt.payload = (int64_t)pkt.ip_len - (int64_t)(IP_HDR_LEN + UDP_HDR_LEN);
    return READ_OK;
}

static ReadResult read_tcp_header(FILE *trace, Packet &pkt)
{
    struct tcphdr tcph;
    if (read_exact(trace, &tcph, TCP_MIN_HDR_LEN) != READ_OK)
    {
        return trace_error("truncated TCP header");
    }

    pkt.tcp_hdr_len = tcph.th_off * TCP_OFFSET_UNIT;
    if (pkt.tcp_hdr_len < TCP_MIN_HDR_LEN)
    {
        return trace_error("TCP header length below minimum");
    }

    // The trace stores the full TCP header, so any option bytes must be consumed to keep
    // the next record aligned.
    size_t options_len = pkt.tcp_hdr_len - TCP_MIN_HDR_LEN;
    unsigned char options[TCP_MAX_HDR_LEN - TCP_MIN_HDR_LEN];
    if (options_len > 0 && read_exact(trace, options, options_len) != READ_OK)
    {
        return trace_error("truncated TCP options");
    }

    pkt.src_port = ntohs(tcph.th_sport);
    pkt.dst_port = ntohs(tcph.th_dport);
    pkt.seq = ntohl(tcph.th_seq);
    pkt.ack = ntohl(tcph.th_ack);
    pkt.ack_set = (tcph.th_flags & TH_ACK) != 0;
    pkt.payload = (int64_t)pkt.ip_len - (int64_t)(IP_HDR_LEN + pkt.tcp_hdr_len);
    return READ_OK;
}

static bool is_transport(const Packet &pkt)
{
    return pkt.protocol == IPPROTO_TCP || pkt.protocol == IPPROTO_UDP;
}

// Reads the next packet record and decodes the fields used by the three modes.
static ReadResult read_packet(FILE *trace, Packet &pkt)
{
    memset(&pkt, 0, sizeof(pkt));

    ReadResult result = read_metadata(trace, pkt);
    if (result != READ_OK)
    {
        return result;
    }
    if (read_ip_header(trace, pkt) != READ_OK)
    {
        return READ_ERROR;
    }

    // Only TCP and UDP records carry a transport header; other protocols end here.
    if (pkt.protocol == IPPROTO_UDP)
    {
        result = read_udp_header(trace, pkt);
    }
    else if (pkt.protocol == IPPROTO_TCP)
    {
        result = read_tcp_header(trace, pkt);
    }
    if (result != READ_OK)
    {
        return READ_ERROR;
    }

    if (is_transport(pkt) && pkt.payload < 0)
    {
        return trace_error("IPv4 total length smaller than its headers");
    }
    return READ_OK;
}

static void print_timestamp(uint64_t usec)
{
    printf("%" PRIu64 ".%06" PRIu64, usec / USEC_PER_SEC, usec % USEC_PER_SEC);
}

static void print_ip(uint32_t ip)
{
    struct in_addr addr;
    addr.s_addr = ip;
    fputs(inet_ntoa(addr), stdout);
}

static void print_packet(const Packet &pkt)
{
    print_timestamp(pkt.ts_usec);
    putchar(' ');
    print_ip(pkt.src_ip);
    putchar(' ');
    print_ip(pkt.dst_ip);
    printf(" %u", (unsigned)pkt.ip_len);

    if (pkt.protocol == IPPROTO_UDP)
    {
        printf(" %c %u %u %" PRId64 "\n", PROTO_CHAR_UDP, (unsigned)pkt.src_port,
               (unsigned)pkt.dst_port, pkt.payload);
    }
    else if (pkt.protocol == IPPROTO_TCP)
    {
        printf(" %c %u %u %u %" PRId64 " %u ", PROTO_CHAR_TCP, (unsigned)pkt.src_port,
               (unsigned)pkt.dst_port, (unsigned)pkt.tcp_hdr_len, pkt.payload,
               (unsigned)pkt.seq);
        if (pkt.ack_set)
        {
            printf("%u\n", (unsigned)pkt.ack);
        }
        else
        {
            printf("%s\n", NO_ACK_MARKER);
        }
    }
    else
    {
        printf(" %u\n", (unsigned)pkt.protocol);
    }
}

static FlowKey make_flow_key(const Packet &pkt)
{
    bool src_is_low = pkt.src_ip < pkt.dst_ip ||
                      (pkt.src_ip == pkt.dst_ip && pkt.src_port <= pkt.dst_port);
    FlowKey key;
    key.protocol = pkt.protocol;
    if (src_is_low)
    {
        key.low_ip = pkt.src_ip;
        key.low_port = pkt.src_port;
        key.high_ip = pkt.dst_ip;
        key.high_port = pkt.dst_port;
    }
    else
    {
        key.low_ip = pkt.dst_ip;
        key.low_port = pkt.dst_port;
        key.high_ip = pkt.src_ip;
        key.high_port = pkt.src_port;
    }
    return key;
}

static void update_flow(FlowTable &flows, const Packet &pkt)
{
    std::pair<FlowTable::iterator, bool> entry = flows.try_emplace(make_flow_key(pkt));
    FlowStats &stats = entry.first->second;

    // The first packet seen for a flow fixes its A (source) and B (destination) sides.
    if (entry.second)
    {
        memset(&stats, 0, sizeof(stats));
        stats.a.ip = pkt.src_ip;
        stats.a.port = pkt.src_port;
        stats.b.ip = pkt.dst_ip;
        stats.b.port = pkt.dst_port;
        stats.protocol = pkt.protocol;
        stats.first_usec = pkt.ts_usec;
    }
    stats.last_usec = pkt.ts_usec;

    // The key already matched, so a source equal to A means the packet travels A to B.
    if (pkt.src_ip == stats.a.ip && pkt.src_port == stats.a.port)
    {
        stats.a_to_b_packets++;
        stats.a_to_b_bytes += (uint64_t)pkt.payload;
    }
    else
    {
        stats.b_to_a_packets++;
        stats.b_to_a_bytes += (uint64_t)pkt.payload;
    }
}

static void print_flow(const FlowStats &stats)
{
    // A trace whose timestamps go backwards within a flow is reported with zero duration.
    uint64_t duration = 0;
    if (stats.last_usec > stats.first_usec)
    {
        duration = stats.last_usec - stats.first_usec;
    }

    print_ip(stats.a.ip);
    printf(" %u ", (unsigned)stats.a.port);
    print_ip(stats.b.ip);
    printf(" %u %c ", (unsigned)stats.b.port,
           stats.protocol == IPPROTO_TCP ? PROTO_CHAR_TCP : PROTO_CHAR_UDP);
    print_timestamp(stats.first_usec);
    putchar(' ');
    print_timestamp(duration);
    printf(" %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n", stats.a_to_b_packets,
           stats.b_to_a_packets, stats.a_to_b_bytes, stats.b_to_a_bytes);
}

static bool print_packets(FILE *trace)
{
    Packet pkt;
    ReadResult result;
    while ((result = read_packet(trace, pkt)) == READ_OK)
    {
        print_packet(pkt);
    }
    return result == READ_EOF;
}

static bool count_protocols(FILE *trace)
{
    // The protocol field is one byte, so a fixed table covers every possible value.
    uint64_t counts[NUM_PROTOCOLS] = {0};
    Packet pkt;
    ReadResult result;
    while ((result = read_packet(trace, pkt)) == READ_OK)
    {
        counts[pkt.protocol]++;
    }
    if (result != READ_EOF)
    {
        return false;
    }

    for (size_t proto = 0; proto < NUM_PROTOCOLS; proto++)
    {
        if (counts[proto] > 0)
        {
            printf("%zu %" PRIu64 "\n", proto, counts[proto]);
        }
    }
    return true;
}

static bool report_flows(FILE *trace)
{
    FlowTable flows;
    Packet pkt;
    ReadResult result;
    while ((result = read_packet(trace, pkt)) == READ_OK)
    {
        if (is_transport(pkt))
        {
            update_flow(flows, pkt);
        }
    }
    if (result != READ_EOF)
    {
        return false;
    }

    for (FlowTable::const_iterator it = flows.begin(); it != flows.end(); ++it)
    {
        print_flow(it->second);
    }
    return true;
}

int main(int argc, char *argv[])
{
    Options opts;
    parse_args(argc, argv, opts);

    FILE *trace = fopen(opts.trace_file, "rb");
    if (trace == NULL)
    {
        fprintf(stderr, "error: cannot open trace file '%s': %s\n", opts.trace_file,
                strerror(errno));
        return EXIT_FAILURE;
    }

    bool ok;
    if (opts.flags & ARG_PRINT)
    {
        ok = print_packets(trace);
    }
    else if (opts.flags & ARG_COUNT)
    {
        ok = count_protocols(trace);
    }
    else
    {
        ok = report_flows(trace);
    }
    fclose(trace);

    if (fflush(stdout) != 0)
    {
        fprintf(stderr, "error: cannot write output: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}

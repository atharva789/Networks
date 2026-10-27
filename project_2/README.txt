Name: Atharva Gupta
Case Network ID: axg1395
date created: 10/02/2026
date updated: 10/05/2026
filename: README.txt
description: build, run and test instructions for proj2, and the edge-case choices it makes.

proj2 - IPv4 router simulator

proj2 reads binary forwarding-table and packet-trace files. It prints the forwarding table (-f), a packet dump (-d), or a simulated routing decision for each packet (-r). Only /8 prefixes are supported.

Building and testing:
make - Linux/Unix build of ./proj2 (g++)
make local_mac_executable - macOS build of ./proj2 (clang++)
make test - build ./proj2 and ./tests, then run the tests
make clean - remove objects, ./tests and test fixtures
make distclean - clean, and also remove ./proj2

Running:
./proj2 -f -t table_file
./proj2 -d -p trace_file
./proj2 -r -t table_file -p trace_file

Files:
proj2.cpp - the program. Arguments are parsed with getopt, following the course sample.
tests.cpp - generates fixtures, runs ./proj2 and compares its output byte-for-byte. It also runs the course sample files from samples/ (or from the directory given as ./tests DIR). Missing samples are reported as SKIP.
Makefile - build rules (see above).

Edge-case choices:
- Exactly one mode is required. Options may appear in any order.
- These are errors: a repeated option, an unknown option, a positional argument, or a missing filename (including "-t -d").
- A file option the mode does not need is ignored and not opened.
- Routing decisions are checked in this order, and the first one that applies wins: drop checksum (checksum is not 54321), drop expired (TTL is exactly 1; TTL 0 is not expired), drop loop N (chosen interface equals the incoming interface), drop policy (chosen interface is 0), send N (a /8 rule matched) or default N (the default rule was used), and drop unknown (no rule matched and there is no default rule).
- A rule matches the destination's first octet. 0.0.0.0 is the default rule; any other 0.x.y.z address is an ordinary 0/8 rule.
- -r rejects duplicate prefixes before reading any packet, even when the trace is empty. This includes two default rules, or 0.0.0.0 together with 0.x.y.z. -f prints duplicates as stored.
- These are errors: a prefix length other than 8, microseconds above 999999, a partial final record, and an unreadable file. Output already printed before a bad trace record stays.
- Both files are read one record at a time; the routing table is a fixed 256-entry array.
- Course samples 10, 16 and 18 (-f and -r) use /16, /24 and /32 prefixes. They are skipped because they are outside this project's /8 scope.

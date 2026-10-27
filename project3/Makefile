# // Name: Atharva Gupta
# // Case Network ID: axg1395
# // date created: 10/21/2026
# // date updated: 10/27/2026
# // filename: Makefile
# // description: builds the proj3 executable and the test trace generator, and runs the tests.
# // 'make' builds proj3 natively (Linux/Unix); 'make local_mac_executable' builds it with clang++ on macOS.

CXX=g++
MAC_CXX=clang++
CXXFLAGS=-std=c++17 -Wall -Wextra -pedantic -O2
LDFLAGS=$(CXXFLAGS)

TARGETS=proj3 gen_traces

all: proj3

proj3: proj3.o
	$(CXX) $(LDFLAGS) -o $@ $<

gen_traces: gen_traces.o
	$(CXX) $(LDFLAGS) -o $@ $<

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $<

local_mac_executable:
	$(MAC_CXX) $(CXXFLAGS) -o proj3 proj3.cpp

test: proj3 gen_traces
	sh run_tests.sh

clean:
	rm -f *.o $(TARGETS)

.PHONY: all local_mac_executable test clean

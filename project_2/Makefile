# Name: Atharva Gupta
# Case Network ID: axg1395
# date created: 10/02/2026
# date updated: 10/05/2026
# filename: Makefile
# description: builds proj2 (the IPv4 router simulator) and its tests.
#
#   make                        build ./proj2 with g++ (the Linux/Unix build)
#   make local_mac_executable   build ./proj2 with clang++ for running on macOS
#   make test                   build ./proj2 and ./tests, then run the tests
#   make clean                  remove objects, test binary and test fixtures
#   make distclean              clean, and also remove ./proj2

CXX=g++
MAC_CXX=clang++
CXXFLAGS=-std=c++17 -Wall -Wextra -Wpedantic -O2
LDFLAGS=$(CXXFLAGS)

TARGETS=proj2
TEST_TARGET=tests

all: $(TARGETS)

proj2: proj2.o
	$(CXX) $(LDFLAGS) -o $@ $<

$(TEST_TARGET): tests.o
	$(CXX) $(LDFLAGS) -o $@ $<

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $<

# Always rebuilds from source so a Linux object file is never reused.
local_mac_executable: proj2.cpp
	$(MAC_CXX) $(CXXFLAGS) -o proj2 proj2.cpp

test: $(TARGETS) $(TEST_TARGET)
	./$(TEST_TARGET)

clean:
	rm -f *.o $(TEST_TARGET) test_tmp_*

distclean: clean
	rm -f $(TARGETS)

.PHONY: all local_mac_executable test clean distclean

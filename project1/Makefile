# Uses g++ (part of the GNU Compiler Collection) since the source is C++, not C.
CXX      := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2 -MMD -MP

TARGET      := proj1
TEST_TARGET := tests

SRC      := proj1.cpp
TEST_SRC := tests.cpp

OBJ      := $(SRC:.cpp=.o)
TEST_OBJ := $(TEST_SRC:.cpp=.o)

DEPS := $(OBJ:.o=.d) $(TEST_OBJ:.o=.d)

.PHONY: all test clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^

$(TEST_TARGET): $(TEST_OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

test: $(TARGET) $(TEST_TARGET)
	./$(TEST_TARGET)

clean:
	rm -f $(TARGET) $(TEST_TARGET) $(OBJ) $(TEST_OBJ) $(DEPS)

-include $(DEPS)

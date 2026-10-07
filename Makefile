CXX ?= c++
CXXFLAGS ?= -std=c++20 -O3 -Wall -Wextra -pthread
INCLUDES = -I.

TARGETS = bserve bcurl

all: $(TARGETS)

bserve: bserve.cpp protocol.hpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ bserve.cpp

bcurl: bcurl.cpp protocol.hpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ bcurl.cpp

clean:
	rm -f $(TARGETS) *.o

.PHONY: all clean

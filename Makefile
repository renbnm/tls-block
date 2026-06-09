CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
LDLIBS = -lpcap

TARGET = tls-block
SRCS = main.cpp mac.cpp ip.cpp tcp.cpp tls.cpp
OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS) $(LDLIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS)

CXX = g++
CXXFLAGS = -std=c++17 -Wall -g
LDFLAGS = -lcapstone
TARGET = sdb
SRC = sdb.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET) *.o
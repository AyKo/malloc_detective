# Malloc Detective: makefile

TARGET = malloc_detective.so
DEMO_PROGRAM = test_memory_leak

.PHONY: all clean

all: $(TARGET) $(DEMO_PROGRAM)

test_memory_leak: test_memory_leak.cpp
	$(CXX) -g -o $@ $^ -pthread

malloc_detective.so: malloc_detective.c
	$(CC) -g -O2 -Wall -shared -fPIC -o $@ $^ -ldl -pthread

clean:
	$(RM) $(TARGET) $(DEMO_PROGRAM)


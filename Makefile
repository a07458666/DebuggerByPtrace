CC = gcc
CXX = g++
CFLAGS = -Wall -g
LDFLAGS = -g -Wall

PROGS = hw4

all: $(PROGS)

%: %.c
	$(CC) -o $@ $(CFLAGS) $< $(LDFLAGS) -lcapstone

%: %.cpp
	$(CXX) -o $@ $(CFLAGS) $< $(LDFLAGS) -lcapstone

hw4: debugger.o hw4.o
	$(CXX) -o $@ $^ $(LDFLAGS) -lcapstone

clean:
	rm -f *~ $(PROGS)
	rm -f *.o
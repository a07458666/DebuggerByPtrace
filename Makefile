CC = gcc
CXX = g++
CFLAGS = -Wall -g
LDFLAGS = -g -Wall

PROGS = hw4

all: $(PROGS)

%: %.c
	$(CC) -o $@ $(CFLAGS) $< $(LDFLAGS)

%: %.cpp
	$(CXX) -o $@ $(CFLAGS) $< $(LDFLAGS)

hw4: debugger.o hw4.o
	$(CXX) -o $@ $^ $(LDFLAGS)

clean:
	rm -f *~ $(PROGS)
	rm -f *.o
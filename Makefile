CC = gcc
CXX = g++
EDCFLAGS = -I ./ -Wall -std=c11 $(CFLAGS)
EDCXXFLAGS = -I./ -Wall -std=c++11 $(CXXFLAGS)
EDLDFLAGS = -lpthread -lm -lssl -lcrypto $(LDFLAGS)

CXXOBJS = network.o \
			server.o \
			client.o

all: server client

server: $(CXXOBJS)
	$(CXX) -o $@.out $@.o $< $(EDLDFLAGS)

client: $(CXXOBJS)
	$(CXX) -o $@.out $@.o $< $(EDLDFLAGS)

%.o: %.cpp
	$(CXX) $(EDCXXFLAGS) -o $@ -c $<

%.o: %.c
	$(CC) $(EDCFLAGS) -o $@ -c $<

.PHONY: clean

clean:
	rm -vf *.out
	rm -vf *.o
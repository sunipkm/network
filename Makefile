CC = gcc
CXX = g++
EDCFLAGS = -I ./ -I/opt/homebrew/opt/openssl@1.1/include -Wall -std=c11 $(CFLAGS)
EDCXXFLAGS = -I./ -I/opt/homebrew/opt/openssl@1.1/include -Wall -std=c++11 $(CXXFLAGS)
EDLDFLAGS = -lpthread -lm -L/opt/homebrew/opt/openssl@1.1/lib -lssl -lcrypto $(LDFLAGS)

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
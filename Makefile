CC = gcc
CXX = g++
EDCFLAGS = -I ./ -Wall -std=c11 -O2 -Wno-deprecated-declarations `pkg-config --cflags openssl` $(CFLAGS)
EDCXXFLAGS = -I./ -Wall -std=c++11 -O2 -Wno-deprecated-declarations `pkg-config --cflags openssl` $(CXXFLAGS)
EDLDFLAGS = -lpthread -lm `pkg-config --libs openssl` -lssl -lcrypto $(LDFLAGS)

CXXOBJS = network_common.o
		

all: server client

server: server.o network_server.o $(CXXOBJS)
	$(CXX) -o $@.out $@.o network_server.o $(CXXOBJS) $(EDLDFLAGS)

client: client.o network_client.o $(CXXOBJS)
	$(CXX) -o $@.out $@.o network_client.o $(CXXOBJS) $(EDLDFLAGS)

%.o: %.cpp
	$(CXX) $(EDCXXFLAGS) -o $@ -c $<

%.o: %.c
	$(CC) $(EDCFLAGS) -o $@ -c $<

.PHONY: clean

clean:
	rm -vf *.out
	rm -vf *.o
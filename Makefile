all: encrypt decrypt rsa_genkey

CXX = g++
CXXFLAGS = -pipe -std=c++11 -Wall -O3 -march=native -fopenmp
#CXXFLAGS = -pipe -std=c++11 -Wall -g -fsanitize=address
LDFLAGS = -lgmp -lgmpxx

encrypt: encrypt.o file_encrypt.o bigint.o util.o aes.o securesharing.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^

encrypt.o: encrypt.cc file_encrypt.hh
	$(CXX) $(CXXFLAGS) -c -o $@ $<

decrypt: decrypt.o file_decrypt.o bigint.o util.o aes.o securesharing.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^

decrypt.o: decrypt.cc file_decrypt.hh
	$(CXX) $(CXXFLAGS) -c -o $@ $<

file_encrypt.o: file_encrypt.cc file_encrypt.hh securesharing.hh include/aes.hpp include/rsa.hpp include/oaep.hpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

file_decrypt.o: file_decrypt.cc file_decrypt.hh securesharing.hh include/aes.hpp include/rsa.hpp include/oaep.hpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

bigint.o: bigint.cc include/bigint.hpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

util.o: util.cc include/util.hpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

aes.o: aes.cc include/aes.hpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

securesharing.o: securesharing.cc securesharing.hh include/config.hh include/oaep.hpp include/aes.hpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

rsa_genkey: rsa_genkey.o util.o bigint.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^

rsa_genkey.o: rsa_genkey.cc include/rsa.hpp include/bigint.hpp include/config.hh
	$(CXX) $(CXXFLAGS) -c -o $@ $<

.PHONY: clean

clean:
	rm -rf *.o

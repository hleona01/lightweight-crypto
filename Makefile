CC = gcc
CXXFLAGS = -g3  -std=c++11 -Wall -Wextra  -Wpedantic -Wshadow
LDFLAGS  = -g3

INCLUDES = $(shell echo *.h)

main: main.o elephant160v1/ref/encrypt.o elephant160v1/ref/spongent.o \
	tinyjambu/Implementations/crypto_aead/tinyjambu128v2/opt/encrypt.o \
	tinyjambu/Implementations/crypto_aead/tinyjambu192v2/opt/j192_encrypt.o \
	tinyjambu/Implementations/crypto_aead/tinyjambu256v2/opt/j256_encrypt.o \
	elephant200v2/ref/e200_encrypt.o elephant200v2/ref/keccak.o
	${CXX} ${LDFLAGS} $^ -o $@
	
%.o: %.c ${INCLUDES}
	${CXX} ${CXXFLAGS} -c -o $@ $<

.PHONY: clean
clean:
	rm -f ${EXECS} *.o *.dSYM./ 
CC=g++
CFLAGS=-I/usr/local/include -I/usr/include
LFLAGS=-L/usr/local/lib -L/usr/lib
LIBS=-lcrypto -lpthread -lboost_system -lnfc
DEFINES=-DDBG
DEPS=ECCBase.cpp Base64Coder.cpp main.cpp NFCHandler.cpp ServerFunctions.cpp

ecc_sign: $(DEPS)
	$(CC) -std=c++11 $(DEPS) $(CFLAGS) $(LFLAGS) $(LIBS) $(DEFINES) -o ecc_sign
tpm: $(DEPS)
	$(CC) -std=c++11 $(DEPS) $(CFLAGS) $(LFLAGS) $(LIBS) $(DEFINES) -DENGINETSS -o ecc_sign_tpm
clean: 
	rm -rf ecc_sign* *.o

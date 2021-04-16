#ifndef NFCHelper_h
#define NFCHelper_h
#include <Arduino.h>
#include "string.h"
#include "ecc_config.h"

#include <PN532_HSU.h>
#include <PN532.h>
#define STARTBLOCK 4
#define USE_KEY_B 1
#define USE_KEY_A 0
#define NUMBLOCKS (((PASSLEN+SALTLEN)/16) + (((PASSLEN+SALTLEN)%16) > 0 ? 1:0))

#if DBG 
  #define DEBUG_STDOUT(x) Serial.printf("[*] %s\n", (x))
  #define DEBUG_STDERR(x) Serial.printf("[-] %s\n", (x))
  #define DEBUG_STDSUC(x) Serial.printf("[+] %s\n", (x))
  #define DEBUG_SIG(x) Serial.println(x);
  #define DEBUG_INFO(x) Serial.printf("+++ %s +++\n", (x))
#else
  #define DEBUG_STDOUT(x) {}
  #define DEBUG_STDERR(x) {}
  #define DEBUG_STDSUC(x) {}
  #define DEBUG_SIG(x) {}
  #define DEBUG_INFO(x) {}
#endif

class NFCHelper{
public:
    NFCHelper();
    ~NFCHelper();
    int begin();
    int searchTag();
    int authenticate(bool useKeyA, uint8_t block);
    int readPasswordFromCard(uint8_t* buffer, size_t bufsize);

private:    
    PN532_HSU pn532hsu;
    PN532 nfc;
    uint8_t keyuniversal[6];
    uint8_t keyB[6];  
    uint8_t keyA[6];
    uint8_t uid[7];
    uint8_t uid_len;
    inline bool isDataBlock(uint8_t block);
    inline bool isTrailer(uint8_t block);
    inline bool isFirstBlock(uint8_t block);

    bool isInitialized;
};

#endif
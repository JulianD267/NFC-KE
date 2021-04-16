#pragma once
#define BASE64_LEN(n) (((((n) + 2) / 3) << 2)+1)

#define OLED
// PKDF2_HMAC
#define PASSLEN 64
#define SALTLEN 16
#define ITERATIONS 10000    
#define IVLEN 12
#define KEYLEN 32
// HASH
#define USE_HMAC 1
#define NOT_USE_HMAC 0

#define MYID "sensorJD"
#define USE_SHA256 

#ifdef USE_SHA256
    #define HASHLEN 32
    #define HASH(w, x, y, z) mbedtls_sha256_ret(w, x, y, z)
    #define HASHTYPE MBEDTLS_MD_SHA256
    #define SIGNATURE_LEN 72
#else
    #define HASHLEN 64
    #define HASH(w, x, y, z) mbedtls_sha512_ret(w, x, y, z)
    #define HASHTYPE MBEDTLS_MD_SHA512
#endif


#define DBG 1
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

#define hfmk 0
#if hfmk
#define SSID "hfmk"
#define URL "http://192.168.32.58:8080"
#define WIFIPASS 
#else 
#define SSID "R2D2.4 GHz"
#define URL "http://192.168.178.38:8080"
#define WIFIPASS 
#endif

// Functions

#ifndef Exchanger_h
#define Exchanger_h
#include "HTTPClient.h"
#include "ECCSigner.h"
#include "ecc_config.h"
#ifdef OLED
    #ifndef OLED_CONFIG
        #define OLED_CONFIG
        #include "U8x8lib.h"
        #define OLED_WRITE(x,y,msg) u8x8->drawString(x,y,msg)
        #define OLED_CLEAR()  u8x8->clearDisplay()
        #define OLED_CLEAR_LINE(y) u8x8->clearLine(y)
    #endif
#else
    #ifndef OLED_CONFIG
        #define OLED_CONFIG
        #define OLED_WRITE(x,y,msg) {}
        #define OLED_CLEAR()  {}
        #define OLED_CLEAR_LINE(y) {}
    #endif
#endif

class Exchanger{
public:
    #ifdef OLED
    Exchanger(U8X8_SSD1306_128X64_NONAME_SW_I2C* u8x8);
    #else
    Exchanger();
    #endif    
    virtual ~Exchanger();
    virtual void begin() = 0;
    virtual int getTPMPublickey(String* tpmkey);
    virtual int exchangeKey(ECCSigner* signer) = 0;
protected:
    virtual int _sendKey(byte *concatPw, int flag, ECCSigner* signer);
    bool initialized;
#ifdef OLED
    U8X8_SSD1306_128X64_NONAME_SW_I2C* u8x8;
#endif
    HTTPClient http;
};

#endif
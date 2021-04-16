
#ifndef ECDHExchanger_h
#define ECDHExchanger_h
#include "Exchanger.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"

class ECDHExchanger: public Exchanger{
public:
#ifdef OLED
    ECDHExchanger(U8X8_SSD1306_128X64_NONAME_SW_I2C* _u8x8);
#endif
    virtual ~ECDHExchanger();
    virtual int exchangeKey(ECCSigner* signer);
    virtual void begin();
protected:
    mbedtls_ecdh_context ctx_cli;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char cli_to_srv[32];
};
#endif
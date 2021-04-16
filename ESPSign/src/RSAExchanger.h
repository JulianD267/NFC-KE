
#ifndef RSAExchanger_h
#define RSAExchanger_h
#include "Exchanger.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/rsa.h"
#include "mbedtls/pk.h"

class RSAExchanger: public Exchanger{
public:
#ifdef OLED
    RSAExchanger(U8X8_SSD1306_128X64_NONAME_SW_I2C* _u8x8);
#endif
    virtual ~RSAExchanger();
    virtual int exchangeKey(ECCSigner* signer);
    virtual void begin();
protected:
    mbedtls_rsa_context rsa;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    

};
#endif
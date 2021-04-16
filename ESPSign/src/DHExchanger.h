#ifndef DHExchanger_h
#define DHExchanger_h
#include "Exchanger.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/dhm.h"

class DHExchanger: public Exchanger{
public:
#ifdef OLED
    DHExchanger(U8X8_SSD1306_128X64_NONAME_SW_I2C* _u8x8);
#endif
    virtual ~DHExchanger();
    virtual int exchangeKey(ECCSigner* signer);
    virtual void begin();
protected:
    mbedtls_dhm_context dhm;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    unsigned char dhm_P_2048[256] = MBEDTLS_DHM_RFC3526_MODP_2048_P_BIN;
    unsigned char dhm_G_2048[1] = MBEDTLS_DHM_RFC3526_MODP_2048_G_BIN;

};
#endif
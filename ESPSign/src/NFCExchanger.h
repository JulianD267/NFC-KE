#ifndef NFCExchanger_h
#define NFCExchanger_h
#include "ArduinoJson.h"
#include "Exchanger.h"
#include "ECCSigner.h"
#include "NFCHelper.h"
class NFCExchanger: public Exchanger{
public:
#ifdef OLED
    NFCExchanger(U8X8_SSD1306_128X64_NONAME_SW_I2C* u8x8);
#else
    NFCExchanger();
#endif
    virtual ~NFCExchanger();
    virtual int exchangeKey(ECCSigner* signer);
    virtual void begin();
protected:
    NFCHelper nfc;

};
#endif
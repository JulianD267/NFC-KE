#include "NFCExchanger.h"

#ifdef OLED
NFCExchanger::NFCExchanger(U8X8_SSD1306_128X64_NONAME_SW_I2C* _u8x8)
:Exchanger(_u8x8){
}
#else
NFCExchanger::NFCExchanger(){
}
#endif

NFCExchanger::~NFCExchanger(){
}

void NFCExchanger::begin(){
    // Get the Password via nfc
    nfc.begin();
    this->initialized = true;
}

/*
This function will send the public key to the TPM Server. For that it needs to open the password and public key files on SPIFFS.
After that it will generate the shared secret using PKDF2_HMAC. Using the resulting password and iv, the public key will be encrypted
with AES GCM 256. 
The resulting ciphertext and tag will get concatenated and base64 formatted. Additionally, the base64 encoded ciphertext gets signed using
the private key. 
The final json message, which gets sent off to the TPM server, thus includes the sensorID, which is the AD part of the GCM, the ciphertext
and its signature for verification.
Return:
-2 - Init error
0  - Success
-1 - Format Error
1  - PKDF2 Error
2  - GCM Error
3  - Signature/B64 Error
*/
int NFCExchanger::exchangeKey(ECCSigner* signer){
    if(!this->initialized){ 
        return -2;
    }
    OLED_CLEAR_LINE(3);
    OLED_WRITE(0,3, "NFC search Tag");
    
    // Search for an NFC Tag
    nfc.searchTag();

    OLED_CLEAR_LINE(3);
    OLED_WRITE(0,3, "*Tag found*");

    byte password[PASSLEN+SALTLEN];  
    while(nfc.readPasswordFromCard(password, sizeof(password)) != 0){
      OLED_CLEAR_LINE(3);
      OLED_WRITE(0,3, "Read Failed");
      DEBUG_STDERR("NFC failed");
    }    
    OLED_CLEAR_LINE(3);
    OLED_WRITE(0,3, "*Read OK*");
    
    return this->_sendKey(password, 0, signer);
}


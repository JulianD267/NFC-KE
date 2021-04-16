#include "Exchanger.h"

#ifdef OLED
Exchanger::Exchanger(U8X8_SSD1306_128X64_NONAME_SW_I2C* _u8x8)
:u8x8(_u8x8)
{
  this->initialized = false;
}
#else
Exchanger::Exchanger(){    
  this->initialized = false;
}

#endif
Exchanger::~Exchanger(){
    http.end();
}

int Exchanger::_sendKey(byte *concatPw, int flag, ECCSigner* signer){

    // Destination buffers
    size_t sig_bytes_written, bytes_written;
    String publickey = signer->getPubkey();
    size_t pk_len = publickey.length();
    byte b64_signature_tmp[BASE64_LEN(BASE64_LEN(SIGNATURE_LEN)+16)];   // B64 ( B64 Signature + Tag size )
    byte b64_ct[BASE64_LEN(pk_len)];
    // Now lets derive the encrypted and signed pubkey
    if(signer->deriveEncryptedPubkey(b64_ct, &bytes_written, b64_signature_tmp, &sig_bytes_written, concatPw, (PASSLEN+SALTLEN)) != 0){
      DEBUG_STDERR("ERROR in pubkey derivation"); 
      return -1;     
    }

    // Format it to json
    StaticJsonDocument<700> json;
    json["s_id"] = MYID;
    json["pkey"] = (char*)b64_ct;
    json["sig"]  = (char*)b64_signature_tmp;
    json["flag"] = flag;
    String ptr;
    serializeJson(json, ptr); 
    OLED_CLEAR_LINE(3);
    OLED_WRITE(0,3, "Send enc. key");  


    // Send it off
    http.begin(String(URL)+ "/append");
    DEBUG_INFO("[HTTP2] GET...");
    // start connection and send HTTP header
    int httpCode = 0;

    // httpCode will be negative on error
    while(httpCode != HTTP_CODE_OK) {
      // HTTP header has been send and Server response header has been handled
      httpCode = http.POST(ptr);
      DEBUG_STDOUT(("[HTTP2] GET... code: " + String(httpCode)).c_str());
      // file found at server
      if(httpCode == HTTP_CODE_OK) {
        String tpmkey = http.getString();
        if(tpmkey == publickey){
          OLED_CLEAR_LINE(3);
          OLED_WRITE(0,3, "Send SUCCESS");
          DEBUG_STDSUC("TPM Returned my key!");
          http.end();
          return 0;
        }else{
          OLED_CLEAR_LINE(3);
          OLED_WRITE(0,3, "Send ERROR");
          DEBUG_STDERR(("[HTTP2] GET... failed, error: " + http.errorToString(httpCode)).c_str());
          DEBUG_STDERR("TPM Returned wrong key!");
        }
      }
  }
  http.end();
  return -1;
}


/*
This function will retrieve the TPM public key. Nothing special here.
Can be the same for all the derivate classes, since this is doing the same thing
Return
0     - Success
1     - Error
*/
int Exchanger::getTPMPublickey(String* tpmkey){
  OLED_CLEAR_LINE(3);
  OLED_WRITE(0,3, "Get TPM Key");
  http.begin(String(URL)+"/pkey"); //HTTP

  DEBUG_STDOUT("[HTTP] GET...");
  // start connection and send HTTP header
  int httpCode = http.GET();

  // httpCode will be negative on error
  if(httpCode > 0) {
    // HTTP header has been send and Server response header has been handled
    DEBUG_STDOUT(("[HTTP] GET... code: " + String(httpCode)).c_str());

    // file found at server
    if(httpCode == HTTP_CODE_OK) {
      *tpmkey = http.getString();
      OLED_CLEAR_LINE(3);
      OLED_WRITE(0,3, "TPM Key OK");
      DEBUG_SIG(*tpmkey);
      // Might be useful to apply a sanity check in here...
      http.end();
      return 0;
    }
    else{
      OLED_CLEAR_LINE(3);
      OLED_WRITE(0,3, "TPM Key FAILED");
      DEBUG_STDERR("Error in TPM Key");
      http.end();
      return 1;
    }
  } else {
    DEBUG_STDERR(("[HTTP] GET... failed, error: " + http.errorToString(httpCode)).c_str());
    OLED_CLEAR_LINE(3);
    OLED_WRITE(0,3, "TPM Key ERROR");
    http.end();
    return 1;
  }
  
  return 1;
}
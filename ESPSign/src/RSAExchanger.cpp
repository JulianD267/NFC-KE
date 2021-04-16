#include "RSAExchanger.h"

#ifdef OLED
RSAExchanger::RSAExchanger(U8X8_SSD1306_128X64_NONAME_SW_I2C* _u8x8)
:Exchanger(_u8x8){
    
}
#endif

RSAExchanger::~RSAExchanger(){
    mbedtls_rsa_free(&rsa);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

void RSAExchanger::begin(){
    const char pers[] = "i4sec";
    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
    int rsa_keysize = 2048;
    int exponent = 65537;
        
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    // Seed the DRBG
    if(mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, sizeof(pers)) != 0 ){
        DEBUG_STDERR("[RSAExchanger] Seeding DRBG Failed");
    }
    OLED_CLEAR_LINE(3);
    OLED_WRITE(0,3, "GEN RSA KEY...");
    // Read the Prime into the local buffer
    if( mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, rsa_keysize, exponent) != 0){
        DEBUG_STDERR("[RSAExchanger] Key generation failed");
    }        

    OLED_CLEAR_LINE(3);
    OLED_WRITE(0,3, "GEN RSA KEY DONE");
    this->initialized = true;
}

/*
This function will send the public key to the TPM Server. For that it implements a ECDH Key exchange. It will first generate a local client
secret and form a public key from that. After that, a salt is generated and later transmitted along the public key to the server. If all
works well, the server will respond with its public key. With this at hand, the shared secret can be generated using the ECDH algorithm. 
The shared secret can then be used as the password for the _sendKey method, in order to generate a symmetric AES Key for encryption.
Return 
-2      Init error
-1      Crypto Error
0       Success
1       Hash error
2       Base64 Error
*/
int RSAExchanger::exchangeKey(ECCSigner* signer){
    if(!this->initialized){
        return -2;
    }
    
    // Create a public key context
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    if(mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0){
        DEBUG_STDERR("Setting PK info failed");
        return -1;
    }; 

    // Assign the RSA context to the public key context
    pk.pk_ctx = &rsa;

    // Export Key to PEM
    OLED_CLEAR_LINE(3);
    OLED_WRITE(0,3, "RSA WRITE PEM");
    byte keypem[500];
    if(mbedtls_pk_write_pubkey_pem(&pk, keypem, sizeof(keypem)) != 0){
        DEBUG_STDERR("Key to PEM failed");
        return -1;
    }
    
    // Send the public data
    OLED_CLEAR_LINE(3);
    OLED_WRITE(0,3, "KEY EX INIT");
    http.begin(String(URL)+"/rsaappend");
    DEBUG_INFO("[HTTP2] GET...");

    // The Server content
    int httpCode = 0;
    
    // httpCode will be negative on error
    while(httpCode != HTTP_CODE_OK) {

      // Pack the payload into a String and send that
      String tmp((char*)keypem);
      httpCode = http.POST(tmp);
      DEBUG_STDOUT(("[HTTP2] GET... code: " + String(httpCode)).c_str());

      // Decode from b64
      String rsa_payload = http.getString();
      byte decoded_payload[rsa_payload.length()];
      size_t b64_bytes_written;
      if(mbedtls_base64_decode(decoded_payload, sizeof(decoded_payload), &b64_bytes_written, (byte*)rsa_payload.c_str(), rsa_payload.length()) != 0){
          DEBUG_STDERR("B64 decoding failed");
          return 2;
      };

      // Decrypt      
      byte pass_salt[PASSLEN+SALTLEN];      // 80 bytes mostly
      size_t bytes_written;
      
      if(mbedtls_rsa_pkcs1_decrypt(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, &bytes_written, decoded_payload, pass_salt, PASSLEN+SALTLEN) != 0){
          DEBUG_STDERR("DECRYPTION FAILED");
      }else{
        OLED_CLEAR_LINE(3);
        OLED_WRITE(0,3, "RSA DECRYPT OK");
        // Pass and Salt received and stored in outputbuf
        return this->_sendKey(pass_salt, 1, signer);
      }
      // Wait after fail
      delay(500);
    } 
    
    return 0;
  }
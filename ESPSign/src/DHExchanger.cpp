#include "DHExchanger.h"

#ifdef OLED
DHExchanger::DHExchanger(U8X8_SSD1306_128X64_NONAME_SW_I2C* _u8x8)
:Exchanger(_u8x8){
    
}
#endif

DHExchanger::~DHExchanger(){
    mbedtls_dhm_free(&dhm);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

void DHExchanger::begin(){
    const char pers[] = "i4sec";
    mbedtls_dhm_init(&dhm);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    // Seed the DRBG
    if(mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, sizeof(pers)) != 0 ){
        DEBUG_STDERR("[DHExchanger] Seeding DRBG Failed");
    }
    // Read the Prime into the local buffer
    if( mbedtls_mpi_read_binary( &dhm.P, dhm_P_2048, sizeof( this->dhm_P_2048) ) != 0){
        DEBUG_STDERR("[DHExchanger] Read Prime into buffer failed");
    }        
    // Read the Generator G into the local buffer
    if( mbedtls_mpi_read_binary( &dhm.G, dhm_G_2048, sizeof( dhm_G_2048 ) ) != 0 ){
        DEBUG_STDERR("[DHExchanger] Read Generator into buffer failed");
    }
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
int DHExchanger::exchangeKey(ECCSigner* signer){
    if(!this->initialized){
        return -2;
    }
    dhm.len = mbedtls_mpi_size( &dhm.P );
    unsigned char cli_to_srv[dhm.len];

    // Create the Public key G*x mod P, with x being our secret
    if(mbedtls_dhm_make_public( &dhm, (int) dhm.len, cli_to_srv, dhm.len, mbedtls_ctr_drbg_random, &ctr_drbg ) != 0){
        // Public Key generation failed
        DEBUG_STDERR("DH Pubkey generation failed");
        return -1;
    }
    
    // Generate a salt for later
    byte salt[SALTLEN];
    int ret = mbedtls_ctr_drbg_random(&ctr_drbg, salt, SALTLEN); 
    if(ret != 0){
        DEBUG_STDERR("Random Salt generation failed");
        return -1;
    };

    // Concat key and salt
    // [--- KEY[0:32]---|--- SALT[32:48]---]
    byte payload[dhm.len+SALTLEN];
    memcpy(payload, cli_to_srv, dhm.len);
    memcpy(payload+dhm.len, salt, SALTLEN);

    // B64 encode
    size_t bytes_written;
    byte b64_payload[BASE64_LEN(dhm.len+SALTLEN)];
    if(mbedtls_base64_encode(b64_payload, BASE64_LEN(dhm.len+SALTLEN), &bytes_written, payload, dhm.len+SALTLEN) == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL){
        DEBUG_STDERR("Buffer too small for Base64 encoding!");
        return 2;
    }
    
    OLED_CLEAR_LINE(3);
    OLED_WRITE(0,3, "DH 1. Phase");
    //================= FIRST EXCHANGE ===================
    // Client                                       Server
    //   |                                             |
    //   |------- b64(cli_to_srv + salt)[48] --------->|
    //   |                                             |
    //====================================================

    // Send the public data
    http.begin(String(URL)+"/dhappend");
    DEBUG_INFO("[HTTP2] GET...");

    // The Server content
    int httpCode = 0;
    byte srv_to_cli[dhm.len];
    
    // httpCode will be negative on error
    while(httpCode != HTTP_CODE_OK) {

      // Pack the payload into a String and send that
      String tmp((char*)b64_payload);
      httpCode = http.POST(tmp);
      DEBUG_STDOUT(("[HTTP2] GET... code: " + String(httpCode)).c_str());
      
      // Lets have a look at the response
      // Server will respond with its b64 encoded key
      if(httpCode == HTTP_CODE_OK) {
        //==================== 2. Phase  =====================
        // Client                                       Server
        //   |                                             |
        //   |<--------- b64(srv_to_cli)[32] --------------|
        //   |                                             |
        //====================================================
        String srv_pub = http.getString(); 

        // Decode the Server key
        if(mbedtls_base64_decode(srv_to_cli, dhm.len, &bytes_written, (byte*) srv_pub.c_str(), srv_pub.length()) == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL){
            DEBUG_STDERR("[2.Phase DH] Buffer too small for Base64 decoding!");
            return 2;
        };    
      }
    }

    OLED_CLEAR_LINE(3);
    OLED_WRITE(0,3, "DH 2. Phase");

    // Read Public Server key into the G*y buffer    
    if((ret = mbedtls_mpi_read_binary( &dhm.GY, srv_to_cli, dhm.len)) != 0){
        DEBUG_STDERR("Read binary failed for srv_to_cli");
        return -1;
    }

    // Calc the secret
    byte shared_key[dhm.len];
    if(mbedtls_dhm_calc_secret( &dhm, shared_key, dhm.len, &bytes_written, mbedtls_ctr_drbg_random, NULL ) != 0){
        // Secret generation failed
        DEBUG_STDERR("Generation of Secret failed");
        return -1;
    }

    // Stick to 64 Bytes of pw
    byte hash_secret[PASSLEN];
    if(mbedtls_sha512_ret(shared_key, dhm.len, hash_secret, NOT_USE_HMAC) !=0){
        DEBUG_STDERR("Hash of Message failed");
        return 1;
    };
    DEBUG_STDOUT("Secret generated successfully");

    OLED_CLEAR_LINE(3);
    OLED_WRITE(0,3, "DH Complete");
    // Concat the password and salt
    byte password[PASSLEN+SALTLEN];
    memcpy(password, hash_secret, PASSLEN);
    memcpy(password+PASSLEN, salt, SALTLEN);

    // Exchange
    return this->_sendKey(password, 1, signer);
  }
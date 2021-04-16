#include "ECDHExchanger.h"
#define PL PASSLEN/2
#ifdef OLED
ECDHExchanger::ECDHExchanger(U8X8_SSD1306_128X64_NONAME_SW_I2C* _u8x8)
:Exchanger(_u8x8)
{        
}
#endif

ECDHExchanger::~ECDHExchanger(){
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_ecdh_free(&ctx_cli);
    mbedtls_entropy_free(&entropy);
}

void ECDHExchanger::begin(){
    const char pers[] = "i4sec";
    mbedtls_ecdh_init(&ctx_cli);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    // Seed the DRBG
    if(mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, sizeof(pers)) != 0 ){
        DEBUG_STDERR("[ECDHExchanger] Seeding DRBG Failed");
    }
    // Load the EC Group
    if(mbedtls_ecp_group_load(&ctx_cli.ctx.mbed_ecdh.grp, MBEDTLS_ECP_DP_CURVE25519) != 0){
        DEBUG_STDERR("[ECDHExchanger] EC Group Load failed");
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
int ECDHExchanger::exchangeKey(ECCSigner* signer){
    if(!this->initialized){
        return -2;
    }
    // Generate Client public key 
    int ret = mbedtls_ecdh_gen_public( &ctx_cli.ctx.mbed_ecdh.grp, &ctx_cli.ctx.mbed_ecdh.d, &ctx_cli.ctx.mbed_ecdh.Q, mbedtls_ctr_drbg_random, &ctr_drbg );
    if( ret != 0 ){
        DEBUG_STDERR("[ECDHExchanger] Public Key generation failed");
        return -1;
    }

    // Write the public key to the payload buffer
    ret = mbedtls_mpi_write_binary( &ctx_cli.ctx.mbed_ecdh.Q.X, cli_to_srv, sizeof(cli_to_srv) );
    if( ret != 0 ){
        DEBUG_STDERR("[ECDHExchanger] Write Public Key to bytes failed");
        return -1;
    }

    // Generate a salt for later
    byte salt[SALTLEN];
    ret = mbedtls_ctr_drbg_random(&ctr_drbg, salt, SALTLEN); 
    if(ret != 0){
        DEBUG_STDERR("Random Salt generation failed");
        return -1;
    };

    // Concat key and salt
    // [--- KEY[0:32]---|--- SALT[32:48]---]
    byte payload[PL+SALTLEN];
    memcpy(payload, cli_to_srv, PL);
    memcpy(payload+PL, salt, SALTLEN);

    // B64 encode
    size_t bytes_written;
    byte b64_payload[BASE64_LEN(PL+SALTLEN)];
    if(mbedtls_base64_encode(b64_payload, BASE64_LEN(PL+SALTLEN), &bytes_written, payload, PL+SALTLEN) == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL){
        DEBUG_STDERR("Buffer too small for Base64 encoding!");
        return 2;
    }
    
    OLED_CLEAR_LINE(3);
    OLED_WRITE(0,3, "ECDH 1. Phase");
    //================= FIRST EXCHANGE ===================
    // Client                                       Server
    //   |                                             |
    //   |------- b64(cli_to_srv + salt)[48] --------->|
    //   |                                             |
    //====================================================

    // Send the public data
    http.begin(String(URL)+"/ecdhappend");
    DEBUG_INFO("[HTTP2] GET...");

    // The Server content
    int httpCode = 0;
    byte srv_to_cli[PL];
    
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
        if(mbedtls_base64_decode(srv_to_cli, PL, &bytes_written, (byte*) srv_pub.c_str(), srv_pub.length()) == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL){
            DEBUG_STDERR("[2.Phase ECDH] Buffer too small for Base64 decoding!");
            return 2;
        };    
      }
    }

    OLED_CLEAR_LINE(3);
    OLED_WRITE(0,3, "ECDH 2. Phase");
    
    if((ret = mbedtls_mpi_lset(&ctx_cli.ctx.mbed_ecdh.Qp.Z, 1)) != 0){
        DEBUG_STDERR("LSET failed after exchange");
        return -1;
    }

    
    if((ret = mbedtls_mpi_read_binary( &ctx_cli.ctx.mbed_ecdh.Qp.X, srv_to_cli, PL)) != 0){
        DEBUG_STDERR("Read binary failed for srv_to_cli");
        return -1;
    }

    // Generate the secret
    ret = mbedtls_ecdh_compute_shared( &ctx_cli.ctx.mbed_ecdh.grp, &ctx_cli.ctx.mbed_ecdh.z,
                                       &ctx_cli.ctx.mbed_ecdh.Qp, &ctx_cli.ctx.mbed_ecdh.d,
                                       mbedtls_ctr_drbg_random, &ctr_drbg );
    if( ret != 0 ){
        DEBUG_STDERR( "Secret generation failed");    
        return -1;    
    }

    // Generate Byte array from Secret
    byte secret[PL];
    if((ret = mbedtls_mpi_write_binary(&ctx_cli.ctx.mbed_ecdh.z, secret, PL)) != 0){
        DEBUG_STDERR("Write secret bytes failed");  
        return -1;     
    }

    // Stick to 64 Bytes of pw
    byte hash_secret[PASSLEN];
    if(mbedtls_sha512_ret(secret, PL, hash_secret, NOT_USE_HMAC) !=0){
        DEBUG_STDERR("Hash of Message failed");
        return 1;
    };
    DEBUG_STDOUT("Secret generated successfully");

    OLED_CLEAR_LINE(3);
    OLED_WRITE(0,3, "ECDH Complete");
    // Concat the password and salt
    byte password[PASSLEN+SALTLEN];
    memcpy(password, hash_secret, PASSLEN);
    memcpy(password+PASSLEN, salt, SALTLEN);

    // Exchange
    return this->_sendKey(password, 1, signer);
  }
#ifndef ECCSigner_h
#define ECCSigner_h
#include <Arduino.h>
#include <ArduinoJson.h>
#include <WiFiMulti.h>
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecp_internal.h"
#include "mbedtls/hmac_drbg.h"
#include "mbedtls/pk.h"
#include "mbedtls/base64.h"
#include "mbedtls/sha256.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/gcm.h"
#include "string.h"
#include "WiFi.h"
#include "HTTPClient.h"
#include "ecc_config.h"

class ECCSigner{
public:
    ECCSigner();
    virtual ~ECCSigner();

    virtual void begin();
    virtual void printHex(byte num);

    virtual int sign(byte* message, size_t msg_len, byte* signature, size_t* sig_bytes);
    virtual int sign_b64(byte* message, size_t msg_len, byte* b64_sig_buf, size_t b64_sig_bytes, size_t* bytes_written);

    virtual int verify(byte* message, size_t msg_len, byte* signature, size_t sig_len, byte* publickey, size_t keylen);
    virtual int verify_b64(String message, String b64_signature, String publickey);
    virtual int deriveEncryptedPubkey(byte* ct_dst, size_t* ct_len_dst, byte* sig_dst, size_t* sig_len_dst, byte* password, size_t passlen);
    virtual String getPubkey();
    
protected:
    String publickey;
    mbedtls_ecdsa_context ecdsa;

    virtual int deriveKeys(byte* concatPW, size_t passlen, byte* kdf_key, size_t key_len, byte* kdf_iv, size_t iv_len);
    virtual void ecp_clear_precomputed( mbedtls_ecp_group *grp );
    mbedtls_ctr_drbg_context drbg;
    bool isInitialized;
};

#endif
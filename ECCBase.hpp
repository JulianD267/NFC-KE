//
//  ECCBase.hpp
//  ecc-sign-ossl
//
//  Created by Julian on 12.08.20.
//  Copyright © 2020 HS Osnabrück. All rights reserved.
//

#ifndef ECCBase_hpp
#define ECCBase_hpp
#include <cstring>
#include <cstdio>
#include <string>
#include <fstream>
#include <iostream>
#include <openssl/aes.h>
#include <openssl/conf.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "Base64Coder.hpp"

#ifdef DBG
#define INFO(x) (std::cout << "+++ " << (x) << " +++" << std::endl)
#define SUCCESS(x) (std::cout << "\t*** " << (x) << " ***" << std::endl)
#define DEBUG_STDERR(x) (std::cerr << "[!] " << (x) << std::endl)
#define DEBUG_STDOUT(x) (std::cout << "\t[*] " << (x) << std::endl)
//... etc
#else
#define SUCCESS(x) do{}while(0)
#define INFO(x) (std::cout << "+++ " << (x) << " +++" << std::endl)
#define DEBUG_STDERR(x) (std::cerr << "[!] " << (x) << std::endl)
#define DEBUG_STDOUT(x) do{}while(0)
//... etc
#endif
typedef unsigned char byte;
class ECCBase{
public:
    ECCBase();
    ECCBase(bool);
    ~ECCBase();
    
    /* Key export/import/generation */
    int load_public_key_from_file(const std::string& filename);
    int load_private_key_from_file(const std::string& filename);
    int generate_keys();
    int export_keys_to_files(const std::string& filename);
    int export_private_key_to_file(const std::string& filename);
    int export_public_key_to_file(const std::string& filename);
    
    /* Signing and verification */
    int sign(unsigned char* message, size_t message_length);
    int sign(std::string message);
    
    int verify(unsigned char* msg, size_t msglen, unsigned char* signature, size_t signature_len, EC_KEY*);
    int verify(std::string& msg, std::string& signature);
    int verify(std::string& msg, std::string& signature, EC_KEY* key);
    int verify(std::string& msg, std::string& signature, std::string& pubkey_filename);
    
    /* Encryption and decryption */
    int encrypt_b64(unsigned char* plaintext, size_t ptlen,
                unsigned char* additional_data, size_t aad_len,
                unsigned char* password, int passlen, unsigned char* ciphertext);
    int encrypt(unsigned char* plaintext, size_t ptlen,
                unsigned char* additional_data, size_t aad_len,
                unsigned char* password, int passlen, unsigned char* ciphertext);
    int decrypt_b64(std::string ciphertext,
                unsigned char* additional_data, size_t aad_len,
                unsigned char* password, int passlen,
                unsigned char* salt, int saltlen,
                unsigned char* plaintext);
    int decrypt(unsigned char* ciphertext, size_t ctlen,
                unsigned char* additional_data, size_t aad_len,
                unsigned char* password, int passlen,
                unsigned char* salt, int saltlen,
                unsigned char* plaintext);
    
    /* Helper methods */
    std::string dump_signature(const std::string& filename);
    void clean();
    
    /* Getter/Setter */
    EC_KEY* getPubkey();
    EVP_PKEY* getVerifyKey();
    unsigned char* getSignature();
    size_t getSignatureLength();
    void setCurve(int);
    
    // Static methods
    static int create_password(unsigned char* pwbuffer, int pw_length, unsigned char* saltbuffer, int salt_length);
private:
    /* Private Methods */
    EC_KEY* _load_public_key_from_file(const std::string&);
    EC_KEY* _load_private_key_from_file(const std::string&);
    int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                    unsigned char *aad, int aad_len,
                    unsigned char *tag,
                    unsigned char *key,
                    unsigned char *iv, int iv_len,
                    unsigned char *plaintext);
    void handleErrors(void);
    int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                    unsigned char *aad, int aad_len,
                    unsigned char *key,
                    unsigned char *iv, int iv_len,
                    unsigned char *ciphertext,
                    unsigned char *tag);
    
    /* Local Attributes */
    EC_KEY* pubkey, *privkey;
    EVP_PKEY* evp_sign_key, *evp_verify_key;
    unsigned char signature[256];
    size_t signature_len;
    Base64Coder coder;
    int nid;                // Curve id
    ENGINE* tpmtss;         // Only set if engine exists!
};
#endif /* ECCBase_hpp */

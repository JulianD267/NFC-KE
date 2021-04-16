//
//  ServerFunctions.hpp
//  ecc-sign-ossl
//
//  Created by Julian on 12.11.20.
//  Copyright © 2020 HS Osnabrück. All rights reserved.
//

#ifndef ServerFunctions_hpp
#define ServerFunctions_hpp
#include <iostream>
#include <cstdio>
#include <cstring>
#include <openssl/rand.h>
#include "ECCBase.hpp"
#include "server/httplib.h"
#include "server/client_http.hpp"
#include "server/server_http.hpp"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include "NFCHandler.hpp"
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/dhm.h>
#include <mbedtls/rsa.h>
#include <mbedtls/pk.h>
#include <vector>

#define PASSLEN 64          // Password has 64 Bytes
#define SALTLENGTH 16
#define PORT 8080
#define KEYNAME_PRIV "base_key_priv.pem"
#define KEYNAME_PUB "base_key_pub.pem"
#define KEYNAME "base_key"
#define BASE64_LEN(n) (((((n) + 2) / 3) << 2)+1)
typedef uint8_t byte;

// Setup a rest interface
using HttpServer = SimpleWeb::Server<SimpleWeb::HTTP>;
using HttpClient = SimpleWeb::Client<SimpleWeb::HTTP>;

class ServerFunctions{
public:
    ServerFunctions();
    ~ServerFunctions();
    
    void nfcAppend(std::shared_ptr<HttpServer::Response> response, std::shared_ptr<HttpServer::Request> request);
    
    void dataGet(std::shared_ptr<HttpServer::Response> response, std::shared_ptr<HttpServer::Request> request);
    
    void jsonPost(std::shared_ptr<HttpServer::Response> response, std::shared_ptr<HttpServer::Request> request);
    
    void pubkeyGet(std::shared_ptr<HttpServer::Response> response, std::shared_ptr<HttpServer::Request> request);
    
    void nfcReissue(std::shared_ptr<HttpServer::Response> response, std::shared_ptr<HttpServer::Request> request);
    
    void clear(std::shared_ptr<HttpServer::Response> response, std::shared_ptr<HttpServer::Request> request);
    
private:
    int genPasswordForNFC(byte* nfcdata, int nfcdatalen, bool force=false);
    int verify_sig(ECCBase* ec, const std::string& filepath, std::string sig, std::string message);
    
    int beginNFC();
    
    static std::string absPath(std::string file);
    ECCBase *signer, *ec;
    byte nfcdata[PASSLEN+SALTLENGTH];
    NFCHandler nfc;
    
    Base64Coder coder;
    std::vector<std::string> data;
    std::vector<std::string> valid_pws;
    
};

#endif /* ServerFunctions_hpp */

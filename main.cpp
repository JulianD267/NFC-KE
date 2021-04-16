//
//  main.cpp
//  ecc-sign-ossl
//
//  Created by Julian on 12.08.20.
//  Copyright © 2020 HS Osnabrück. All rights reserved.
//

#include <iostream>
#include <string.h>
#include "server/httplib.h"
#include "server/client_http.hpp"
#include "server/server_http.hpp"
#include "ServerFunctions.hpp"

#define PORT 8080

// Setup a rest interface
using HttpServer = SimpleWeb::Server<SimpleWeb::HTTP>;
using HttpClient = SimpleWeb::Client<SimpleWeb::HTTP>;


int main(int argc, const char * argv[]) {
    ServerFunctions funcs;
    
    // ================= Server =======================
    HttpServer server;
    server.config.port = PORT;
    server.config.thread_pool_size = 2;
    
    // Endpoint Configuration
    server.resource["^/clear$"]["GET"] =[&](std::shared_ptr<HttpServer::Response> response, std::shared_ptr<HttpServer::Request> request) {
        funcs.clear(response, request);
    };
    server.resource["^/nfc$"]["GET"] = [&](std::shared_ptr<HttpServer::Response> response, std::shared_ptr<HttpServer::Request> request) {
        funcs.nfcReissue(response, request);
    };
    server.resource["^/pkey$"]["GET"] = [&](std::shared_ptr<HttpServer::Response> response, std::shared_ptr<HttpServer::Request> request) {
        funcs.pubkeyGet(response, request);
    };
    server.resource["^/append$"]["POST"] = [&](std::shared_ptr<HttpServer::Response> response, std::shared_ptr<HttpServer::Request> request){
        funcs.nfcAppend(response, request);
        };
    server.resource["^/data$"]["GET"] = [&](std::shared_ptr<HttpServer::Response> response, std::shared_ptr<HttpServer::Request> request) {
        funcs.dataGet(response, request);
    };
    server.resource["^/json$"]["POST"] = [&](std::shared_ptr<HttpServer::Response> response, std::shared_ptr<HttpServer::Request> request) {
        funcs.jsonPost(response, request);
    };
    
    // Start server and receive assigned port when server is listening for requests
    std::promise<unsigned short> server_port;
    std::thread server_thread([&server, &server_port]() {
        // Start server
        server.start([&server_port](unsigned short port) {
            server_port.set_value(port);
        });
    });
    std::cout << "Server listening on port " << server_port.get_future().get() << std::endl
    << std::endl;
    
    server_thread.join();
    return 0;
}


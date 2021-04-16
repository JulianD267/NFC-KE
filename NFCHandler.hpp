//
//  NFCHandler.hpp
//  ecc-sign-ossl
//
//  Created by Julian on 20.10.20.
//  Copyright © 2020 HS Osnabrück. All rights reserved.
//

#ifndef NFCHandler_hpp
#define NFCHandler_hpp

#include <cstdio>
#include <nfc/nfc.h>
#include <nfc/nfc-types.h>
#include <nfc/nfc-emulation.h>
#include "mifare.h"
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <cstddef>
#include <cctype>
#include <iostream>
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
typedef enum {
    ACTION_READ,
    ACTION_WRITE,
    ACTION_USAGE
} action_t;

typedef uint8_t byte;

class NFCHandler{
public:
    NFCHandler();
    ~NFCHandler();
    bool write_card(byte begin_block, byte* data, size_t datalen, bool clean=false);
    bool read_card(byte begin_block, byte end_block, byte* data);
    bool find_card();
    
private:
    byte default_key[6];     // 6 Bytes key
    byte default_acl[4];     // 4 Bytes ACL
    byte mykeyA[6];
    byte mykeyB[6];
    
    // NFC Fields
    nfc_device *nfc_dev;
    nfc_context *context;
    nfc_target nfcTarget;
    const nfc_modulation modulation;
    
    // Mifare specific fields
    mifare_param mifareParam;
    mifare_classic_tag mifaretagKeys;
    byte *uid;
    size_t uid_len;
    
    // Methods
    static inline bool is_trailer_block(byte block);
    static inline bool is_first_block(byte block);
    byte get_trailer_block(byte firstBlock);
    bool authenticate(byte block, bool bUseKeyA);
    
    bool nfc_initiator_mifare_cmd(mifare_cmd mifareCmd, byte block);
    
};
#endif /* NFCHandler_hpp */

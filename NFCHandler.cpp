//
//  NFCHandler.cpp
//  ecc-sign-ossl
//
//  Created by Julian on 20.10.20.
//  Copyright © 2020 HS Osnabrück. All rights reserved.
//

#include "NFCHandler.hpp"


NFCHandler::NFCHandler()
:default_key{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, default_acl{0xff, 0x07, 0x80, 0x69},
 mykeyA{0xAF, 0xFE, 0xAF, 0xFE, 0xAF, 0xFE}, mykeyB{0xFE, 0xAF, 0xFE, 0xAF, 0xFE, 0xAF},
 modulation{.nmt = NMT_ISO14443A , .nbr = NBR_106,}
{
    nfc_init(&context);
    if (context == nullptr) {
        DEBUG_STDERR("Unable to init libnfc (malloc)\n");
        exit(EXIT_FAILURE);
    }
    
    // Open the nfc device
    nfc_dev = nfc_open(context, nullptr);
    if (nfc_dev == nullptr) {
        DEBUG_STDERR("Error opening NFC reader\n");
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }
    
    // initiate the device
    if (nfc_initiator_init(nfc_dev) < 0) {
        nfc_perror(nfc_dev, "nfc_initiator_init");
        nfc_close(nfc_dev);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    };
    
    // Let the reader only try once to find a tag
    if (nfc_device_set_property_bool(nfc_dev, NP_INFINITE_SELECT, false) < 0) {
        nfc_perror(nfc_dev, "nfc_device_set_property_bool");
        nfc_close(nfc_dev);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }
    
    // Disable ISO14443-4 switching in order to read devices that emulate Mifare Classic with ISO14443-4 compliance.
    if (nfc_device_set_property_bool(nfc_dev, NP_AUTO_ISO14443_4, false) < 0) {
        nfc_perror(nfc_dev, "nfc_device_set_property_bool");
        nfc_close(nfc_dev);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }
    
    DEBUG_STDOUT("NFC reader opened");
}

NFCHandler::~NFCHandler(){
    
    nfc_close(nfc_dev);
    nfc_exit(context);
};
     

     
/*
This method will read all the data contained within a tag. The data will be written
to the provided data buffer. Make sure, that it has the necessary length! It will
attempt to read from the begin_block onward up to the end_block.
-- Input
 begin_block            First block that will be read
 end_block              Last block that will be read
 data                   Buffer destination for the data
-- Output
 true           Read succeeded
 false          Error occured
*/
bool NFCHandler::read_card(byte begin_block, byte end_block, byte* data){
    // Sanity check
    if(begin_block < 0 || begin_block > end_block){
        return false;
    }
    
    byte bytes_written=0;
    
    // This assumes that the authentication is valid for 4 consecutive blocks,
    // so authentication has to be executed on the first block only.
    for(int i=begin_block; i<=end_block; i++){
        if(is_first_block(i)){
            authenticate(i, true);
        }
        if (nfc_initiator_mifare_cmd(MC_READ, i)) {
            memcpy(data+bytes_written, mifareParam.mpd.abtData, 16);
#ifdef DBG
            printf("Block %d:  ",i);
            for(int j=0; j<16; j++){
                printf("%02X", (data+bytes_written)[j] );
            }
            printf("\n");
#endif
            bytes_written+=16;
        } else {
#ifdef DBG
            printf("!\nError: unable to read block 0x%02x\n", 4);
#endif
            return false;
        }
    }
    return true;
}

/*
This method will attempt find a new MIFARE Card until it really finds one. If it really finds one,
it checks if it is a MIFARE classic tag and then set the UID and UID_len accordingly. Depending on
the Debug configuration, it will also read all the data contained on the card.
-- Input
 
-- Output
 true           Card found
 false          Wrong card type
*/
bool NFCHandler::find_card(){
    // Try to find a MIFARE Classic tag
    bool notag = true;
    DEBUG_STDOUT("Waiting for tag...\n");
    while(notag){
        // Continuously scanning for tag
        if (nfc_initiator_select_passive_target(nfc_dev, modulation, nullptr, 0, &nfcTarget) > 0) {
            // Tag found!
            // Test if we are dealing with a MIFARE compatible tag
            if ((nfcTarget.nti.nai.btSak & 0x08) != 0) {
                notag = false;
                DEBUG_STDOUT("FOUND THE CARD, continue\n");
                
                uid = nfcTarget.nti.nai.abtUid;
                uid_len = nfcTarget.nti.nai.szUidLen;
#ifdef DBG
                byte data[1000];
                read_card(4, 63, data);
#endif
            }
            else{
                DEBUG_STDERR("Warning: tag is probably not a MFC!\n");
                return false;
            }
        }
    
    }
    return true;
}
    

// Some descriptive helper methods
bool NFCHandler::is_first_block(byte block)
{
    // Test if we are in the small or big sectors
    return ((block) % 4 == 0);
}

bool NFCHandler::is_trailer_block(byte block)
{
        return ((block) % 4 == 3);
}

byte NFCHandler::get_trailer_block(byte firstBlock)
{
    // Test if we are in the small or big sectors
    byte trailer_block = firstBlock + (3 - (firstBlock % 4));
    
    return trailer_block;
}

/*
 This method is responsible for the authentication of a given block. Depending on the
 provided useKeyA flag, either KeyA or KeyB will be used to authenticate to the card.
 Though, when the authentication failes, the method will attempt to authenticate using
 another key.
 -- Input
 block          The block that will be authenticated
 useKeyA        Flag, either use KeyA (true) or KeyB (false)
 -- Output
 true           Authentication success
 false          Authentication failed
 */
bool NFCHandler::authenticate(byte block, bool useKeyA)
{
    mifare_cmd cmd;
    
    // Set the authentication information (uid)
    memcpy(mifareParam.mpa.abtAuthUid, uid + uid_len - 4, 4);
    
    // Should we use key A or B?
    cmd = (useKeyA) ? MC_AUTH_A : MC_AUTH_B;
    
    // Lets assume we got the right key
    memcpy(mifareParam.mpa.abtKey, default_key, 6);
    
    // Try that
    if (nfc_initiator_mifare_cmd(cmd, block)) {
        DEBUG_STDOUT("Success for Key Default");
        if (useKeyA){
            memcpy(mifaretagKeys.amb[block].mbt.abtKeyA, &mifareParam.mpa.abtKey, 6);
        }
        else{
            memcpy(mifaretagKeys.amb[block].mbt.abtKeyB, &mifareParam.mpa.abtKey, 6);
        }
        return true;
    }
    if (nfc_initiator_select_passive_target(nfc_dev, modulation, uid, uid_len, nullptr) <= 0) {
        DEBUG_STDERR("Tag was removed");
        return false;
    }
    
    // Hm lets try again using another key
    memcpy(mifareParam.mpa.abtKey, mykeyA, 6);
    if (nfc_initiator_mifare_cmd(cmd, block)) {
        DEBUG_STDOUT("Success for Key A\n");
        if (useKeyA){
            memcpy(mifaretagKeys.amb[block].mbt.abtKeyA, &mifareParam.mpa.abtKey, 6);
        }
        else{
            memcpy(mifaretagKeys.amb[block].mbt.abtKeyB, &mifareParam.mpa.abtKey, 6);
        }
        return true;
    }
    // Hm lets try again using another key
    memcpy(mifareParam.mpa.abtKey, mykeyB, 6);
    if (nfc_initiator_mifare_cmd(cmd, block)) {
        DEBUG_STDOUT("Success for Key B\n");
        if (useKeyA){
            memcpy(mifaretagKeys.amb[block].mbt.abtKeyA, &mifareParam.mpa.abtKey, 6);
        }
        else{
            memcpy(mifaretagKeys.amb[block].mbt.abtKeyB, &mifareParam.mpa.abtKey, 6);
        }
        return true;
    }
  return false;
}

/*
 This method is quite generic. It is directly derived from the mifare.c file contained within utils of the libnfc library.
 Found here: https://github.com/nfc-tools/libnfc
 --Input
 cmd        The command that will be written to the card
 block      The block that is affected by the command
 --Output
 true       Command executed successfully
 false      Error during command execution
 */
bool NFCHandler::nfc_initiator_mifare_cmd(const mifare_cmd cmd, const byte block)
{
    byte  abtRx[265];
    size_t  szParamLen;
    byte  abtCmd[265];
    //bool    bEasyFraming;
    
    abtCmd[0] = cmd;               // The MIFARE Classic command
    abtCmd[1] = block;         // The block address (1K=0x00..0x39, 4K=0x00..0xff)
    
    switch (cmd) {
            // Read and store command have no parameter
        case MC_READ:
        case MC_STORE:
            szParamLen = 0;
            break;
            
            // Authenticate command
        case MC_AUTH_A:
        case MC_AUTH_B:
            szParamLen = sizeof(struct mifare_param_auth);
            break;
            
            // Data command
        case MC_WRITE:
            szParamLen = sizeof(struct mifare_param_data);
            break;
            
            // Value command
        case MC_DECREMENT:
        case MC_INCREMENT:
        case MC_TRANSFER:
            szParamLen = sizeof(struct mifare_param_value);
            break;
            
            // Please fix your code, you never should reach this statement
        default:
            return false;
            break;
    }
    
    // When available, copy the parameter bytes
    if (szParamLen)
        memcpy(abtCmd + 2, (byte *) &this->mifareParam, szParamLen);
    
    // FIXME: Save and restore bEasyFraming
    if (nfc_device_set_property_bool(nfc_dev, NP_EASY_FRAMING, true) < 0) {
#ifdef DBG
        nfc_perror(nfc_dev, "nfc_device_set_property_bool");
#endif
        return false;
    }
    
    // Fire the mifare command
    int res;
    if ((res = nfc_initiator_transceive_bytes(nfc_dev, abtCmd, 2 + szParamLen, abtRx, sizeof(abtRx), -1))  < 0) {
        if (res == NFC_ERFTRANS) {
            // "Invalid received frame",  usual means we are
            // authenticated on a sector but the requested MIFARE cmd (read, write)
            // is not permitted by current access bytes;
            // So there is nothing to do here.
        } else {
#ifdef DBG
            nfc_perror(nfc_dev, "nfc_initiator_transceive_bytes");
#endif
        }
        // XXX nfc_device_set_property_bool (pnd, NP_EASY_FRAMING, bEasyFraming);
        return false;
    }
    
    // When we have executed a read command, copy the received bytes into the param
    if (cmd == MC_READ) {
        if (res == 16) {
            memcpy(mifareParam.mpd.abtData, abtRx, 16);
        } else {
            return false;
        }
    }
    // Command succesfully executed
    return true;
}

/*
 This method will write the provided data to the tag/card. It will take the begin_block block
 for the beginning of the write operation. First it will determine the required amount of data
 blocks to write the data. If the number exceeds the maximum amount of blocks, the operation
 will be aborted. The last flag is quite useful. If true, all the data on the card will be erased
 and the keys will be set to the default key.
 -- Input
 begin_block        First data block
 data               Buffer with data
 datalen            Should not be 0, length of the data that will be written
 clean              Flag, Clean all the data on the card(true), write the data only (false)
 -- Output
 true           Write was successful
 false          Write failed
 */
bool NFCHandler::write_card(byte begin_block, byte* data, size_t datalen, bool clean){
    // Bytes per Block: 16
    // Blocks per Secor: 4-1(trailer)
    // Sectors per tag: 16-1(Begin)
    if(datalen > (16*3*15)){
        DEBUG_STDERR("Data too large");
        return false;
    }
    
    bool bFailure = false;
    size_t bytes_written = 0;
    // Calculate the required blocks
    // Extract the length out of it
    byte numblocks = datalen/16;
    if(datalen%16 != 0){
        numblocks++;    //Doesnt fit properly
    }
    
    // Write the card from begin to end;
    int currentBlock = begin_block;
    size_t remainingBytes = datalen;
    while(numblocks > 0){
        
        // Authenticate everytime we reach the first sector of a new block
        if (is_first_block(currentBlock)) {
            fflush(stdout);
            
            // Try to authenticate for the current sector
            if (!authenticate(currentBlock, true)) {
#ifdef DBG
                printf("!\nError: authentication failed for block %02x\n", currentBlock);
#endif
                return false;
            }
        }
        
        if (is_trailer_block(currentBlock)) {
            
            // Trailer:
            // |_ _ _ _ _ _ | _ _ _ _ | _ _ _ _ _ _|
            //   Key A       ACL   UD     Key B
            // Dont decrement the number of blocks, since we did not write anything
            if(clean){
                // Use default key
                memcpy(mifareParam.mpd.abtData, default_key, 6);
                memcpy(mifareParam.mpd.abtData + 6, default_acl, 4);
                memcpy(mifareParam.mpd.abtData + 10, default_key, 6);
            }
            else{
                memcpy(mifareParam.mpd.abtData, mykeyA, 6);
                memcpy(mifareParam.mpd.abtData + 6, default_acl, 4);
                memcpy(mifareParam.mpd.abtData + 10, mykeyB, 6);
            }
            
            
            // Try to write the trailer
            if (nfc_initiator_mifare_cmd(MC_WRITE, currentBlock) == false) {
#ifdef DBG
                printf("failed to write trailer block %d \n", currentBlock);
#endif
                bFailure = true;
            }
            currentBlock++;
            
        } else {
            // The first sector 0x00 is read only, skip this
            
            if (currentBlock < 4){
                currentBlock++;
                continue;
            }
            // Make sure an earlier write did not fail
            if (!bFailure) {
                
                // Try to write the data block
                if (clean){
                    // Clean the Card, write all 0es
                    memset(mifareParam.mpd.abtData, 0x00, 16);
                }
                else{
                    // Write actual data
                    if(remainingBytes < 16){
                        // Length of the remaining data does not fill the whole buffer. 0 out
                        //memset(buffer, 0, 16);
                        //memcpy(mp.mpd.abtData, buffer, remainingBytes);
                        memset(mifareParam.mpd.abtData, 0x0, 16);
                        memcpy(mifareParam.mpd.abtData, data+bytes_written, 16);
                    }
                    else{
                        // Enough bytes left
                        memcpy(mifareParam.mpd.abtData, data+bytes_written, 16);
                    }
                    
                }
                // do not write a block 0 with incorrect BCC - card will be made invalid!
                
                if (!nfc_initiator_mifare_cmd(MC_WRITE, currentBlock)){
                    bFailure = true;
                }
                else{
#ifdef DBG
                    printf("Write for Block %d succeeded.\n", currentBlock);
#endif
                    bytes_written += 16;
                    remainingBytes -= 16;
                }
            }
            numblocks--;
            // Now since we might have written into another Block by now, but the Trailer has not been set,
            // lets write to that at the end! The last Trailer so to say
            if(numblocks == 0){
                // Search for the trailer
                int delta = 3-currentBlock%4;     // 3 if trailer
                if(delta > 0 && is_trailer_block(currentBlock+delta)){
                    memcpy(mifareParam.mpd.abtData, mykeyA, 6);
                    memcpy(mifareParam.mpd.abtData + 6, default_acl, 4);
                    memcpy(mifareParam.mpd.abtData + 10, mykeyB, 6);                    
                    
                    // Try to write the trailer
                    if (nfc_initiator_mifare_cmd(MC_WRITE, currentBlock+delta) == false) {
                        printf("failed to write trailer block %d \n", currentBlock);
                        bFailure = true;
                    }
                }
            }
            
            currentBlock++;
        }
    }
#ifdef DBG
    printf("Done, %lu bytes written\n", datalen);
    fflush(stdout);
#endif
    
    return true;
}

#include "NFCHelper.h"

// Change Key values here
NFCHelper::NFCHelper()
:pn532hsu(Serial2), nfc(pn532hsu),
keyuniversal{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
keyB{0xFE, 0xAF, 0xFE, 0xAF, 0xFE, 0xAF},
keyA{0xAF, 0xFE, 0xAF, 0xFE, 0xAF, 0xFE},
uid{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
{
    uid_len = 0;
    this->isInitialized = false;
}

NFCHelper::~NFCHelper(){
}

/*
This method is responsible for the initialization of the whole class. It needs to be called first, 
before executing anything using the NFC Shield!
*/
int NFCHelper::begin(){
    DEBUG_INFO("Looking for PN532...");
    this->nfc.begin();

    uint32_t versiondata = this->nfc.getFirmwareVersion();
    if (! versiondata) {
        DEBUG_STDERR("Didn't find PN53x board");
        while (1); // halt
    }
    // Got ok data, print it out!
#if DBG
    Serial.print("Found chip PN5"); Serial.println((versiondata>>24) & 0xFF, HEX);
    Serial.print("Firmware ver. "); Serial.print((versiondata>>16) & 0xFF, DEC);
    Serial.print("."); Serial.println((versiondata>>8) & 0xFF, DEC);
#endif
    // configure board to read RFID tags
    this->nfc.SAMConfig();
    DEBUG_STDSUC("NFC configured");  
    this->isInitialized = true;
    return 0;
}

/*
This method will initialize the search for a new NFC tag for reading. After call,
it will actively search for a passive MIFARE ISO 14443A Card/tag. If it finds one,
it will print out its UID Information, indicating the success
-- Output:
-1      Initialization error
0       Success
*/
int NFCHelper::searchTag(){
    if(!this->isInitialized){
      DEBUG_STDERR("ECCSigner NOT INITIALIZED. Run begin() first!");
      return -1;
    }
    // Actively search for the tag
    while(!this->nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A,this->uid, &this->uid_len)){
        Serial.println("Wating for NFC");
        delay(500);
    }
    // Display some basic information about the card
    DEBUG_STDSUC("Found an ISO14443A card");
    DEBUG_INFO("  UID Value: ");
    this->nfc.PrintHex(this->uid, this->uid_len);
    DEBUG_INFO("");

    return 0;
}

/*
The authentication method. This one is a little delicate since it handles the keys for the card. Generally
a Mifare card needs to be authenticated secorwise. Thus, every fourth block, the authentication of the sector
needs to be reinitialized. This method takes care of authenticating the provided block. 
The protocol for this application says, that the data (NUMBLOCKS of data) is being encrypted using the KeyA,
beginning from Block 4 onwards. This ensures that the first Block is not being touched. The remaining section 
of the tag is being encrypted under the universalkey. Depending on the flag useKeyA, either the KeyA or KeyB
is used. This depends on the access policy, written in the trailing bytes 6-8.
-- Input:
useKeyA         Flag, if true: KeyA will be used, else KeyB will be used
block           The block that will be authenticated
-- Output:
-1      Format error
0       Authenticated
1       Authentication error
*/
int NFCHelper::authenticate(bool useKeyA, uint8_t block){
    if(!this->isInitialized){
      DEBUG_STDERR("ECCSigner NOT INITIALIZED. Run begin() first!");
      return -1;
    }
    if(this->uid_len < 4){
        //Abort
        DEBUG_STDERR("UID NOT VALID");
        return -1;
    }
#if DBG
    Serial.printf("Beginning, authenticating %d\n", block);
#endif
    // Check for Block number!
    bool success = false;
    if(isDataBlock(block)){
        // Data Block, KeyA!
        success = this->nfc.mifareclassic_AuthenticateBlock(this->uid, this->uid_len, block, useKeyA ? USE_KEY_A: USE_KEY_B, this->keyA);
        if(!success){
            DEBUG_STDERR("Key A not valid");
            return 1;
        }
    }
    else{
        // No Data Block, universal
        success = this->nfc.mifareclassic_AuthenticateBlock(this->uid, this->uid_len, block, useKeyA ? USE_KEY_A: USE_KEY_B, this->keyuniversal);
        if(!success){
            DEBUG_STDERR("Key Universal not valid");
            return 1;
        }
    }
    return 0;
}

/*
This method will read the Password from a NFC Tag. This method assumes, that the data
begins at Block 4 and has a length of PASSLEN+SALTLEN bytes. Thus it will iterate through
all of the necessary Blocks, thereby skipping the trailing blocks as these don't include 
any user data.
-- Input:
buffer          The buffer location that will receive the tag data
buffersize      The size of the buffer, needs to be at least PASSLEN+SALTLEN bytes long!
-- Output:
-1      Format error
0       Read success
1       Read error
*/
int NFCHelper::readPasswordFromCard(uint8_t* buffer, size_t bufsize){
    if(!this->isInitialized){
      DEBUG_STDERR("NFCHelper NOT INITIALIZED. Run begin() first!");
      return -1;
    }
    // PW len is PASSLEN+SALTLEN
    if(bufsize < PASSLEN+SALTLEN || this->uid_len < 4){
        DEBUG_STDERR("Buffer too small");
        return -1;
    }

    // Counters  
    int currentblock = STARTBLOCK;
    int bytes_written = 0;

    // Begin reading. We need to read NUMBLOCKS blocks after the STARTBLOCK
    while(currentblock <= (STARTBLOCK+NUMBLOCKS)){
        // Check if the currentblock is the trailer
        if(isTrailer(currentblock)){
            // Trailer, dont read or write!
            currentblock++;  
            continue;  
        }
        
        if(isFirstBlock(currentblock)){
            // First Block needs to be authenticated
            if(authenticate(true, currentblock) != 0){
                DEBUG_STDERR("Authentication failed");
                return 1;
            };
        }
        // Read the data into the Buffer, notice the pointer arithmetic! 
        if(nfc.mifareclassic_ReadDataBlock(currentblock, buffer+bytes_written)){
            // Increment the bytes_written counter, since we wrote new bytes!
            bytes_written+=16;
        }else{
            return 1;
        }
        // Finally increment the block counter
        currentblock++;
            
    }
    DEBUG_STDSUC("Read success");
    return 0;
}

// Helper Methods
inline bool NFCHelper::isDataBlock(uint8_t block){
    return (block < (STARTBLOCK+NUMBLOCKS));
}

inline bool NFCHelper::isTrailer(uint8_t block){
    return (block % 4 == 3);
}

inline bool NFCHelper::isFirstBlock(uint8_t block){
    return (block % 4 == 0);
}
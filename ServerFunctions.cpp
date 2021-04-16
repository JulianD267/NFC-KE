//
//  ServerFunctions.cpp
//  ecc-sign-ossl
//
//  Created by Julian on 12.11.20.
//  Copyright © 2020 HS Osnabrück. All rights reserved.
//

#include "ServerFunctions.hpp"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#define KEYDIR "keys"
ServerFunctions::ServerFunctions()
{
    // Make sure keys directory exists
    
    struct stat st = {0};
    if (stat(KEYDIR, &st) == -1){
        DEBUG_STDOUT("CREATING DIR");
        mkdir(KEYDIR, 0744);
    }
#ifdef ENGINETSS
    signer = new ECCBase(true);
    ec = new ECCBase(true);
#else
    signer = new ECCBase(false);
    ec = new ECCBase(false);
#endif
    
    // =================== NFC ======================
    this->beginNFC();
    
    
}

ServerFunctions::~ServerFunctions(){
    delete this->ec;
    delete this->signer;
}

// ========================= BEGIN FUNCTIONS =============================
/*
 This function will just initialize the NFC Reader and Tag. In particular, it will write the
 password and salt, contained within the nfcdata field, onto the tag. After that, it will write the
 private and public keys to the given key files for later use. ATTENTION: REMOVE THAT IN PRODUCTION
 Input:
 -
 Output:
 -2         Write operation was unsuccessful
 -1         No Mifare classic card was found
 0          Success
 */
int ServerFunctions::beginNFC(){
    this->genPasswordForNFC(nfcdata, PASSLEN+SALTLENGTH);
    INFO("Waiting for NFC Tag");
    if(!this->nfc.find_card()){
        // No Mifare Card found
        return -1;
    }
    if(!this->nfc.write_card(4, nfcdata, PASSLEN+SALTLENGTH)){
        // Write operation failed
        return -2;
    }
    INFO("Wrote Password");
    // Take care of the keys. If the files exist, use them. Else generate new keys
    FILE *fp = fopen(absPath(KEYNAME_PRIV).c_str(), "rb");
    if(!fp){
        // File does not exist!!
        this->signer->generate_keys();
        this->signer->export_keys_to_files(absPath(KEYNAME));
    }
    else{
        // Private key exists, lets load, assuming that the pubkey also exists
        this->signer->load_private_key_from_file(absPath(KEYNAME_PRIV));
        this->signer->load_public_key_from_file(absPath(KEYNAME_PUB));
        fclose(fp);
    }
    return 0;
}

/*
 This method will care about the password passing to the NFC tag and r/w operations on
 the password file. It first attempts to read an existing password and salt from a file.
 If that does not exist, a new password will be generated and written to the aforementioned
 file.
 If the file already exists, the force flag is been reviewed. If true, the existing password
 file gets replaced by a new password file, containing a fresh password. If false, the method
 will read in the contents of the file and attempts to populate the buffers accordingly.
 --Input:
 nfcdata, nfcdatalen            Data buffer for the NFC tag and its length
 force                          Flag to either read or overwrite existing data
 --Output:
 -1     File error
 0      Success
 */
int ServerFunctions::genPasswordForNFC(byte* _nfcdata, int nfcdatalen, bool force){
    
    byte password[PASSLEN];
    byte salt[SALTLENGTH];
    FILE *fp = fopen(absPath("pass.bin").c_str(), "rb");
    if(!fp){
        // File does not exist, create
        ECCBase::create_password(password, PASSLEN, salt, SALTLENGTH);
        // No fclose, may result in errors
        fp = fopen(absPath("pass.bin").c_str(), "wb+");
        if(!fp){
            return -1;
        }
        fwrite(password, sizeof(byte), PASSLEN, fp);
        fwrite(salt, sizeof(byte), SALTLENGTH, fp);
    }
    else{
        if(force){
            // Overwrite the file
            fclose(fp);
            if(remove(absPath("pass.bin").c_str()) != 0){
                DEBUG_STDERR("Remove of pass.bin failed");
                return -1;
            }
            ECCBase::create_password(password, PASSLEN, salt, SALTLENGTH);
            fp = fopen(absPath("pass.bin").c_str(), "wb+");
            if(!fp){
                return -1;
            }
            fwrite(password, sizeof(byte), PASSLEN, fp);
            fwrite(salt, sizeof(byte), SALTLENGTH, fp);
            
        }else{
            // No Force, only read
            // Read password from file
            fread(password, sizeof(byte), PASSLEN, fp);
            fread(salt, sizeof(byte), SALTLENGTH, fp);
        }
    }
    fseek(fp, 0, SEEK_SET);
    if(nfcdatalen == (PASSLEN + SALTLENGTH)){
        fread(_nfcdata, sizeof(byte), PASSLEN+SALTLENGTH, fp);
    }
    else{
        DEBUG_STDERR("NFC Data is too small");
    }
    fclose(fp);
    return 0;
}


/*
 This method just makes sure, that the file containing the public key of the sensor does exist.
 -- Input
 ec         The ECBase object pointer used for verification
 filepath   The filepath of the sensor public key
 sig        The signature that needs to be verified
 message    The message of the signature
 -- Output
 1          File not found
 else       See ec->verify()
 */
int ServerFunctions::verify_sig(ECCBase* _ec, const std::string& filepath, std::string sig, std::string message){
    /* Check if file even exists BEFORE entering the Engine */
    FILE* fd = fopen(filepath.c_str(), "rb");
    if(!fd){
        DEBUG_STDERR("No valid key found");
        return 1;
    }
    fclose(fd);
    _ec->load_public_key_from_file(filepath);
    return _ec->verify(message, sig);
}


std::string ServerFunctions::absPath(std::string file){
    char cwd[PATH_MAX];
    if(getcwd(cwd, sizeof(cwd))!= nullptr){
        // Create a String object
        std::string abs = cwd;
        if(file[0] != '/'){
            abs += "/";
        }else{
            // Already absolute
            return file;
        }
        
        abs += file;
        return abs;
    }
    return nullptr;
}

// ======================== FUNCTIONS =========================

void ServerFunctions::nfcAppend(std::shared_ptr<HttpServer::Response> response, std::shared_ptr<HttpServer::Request> request){
        try {
            
            rapidjson::Document d;
            d.Parse(request->content.string().c_str());
            // Json Structure is as follows
            /*
             {
             s_id: sensorid
             pkey: encrypted public key of the sensor   -b64
             sig: encrypted signature of the message    -b64
             }
             */
            
            // Sanity Check
            if(!d.IsObject() || !d.HasMember("s_id") || !d.HasMember("pkey") || !d.HasMember("sig")){
                *response << "HTTP/1.1 400 Error\r\n"
                << "Content-Length: " << 11 << "\r\n\r\n"
                << "JSON failed";
                return;
            }
            
            
            // Safe now?
            // Extract the json fields from that
            std::string s_id(d["s_id"].GetString());
            std::string b64ct(d["pkey"].GetString());
            std::string b64sig(d["sig"].GetString());       // Encrypted
            
            // Copy over the necessary data
            byte additional[s_id.length()];             // AD is the sensorid, i mean why not? Authentication is great anyway
            memcpy(additional, s_id.data(), s_id.length());
            
            // Now lets decode the ciphertext of the pubkey
            std::string decoded_ct = this->coder.base64_decode(b64ct);
            size_t ct_length = decoded_ct.length();
            byte ct_buf[ct_length];
            memcpy(ct_buf, decoded_ct.data(), ct_length);
            byte plaintext[ct_length-16];
            
            // Now lets decode the signature of the pubkey
            std::string decoded_sig = this->coder.base64_decode(b64sig);
            size_t enc_sig_length = decoded_sig.length();
            byte enc_sig_buf[enc_sig_length];
            memcpy(enc_sig_buf, decoded_sig.data(), enc_sig_length);
            byte signature[enc_sig_length-16];      // -16 Bytes of Tag material. Only necessary for decryption
            
            int res = -3;
            
            // Classic NFC
            byte pass[PASSLEN];
            byte salt[SALTLENGTH];
            
            // Split password and salt
            memcpy(pass, this->nfcdata, PASSLEN);
            memcpy(salt, this->nfcdata+PASSLEN, SALTLENGTH);
                
            // Decrypt the ciphertext, revealing the public key if all goes well.
            res = this->ec->decrypt((byte*)ct_buf, ct_length, additional, s_id.length(), pass, PASSLEN, salt, SALTLENGTH, plaintext);
            int res_sig = this->ec->decrypt((byte*)enc_sig_buf, enc_sig_length, additional, s_id.length(), pass, PASSLEN, salt, SALTLENGTH, signature);
            
            
            if(res == -1 || res_sig == -1){
                *response << "HTTP/1.1 400 Error\r\n"
                << "Content-Length: " << 20 << "\r\n\r\n"
                << "Verification Failed";
            }
            else if(res == -2 || res_sig == -2){
                *response << "HTTP/1.1 400 Error\r\n"
                << "Content-Length: " << 20 << "\r\n\r\n"
                << "Derivation Failed";
            }
            else{
                std::string clean_pt(reinterpret_cast<char*>(plaintext), ct_length-16);
                *response << "HTTP/1.1 200 OK\r\n"
                << "Content-Length: " << ct_length-16 << "\r\n\r\n"
                << clean_pt;
                // Write to file
                std::ofstream o;
                o.open(absPath("keys/"+s_id+"_pubkey.pem").c_str());
                if(o.is_open()){
                    o.write(clean_pt.c_str(), ct_length-16);
                    
                }
                o.close();
                
                // Okay we wrote that, lets verify that the signature is signed properly!
                // UNTESTED
                if(verify_sig(this->ec, absPath("keys/"+s_id+"_pubkey.pem"), (char*)signature, b64ct) != 0){
                    // Verify failed! Delete the key
                    if(std::remove(absPath("keys/"+s_id+"_pubkey.pem").c_str()) != 0){
                        DEBUG_STDERR("Remove of faulty failed!");
                    }
                    else{
                        DEBUG_STDOUT("Faulty key removed successfully");
                    }
                }
            }
        }
        catch(const std::exception &e) {
            *response << "HTTP/1.1 400 Bad Request\r\nContent-Length: " << strlen(e.what()) << "\r\n\r\n"
            << e.what();
        }
}

void ServerFunctions::dataGet(std::shared_ptr<HttpServer::Response> response, std::shared_ptr<HttpServer::Request> request){
    rapidjson::Document d;
    d.SetArray();
    DEBUG_STDOUT("Requested Data... ");
    rapidjson::Document::AllocatorType& allocator = d.GetAllocator();
    // Read data into the JSON Struct
    for(int i=0; i<this->data.size(); i++){
        rapidjson::Value val;
        val.SetString(data[i].c_str(), (unsigned int)this->data[i].length());
        d.PushBack(val, allocator);
    }
    
    // Write the JSON Data from the buffer into the string
    rapidjson::StringBuffer strbuf;
    rapidjson::Writer<rapidjson::StringBuffer> writer(strbuf);
    d.Accept(writer);
    std::string ret = strbuf.GetString();
    *response << "HTTP/1.1 200 OK\r\n"
    << "Content-Length: " << ret.length() << "\r\n\r\n"
    << ret;
    
}

void ServerFunctions::jsonPost(std::shared_ptr<HttpServer::Response> response, std::shared_ptr<HttpServer::Request> request){
    try {
        rapidjson::Document d;
        d.Parse(request->content.string().c_str());
        // Json Structure is as follows
        /*
         {
         s_id: sensorid
         msg: encrypted message of the sensor
         sig: signature of the message
         }
         */
        
        // Sanity Check
        if(!d.IsObject() || !d.HasMember("s_id") || !d.HasMember("msg") || !d.HasMember("sig")){
            *response << "HTTP/1.1 400 Error\r\n"
            << "Content-Length: " << 11 << "\r\n\r\n"
            << "JSON failed";
            return;
        }
        std::string s_id(d["s_id"].GetString());
        std::string message(d["msg"].GetString());
        std::string sig(d["sig"].GetString());
        
        int res = verify_sig(this->ec, absPath("keys/"+s_id+"_pubkey.pem"), sig, message);
        if( res == 0){
            // Signature is valid, signing it myself
            this->signer->sign(message);
            std::string mysig = this->signer->dump_signature("");      // no file provided, just the string in return
            d["sig"].SetString(mysig.c_str(), (unsigned int)mysig.length());
            
            // Write the JSON Data to the local data interface.
            rapidjson::StringBuffer buffer;
            buffer.Clear();
            rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
            d.Accept(writer);
            std::string msg = std::string(buffer.GetString());
            if(this->data.size() >= 10){
                this->data.clear();
            }
            // data.push_back(msg);
            *response << "HTTP/1.1 200 OK\r\n"
            << "Content-Length: " << mysig.length() << "\r\n\r\n"
            << mysig;
        }
        else if(res == 1){
            *response << "HTTP/1.1 500 OK\r\n"
            << "Content-Length: " << 16 << "\r\n\r\n"
            << "Unknown Sensor\r\n";
        }
        else{
            *response << "HTTP/1.1 422 OK\r\n"
            << "Content-Length: " << 15 << "\r\n\r\n"
            << "Verify FAILED\r\n";
        }
    }
    catch(const std::exception &e) {
        *response << "HTTP/1.1 400 Bad Request\r\nContent-Length: " << strlen(e.what()) << "\r\n\r\n"
        << e.what();
    }
}

void ServerFunctions::pubkeyGet(std::shared_ptr<HttpServer::Response> response, std::shared_ptr<HttpServer::Request> request){
    std::ifstream i;
    std::cout << request->remote_endpoint().address() << std::endl;
    i.open(absPath("base_key_pub.pem").c_str());
    if(i.good()){
        i.seekg(0, std::ios::end);
        size_t file_length = i.tellg();
        i.seekg(0, std::ios::beg);
        char key[file_length];
        i.read(key, file_length);
        i.close();
        
        *response << "HTTP/1.1 200 OK\r\n"
        << "Content-Length: " << file_length << "\r\n\r\n"
        << key;
    }
    else{
        *response << "HTTP/1.1 400 ERROR\r\n"
        << "Content-Length: " << "14" << "\r\n\r\n"
        << "Get Key failed";
    }
    
}

void ServerFunctions::nfcReissue(std::shared_ptr<HttpServer::Response> response, std::shared_ptr<HttpServer::Request> request){
        // Generate the new Tag again
        genPasswordForNFC(nfcdata, PASSLEN+SALTLENGTH, true);
        this->nfc.find_card();
        
        if(this->nfc.write_card(4, this->nfcdata, PASSLEN+SALTLENGTH)){
            std::string succ ="{\"result\": \"ok\"}";
            *response << "HTTP/1.1 200 OK\r\n"
            << "Content-Length: " << succ.length() << "\r\n\r\n"
            << succ;
        }
        else{
            std::string nosucc ="{\"result\": \"fail\"}";
            *response << "HTTP/1.1 400 Error\r\n"
            << "Content-Length: " << nosucc.length() << "\r\n\r\n"
            << nosucc;
        };
}

void ServerFunctions::clear(std::shared_ptr<HttpServer::Response> response, std::shared_ptr<HttpServer::Request> request){
    this->data.clear();
    *response << "HTTP/1.1 200 Ok\r\n"
    << "Content-Length: " << 2 << "\r\n\r\n"
    << "ok";
}

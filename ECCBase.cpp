//
//  ECCBase.cpp
//  ecc-sign-ossl
//
//  Created by Julian on 12.08.20.
//  Copyright © 2020 HS Osnabrück. All rights reserved.
//

#include "ECCBase.hpp"

/*
 Constructor, initialize the OpenSSL Environment
 */

ECCBase::ECCBase()
:ECCBase(false){
// No default support for engine
}

ECCBase::ECCBase(bool engine_enable):
evp_verify_key(nullptr), evp_sign_key(nullptr), nid(NID_X9_62_prime256v1), tpmtss(nullptr)
{
    /*
     The Signing can be done with the TPM Module support. Just compile with -DENGINETSS flag
     */
    if(engine_enable){
        ENGINE_load_dynamic();
        this->tpmtss = ENGINE_by_id("tpm2tss");
        if (tpmtss == nullptr){
            printf("Engine could not be loaded\n");
            exit(1);
        }
        
        DEBUG_STDOUT("Engine TPM2TSS loaded\n");
        int res = ENGINE_init(tpmtss);
        if(res == 0){
            DEBUG_STDERR("Engine initialization failed!");
            exit(1);
        }
        
        DEBUG_STDOUT("Engine name: ");
        DEBUG_STDOUT(ENGINE_get_name(tpmtss));
        ENGINE_set_default_EC(tpmtss);//, key_method);
        ENGINE_set_default_RAND(tpmtss);
        ENGINE_set_default_DSA(tpmtss);
        ENGINE_set_default_RSA(tpmtss);
        ENGINE_set_default_digests(tpmtss);
    };
    signature_len = sizeof(signature);
    memset(this->signature, 0 , sizeof(this->signature));
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    CONF_modules_load_file(nullptr, nullptr, 0);
    RAND_poll();
}

/*
 Destructor, destroy the OpenSSL Environment
 */
ECCBase::~ECCBase(){
    if (evp_sign_key){
        EVP_PKEY_free(evp_sign_key);
        evp_sign_key = nullptr;
    }
    if (evp_verify_key){
        EVP_PKEY_free(evp_verify_key);
        evp_verify_key = nullptr;
    }
    if(this->tpmtss){
        ENGINE_finish(tpmtss);
        ENGINE_free(tpmtss);
        tpmtss = nullptr;
        ENGINE_cleanup();
    }
    
    FIPS_mode_set(0);
    CRYPTO_set_locking_callback(NULL);
    CRYPTO_set_id_callback(NULL);
    ENGINE_cleanup();
    ERR_free_strings();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
}

/*
 This static method will generate a brand new password and salt by utilizing the openssl RAND_bytes and the TPM
 if it is supported
 --Input
 pwbuffer, pw_length        Destination buffer for the password and its length
 saltbuffer, salt_length    Destination buffer for the salt and its length
 --Output
 0          Error during creation of password
 1          Success
 */
int ECCBase::create_password(unsigned char* pwbuffer, int pw_length, unsigned char* saltbuffer, int salt_length){
    int res = RAND_bytes(pwbuffer, pw_length);
    if(res != 1){
        ERR_get_error();
        return 0;
    }
    res = RAND_bytes(saltbuffer, salt_length);
    if(res != 1){
        ERR_get_error();
        return 0;
    }
    return 1;
}

void ECCBase::clean(){
    memset(this->signature, 0, 256);
    this->signature_len = 256;
}

/*
 This function will load the Public Key in PEM Format from the given filename. After a successful read and parse
 a new EnVeloPe key gets generated for verification. It needs to be stored within the class field evp_verify_key
 for later use.
 */
EC_KEY* ECCBase::_load_public_key_from_file(const std::string& _pubkey){
    INFO("LOAD_PUBLIC_KEY_FROM_FILE");
    FILE *fp = fopen(_pubkey.c_str(), "r");
    if (!fp) {
        DEBUG_STDERR("The File "+ _pubkey+ " could not be opened, quitting");
        return nullptr;
    }
    
    DEBUG_STDOUT("Reading the Public Key from the opened file...");
    EC_KEY* pk = PEM_read_EC_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    
    if (!pk) {
        DEBUG_STDERR("The Public Key could not be read, quitting!");
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
    return pk;
}

int ECCBase::load_public_key_from_file(const std::string& _pubkey)
{
    this->pubkey = _load_public_key_from_file(_pubkey);
    DEBUG_STDOUT("Creating a new EVP (EnVeloPe) Key for Verification");
    this->evp_verify_key = EVP_PKEY_new();
    int ret = EVP_PKEY_assign_EC_KEY(this->evp_verify_key, this->pubkey);
    if (ret == 0) {
        DEBUG_STDERR("The Verification Key could not be assigned, quitting!");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    SUCCESS("Public Key loaded successfully and EVP Key created.");
    return 0;
}


/*
 This function will load the Private Key in PEM format from the given filename. After a successfull
 read and parse, the private key needs to be validated. Only if the key is valid it can get used to
 generate a new EnVeloPe Public Key for signing. This key needs to be stored within the class field
 evp_sign_key for later use.
 Input:
 - std::string privatekey       The private Key file containing the key
 Output:
 - 0 on success, -1 on failure
 */
EC_KEY* ECCBase::_load_private_key_from_file(const std::string& privatekey){
    INFO("LOAD_PRIVATE_KEY_FROM_FILE");
    FILE *fp = fopen(privatekey.c_str(), "r");
    if (!fp) {
        DEBUG_STDERR("The File "+ privatekey+ " could not be opened, quitting");
        return nullptr;
    }
    
    DEBUG_STDOUT("Reading the Private Key from the opened file...");
    EC_KEY* sk = PEM_read_ECPrivateKey(fp, nullptr, nullptr, nullptr);
    if (!sk) {
        DEBUG_STDERR("The Private Key could not be read, quitting!");
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
    fclose(fp);
    
    // validate the key
    
    int ret = EC_KEY_check_key(sk);
    if(ret == 0){
        //Error
        DEBUG_STDERR("The Private EC Key is not valid, quitting!");
        return nullptr;
    }
    return sk;
}

int ECCBase::load_private_key_from_file(const std::string& privatekey){
    this->privkey = _load_private_key_from_file(privatekey);
    int ret = EC_KEY_check_key(this->privkey);
    if(ret == 0){
        //Error
        DEBUG_STDERR("The Private EC Key is not valid, quitting!");
        return -1;
    }
    
    DEBUG_STDOUT("Creating a new EVP (EnVeloPe) Key for signing");
    this->evp_sign_key = EVP_PKEY_new();
    
    
    ret = EVP_PKEY_assign_EC_KEY(this->evp_sign_key, this->privkey);
    if (ret == 0) {
        DEBUG_STDERR("The Signing Key could not be assigned, quitting!");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    SUCCESS("Private Key loaded successfully and EVP Signing Key created.");
    return 0;
}

/*
 This function will generate a new public and private key pair for EC Signing. For that
 it will use the curve provided by the nid field within the ECCBase class. The resulting
 keys will be validated to ensure that the parameters lie on the curve and thus are valid.
 
 After successful validation, both keys will be written to the corresponding files in PEM
 format.
 */
int ECCBase::generate_keys(){
    INFO("GENERATE_KEYS");
    
    // Set Curve of TPM2
    EC_KEY* keygen = EC_KEY_new_by_curve_name(this->nid);
    DEBUG_STDOUT("Curve P256v1 is set!");
    if(!keygen){
        DEBUG_STDERR("The Curve is not valid");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    //Generate the key
    DEBUG_STDOUT("Generating EC Keys");
    int ret = EC_KEY_generate_key(keygen);
    if(ret == 0){
        //error
        DEBUG_STDERR("The EC Keys could not be generated, quitting.");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    //Now validate the Key against the Curve
    ret = EC_KEY_check_key(keygen);
    if(ret != 1){
        DEBUG_STDERR("The Keys are invalid, quitting.");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    EVP_PKEY* tmp = EVP_PKEY_new();
    ret = EVP_PKEY_assign_EC_KEY(tmp, keygen);
    
    if(ret != 1){
        DEBUG_STDERR("EC Key assign to EVP failed, quitting.");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    // That's where the fun begins. PEM export...
    // First create a BIO Object in memory
    BIO *priv, *pub;
    priv = BIO_new(BIO_s_mem());
    pub = BIO_new(BIO_s_mem());
    
    // Write key data to BIO memory objects
    ret = PEM_write_bio_EC_PUBKEY(pub, keygen);
    if(ret == 0){
        // 0 bytes written, not good
        DEBUG_STDERR("0 Bytes have been written to the BIO pubkey object, quitting");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    ret = PEM_write_bio_ECPrivateKey(priv, keygen, nullptr, nullptr, 0, nullptr, nullptr);
    if(ret == 0){
        // 0 bytes written, not good
        DEBUG_STDERR("0 Bytes have been written to the BIO privkey object, quitting");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    this->privkey = EC_KEY_new();
    this->pubkey = EC_KEY_new();
    
    if(!PEM_read_bio_EC_PUBKEY(pub, &this->pubkey, nullptr, nullptr)){
        // NULL Ptr returned, not good
        DEBUG_STDERR("Pubkey could not be read from BIO object");
        ERR_print_errors_fp(stderr);
        return -1;
    };
    if(!PEM_read_bio_ECPrivateKey(priv, &this->privkey, nullptr, nullptr)){
        // NULL Ptr returned, not good
        DEBUG_STDERR("Privkey could not be read from BIO object");
        ERR_print_errors_fp(stderr);
        return -1;
    };
    
    // Alright everything should be fine now. Now create EVP keys from the material
    this->evp_sign_key = EVP_PKEY_new();
    this->evp_verify_key = EVP_PKEY_new();
    
    if(EVP_PKEY_assign_EC_KEY(this->evp_sign_key, this->privkey) != 1){
        // That failed
        DEBUG_STDERR("EVP assign failed for sign key, quitting");
        ERR_print_errors_fp(stderr);
        return -1;
    };
    if(EVP_PKEY_assign_EC_KEY(this->evp_verify_key, this->pubkey) != 1){
        // That failed
        DEBUG_STDERR("EVP assign failed for verify key, quitting");
        ERR_print_errors_fp(stderr);
        return -1;
    };
    BIO_free(priv);
    BIO_free(pub);
    EC_KEY_free(keygen);
    return 0;
}

int ECCBase::export_private_key_to_file(const std::string& filename){
    INFO("Begin Private Key export");
    FILE* fp = fopen((filename+"_priv.pem").c_str(), "w");
    if(!fp){
        DEBUG_STDERR("Error Opening Privkey file, quitting.");
        return -1;
    }
    
    DEBUG_STDOUT("Writing private key to file ...");
    //File Key passwd keysize something something
    PEM_write_ECPrivateKey(fp, this->privkey, nullptr, nullptr, 0, nullptr, nullptr);
    
    // Cleanup
    fclose(fp);
    SUCCESS("Private Key export complete");
    return 0;
}

int ECCBase::export_public_key_to_file(const std::string& filename){
    INFO("Begin Public Key export");
    DEBUG_STDOUT("Creating a new public key file with name: " + filename);
    FILE* fp = fopen((filename+"_pub.pem").c_str(), "w");
    if(!fp){
        DEBUG_STDERR("Error Opening Pubkey file");
        return -1;
    }
    
    DEBUG_STDOUT("Write new public key to file...");
    PEM_write_EC_PUBKEY(fp, this->pubkey);
    fclose(fp);
    SUCCESS("Public Key export complete");
    return 0;
}

int ECCBase::export_keys_to_files(const std::string& filename){
    
    INFO("Begin ECC Keys export");
    if(this->export_public_key_to_file(filename) != 0){
        DEBUG_STDERR("Error exporting public key");
        return -1;
    };
    if(this->export_private_key_to_file(filename) != 0){
        DEBUG_STDERR("Error exporting private key");
        return -1;
    };
    return 0;
}

/*
 Overloaded function for the sign function. It takes a string message and passes it
 to the main sign function by casting it to a byte field.
 Input:
 - std::string msg          The message to be signed
 Output:
 - see overloaded sign function
 */
int ECCBase::sign(std::string msg){
    byte* message = (byte*)msg.c_str();
    return this->sign(message, msg.length());
}

/*
 The main signing function. It highly depends on the signing key to be present, as well as the
 private key for that matter. Per default the SHA256 Algorithm is used to hash the message before signing.
 
 After the Digest Setup the main signing operation is being executed. It contains the updating of the hash state
 by providing the message and the context. This gets finalized eventually and returns the signed version of the
 message (hash).
 Input:
 - unsigned char *msg         Pointer to the Message Byte array that gets signed
 - size_t  msglen       The length of the message array in bytes
 */
int ECCBase::sign(unsigned char *msg, size_t msglen)
{
    INFO("SIGNING");
    bzero(signature, sizeof(signature));
    signature_len = sizeof(signature);
    if (!this->evp_sign_key || !this->privkey) {
        DEBUG_STDERR("invalid sign key or private key is not loaded");
        return -1;
    }
    
    DEBUG_STDOUT("Setting Hash Algorithm to SHA256");
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    
    DEBUG_STDOUT("Initializing the Signing operation...");
    int ret = EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, evp_sign_key);
    if (ret != 1) {
        DEBUG_STDERR("Error initializing signing operation, quitting.");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    DEBUG_STDOUT("Updating internal Hash state...");
    ret = EVP_DigestSignUpdate(mdctx, msg, msglen);
    if (ret != 1) {
        DEBUG_STDERR("Error updating Hash state, quitting.");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    DEBUG_STDOUT("Finalizing the Signing operation...");
    ret = EVP_DigestSignFinal(mdctx, signature, &signature_len);
    if (ret != 1) {
        DEBUG_STDERR("Error Finalizing the signing operation, quitting.");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    EVP_MD_CTX_destroy(mdctx);
    DEBUG_STDOUT("Signature created successfully");
    EVP_cleanup();
    SUCCESS("Signing complete");
    return 0;
}

/*
 A wrapper function for the verification of the signature. It takes in a signature and a message to be signed with
 the provided public key, contained within the class object.
 */
int ECCBase::verify(std::string& msg, std::string& sig){
    return this->verify(msg, sig, this->pubkey);
}

/*
 This wrapper function facilitates the use of string formatted messages and signatures with a cutsom publickey
 */
int ECCBase::verify(std::string& msg, std::string& sig, std::string& publickey_file){
    EC_KEY* pk = _load_public_key_from_file(publickey_file);
    return this->verify(msg, sig, pk);
}

/*
 This wrapper function facilitates the use of string formatted messages and signatures with a cutsom publickey
 */
int ECCBase::verify(std::string& msg, std::string& sig, EC_KEY* publickey){
    byte* _byte_message = (byte*) msg.c_str();
    std::string _decoded_signature = this->coder.base64_decode(sig);
    byte sign[_decoded_signature.length()];
    memcpy(sign, _decoded_signature.data(), _decoded_signature.length());
    return this->verify(_byte_message, msg.length(), sign, _decoded_signature.length(), publickey);
}


/*
 The Verification process involves a message and a corresponding signature, which get validated against
 each other using the verification key. The process begins with the buildup of the Message Digest context.
 In this case a SHA256 Context is created, as this is the current standard.
 
 After that, the Verification is initialized with the verification key, updated with the message and finalized
 with the signature. If no error occurs, a the signature is valid. If the finalization process fails, the signature
 is not valid. The Debug error message will give you details then.
 Input:
 - unsigned char* msg         Message that has been signed
 - size_t msglen        Length of the message in bytes
 - unsigned char* signature   signature of the message as a byte array
 - size_t signature_len length of the signature in bytes
 */
int ECCBase::verify(byte *msg, size_t msglen, byte *signature, size_t signature_len, EC_KEY* publickey)
{
    INFO("VERIFY");
    if (!msg || !signature) {
        DEBUG_STDERR("The provided Message or Signature are not initialized, quitting.");
        return -1;
    }
    
    DEBUG_STDOUT("Setting the Hash Algorithm to SHA256");
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    
    DEBUG_STDOUT("Initializing the Verification operation...");
    int ret = EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), nullptr, evp_verify_key);
    if (ret != 1) {
        DEBUG_STDERR("Error initializing the Verification operation");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    DEBUG_STDOUT("Updating the internal Hash state...");
    ret = EVP_DigestVerifyUpdate(mdctx, msg, msglen);
    if (ret != 1) {
        DEBUG_STDERR("Error updating the internal Hash state, quitting.");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    DEBUG_STDOUT("Finalizing the Verification operation...");
    ret = EVP_DigestVerifyFinal(mdctx, signature, signature_len);
    if (ret != 1) {
        DEBUG_STDERR("Error finalizing the Verification operation, quitting.");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    // Alright if there are no errors until now, the signature is valid!
    EVP_MD_CTX_destroy(mdctx);
    SUCCESS("Signature ok");
    SUCCESS("Verification complete");
    
    return 0;
}

std::string ECCBase::dump_signature(const std::string& filename)
{
    INFO("DUMP_SIGNATURE");
    if(filename != ""){
        std::ofstream of;
        DEBUG_STDOUT("Exporting binary signature to file");
        of.open(filename, std::ios_base::binary);
        of.write((const char*) this->signature, this->signature_len);
        if(!of.good()){
            DEBUG_STDERR("Signature File export failed");
        }
        of.close();
    }
    DEBUG_STDOUT("Printing signature as Base64 String:");
    
    std::string sig = this->coder.base64_encode(this->signature, this->signature_len);
    
    return sig;
}

byte* ECCBase::getSignature()
{
    return signature;
}

size_t ECCBase::getSignatureLength()
{
    return this->signature_len;
}


EC_KEY* ECCBase::getPubkey(){
    return this->pubkey;
}

EVP_PKEY* ECCBase::getVerifyKey(){
    return this->evp_verify_key;
}


void ECCBase::handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}


int ECCBase::gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                         unsigned char *aad, int aad_len,
                         unsigned char *key,
                         unsigned char *iv, int iv_len,
                         unsigned char *ciphertext,
                         unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;
    
    int len;
    
    int ciphertext_len;
    
    
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
    
    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr))
        handleErrors();
    
    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, nullptr))
        handleErrors();
    
    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv))
        handleErrors();
    
    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(1 != EVP_EncryptUpdate(ctx, nullptr, &len, aad, aad_len))
        handleErrors();
    
    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;
    
    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;
    
    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        handleErrors();
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    
    return ciphertext_len;
}


int ECCBase::gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                         unsigned char *aad, int aad_len,
                         unsigned char *tag,
                         unsigned char *key,
                         unsigned char *iv, int iv_len,
                         unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;
    
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
    
    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr))
        handleErrors();
    
    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, nullptr))
        handleErrors();
    
    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv))
        handleErrors();
    
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(!EVP_DecryptUpdate(ctx, nullptr, &len, aad, aad_len))
        handleErrors();
    
    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;
    
    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        handleErrors();
    
    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    
    if(ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        ERR_print_errors_fp(stderr);
        return -1;
    }
}

int ECCBase::encrypt(unsigned char* plaintext, size_t ptlen,
                     unsigned char* additional_data, size_t aad_len,
                     unsigned char* password, int passlen, unsigned char* ciphertext){
    
    return 0;
}
int ECCBase::encrypt_b64(unsigned char *plaintext
                         , size_t ptlen
                         , unsigned char *additional_data
                         , size_t aad_len
                         , unsigned char *password
                         , int passlen
                         , unsigned char *ciphertext){
    
    return 0;
}
/*
 GCM decryption method. It will first derive the key and IV from the given password using the PKCS5 PBKDF2 HMAC function.
 The Key is derived using the SHA 256 and the IV is derived using the SHA1. It then attempts to decrypt the message using AES GCM.
 The passed ciphertext needs to include the authentication tag APPENDED to the ciphertext itself. Its size is fixed to 16 Bytes.
 Input:
 - unsigned char* ciphertext                The concatenated ciphertext and tag c
 - size_t ctlen                             The total length of the ciphertext buffer
 - unsigned char* additional_data           The associated data for GCM, can be NULL
 - size_t aad_len,                          The length of the aad Buffer in bytes
 - char* password                           The shared password for the key derivation
 - size_t passlen                           The length of the password
 - unsigned char* plaintext                 The plaintext destination buffer
 Output:
 - -2       Derivation failure
 - -1       Verification failure - wrong password?
 - else     length of the plaintext in bytes.
 */
int ECCBase::decrypt(unsigned char* ciphertext, size_t ctlen,
                     unsigned char* additional_data, size_t aad_len,
                     unsigned char* password, int passlen,
                     unsigned char* salt, int saltlen,
                     unsigned char* plaintext){
    
    //unsigned char salt[] = "salt";
    // Some sanity checks before
    if(ctlen <= 16+1){
        //Malformed ct
        DEBUG_STDERR("Malformed ct\n");
        return -1;
    }
    int iterations = 10000;
    int key_length = 256/8;     // 32 Bytes should be enough
    int iv_length = 12;         // Most effective - NIST
    unsigned char iv[iv_length];
    unsigned char key[key_length];
    // Derive the key and iv from the password
    int res = PKCS5_PBKDF2_HMAC((char*)password, passlen, salt, saltlen, iterations, EVP_sha256(), key_length, key);
    
    if(1 != res){
        DEBUG_STDERR("Key derivation failed\n");
        return -2;
    }
    
    // Derive iv using the SHA-1
    res = PKCS5_PBKDF2_HMAC((char*)password, passlen, salt, saltlen, iterations, EVP_sha1(), iv_length, iv);
    if(1 != res){
        DEBUG_STDERR("IV derivation failed\n");
        return -2;
    }
    
    // Buffer contains the concatenation of ciphertext and tag
    // Tag length is fixed at 16 bytes with GCM!
    unsigned char ct[ctlen-16];
    unsigned char tag[16];
    memcpy(ct, ciphertext, ctlen-16);
    memcpy(tag, ciphertext+ctlen-16, 16);
    
    int ret = gcm_decrypt(ciphertext, (int)(ctlen-16), additional_data, (int)aad_len, (unsigned char*)tag, key, iv, iv_length, plaintext);
    
    return ret;
}

int ECCBase::decrypt_b64(std::string ciphertext, unsigned char* additional_data, size_t aad_len,
                         unsigned char* password, int passlen,
                         unsigned char* salt, int saltlen, unsigned char* plaintext){
    // Same thing but with base64 decoding
    std::string _decoded_message = this->coder.base64_decode(ciphertext);
    unsigned char ct[_decoded_message.length()];
    memcpy(ct, _decoded_message.data(), _decoded_message.length());
    return this->decrypt(ct, _decoded_message.length(), additional_data, aad_len, password, passlen, salt, saltlen, plaintext);
    
}

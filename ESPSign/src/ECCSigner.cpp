#include "ECCSigner.h"
ECCSigner::ECCSigner()
{
  this->isInitialized = false;
}

ECCSigner::~ECCSigner(){
}
/*
This is just a wrapper for the DRBG
*/
static int myrand( void *rng_state, unsigned char *output, size_t len )
{
    size_t use_len;
    int rnd;

    if( rng_state != NULL )
        rng_state  = NULL;

    while( len > 0 )
    {
        use_len = len;
        if( use_len > sizeof(int) )
            use_len = sizeof(int);

        rnd = esp_random();     // Use esp_random() for hardware RNG!!!
        memcpy( output, &rnd, use_len );
        output += use_len;
        len -= use_len;
    }

    return( 0 );
}

void ECCSigner::begin(){
    // Seed the DRBG
    mbedtls_ctr_drbg_init(&this->drbg);
    if(mbedtls_ctr_drbg_seed(&this->drbg, myrand, NULL, NULL, 0) != 0){
      DEBUG_STDERR("SEED ERROR");
    }
    mbedtls_ctr_drbg_set_prediction_resistance(&this->drbg, MBEDTLS_CTR_DRBG_PR_ON);

    // Initialize the ecdsa context
    mbedtls_ecdsa_init(&this->ecdsa);

    // Generate a brand new Keypair
    if(mbedtls_ecdsa_genkey(&this->ecdsa,MBEDTLS_ECP_DP_SECP256R1, mbedtls_ctr_drbg_random, &this->drbg) != 0){
      DEBUG_STDERR("NO KEY GENERATED");
    };
    
    // Export the public key
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    if(mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) != 0){
      DEBUG_STDERR("SETUP FAILED FOR KEY");
    };

    // Set the context to the ecdsa object
    pk.pk_ctx = &this->ecdsa;    

    // Write to PEM and attribute string
    byte key[200];    // 178 should be enough though. The 0x0 Terminator will work with the String
    if(mbedtls_pk_write_pubkey_pem(&pk, key, 200) != 0){
      DEBUG_STDERR("PEM FAILED WITH CODE");
    };

    String pkey((char*)key);
    publickey = pkey;
    DEBUG_STDSUC("PUBKEY:");
    DEBUG_STDSUC(publickey.c_str());

    this->isInitialized = true;
}
/*
Just a helper to print a hex number, mainly for Debugging
*/
void ECCSigner::printHex(byte num) {
  char hexCar[3];
  snprintf(hexCar, 3, "%02X ", num);
  Serial.print(hexCar);
}


/*
A cleanup function to erase all precomputed points within an ec group
*/
void ECCSigner::ecp_clear_precomputed( mbedtls_ecp_group *grp )
{
  if( grp->T != NULL )
  {
    size_t i;
    for( i = 0; i < grp->T_size; i++ ){
      mbedtls_ecp_point_free( &grp->T[i] );
    }
    free( grp->T );
  }
  grp->T = NULL;
  grp->T_size = 0;
}

String ECCSigner::getPubkey(){
    return this->publickey;
}

/*
The main signing function.
The function itself will perform an ECDSA signature. First it will open the private key file from SPIFFS. 
Using this key, it will attempt to generate an ECP key from that, which gets used for the signing operation.
Oddly enough, mbedtls will not hash the message for us! This is something we need to do manually in the next 
step.
Finally the signature can be written to the buffer. 
-- Input:
message        Message buffer
msg_len        length of the message buffer
signature      Destination buffer for the signature, must not be null
sig_bytes      Location to write the signature length to
-- Output:
-1  - File error
0   - Success
1   - ECDSA error
*/
int ECCSigner::sign(byte* message, size_t msg_len, byte* signature, size_t* sig_bytes){
  if(!this->isInitialized){
    DEBUG_STDERR("ECCSigner NOT INITIALIZED. Run begin() first!");
    return -1;
  }
  // Sanity check
  if(!message || !signature || !sig_bytes ){
    DEBUG_STDERR("message/signature/signature length must not be null");
    return -1;
  }

  // Now that's a bit odd. We have to first hash the Message, as the ECDSA routine of mbedtls does
  // not do that for us... No problem then. Use SHA256, 32 Byte hash
  byte hash_msg[HASHLEN];
  if(HASH(message, msg_len, hash_msg, NOT_USE_HMAC) !=0){
    DEBUG_STDERR("Hash of Message failed");
    return 1;
  };

  // Write the signature                                                                        
  if(mbedtls_ecdsa_write_signature(&ecdsa, HASHTYPE, hash_msg, HASHLEN, signature, sig_bytes, mbedtls_ctr_drbg_random, &this->drbg) != 0){
    DEBUG_STDERR("Write Signature failed");
    return 1;
  }

  // Cleanup
  ecp_clear_precomputed(&ecdsa.grp);
  DEBUG_STDSUC("Signing complete");
  return 0;
}
/*
Just a wrapper function to produce a Base64 encoded signature. Takes basically the same inputs as sign()
-- Input
message             Message buffer
msg_len             Length of the message buffer
b64_sig_buf         Destination buffer for the base 64 encoded signature, must not be null
b64_sig_bytes       Length of the signature buffer
bytes_written       Location for the effective number of written bytes
-- Output
0 - Success
1 - Signature error
2 - Base64 error
*/
int ECCSigner::sign_b64(byte* message, size_t msg_len, byte* b64_sig_buf, size_t b64_sig_bytes, size_t* bytes_written){
  if(!this->isInitialized){
    DEBUG_STDERR("ECCSigner NOT INITIALIZED. Run begin() first!");
    return -1;
  }  
  // Sanity Check
  if(!message || !b64_sig_buf || !bytes_written){
    DEBUG_STDERR("message/signature buffer/bytes written must not be null");
    return 1;
  }
  if(b64_sig_bytes < BASE64_LEN(SIGNATURE_LEN)){
    DEBUG_STDERR("Base64 Buffer too small");
    return 1;
  }
    
  byte signature[SIGNATURE_LEN];   // 72 is the standard Signature length with ECDSA SECP256R1 256 Bit key. Might be smaller though! pay attention
  size_t sig_bytes_written;
  if(sign(message, msg_len, signature, &sig_bytes_written) != 0){
    DEBUG_STDERR("Signature of pkey failed");
    return 1;
  }
  // Great now we have a signature. Lets encode it in Base64, so that we can send it!
  if(mbedtls_base64_encode(b64_sig_buf, b64_sig_bytes, bytes_written, signature, sig_bytes_written) == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL){
    DEBUG_STDERR("Buffer too small for Base64 encoding!");
    return 2;
  }
  return 0;
}

/*
The main verification method. It is not dependent on any fields within the ECCSigner class, thus it can operate on its
own. In order to verify the passed message and signature, it therefore depends on a publickey that gets passed as well.
First it will sanity check all the necessary inputs. Then it will create a new ECDSA context for verification and load
the provided key into a new PK object. Aftera that, the provided message needs to be hashed, because the signature was
created with the hash of the message in the first place. If that succeeds, the Method will return a signature validation
success message. Thus:
-- Input
message, msg_len        Byte version of the message and its length
signature, sig_len      Byte version of the raw signature and its length
publickey, key_len      Byte version of the public PEM Key and its length
-- Output
-1    Format error
0     Signature ok
1     Signature/ECDSA failed
*/
int ECCSigner::verify(byte* message, size_t msg_len, byte* signature, size_t sig_len, byte* publickey, size_t key_len){
  if(!this->isInitialized){
    DEBUG_STDERR("ECCSigner NOT INITIALIZED. Run begin() first!");
    return -1;
  }

  // Sanity check
  if(!message || !signature || !publickey){
    DEBUG_STDERR("message/signature/publickey must not be null");
    return -1;
  }

  // Create a ECDSA context
  mbedtls_ecdsa_context ecdsa;
  mbedtls_ecdsa_init(&ecdsa);

  // Create the key
  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk); 
                                                  // Length must account for 0 byte at the end! +1
  if(mbedtls_pk_parse_public_key(&pk, publickey, key_len+1) != 0){
    DEBUG_STDERR("Parse publickey failed");
    return -1;
  }
  
  if( mbedtls_pk_get_type( &pk ) == MBEDTLS_PK_ECKEY ){
    // We got an EC key! Lets create a keypair from that
    mbedtls_ecp_keypair *ecp = mbedtls_pk_ec(pk);    
    if(mbedtls_ecdsa_from_keypair(&ecdsa, ecp) != 0){
      DEBUG_STDERR("ECDSA from key failed");
      return 1;
    }

    // Now that's a bit odd. We have to first hash the Message, as the ECDSA routine of mbedtls does
    // not do that for us... No problem then. Use SHA256, 32 Byte hash
    byte hash_msg[HASHLEN];
    if(HASH(message, msg_len, hash_msg, NOT_USE_HMAC) !=0){
      DEBUG_STDERR("Hash of Message failed");
      return 1;
    };

    // Read/Verify the signature
    if(mbedtls_ecdsa_read_signature(&ecdsa, hash_msg, HASHLEN, signature, sig_len) != 0){
      DEBUG_STDERR("Signature failed");
      return 1;
    }
    DEBUG_STDSUC("SIGNATURE OK");

    // Cleanup
    ecp_clear_precomputed(&ecdsa.grp);
    mbedtls_ecp_keypair_free(ecp);
    mbedtls_pk_free(&pk);  
    mbedtls_ecdsa_free(&ecdsa);
    
  }
  DEBUG_STDSUC("Verification complete");
  return 0;
}

/*
This function is responsible for verifying the signature and message, of which the signature is provided in Base64 encoded form.
First it will check if all the inputs are of proper length and not null. Then it will attempt to decode the Signature using the
integrated Base64_decoder. After that it will pass the decoded signature and message to the verify method and return its output
results. Thus:
-- Input:
- message        String message to be verified
- b64_signature  Signature of the message, base64 encoded
- publickey      Public verification key
-- Output:
-1   Format error
0    Signature Ok
1    Signature not ok
2    Base64 error
*/
int ECCSigner::verify_b64(String message, String b64_signature, String publickey){
    if(!this->isInitialized){
      DEBUG_STDERR("ECCSigner NOT INITIALIZED. Run begin() first!");
      return -1;
    }
      // Sanity Check
    if(!message || !b64_signature || !publickey){
      DEBUG_STDERR("message/signature buffer/publickey written must not be null");
      return -1;
    }

    byte signature[SIGNATURE_LEN];   // 72 is the standard Signature length with ECDSA SECP256R1 256 Bit key. Might be smaller though! pay attention
    size_t sig_bytes_written;
    if(mbedtls_base64_decode(signature, SIGNATURE_LEN, &sig_bytes_written, (byte*)b64_signature.c_str(), b64_signature.length()) !=0){
      DEBUG_STDERR("Base64 decoding of signature failed");
      return 2;
    };
    
    size_t msg_len = message.length();
    byte byte_message[msg_len+1];    // Must be one place longer
    message.getBytes(byte_message, msg_len+1);

    byte pubkey_bytes[publickey.length()+1];
    publickey.getBytes(pubkey_bytes, publickey.length()+1);

    if(verify(byte_message, msg_len, signature, sig_bytes_written, pubkey_bytes, publickey.length()) != 0){
      // can be shortened, but i think this is more readable
      return 1;
    }
    
  return 0;
}

/*
This method is highly specialized for the desired i4sec usecase. It will perform numerous tasks. First it will take the concatenation of
the password and salt (concatPW) and derive the key and iv for AES from those. This is done using the deriveKeys() method. After that, it
takes the newly derived key and iv to symmetrically encrypt the publickey of the current object. Make sure that this exists beforehand!
Then, it will take the created ciphertext and base64-encode it. This will ensure that there exist no formatting errors during later verification.
Said b64_ciphertext will then be signed using the private key of the current object. This is handled by the sign method.
-- Input:
ct_dst, ct_dst_len      The ciphertext destination buffer and its length
sig_dst, sig_dst_len    The signature destination buffer and its length
concatPW, concatPW_len  The concatenation of password and salt, its length
-- Output:
-1    Format error
0     Ok
1     Key derivation error
2     AES GCM error
3     Signature error
*/
int ECCSigner::deriveEncryptedPubkey(byte* ct_dst, size_t* ct_dst_len, byte* sig_dst, size_t* sig_dst_len, byte* concatPW, size_t concatPW_len){
    if(!this->isInitialized){
      DEBUG_STDERR("ECCSigner NOT INITIALIZED. Run begin() first!");
      return -1;
    }
    byte kdf_key[KEYLEN];
    byte kdf_iv[IVLEN];     // IV length set to 12.. optimal i guess
    if(deriveKeys(concatPW, concatPW_len, kdf_key, KEYLEN, kdf_iv, IVLEN)){
      // Return code >0, so error
      return 1;
    }

    // AES GCM Encryption for Pubkey. GCM Mode produces the same ciphertext length as the plaintext length!
    size_t pk_len = publickey.length();
    if(pk_len == 0){
      return -1;
    }
    byte ciphertext[pk_len];            
    byte tag[16];                       // GCM Tag is always 16 Bytes
    mbedtls_gcm_context aes;
    mbedtls_gcm_init(&aes);                                     // BITS, WHY?!
    if(mbedtls_gcm_setkey(&aes, MBEDTLS_CIPHER_ID_AES, kdf_key, KEYLEN*8) != 0){
      DEBUG_STDERR("GCM setkey failed");
      return 2;
    };                                                                // The id is Additional Data, complying to the protocol
    if(mbedtls_gcm_starts(&aes,MBEDTLS_GCM_ENCRYPT, kdf_iv, IVLEN, (byte*)MYID, strlen(MYID)) != 0){
      DEBUG_STDERR("GCM Start failed");
      return 2;
    };              // Update, feed the stream and the ciphertext
    if(mbedtls_gcm_update(&aes, publickey.length(), (byte*) publickey.c_str(), ciphertext) != 0){
      DEBUG_STDERR("GCM Update failed");
      return 2;
    };              // Finish, produce the Authenticity Tag. Tag Length is ALWAYS 16 bytes!
    if(mbedtls_gcm_finish(&aes, tag, 16)){
      DEBUG_STDERR("GCM Finish failed");
      return 2;
    };
    mbedtls_gcm_free(&aes);

    
    // Concat Tag and Ciphertext
    byte ciphertag[pk_len+16];
    memcpy(ciphertag, ciphertext, pk_len);
    memcpy(ciphertag+pk_len, tag, 16);
    
    // Encode the Ciphertext
    if(mbedtls_base64_encode(ct_dst, BASE64_LEN(pk_len+16), ct_dst_len, ciphertag, pk_len+16)){
      DEBUG_STDERR("Buffer too small for Base64 encoding!");
      return 3;
    };

    size_t sig_len;
    byte signature_dest[BASE64_LEN(SIGNATURE_LEN)];
    // Sign the encoded ciphertext using my own key buffer
    if(sign_b64(ct_dst, *ct_dst_len, signature_dest, BASE64_LEN(SIGNATURE_LEN), &sig_len) != 0){
      DEBUG_STDERR("Signature of Ct failed");
      return 3;
    }; 
    
    // Encrypt the B64 encoded Signature, thus preventing any appending of fraudulent signatures
    byte enc_sig[sig_len];   

    // Clear the tag buffer  
    memset(tag, 0x0, 16);       
    
    // Reuse the Context. Reinit
    mbedtls_gcm_init(&aes);                                     // BITS, WHY?!
    if(mbedtls_gcm_setkey(&aes, MBEDTLS_CIPHER_ID_AES, kdf_key, KEYLEN*8) != 0){
      DEBUG_STDERR("Signature Enc GCM setkey failed");
      return 2;
    };                                                                // The id is Additional Data, complying to the protocol
    if(mbedtls_gcm_starts(&aes,MBEDTLS_GCM_ENCRYPT, kdf_iv, IVLEN, (byte*)MYID, strlen(MYID)) != 0){
      DEBUG_STDERR("Signature Enc GCM Start failed");
      return 2;
    };              // Update, feed the stream and the ciphertext
    if(mbedtls_gcm_update(&aes, sig_len, signature_dest, enc_sig) != 0){
      DEBUG_STDERR("Signature Enc GCM Update failed");
      return 2;
    };              // Finish, produce the Authenticity Tag. Tag Length is ALWAYS 16 bytes!
    if(mbedtls_gcm_finish(&aes, tag, 16)){
      DEBUG_STDERR("Signature Enc GCM Finish failed");
      return 2;
    };
    mbedtls_gcm_free(&aes);

    // Kill the key
    memset(kdf_iv, 0x0, IVLEN);
    memset(kdf_key, 0x0, KEYLEN);

    // Append the GCM tag
    byte raw_enc_sig[sig_len+16];
    memcpy(raw_enc_sig, enc_sig, sig_len);
    memcpy(raw_enc_sig+sig_len, tag, 16);

    // Encode the Encrypted Signature + Tag
    if(mbedtls_base64_encode(sig_dst, BASE64_LEN(sig_len+16), sig_dst_len, raw_enc_sig, sig_len+16)){
      DEBUG_STDERR("Buffer too small for Base64 encoding!");
      return 3;
    };

    return 0;
}

/*
This function is responsible for deriving the Key and IV from a given password. It will first extract the password and
salt from the provided concatenation of the password. After that, it will make use of the PKDF2_HMAC function to derive
the Key (32 Bytes) and the IV (12 Bytes) from the password and salt. After successfull derivation, it will write the 
new key and iv to the provided destination buffers.
-- Input:
concatPW, passlen           The concatenation of the password and salt, its length
kdf_key, key_len            The destination buffer for the derived key, the key length
kdf_iv, iv_len              The destination buffer for the derived Iv, the iv length
-- Output:
-1      Format error
0       All ok
1       Message Digest error
*/
int ECCSigner::deriveKeys(byte* concatPW, size_t passlen, byte* kdf_key, size_t key_len, byte* kdf_iv, size_t iv_len){
    if(!this->isInitialized){
      DEBUG_STDERR("ECCSigner NOT INITIALIZED. Run begin() first!");
      return -1;
    }
    // The concatPW is the concatenation of the password and the salt. Lets copy the items
    byte password[PASSLEN];
    byte salt[SALTLEN];

    if(passlen != PASSLEN+SALTLEN){
      Serial.println("LENGTH MISSMATCH");
      return -1;
    }
    memcpy(password, concatPW, PASSLEN);
    memcpy(salt, concatPW+PASSLEN, SALTLEN);
    //Reset
    memset(concatPW, 0x0, PASSLEN + SALTLEN);   

    // Derive Password using PBKDF2_HMAC
    mbedtls_md_context_t sha256_ctx;
    mbedtls_md_context_t sha1_ctx;
    mbedtls_md_init(&sha256_ctx);
    mbedtls_md_init(&sha1_ctx);
                                                                                // Use HMAC
    if(mbedtls_md_setup(&sha256_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), USE_HMAC) != 0){
      DEBUG_STDERR("MD256 setup Failed");
      return 1;
    }
    if(mbedtls_md_setup(&sha1_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), USE_HMAC) != 0){
      DEBUG_STDERR("MD1 setup Failed");
      return 1;
    }
    if(mbedtls_pkcs5_pbkdf2_hmac(&sha256_ctx, password, PASSLEN, salt, SALTLEN, ITERATIONS, key_len, kdf_key) != 0){
      DEBUG_STDERR("PW Gen failed");
      return 1;
    }
    
    if(mbedtls_pkcs5_pbkdf2_hmac(&sha1_ctx, password, PASSLEN, salt, SALTLEN, ITERATIONS, iv_len, kdf_iv) != 0){
      DEBUG_STDERR("IV Gen failed");
      return 1;
    }
    memset(password, 0x0, PASSLEN);
    memset(salt, 0x0, SALTLEN);
    mbedtls_md_free(&sha1_ctx);
    mbedtls_md_free(&sha256_ctx);
    return 0;
}



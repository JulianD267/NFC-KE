# ESP32 Software

This project is a PlatformIO project for Visual Studio Code. After cloning you can directly open and compile it. Mostly it consists of two central components which offer different functionalities. Though, it has a few requirements, that need to be fullfilled first.

## Prerequisites
The following Libraries need to be installed. This is done via PIO automatically most of the time though. You just need to install the Heltec LoRa 32 V2 Platform, which is part of the overall ESP32 Board package. So go ahead and install that.

- mbedtls [2.23.0](https://github.com/ARMmbed/mbedtls)
- ArduinoJson [6.15.2](https://arduinojson.org/)
- *PN532 NFC Library [1.0](https://github.com/Seeed-Studio/PN532)
- *u8g2 OLED Library [2.0](https://github.com/olikraus/u8g2)
- Adafruit unified sensor [1.1.4](https://github.com/adafruit/Adafruit_Sensor)
- Adafruit DHT sensor library [1.3.0](https://github.com/adafruit/DHT-sensor-library)

*Download on your own and add the library/ Might already be provided in the ```/lib``` folder

**Attention:**
Due to the integrated OLED display, the RX2 Pin for ```Serial2``` on Pin 16 cannot be used! Therefore, RX2 needs to be changed within ```HardwareSerial.h``` **to Pin 2**.
The latter two libraries are necessary for our demonstrator which makes use of a DHT22. If you deploy a different sensor, you may choose to install a different library.

You may refer to the wiring diagram below:

![ESP](https://github.com/JulianD267/NFC-KE/raw/master/img/esp32_wiring.png)

## Components
There exist two basic components for this ESP32 software
1. NFCHelper
2. ECCSigner
3. main

## 1. NFCHelper
The NFCHelper is responsible for handling every interaction with the NFC world. It is compactly organized within the ```NFCHelper.hpp``` header and the contained ```NFCHelper``` class. The class wraps the necessary functions of the ```PN532``` library and implements the custom NFC reading for our needs. There are a few DEFINEs at the beginning of the header.

### Authentication
The Mifare classic 1k tag officially has 1024 Bytes of usable data. That's not the complete truth though. Every tag has a memory layout, which takes care for a mostly fine-granular authentication mechanism. Every tag is separated into 16 sectors, each containing 4 Data blocks of 16 Bytes. So in therory there are
```
16 Sectors * 4 Blocks/Sector * 16 Bytes/Block = 1024 Bytes
```
Though, every fourth Block is reserved to be a "Trailer". Additionally, the first Block should not be used since it has the UID and Manufacturer Data in it. So, by subtracting every fourth Block, the real world user data is reduced significantly. By convention for this demonstrator, we will not touch the first sector as a whole! The resulting use data comes down to:
```
15 Sectors * 3 Blocks/Sector * 16 Bytes/Block = 720 Bytes
```

As previously stated, every fouth block is a trailer block, containing the authentication scheme. The 16 Bytes are each assiged a special function. The first 6 Bytes [0:5] contain the secret ```KeyA```. The following 4 Bytes [5:9] describe the authentication policy, described [here](https://www.nxp.com/docs/en/data-sheet/MF1S50YYX_V1.pdf). The last 6 bytes [10:15] finally include the private ```KeyB```. Depending on the policy in [5:9], either ```KeyA```, ```KeyB``` or both will be needed to authenticate.

```
=================== Block 0 =================== ===
AC ED BF 08 A8 AA 91 23 32 9D 10 AF FE AF FE 00   |
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   | Key A
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   |
00 00 00 00 00 00 FF 07 80 69 FF FF FF FF FF FF   |
|---- Key A -----|--Policy---|---- Key B ------|

=================== Block 1 =================== ===
ED 7A 7E 87 72 95 34 50 5E 72 99 28 BD CA 84 EA   |
14 00 05 AD 2B 41 13 DB B9 8F 06 B6 7A C9 75 A7   | Key A
CB C3 95 9C FC B4 23 7F 1F 27 48 99 FA FF D4 54   |
00 00 00 00 00 00 FF 07 80 69 FE AF FE AF FE AF   |
=================== Block 2 =================== ===
9D 1D 23 26 80 16 FD 1B 49 83 2D 93 2C 86 67 FA   |
2E FC 54 05 68 F0 D1 BF CD 39 90 A2 A0 A8 CF 2C   | Key A
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   |
00 00 00 00 00 00 FF 07 80 69 FE AF FE AF FE AF   |
=================== Block 3 =================== ===
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   |
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   | Key Universal
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   |
00 00 00 00 00 00 FF 07 80 69 FF FF FF FF FF FF   |
...
```
Whenever a reader (or writer) wants to access a new Block, it needs to authenticate to it, using one of ```KeyA``` or ```KeyB```. If the authentication fails, no data can be read/written. If it succeeds, the data within the whole sector can be accessed. (Note: Depending on the access policy, each Block can configured to be individually authenticated). When reading the keys within the trailer, they are masked as logical zeros, making them not readable. The ```NFCHelper``` class therefore implements an ```authenticate(bool, uint8_t)``` method. It will authenticate a given Block using either ```KeyA``` or ```KeyB```.

### Workflow
The constructor sets up the secret keys ```KeyA``` and ```KeyB```. These are not that "private", since this is open source, but it prevents any random reader from authenticating and writing malicious data.
Before using the NFCHelper class, you need to call the ```begin()``` method first. It will setup the hardware and required parameters for the tag reading. It will display if the PN532 Board has been found or not.

After that, the ```searchTag()``` method can be called for searching a passive NFC tag. When found, it will populate the ```uid``` field with the read uid of the tag. This is needed for authentication to the tag.

After that the final ```readPasswordFromCard``` method can be called, which will read the data on the tag as bytes. With the DEFINEs ```PASSLEN``` and ```SALTLEN``` the method will determine how much data it should read. It will iterate through every block, skipping the trailer and authenticating at every new first block. Fianlly, all the tag data will be stored within the supplied buffer.

## 2. ECCSigner
This class encapsulates the signing/verification functionality. For that it has two main methods ```sign()``` and ```verify``` with their derivates ```sign_b64()``` and ```verify_b64()```. The latter offer the same functionality as the original methods, but expect/produce a base64 encoded input/output. This might come in handy for sending the data over WiFi e.g. As per default it uses the ```SECP256R1``` curve and 256-Bit hashes/keys.

### Configuration
There exists a file ```ecc_config.h``` which includes a lot of necessary/convenient DEFINEs to customize the behaviour of the ```ECCSigner```. With it, the keylengths and algorithms can be configured. It also offers a macro for calculating the length of a base64 encoded string.

### Workflow
First the ```begin()``` method needs to be called. It will setup any security related parameters and seed the RNG. Most importantly, it also sets up the Elliptic Curve keypair used for the ECDSA signature/verification. The pubkey is exported as PEM and stored within a new variable, making it accessible from outside. The private key remains secret within memory.

The class itself is made in such a way, that it facilitates the use of the specified protocol. So first it needs to derive the encrypted version of its public key. For that, it uses the ```deriveEncryptedPubkey()``` method. It takes, among others, the password+salt from the NFC tag. After the method finished, the provided buffers will be filled with the encrypted pubkey and its signature in base64, which has been created using the private key of the ESP32.
**NOTE:** The method will overwrite all private data with zeros!

After exchanging the encrypted public key, the ```ECCSigner``` can be used as usual. With the sign/verify methods, any arbitrary data (in byte form) can be signed or verified. Any further implementation details can be extracted from the comments within the code.

## 3. Main
The main module has its two required ```loop()``` and ```setup()``` methods. The latter of which takes care of the Serial/OLED/Sensor/Wifi setup and also calls the ```.begin()``` method of the NFCHelper and ECCSigner respectively. Please refer to the following sequence diagram:

![Sequence](https://github.com/JulianD267/ecc-sign-ossl/blob/master/img/seq.png?raw=true)


After connecting to a WiFi network, it will attempt to retrieve the public key of the signing hub using the ```getTPMPublicKey()``` method. This will be done until the key is retrieved! Then the ```setup``` method will use the ```sendMyPubkey()``` method to send the encrypted public key to the signing hub thereby complying to the specified authentication protocol. After that that was successful, the loop phase can begin.

The ```loop()``` method will periodically measure new data and generate a new JSON message from that. Using the ECCSigner object, it will create a signature for the message and send that off to the signing hub. It's then up to the signing hub what will happen with the data (e.g. collection, passing it on etc.). In this example, the signing hub returns the TPM signature for the message on success. This can be verified using the previously retrieved public key of the TPM.

The mentioned ```sendMyPubkey()``` method is responsible for the key exchange, specified within the protocol. It will read the password from a given NFC tag, derive the encrypted publickey and form a JSON message for the signing hub, which will be sent afterwards. If all that succeeds, the key exchange can happen. On success the signing hub will return the public key of the sending ESP32, which has then been added to the local key DB.

The ```getTPMPublicKey()``` method will just do what its name already suggests: retrieving the Public Key of the TPM. Note that this is not strictly necessary for the overall functionality but only for the verification of the TPM signature.

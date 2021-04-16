# NFC Key Exchange Demonstrator 

This proof-of-concept example is part of the BMBF Project "i4sec". It is a proof-of-concept for the NFC Key Exchange schema, presented at the World Forum for IoT 2021.
## Components
This project aims to offer a scalable solution for signing and verifying sensor data in a secure way. For that, two basic component categories are used: The signing hub and the sensor nodes. The data, collected by the sensor nodes, is to be signed by the signing hub. If an attacker were to inject his own data, the system needs to notice the intrusion and reject the data.
### Raspberry Pi
Fundamentally, this system revolves around one central Raspberry Pi model 3B+ and the [TPM 2.0](https://www.infineon.com/cms/de/product/evaluation-boards/iridium-sli-9670-tpm2.0/)
module from Infineon. It is considered to be the signing hub. All other sensor nodes will send their data to this Raspberry Pi. The Pi will then verify the data and sign it, using a TPM generated key. The wiring diagram for the signing hub is shown below:

![RPI](https://github.com/JulianD267/NFC-KE/raw/master/img/rpi_wiring.png)

### ESP32
The other component will be an ESP32 development board [Heltec LoRa 32 v2](https://heltec.org/project/wifi-lora-32/). It offers an integrated OLED display and LoRa capabilities. For a practical example, a DHT22 temperature sensor is attatched to the ESP32, to get some real world measurements. For further information regarding the ESP32 setup, refer to the code/readme within the ```/ESPSign``` directory The wiring diagram for the ESP32 is shown below:

![ESP](https://github.com/JulianD267/NFC-KE/raw/master/img/esp32_wiring.png)

### NFC
For reasons discussed further down, the Sensors and the signing hub make use of an NFC authorization challenge-response scheme to enhance the data security. Therefore, a commonly used NFC reader is used, which uses the [PN532](https://www.nxp.com/docs/en/nxp/data-sheets/PN532_C1.pdf) reader IC and a [MIFARE Classic 1k](https://www.nxp.com/products/rfid-nfc/mifare-hf/mifare-classic/mifare-classic-ev1-1k-4k:MF1S50YYX_V1) NFC tag. In this particular example, the following [Evaluationboard](https://www.bastelgarage.ch/pn532-nfc-rfid-modul-v3-set-mit-rfid-karte-und-key) was used (offers I2C, SPI and UART). Particularly, we used the UART interface with this [library](https://github.com/Seeed-Studio/PN532). For the Raspberry, there exists a rather neat library called ["libnfc"](https://github.com/nfc-tools/libnfc) which is open source and platform independent. This enables any usual Linux device to run this as well.

## Prerequisites

There are a number of dependencies that need to be fullfilled in order to run this example.

### Raspberry Pi
The Raspberry Pi need to run Raspbian Buster or above. There exist a few cases of Model 2s running the TPM software, though it is recommended to at least use a Pi model 3, since it has TPM support builtin. To enable the TPM support, you need to edit the ``` config.txt ``` file in the ```/boot ``` directory and enter the following lines at the end:

```
# Enable TPM
dtparam=spi=on
dtoverlay=tpm-slb9670
# Enable UART
dtoverlay=pi3-disable-bt
enable_uart=1
```
That's it. Now you can go ahead and follow the instructions of Infineon to install all the necessary TPM software components. These are:
- TPM2-TSS ([Github](https://github.com/tpm2-software/tpm2-tss))
- TPM2-Resource-Broker ([Github](https://github.com/tpm2-software/tpm2-abrmd))
- TPM2-Tools ([Github](https://github.com/tpm2-software/tpm2-tools))
- TPM2-Openssl-Engine ([Github](https://github.com/tpm2-software/tpm2-tss-engine))

For further details, consult the Infineon page of the [SLB9670](https://www.infineon.com/cms/de/product/security-smart-card-solutions/optiga-embedded-security-solutions/optiga-tpm/slb-9670vq2.0/) Board and the [installation manual](https://www.infineon.com/dgdl/Infineon-OPTIGA_SLx_9670_TPM_2.0_Pi_4-ApplicationNotes-v07_19-EN.pdf?fileId=5546d4626c1f3dc3016c3d19f43972eb).

In order to compile the code, you need to install the following dependencies onto the Raspberry Pi
- [openssl](https://github.com/openssl/openssl) v1.1.x+
- pthread (should be installed, otherwise google)
- [boost](https://www.boost.org/) library
- ["libnfc"](https://github.com/nfc-tools/libnfc)

To use the NFC board, you may want to specify a configuration file called ```pn532_uart_on_rpi.conf``` within the directory ```/etc/nfc/devices.d/```. This may very well not exist, so feel free to ```mkdir``` that. The file should contain the following lines:

```
## Typical configuration file for PN532 device on R-Pi connected using UART
## Note: to use UART port on R-Pi, you have to disable linux serial console:
##   http://learn.adafruit.com/adafruit-nfc-rfid-on-raspberry-pi/freeing-uart-on-the-pi
name = "PN532 board via UART"
connstring = pn532_uart:/dev/ttyAMA0
allow_intrusive_scan = true
```

This allows the NFC device to be connected via the ```ttyAMA0``` device. NOTE! This may differ on other systems! Please check for your tty first.
## ESP32
We provide a ready to build Platform IO Project for the ESP32 Heltec LoRa 32 v2 Board. Please make sure that you have a working Platform IO runtime with the ESP32 board installed. We won't go deep into this. Please search for suitable tutorials on how to do that.

After installation, the project within ```ESPSign/``` can be imported directly.

## Setup
After cloning, please run ```make tpm```. This will automatically generate an executable called ```ecc_sign_tpm``` with openssl tpm engine support. If you wish to disable the engine, please run ```make clean``` followed by ```make ecc_sign```. The executable takes no inputs. Just run
```
./ecc_sign_tpm
```
It will then setup a Web server, listening on Port 8080. First though, it expects an NFC tag to be held onto the reader for password transfer. So make sure your reader is attatched. Using the ReST Api, different actions can be performed. Within the folder ```TPMDataCollector/```, an example Python flask application is making use of the Api to retrieve all data messages and verify the signatures.

The ESP Should do its thing on its own. It also expects an NFC tag containing the password to be held onto a connected reader. Then it connects to the Pi, using its specified IP. You may change that accordingly!

## Communication
The communication between the sensors and the signing hub is completely designed to be scalable and universally compatible. Before any sort of message exchange can happen, the signing hub needs to verify, that the ESP is authorized to send data. For that it needs the ECDSA public key of the sensor.
### <a name="phase1"></a> Phase 1
The ESP will request the Public key of the TPM using the ReST endpoint ```/pkey```. If everything works fine, this endpoint will return the PEM formatted TPM ECDSA public key.

### <a name="phase2"></a> Phase 2
But how can we exchange keys that only come from authorized parties? Well, that's where NFC comes in. During startup, the TPM generates a new Password and Salt and writes the concatenation of those bytes to the NFC tag. The length is fixed to 64 bytes password + 16 bytes salt. The data is written to the NFC tags, beginning with Block 4 and using the custom KeyA. When reading the card using said key, the output will be the following:
```
[...]
Block 4:   09B9AFB9034598CDB32BC2B5582D028B
Block 5:   0FEDAA53BC9DF44C3F75283FCAF4E4F9
Block 6:   2915D8820E7E68A00B4BDAC6EBE3B913
Block 7:   000000000000FF078069FEAFFEAFFEAF  <- Trailer
Block 8:   E82B239C84888262203E2B33357ABAAC
Block 9:   8EF95ED21CF82F6C2718327AA1E5F4CD  <- End of Data
Block 10:  00000000000000000000000000000000
Block 11:  000000000000FF078069FEAFFEAFFEAF  <- Trailer
Block 12:  00000000000000000000000000000000
Block 13:  00000000000000000000000000000000
Block 14:  00000000000000000000000000000000
Block 15:  000000000000FF078069FFFFFFFFFFFF  <- Trailer
[...]
```
Please make sure that you read about the official Mifare Classic 1k authentication [mechanism](https://www.nxp.com/docs/en/data-sheet/MF1S50YYX_V1.pdf), before you tamper with the code! One bad write to the trailer and your whole Tag is rendered useless... Speaking from experience...

But why are we doing this? Well the password has been written to the Tag. The ESP will now read the password from the tag. The Tag can be considered trusted since it requires physical access to the devices. The ESP will then derive a key from the Password and encrypt its ECDSA public key with it (AES-256-GCM). The ciphertext gets signed using the private key of the ESP and is then being sent along with the sensorID to the signing hub. The format need to comply to the following JSON definition:
```
{
  "s_id": < The Sensor ID: String>,
  "pkey": < The Base64 encoded ciphertext+tag of the encrypted ESP public key>,
  "sig":  < The Base64 encoded ECDSA Signature of the base64 encoded ciphertext.
}
```
Only and only if the message is formatted in that way, the signing hub will process it and append the public key to its database. If the signature is invalid or the decryption fails, the key gets rejected.

The signing hub now owns the ECDSA public key of the sensor and is able to verify message signatures of the sensor.

### Phase <a name="phase3"></a> 3
After the key of the sensor has been sent to the signing hub successfully, a secured communication can be established. The ultimate goal was to enable the sensor to sign a message with its own private ECDSA key and send it to the signature hub, which in return will be able to verify the signature.

For a unified interface to send messages, the signing hub will only accept messages in the following format:
```
{
  "s_id": < The Sernsor ID: String>,
  "msg": < The unencoded message: String>,
  "sig": < The Base64 encoded ECDSA Signature of the unencoded message: String>
}
```
The signature is created using the raw version of the message, making it universally compatible. The sensorID should be unique within the system. After receiving the message, the signing hub will go ahead and verify the signauture with the corresponding public key of the sensor. If this is valid, the signing hub will then sign the message itself with its private key and provide that to any interested party.

By requesting the public key of the signing hub and querying the messages, anyone is able to verify the signature.


## ReST API Endpoints
To interact with the signing up, it offers several ReST endpoints to call.
- ```/clear[GET]```
This endpoint will allow to clear all the messages within the local buffer. Result:
  - 200 : ```"ok"```
- ```/nfc[GET]```
This endpoint will reinitialize the NFC password exchange process. The signing hub will wait for a NFC tag to write a completely new password to. Return:
  - 200 : ```{"result": "ok"}```
  - 400 : ```{"result": "fail"}```
- ```/pkey[GET]```
This will return the public key of the signing hub in PEM format. Return:
  - 200 : All ok
- ```/append[POST]```
This endpoint will be called when an exchange of the public sensor key should happen. The passed message in the POST arguments shall stick to the format mentioned in [Phase 2](#phase2). Return:
  - 200 : Public key in plain form
  - 400 : JSON format failure
  - 400 : Verification failure
  - 400 : Key derivation failure
- ```/data[GET]```
This endpoint will return all the messages within the local message buffer. A JSON array will be returned containing all the messages in the format of [Phase 3](#phase3).
  Return:
  - 200 : all the messages
- ```/json[POST]```
This endpoint will be available when the key exchange has been successfull and now messages shall be exchanged. The POST arguments must be formatted in the format of [Phase 3](#phase3). After receiving a new message, the JSON will be verified and the different fields get extracted. The signature will be verified against the message using the previously exchanged sensor public key. Return:
  - 200 : Signature of the message using the tpm private key
  - 422 : Verification failed
  - 500 : Unknown sensor  

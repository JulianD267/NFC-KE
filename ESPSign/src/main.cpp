#include <Arduino.h>
#include <ArduinoJson.h>
#include <WiFiMulti.h>
#include "string.h"
#include "WiFi.h"
#include "DHT.h"
#include "HTTPClient.h"
#include "ecc_config.h"
#include "ECCSigner.h"
#include "NFCHelper.h"
#include "NFCExchanger.h"
#include "ECDHExchanger.h"
#include "DHExchanger.h"
#include "RSAExchanger.h"
#ifdef OLED
    #define OLED_CONFIG
    #include "U8x8lib.h"
    U8X8_SSD1306_128X64_NONAME_SW_I2C *u8x8 = new U8X8_SSD1306_128X64_NONAME_SW_I2C(/* clock=*/ 15, /* data=*/ 4, /* reset=*/ 16);
    #define OLED_VAR u8x8
    #ifndef OLED_CONFIG
      #define OLED_WRITE(x,y,msg) u8x8->drawString(x,y,msg)
      #define OLED_CLEAR()  u8x8->clearDisplay()
      #define OLED_CLEAR_LINE(y) u8x8->clearLine(y)
    #endif
#else
    #define OLED_VAR void
    #ifndef OLED_CONFIG
      #define OLED_CONFIG
      #define OLED_WRITE(x,y,msg) {}
      #define OLED_CLEAR()  {}
      #define OLED_CLEAR_LINE(y) {}
    #endif
  #endif

#include "Exchanger.h"


// Wifi and HTTP
WiFiMulti wifiMulti;
HTTPClient http;

// Sensor
DHT dht(23, DHT22);
float cur_temp = 0.0;

// Signer
ECCSigner signer;    
String tpmkey = "";

// Exchanger, Polymorphism
Exchanger *exchanger;

String generateMessage(){
  float temp = dht.readTemperature(false, true);
  if(temp < 50.0 && temp > 0.0 ){
    cur_temp = temp;
  }
  return String(cur_temp);
}

void setup() {

    // Serial setup
    Serial.begin(115200);
    #if !DBG
    Serial.println("I'm silent now");
    #endif
    DEBUG_STDOUT("Hello");

    // Setup the OLED
    #ifdef OLED
    u8x8->begin();
    u8x8->setFont(u8x8_font_chroma48medium8_r);
    u8x8->drawString(0, 0, "Starting... ");
    #endif

    // Sensor setup
    pinMode(23, OUTPUT);
    digitalWrite(23, LOW);
    delay(1000);
    dht.begin();

    // Setup the Exchanger
    exchanger = new RSAExchanger(OLED_VAR);
    exchanger->begin();

    // Setup the Signer
    signer.begin();    
    OLED_CLEAR();
    OLED_WRITE(0,3, "Connecting...");

    // Wifi
    wifiMulti.addAP(SSID, WIFIPASS);
    while(wifiMulti.run() != WL_CONNECTED);

    OLED_CLEAR_LINE(3);
    OLED_WRITE(0,3,"GET TPM KEY");
    
    while(exchanger->getTPMPublickey(&tpmkey) != 0){
      // Try again
    }
    DEBUG_STDOUT(tpmkey.c_str());
    OLED_CLEAR_LINE(3);
    OLED_WRITE(0,3, "SEND MY KEY");

    while(exchanger->exchangeKey(&signer) != 0){
      // Try again
    } 
    OLED_CLEAR_LINE(3);
    OLED_WRITE(0,3, "COMPLETE");    
}

void loop() {
  delay(5000);
  OLED_CLEAR();
  // Create the message
  String message = generateMessage();
  OLED_WRITE(0, 0, "MyID:");
  OLED_WRITE(0, 1, MYID);
  OLED_WRITE(0, 3, "Message:");
  OLED_WRITE(0, 4, ("temp: "+String(cur_temp)).c_str());
  OLED_WRITE(0, 6, "Signature:");
  OLED_WRITE(0, 7, "--");
  byte b64_sig[BASE64_LEN(SIGNATURE_LEN)];
  size_t bytes_written;
  signer.sign_b64((byte*)message.c_str(), message.length(), b64_sig, BASE64_LEN(SIGNATURE_LEN), &bytes_written);
  OLED_WRITE(0, 7, "/ ");

  // Form a JSON from the data
  StaticJsonDocument<500> json;
  json["s_id"] = MYID;
  json["msg"] = message;
  json["sig"] = b64_sig;
  String ptr;
  serializeJson(json, ptr);
  OLED_WRITE(0, 7, "| ");
  DEBUG_STDOUT("Sending:");
  DEBUG_SIG(ptr);

  // Send the JSON to the TPM
  http.begin(String(URL)+"/json");
  OLED_WRITE(0, 7, "\\ ");
  int httpCode = http.POST(ptr);

  OLED_WRITE(0, 7, "--");
  if(httpCode > 0) {
    // HTTP header has been send and Server response header has been handled
    DEBUG_STDOUT(("[HTTP3] GET... code: " + String(httpCode)).c_str());

    // We can expect the TPM Signature
    if(httpCode == HTTP_CODE_OK) {
      String tpmsig = http.getString();
      DEBUG_STDSUC("TPM SIG:");
      DEBUG_SIG(tpmsig);

      // Verify?
      int ver = signer.verify_b64(message, tpmsig, tpmkey);
      if(ver != 0){
        OLED_WRITE(0, 7, "*Verify FAIL*");
      }else{
        OLED_WRITE(0, 7, "*Verify SUCCESS*");
      }
    }else if(httpCode == HTTP_CODE_INTERNAL_SERVER_ERROR){
      OLED_WRITE(0, 7, "Error...");
      // Key hasnt been added. Lets try again
      exchanger->exchangeKey(&signer);
    }
    http.end();

  } else {
    DEBUG_STDERR(("[HTTP3] GET... failed, error: " + http.errorToString(httpCode)).c_str());
  }
}
# leon-sgroup
//#include <Wire.h>
//#include "rgb_lcd.h"
#include "IotHttpClient.h"
#include "IotUtils.h"

#include <LWiFi.h>
#include <string>

// ********************************************
// ****** START user defined definitions ******
// ********************************************
#define WIFI_SSID                       "Leeeeeeeeeeeon"
#define WIFI_PASSWORD                   "12121212"
#define LED 3
#define SOUND_SENSOR A0
#define THRESHOLD_VALUE 400
// ******************************************
// ****** END user defined definitions ******
// ******************************************

//#define DELAY 60000

//rgb_lcd lcd;

//const int colorR = 0;
//const int colorG = 255;
//const int colorB = 0;

// ******************************************
// ****** setup()****************************
// ******************************************
void setup()
{
    Serial.begin(9600);
    LWiFi.begin();
    delay(6000);
    pins_init();
    while(!Serial);
    Serial.print("\nSearching for Wifi AP...\n");

    while( LWiFi.connectWPA(WIFI_SSID, WIFI_PASSWORD) != 1 )
    {
        Serial.println("Failed to Connect to Wifi.");
    }
    
    
        Serial.println("Connected to WiFi");
    
}

// ******************************************
// ****** loop() ****************************
// ******************************************
void loop()
{
   /* Serial.print("\nSearching for Wifi AP...\n");

    if ( LWiFi.connectWPA(WIFI_SSID, WIFI_PASSWORD) != 1 )
    {
        Serial.println("Failed to Connect to Wifi.");
    }
    else
    {
        Serial.println("Connected to WiFi");
        
     //   lcd.setCursor(0, 0);
       // lcd.print("Connected WiFi");
        
        // Generate some random data to send to Azure cloud.
        srand(vm_ust_get_current_time());

        int device_id = 1 + (rand() % 50);
        int temperature = (rand() % 100);

        // Construct a JSON data string using the random data.
        std::string json_iot_data;
        
        json_iot_data += "{ \"DeviceId\":" + IotUtils::IntToString(device_id);
        json_iot_data += ", \"Temperature\":" + IotUtils::IntToString(temperature);
        json_iot_data += " }";

        // Send the JSON data to the Azure cloud and get the HTTP status code.
        IotHttpClient     https_client;
        
        int http_code = https_client.SendAzureHttpsData(json_iot_data);

        Serial.println("Print HTTP Code:" + String(http_code));
        //lcd.setCursor(0, 1);
        //lcd.print("Code:" + String(http_code));
    }*/
  //  Serial.println("Disconneting HTTP connection");
     int sensorValue = analogRead(SOUND_SENSOR);//use A0 to read the electrical signal
        delay(1000);
	Serial.print("sensorValue ");
        Serial.println(sensorValue);
        if(sensorValue > THRESHOLD_VALUE)
	{
		turnOnLED();//if the value read from A0 is larger than 400,then light the LED
		delay(1000);
	}
        turnOffLED();
        srand(vm_ust_get_current_time());

        int device_id = sensorValue;
        //int temperature = (rand() % 100);

        // Construct a JSON data string using the random data.
        std::string json_iot_data;
        
        json_iot_data += "{ \"DeviceId\":" + IotUtils::IntToString(device_id);
        json_iot_data += ", \"Sensorvalues\":" + IotUtils::IntToString(sensorValue);
        //json_iot_data += ", \"Temperature\":" + IotUtils::IntToString(temperature);
        json_iot_data += " }";

        // Send the JSON data to the Azure cloud and get the HTTP status code.
        IotHttpClient     https_client;
        
        int http_code = https_client.SendAzureHttpsData(json_iot_data);

        Serial.println("Print HTTP Code:" + String(http_code));
       
    //LWiFi.disconnect();
    
    // Sleeps for a while...
    delay(60000);
}

void pins_init()
{
	pinMode(LED, OUTPUT);
	pinMode(SOUND_SENSOR, INPUT); 
}

void turnOnLED()
{
	digitalWrite(LED,HIGH);
}
void turnOffLED()
{
	digitalWrite(LED,LOW);
}
#include "IotHttpClient.h"
#include "vmssl.h"
#include "LTask.h"

#include "hmac.h"
#include "sha256.h"
#include "IotUtils.h"

int delayTime = 500;

IotHttpClient::IotHttpClient()
{
}

struct MtkHttpContext
{
    const char *request;
    const char *serverUrl;
    VMINT port;
    String response;
    VMINT data_sent;
    VMINT data_read;
};

MtkHttpContext *pContext;

char* IotHttpClient::send(const char* request, const char* serverUrl, int port) {
    // TODO: probably not the best way to detect protocol...
    switch(port)
    {
        case 80:
            return sendHTTP(request, serverUrl, port);
        case 443:
            return sendHTTPS(request, serverUrl, port);
        default:
            return sendHTTP(request, serverUrl, port);
    }
}

char* IotHttpClient::sendHTTP(const char *request, const char* serverUrl, int port)
{
    /* Arduino String to build the response with. */
    String responseBuilder = "";
    if (client.connect(serverUrl, port)) {
        /* Send the requests */
        client.println(request);
        client.println();
        /* Read the request into responseBuilder. */
        delay(delayTime);
        while (client.available()) {
            char c = client.read();
            responseBuilder.concat(c);
        }
        client.stop();
    } else {
        client.stop();
        /* Error connecting. */
        return 0;
    }
    /* Copy responseBuilder into char* */
    int len = responseBuilder.length();
    char* response = new char[len + 1]();
    responseBuilder.toCharArray(response, len + 1);
    return response;
}

int IotHttpClient::SendAzureHttpsData(std::string data)
{
    // Calculate the HMAC Signature based on AZURE_HOST and AZURE_UTC_2020_01_01.

    std::string hmac_msg(AZURE_HOST"\n"AZURE_UTC_2020_01_01);
    std::string hmac_key(AZURE_KEY);

    std::string hmac_sig = hmac<SHA256>(hmac_msg, hmac_key);
    // Serial.println(hmac_sig.c_str());

    hmac_sig = IotUtils::HexStringToBinary(hmac_sig);
    // Serial.println(hmac_sig.c_str());
    hmac_sig = IotUtils::Base64Encode(hmac_sig);
    // Serial.println(hmac_sig.c_str());
    hmac_sig = IotUtils::UrlEncode(hmac_sig);
    // Serial.println(hmac_sig.c_str());

    // Build the JSON data with event hub parameters.
    std::string header_auth;

    header_auth += "Authorization: SharedAccessSignature ";
    header_auth += "sr="AZURE_SERVICE_BUS_NAME_SPACE".servicebus.windows.net";
    header_auth += "&sig=" + hmac_sig;
    header_auth += "&se="AZURE_UTC_2020_01_01;
    header_auth += "&skn="AZURE_POLICY_NAME;

    // Build HTTP POST request

    std::string http_string;

    http_string += "POST "AZURE_URL" HTTP/1.1\n";
    http_string += "Host: "AZURE_HOST"\n";
    http_string += header_auth + "\n";
    http_string += "Content-Length: " + IotUtils::IntToString(data.length()) + "\n";
    http_string += "Connection: Close\n";
    http_string += "Content-Type: application/atom+xml;type=entry;charset=utf-8\n";
    http_string += "\n";
    http_string += data + "\n";
    http_string += "\n";

    Serial.println("=== HTTP Headers ===");
    Serial.println(http_string.c_str());

    // Submit the  HTTP POST request to the remote server.
    char *response = sendHTTPS(http_string.c_str(), "mnstestns.servicebus.windows.net", 443);

    Serial.println("=== HTTP Response ===");
    std::string results(response);
    delete response;

    Serial.print(results.c_str());

   // Extract the HTTP status code from the returned HTTP response.

    // 201 - Success.
    // 401 - Authorization failure.
    // 500 - Internal error.

    std::string pattern("HTTP/1.1 ");
    std::string http_code("0");

    int ix = results.find(pattern);

    if (ix >= 0)
    {
         // The status code is found.
         http_code = results.substr(pattern.length(), 3);
    }

    return atoi(http_code.c_str());
}

char* IotHttpClient::sendHTTPS(const char *request, const char* serverUrl, int port)
{
    //Serial.print("Req=");
    //Serial.println(request);
    //Serial.print("URL=");
    //Serial.println(serverUrl);
    //Serial.print("Port=");
    //Serial.println(port);

    // This method is invoked in Arduino thread
    //
    // Use LTask.remoteCall to invoke the sendHttps()
    // function in LinkIt main thread. vm_ssl APIs must be
    // executed in LinkIt main thread.

    MtkHttpContext context;
    context.data_read = context.data_sent = 0;
    context.request = request;
    context.serverUrl = serverUrl;
    context.port = port;
    context.response = "";
    pContext = &context;
    LTask.remoteCall(sendHTTPS_remotecall, &context);

    // Build the response - TODO: when is this response released?
    int len = context.response.length();
    char* response = new char[len + 1]();
    context.response.toCharArray(response, len + 1);

    //Serial.println("returned response:");
    //Serial.println(response);

    return response;
}

boolean IotHttpClient::sendHTTPS_remotecall(void* user_data)
{
    // This function should be executed in LinkIt main thread.

    // Initialize SSL connection
    vm_ssl_cntx ssl_cntx = {0};
    ssl_cntx.authmod = VM_SSL_VERIFY_NONE;  // Do not limit the encryption type of the server.
    ssl_cntx.connection_callback = sendHTTPS_ssl_callback;   // SSL event handler callback.
    ssl_cntx.host = (VMCHAR*)pContext->serverUrl;
    ssl_cntx.port = pContext->port;
    ssl_cntx.ua = NULL;
    vm_ssl_connect(&ssl_cntx);

    // By returning false in this function,
    // LTask.remoteCall will block the execution
    // of the Arduino thread until LTask.post_signal() is called.
    // We shall invoke LTask.post_signal() in
    // the event handler callback.
    return false;

}

void IotHttpClient::sendHTTPS_ssl_callback(VMINT handle, VMINT event)
{
    // This callback is invoked in LinkIt main thread

    VMINT ret;
    VMCHAR buf[52] = {0,};

    // Serial.print("sslCb event=");
    // Serial.println(event);

    switch(event) {
    case VM_SSL_EVT_CONNECTED:{
        // Serial.println("VM_SSL_EVT_CONNECTED");
    }
        case VM_SSL_EVT_CAN_WRITE:
        {
            // Serial.println("VM_SSL_EVT_CAN_WRITE");
            const size_t requestLength = strlen(pContext->request);

            ret = vm_ssl_write(handle, (VMUINT8*)pContext->request + pContext->data_sent, requestLength);
            if(ret >= 0) {
                pContext->data_sent += ret;
            }
            break;
        }
        case VM_SSL_EVT_CAN_READ:
            // make sure there is an terminating NULL
            // Serial.println("VM_SSL_EVT_CAN_READ");
            ret = vm_ssl_read(handle, (VMUINT8*)buf, sizeof(buf) - 1);
            while(ret > 0) {
                pContext->response.concat(buf);
                memset(buf, 0, sizeof(buf));
                // make sure there is an terminating NULL
                ret = vm_ssl_read(handle, (VMUINT8*)buf, sizeof(buf) - 1);
                pContext->data_read += ret;
            }

            if(ret == VM_TCP_READ_EOF) {
                vm_ssl_close(handle);

                // Allow LTask.remoteCall() to return
                LTask.post_signal();
            }
            break;
        case VM_SSL_EVT_PIPE_BROKEN:
        {Serial.println("VM_SSL_EVT_CAN_READ"); }
        case VM_SSL_EVT_HOST_NOT_FOUND:
        {Serial.println("VM_SSL_EVT_HOST_NOT_FOUND"); }
        case VM_SSL_EVT_PIPE_CLOSED:
        {Serial.println("VM_SSL_EVT_PIPE_CLOSED"); }
        case VM_SSL_EVT_HANDSHAKE_FAILED:
        {Serial.println("VM_SSL_EVT_HANDSHAKE_FAILED"); }
        case VM_SSL_EVT_CERTIFICATE_VALIDATION_FAILED:
        {Serial.println("VM_SSL_EVT_CERTIFICATE_VALIDATION_FAILED"); }
            vm_ssl_close(handle);

            // Allow LTask.remoteCall() to return
            LTask.post_signal();
            break;
        default:
            break;
    }
}
#ifndef IOTHTTPCLIENT_H
#define IOTHTTPCLIENT_H

#include <arduino.h>
#include <LWiFi.h>
#include <LWiFiClient.h>

#include <string>

// ********************************************
// ****** START user defined definitions ******
// ********************************************
#define AZURE_SERVICE_BUS_NAME_SPACE    "JKdevices-ns"
#define AZURE_EVENT_HUB_NAME            "ehdevices"
#define AZURE_POLICY_NAME               "ehPolicy"

//#define AZURE_KEY                       "AhBB/d6/tJj/awnV9MPgj1UzXjeboHNzszF5ShcD2FY="
#define AZURE_KEY                       "BZ6ZXQsBRvfKcjy26mijLmRLTtEy05gdFNQQJkJRMFE="



// ******************************************
// ****** END user defined definitions ******
// ******************************************

#define AZURE_HOST                      AZURE_SERVICE_BUS_NAME_SPACE".servicebus.windows.net"
#define AZURE_URL                       "/"AZURE_EVENT_HUB_NAME"/messages"

// Set to year 2020 so that it will not expire.

#define AZURE_UTC_2020_01_01            "1577836800"

/* HttpClient implementation to be used on the Mtk device. */
class IotHttpClient
{
    LWiFiClient client;
    
public:
    IotHttpClient();
    /* Send http request and return the response. */
    char* send(const char *request, const char* serverUrl, int port);
    int SendAzureHttpsData(std::string);
    
protected:
    char* sendHTTP(const char *request, const char* serverUrl, int port);
    char* sendHTTPS(const char *request, const char* serverUrl, int port);
    
public:
    static boolean sendHTTPS_remotecall(void*);
    static void sendHTTPS_ssl_callback(VMINT handle, VMINT event);
};

#endif
#include "IotUtils.h"
#include "hmac.h"
#include "sha256.h"

#include <arduino.h>

std::string IotUtils::IntToString(int num)
{
    // Format an integer into a string.
    
    return std::string(String(num).c_str());
}

std::string IotUtils::HexStringToBinary(std::string input)
{
    // Convert a hex string into an array of bytes stored in std::string.
    
    std::string out;
  
    while(input.length() > 0)
    {
        std::string tmp(input.c_str(),2);
        input.erase(0, 2);
        
        if (tmp.length() != 2) continue;

        unsigned char byte = 0;
        unsigned char nibble = tmp[0];
        
        if (nibble >= '0' && nibble <= '9')
        {
            byte = (nibble - '0') & 0x0F;
        }
        else if (nibble >= 'A' && nibble <= 'F')
        {
            byte = (nibble - 'A' + 10) & 0x0F;
        }
        else if (nibble >= 'a' && nibble <= 'f')
        {
            byte = (nibble - 'a' + 10) & 0x0F;
        }
        
        byte = byte << 4;
        
        nibble = tmp[1];
        
        if (nibble >= '0' && nibble <= '9')
        {
            byte |= (nibble - '0') & 0x0F;
        }
        else if (nibble >= 'A' && nibble <= 'F')
        {
            byte |= (nibble - 'A' + 10) & 0x0F;
        }
        else if (nibble >= 'a' && nibble <= 'f')
        {
            byte |= (nibble - 'a' + 10) & 0x0F;
        }
        
        out += byte;
    }
    
    return out;
}

std::string IotUtils::Base64Encode(std::string input)
{
    const std::string table_encode("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");

    std::string output;

    while (input.length() > 0)
    {
        // Process 3 bytes at a time.
        std::string input_tmp(input.substr(0, 3));

        // Erase the number of bytes processed.
        input.erase(0, input_tmp.length());

        unsigned int num = 0;

        for (unsigned int ix = 0; ix < 3; ix++)
        {
            num = num * 256;
            if (ix < input_tmp.length()) num += input_tmp[ix] & 0xff;
        }

        // "num" is a 24 bit variable.

        // 4 characters are used to represent "num".
        // 6 bits for each character.

        // Since input_tmp is at least 1 byte in length.
        // This means at least 2 characters are needed.

        output += table_encode[((num >> 18) & 0x3f)];
        output += table_encode[((num >> 12) & 0x3f)];

        if (input_tmp.length() == 3)
        {
            output += table_encode[((num >> 6) & 0x3f)];
            output += table_encode[((num)& 0x3f)];
        }
        else if (input_tmp.length() == 2)
        {
            output += table_encode[((num >> 6) & 0x3f)];
            output += "=";
        }
        else if (input_tmp.length() == 1)
        {
            output += "==";
        }
    }

    return output;
}

std::string IotUtils::UrlEncode(std::string input)
{
    // Encode a string with URL encode format.
    std::string result;

    for (unsigned int ix = 0; ix < input.length(); ix++)
    {
        if (isalnum(input[ix]) != 0 || input[ix] == '-' || input[ix] == '_' || input[ix] == '.' || input[ix] == '~')
        {
            result += input[ix];
        }
        else
        {
            // Note that the %% is to print a % character.
            char buffer[1024];
            sprintf(buffer,"%%%02x",input[ix]);
            
            result += buffer;
        }
    }

    return result;
}
#ifndef IOTUTILS_H
#define IOTUTILS_H

#include <string>

class IotUtils
{
public:
    static std::string HexStringToBinary(std::string);
    static std::string Base64Encode(std::string);
    static std::string IntToString(int);
    static std::string UrlEncode(std::string);
};

#endif
// //////////////////////////////////////////////////////////
// hmac.h
// Copyright (c) 2015 Stephan Brumme. All rights reserved.
// see http://create.stephan-brumme.com/disclaimer.html
//

#pragma once

// based on http://tools.ietf.org/html/rfc2104
// see also http://en.wikipedia.org/wiki/Hash-based_message_authentication_code

/** Usage:
    std::string msg = "The quick brown fox jumps over the lazy dog";
    std::string key = "key";
    std::string md5hmac  = hmac< MD5  >(msg, key);
    std::string sha1hmac = hmac< SHA1 >(msg, key);
    std::string sha2hmac = hmac<SHA256>(msg, key);

    Note:
    To keep my code simple, HMAC computation currently needs the whole message at once.
    This is in contrast to the hashes MD5, SHA1, etc. where an add() method is available
    for incremental computation.
    You can use any hash for HMAC as long as it provides:
    - constant HashMethod::BlockSize (typically 64)
    - constant HashMethod::HashBytes (length of hash in bytes, e.g. 20 for SHA1)
    - HashMethod::add(buffer, bufferSize)
    - HashMethod::getHash(unsigned char buffer[HashMethod::BlockSize])
  */

#include <string>
#include <cstring> // memcpy

/// compute HMAC hash of data and key using MD5, SHA1 or SHA256
template <typename HashMethod>
std::string hmac(const void* data, size_t numDataBytes, const void* key, size_t numKeyBytes)
{
  // initialize key with zeros
  unsigned char usedKey[HashMethod::BlockSize] = {0};

  // adjust length of key: must contain exactly blockSize bytes
  if (numKeyBytes <= HashMethod::BlockSize)
  {
    // copy key
    memcpy(usedKey, key, numKeyBytes);
  }
  else
  {
    // shorten key: usedKey = hashed(key)
    HashMethod keyHasher;
    keyHasher.add(key, numKeyBytes);
    keyHasher.getHash(usedKey);
  }

  // create initial XOR padding
  for (size_t i = 0; i < HashMethod::BlockSize; i++)
    usedKey[i] ^= 0x36;

  // inside = hash((usedKey ^ 0x36) + data)
  unsigned char inside[HashMethod::HashBytes];
  HashMethod insideHasher;
  insideHasher.add(usedKey, HashMethod::BlockSize);
  insideHasher.add(data,    numDataBytes);
  insideHasher.getHash(inside);

  // undo usedKey's previous 0x36 XORing and apply a XOR by 0x5C
  for (size_t i = 0; i < HashMethod::BlockSize; i++)
    usedKey[i] ^= 0x5C ^ 0x36;

  // hash((usedKey ^ 0x5C) + hash((usedKey ^ 0x36) + data))
  HashMethod finalHasher;
  finalHasher.add(usedKey, HashMethod::BlockSize);
  finalHasher.add(inside,  HashMethod::HashBytes);

  return finalHasher.getHash();
}


/// convenience function for std::string
template <typename HashMethod>
std::string hmac(const std::string& data, const std::string& key)
{
  return hmac<HashMethod>(data.c_str(), data.size(), key.c_str(), key.size());
}
// //////////////////////////////////////////////////////////
// sha256.cpp
// Copyright (c) 2014,2015 Stephan Brumme. All rights reserved.
// see http://create.stephan-brumme.com/disclaimer.html
//

#include "sha256.h"

// big endian architectures need #define __BYTE_ORDER __BIG_ENDIAN
// #ifndef _MSC_VER
// #include <endian.h>
// #endif


/// same as reset()
SHA256::SHA256()
{
  reset();
}


/// restart
void SHA256::reset()
{
  m_numBytes   = 0;
  m_bufferSize = 0;

  // according to RFC 1321
  m_hash[0] = 0x6a09e667;
  m_hash[1] = 0xbb67ae85;
  m_hash[2] = 0x3c6ef372;
  m_hash[3] = 0xa54ff53a;
  m_hash[4] = 0x510e527f;
  m_hash[5] = 0x9b05688c;
  m_hash[6] = 0x1f83d9ab;
  m_hash[7] = 0x5be0cd19;
}


namespace
{
  inline uint32_t rotate(uint32_t a, uint32_t c)
  {
    return (a >> c) | (a << (32 - c));
  }

  inline uint32_t swap(uint32_t x)
  {
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap32(x);
#endif
#ifdef MSC_VER
    return _byteswap_ulong(x);
#endif

    return (x >> 24) |
          ((x >>  8) & 0x0000FF00) |
          ((x <<  8) & 0x00FF0000) |
           (x << 24);
  }

  // mix functions for processBlock()
  inline uint32_t f1(uint32_t e, uint32_t f, uint32_t g)
  {
    uint32_t term1 = rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25);
    uint32_t term2 = (e & f) ^ (~e & g); //(g ^ (e & (f ^ g)))
    return term1 + term2;
  }

  inline uint32_t f2(uint32_t a, uint32_t b, uint32_t c)
  {
    uint32_t term1 = rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22);
    uint32_t term2 = ((a | b) & c) | (a & b); //(a & (b ^ c)) ^ (b & c);
    return term1 + term2;
  }
}


/// process 64 bytes
void SHA256::processBlock(const void* data)
{
  // get last hash
  uint32_t a = m_hash[0];
  uint32_t b = m_hash[1];
  uint32_t c = m_hash[2];
  uint32_t d = m_hash[3];
  uint32_t e = m_hash[4];
  uint32_t f = m_hash[5];
  uint32_t g = m_hash[6];
  uint32_t h = m_hash[7];

  // data represented as 16x 32-bit words
  const uint32_t* input = (uint32_t*) data;
  // convert to big endian
  uint32_t words[64];
  int i;
  for (i = 0; i < 16; i++)
#if defined(__BYTE_ORDER) && (__BYTE_ORDER != 0) && (__BYTE_ORDER == __BIG_ENDIAN)
    words[i] =      input[i];
#else
    words[i] = swap(input[i]);
#endif

  uint32_t x,y; // temporaries

  // first round
  x = h + f1(e,f,g) + 0x428a2f98 + words[ 0]; y = f2(a,b,c); d += x; h = x + y;
  x = g + f1(d,e,f) + 0x71374491 + words[ 1]; y = f2(h,a,b); c += x; g = x + y;
  x = f + f1(c,d,e) + 0xb5c0fbcf + words[ 2]; y = f2(g,h,a); b += x; f = x + y;
  x = e + f1(b,c,d) + 0xe9b5dba5 + words[ 3]; y = f2(f,g,h); a += x; e = x + y;
  x = d + f1(a,b,c) + 0x3956c25b + words[ 4]; y = f2(e,f,g); h += x; d = x + y;
  x = c + f1(h,a,b) + 0x59f111f1 + words[ 5]; y = f2(d,e,f); g += x; c = x + y;
  x = b + f1(g,h,a) + 0x923f82a4 + words[ 6]; y = f2(c,d,e); f += x; b = x + y;
  x = a + f1(f,g,h) + 0xab1c5ed5 + words[ 7]; y = f2(b,c,d); e += x; a = x + y;

  // secound round
  x = h + f1(e,f,g) + 0xd807aa98 + words[ 8]; y = f2(a,b,c); d += x; h = x + y;
  x = g + f1(d,e,f) + 0x12835b01 + words[ 9]; y = f2(h,a,b); c += x; g = x + y;
  x = f + f1(c,d,e) + 0x243185be + words[10]; y = f2(g,h,a); b += x; f = x + y;
  x = e + f1(b,c,d) + 0x550c7dc3 + words[11]; y = f2(f,g,h); a += x; e = x + y;
  x = d + f1(a,b,c) + 0x72be5d74 + words[12]; y = f2(e,f,g); h += x; d = x + y;
  x = c + f1(h,a,b) + 0x80deb1fe + words[13]; y = f2(d,e,f); g += x; c = x + y;
  x = b + f1(g,h,a) + 0x9bdc06a7 + words[14]; y = f2(c,d,e); f += x; b = x + y;
  x = a + f1(f,g,h) + 0xc19bf174 + words[15]; y = f2(b,c,d); e += x; a = x + y;

  // extend to 24 words
  for (; i < 24; i++)
    words[i] = words[i-16] +
               (rotate(words[i-15],  7) ^ rotate(words[i-15], 18) ^ (words[i-15] >>  3)) +
               words[i-7] +
               (rotate(words[i- 2], 17) ^ rotate(words[i- 2], 19) ^ (words[i- 2] >> 10));

  // third round
  x = h + f1(e,f,g) + 0xe49b69c1 + words[16]; y = f2(a,b,c); d += x; h = x + y;
  x = g + f1(d,e,f) + 0xefbe4786 + words[17]; y = f2(h,a,b); c += x; g = x + y;
  x = f + f1(c,d,e) + 0x0fc19dc6 + words[18]; y = f2(g,h,a); b += x; f = x + y;
  x = e + f1(b,c,d) + 0x240ca1cc + words[19]; y = f2(f,g,h); a += x; e = x + y;
  x = d + f1(a,b,c) + 0x2de92c6f + words[20]; y = f2(e,f,g); h += x; d = x + y;
  x = c + f1(h,a,b) + 0x4a7484aa + words[21]; y = f2(d,e,f); g += x; c = x + y;
  x = b + f1(g,h,a) + 0x5cb0a9dc + words[22]; y = f2(c,d,e); f += x; b = x + y;
  x = a + f1(f,g,h) + 0x76f988da + words[23]; y = f2(b,c,d); e += x; a = x + y;

  // extend to 32 words
  for (; i < 32; i++)
    words[i] = words[i-16] +
               (rotate(words[i-15],  7) ^ rotate(words[i-15], 18) ^ (words[i-15] >>  3)) +
               words[i-7] +
               (rotate(words[i- 2], 17) ^ rotate(words[i- 2], 19) ^ (words[i- 2] >> 10));

  // fourth round
  x = h + f1(e,f,g) + 0x983e5152 + words[24]; y = f2(a,b,c); d += x; h = x + y;
  x = g + f1(d,e,f) + 0xa831c66d + words[25]; y = f2(h,a,b); c += x; g = x + y;
  x = f + f1(c,d,e) + 0xb00327c8 + words[26]; y = f2(g,h,a); b += x; f = x + y;
  x = e + f1(b,c,d) + 0xbf597fc7 + words[27]; y = f2(f,g,h); a += x; e = x + y;
  x = d + f1(a,b,c) + 0xc6e00bf3 + words[28]; y = f2(e,f,g); h += x; d = x + y;
  x = c + f1(h,a,b) + 0xd5a79147 + words[29]; y = f2(d,e,f); g += x; c = x + y;
  x = b + f1(g,h,a) + 0x06ca6351 + words[30]; y = f2(c,d,e); f += x; b = x + y;
  x = a + f1(f,g,h) + 0x14292967 + words[31]; y = f2(b,c,d); e += x; a = x + y;

  // extend to 40 words
  for (; i < 40; i++)
    words[i] = words[i-16] +
               (rotate(words[i-15],  7) ^ rotate(words[i-15], 18) ^ (words[i-15] >>  3)) +
               words[i-7] +
               (rotate(words[i- 2], 17) ^ rotate(words[i- 2], 19) ^ (words[i- 2] >> 10));

  // fifth round
  x = h + f1(e,f,g) + 0x27b70a85 + words[32]; y = f2(a,b,c); d += x; h = x + y;
  x = g + f1(d,e,f) + 0x2e1b2138 + words[33]; y = f2(h,a,b); c += x; g = x + y;
  x = f + f1(c,d,e) + 0x4d2c6dfc + words[34]; y = f2(g,h,a); b += x; f = x + y;
  x = e + f1(b,c,d) + 0x53380d13 + words[35]; y = f2(f,g,h); a += x; e = x + y;
  x = d + f1(a,b,c) + 0x650a7354 + words[36]; y = f2(e,f,g); h += x; d = x + y;
  x = c + f1(h,a,b) + 0x766a0abb + words[37]; y = f2(d,e,f); g += x; c = x + y;
  x = b + f1(g,h,a) + 0x81c2c92e + words[38]; y = f2(c,d,e); f += x; b = x + y;
  x = a + f1(f,g,h) + 0x92722c85 + words[39]; y = f2(b,c,d); e += x; a = x + y;

  // extend to 48 words
  for (; i < 48; i++)
    words[i] = words[i-16] +
               (rotate(words[i-15],  7) ^ rotate(words[i-15], 18) ^ (words[i-15] >>  3)) +
               words[i-7] +
               (rotate(words[i- 2], 17) ^ rotate(words[i- 2], 19) ^ (words[i- 2] >> 10));

  // sixth round
  x = h + f1(e,f,g) + 0xa2bfe8a1 + words[40]; y = f2(a,b,c); d += x; h = x + y;
  x = g + f1(d,e,f) + 0xa81a664b + words[41]; y = f2(h,a,b); c += x; g = x + y;
  x = f + f1(c,d,e) + 0xc24b8b70 + words[42]; y = f2(g,h,a); b += x; f = x + y;
  x = e + f1(b,c,d) + 0xc76c51a3 + words[43]; y = f2(f,g,h); a += x; e = x + y;
  x = d + f1(a,b,c) + 0xd192e819 + words[44]; y = f2(e,f,g); h += x; d = x + y;
  x = c + f1(h,a,b) + 0xd6990624 + words[45]; y = f2(d,e,f); g += x; c = x + y;
  x = b + f1(g,h,a) + 0xf40e3585 + words[46]; y = f2(c,d,e); f += x; b = x + y;
  x = a + f1(f,g,h) + 0x106aa070 + words[47]; y = f2(b,c,d); e += x; a = x + y;

  // extend to 56 words
  for (; i < 56; i++)
    words[i] = words[i-16] +
               (rotate(words[i-15],  7) ^ rotate(words[i-15], 18) ^ (words[i-15] >>  3)) +
               words[i-7] +
               (rotate(words[i- 2], 17) ^ rotate(words[i- 2], 19) ^ (words[i- 2] >> 10));

  // seventh round
  x = h + f1(e,f,g) + 0x19a4c116 + words[48]; y = f2(a,b,c); d += x; h = x + y;
  x = g + f1(d,e,f) + 0x1e376c08 + words[49]; y = f2(h,a,b); c += x; g = x + y;
  x = f + f1(c,d,e) + 0x2748774c + words[50]; y = f2(g,h,a); b += x; f = x + y;
  x = e + f1(b,c,d) + 0x34b0bcb5 + words[51]; y = f2(f,g,h); a += x; e = x + y;
  x = d + f1(a,b,c) + 0x391c0cb3 + words[52]; y = f2(e,f,g); h += x; d = x + y;
  x = c + f1(h,a,b) + 0x4ed8aa4a + words[53]; y = f2(d,e,f); g += x; c = x + y;
  x = b + f1(g,h,a) + 0x5b9cca4f + words[54]; y = f2(c,d,e); f += x; b = x + y;
  x = a + f1(f,g,h) + 0x682e6ff3 + words[55]; y = f2(b,c,d); e += x; a = x + y;

  // extend to 64 words
  for (; i < 64; i++)
    words[i] = words[i-16] +
               (rotate(words[i-15],  7) ^ rotate(words[i-15], 18) ^ (words[i-15] >>  3)) +
               words[i-7] +
               (rotate(words[i- 2], 17) ^ rotate(words[i- 2], 19) ^ (words[i- 2] >> 10));

  // eigth round
  x = h + f1(e,f,g) + 0x748f82ee + words[56]; y = f2(a,b,c); d += x; h = x + y;
  x = g + f1(d,e,f) + 0x78a5636f + words[57]; y = f2(h,a,b); c += x; g = x + y;
  x = f + f1(c,d,e) + 0x84c87814 + words[58]; y = f2(g,h,a); b += x; f = x + y;
  x = e + f1(b,c,d) + 0x8cc70208 + words[59]; y = f2(f,g,h); a += x; e = x + y;
  x = d + f1(a,b,c) + 0x90befffa + words[60]; y = f2(e,f,g); h += x; d = x + y;
  x = c + f1(h,a,b) + 0xa4506ceb + words[61]; y = f2(d,e,f); g += x; c = x + y;
  x = b + f1(g,h,a) + 0xbef9a3f7 + words[62]; y = f2(c,d,e); f += x; b = x + y;
  x = a + f1(f,g,h) + 0xc67178f2 + words[63]; y = f2(b,c,d); e += x; a = x + y;

  // update hash
  m_hash[0] += a;
  m_hash[1] += b;
  m_hash[2] += c;
  m_hash[3] += d;
  m_hash[4] += e;
  m_hash[5] += f;
  m_hash[6] += g;
  m_hash[7] += h;
}


/// add arbitrary number of bytes
void SHA256::add(const void* data, size_t numBytes)
{
  const uint8_t* current = (const uint8_t*) data;

  if (m_bufferSize > 0)
  {
    while (numBytes > 0 && m_bufferSize < BlockSize)
    {
      m_buffer[m_bufferSize++] = *current++;
      numBytes--;
    }
  }

  // full buffer
  if (m_bufferSize == BlockSize)
  {
    processBlock(m_buffer);
    m_numBytes  += BlockSize;
    m_bufferSize = 0;
  }

  // no more data ?
  if (numBytes == 0)
    return;

  // process full blocks
  while (numBytes >= BlockSize)
  {
    processBlock(current);
    current    += BlockSize;
    m_numBytes += BlockSize;
    numBytes   -= BlockSize;
  }

  // keep remaining bytes in buffer
  while (numBytes > 0)
  {
    m_buffer[m_bufferSize++] = *current++;
    numBytes--;
  }
}


/// process final block, less than 64 bytes
void SHA256::processBuffer()
{
  // the input bytes are considered as bits strings, where the first bit is the most significant bit of the byte

  // - append "1" bit to message
  // - append "0" bits until message length in bit mod 512 is 448
  // - append length as 64 bit integer

  // number of bits
  size_t paddedLength = m_bufferSize * 8;

  // plus one bit set to 1 (always appended)
  paddedLength++;

  // number of bits must be (numBits % 512) = 448
  size_t lower11Bits = paddedLength & 511;
  if (lower11Bits <= 448)
    paddedLength +=       448 - lower11Bits;
  else
    paddedLength += 512 + 448 - lower11Bits;
  // convert from bits to bytes
  paddedLength /= 8;

  // only needed if additional data flows over into a second block
  unsigned char extra[BlockSize];

  // append a "1" bit, 128 => binary 10000000
  if (m_bufferSize < BlockSize)
    m_buffer[m_bufferSize] = 128;
  else
    extra[0] = 128;

  size_t i;
  for (i = m_bufferSize + 1; i < BlockSize; i++)
    m_buffer[i] = 0;
  for (; i < paddedLength; i++)
    extra[i - BlockSize] = 0;

  // add message length in bits as 64 bit number
  uint64_t msgBits = 8 * (m_numBytes + m_bufferSize);
  // find right position
  unsigned char* addLength;
  if (paddedLength < BlockSize)
    addLength = m_buffer + paddedLength;
  else
    addLength = extra + paddedLength - BlockSize;

  // must be big endian
  *addLength++ = (unsigned char)((msgBits >> 56) & 0xFF);
  *addLength++ = (unsigned char)((msgBits >> 48) & 0xFF);
  *addLength++ = (unsigned char)((msgBits >> 40) & 0xFF);
  *addLength++ = (unsigned char)((msgBits >> 32) & 0xFF);
  *addLength++ = (unsigned char)((msgBits >> 24) & 0xFF);
  *addLength++ = (unsigned char)((msgBits >> 16) & 0xFF);
  *addLength++ = (unsigned char)((msgBits >>  8) & 0xFF);
  *addLength   = (unsigned char)( msgBits        & 0xFF);

  // process blocks
  processBlock(m_buffer);
  // flowed over into a second block ?
  if (paddedLength > BlockSize)
    processBlock(extra);
}


/// return latest hash as 64 hex characters
std::string SHA256::getHash()
{
  // compute hash (as raw bytes)
  unsigned char rawHash[HashBytes];
  getHash(rawHash);

  // convert to hex string
  std::string result;
  result.reserve(2 * HashBytes);
  for (int i = 0; i < HashBytes; i++)
  {
    static const char dec2hex[16+1] = "0123456789abcdef";
    result += dec2hex[(rawHash[i] >> 4) & 15];
    result += dec2hex[ rawHash[i]       & 15];
  }

  return result;
}


/// return latest hash as bytes
void SHA256::getHash(unsigned char buffer[SHA256::HashBytes])
{
  // save old hash if buffer is partially filled
  uint32_t oldHash[HashValues];
  for (int i = 0; i < HashValues; i++)
    oldHash[i] = m_hash[i];

  // process remaining bytes
  processBuffer();

  unsigned char* current = buffer;
  for (int i = 0; i < HashValues; i++)
  {
    *current++ = (m_hash[i] >> 24) & 0xFF;
    *current++ = (m_hash[i] >> 16) & 0xFF;
    *current++ = (m_hash[i] >>  8) & 0xFF;
    *current++ =  m_hash[i]        & 0xFF;

    // restore old hash
    m_hash[i] = oldHash[i];
  }
}


/// compute SHA256 of a memory block
std::string SHA256::operator()(const void* data, size_t numBytes)
{
  reset();
  add(data, numBytes);
  return getHash();
}


/// compute SHA256 of a string, excluding final zero
std::string SHA256::operator()(const std::string& text)
{
  reset();
  add(text.c_str(), text.size());
  return getHash();
}
// //////////////////////////////////////////////////////////
// sha256.h
// Copyright (c) 2014,2015 Stephan Brumme. All rights reserved.
// see http://create.stephan-brumme.com/disclaimer.html
//

#pragma once

//#include "hash.h"
#include <string>

// define fixed size integer types
#ifdef _MSC_VER
// Windows
typedef unsigned __int8  uint8_t;
typedef unsigned __int32 uint32_t;
typedef unsigned __int64 uint64_t;
#else
// GCC
#include <stdint.h>
#endif


/// compute SHA256 hash
/** Usage:
    SHA256 sha256;
    std::string myHash  = sha256("Hello World");     // std::string
    std::string myHash2 = sha256("How are you", 11); // arbitrary data, 11 bytes

    // or in a streaming fashion:

    SHA256 sha256;
    while (more data available)
      sha256.add(pointer to fresh data, number of new bytes);
    std::string myHash3 = sha256.getHash();
  */
class SHA256 //: public Hash
{
public:
  /// split into 64 byte blocks (=> 512 bits), hash is 32 bytes long
  enum { BlockSize = 512 / 8, HashBytes = 32 };

  /// same as reset()
  SHA256();

  /// compute SHA256 of a memory block
  std::string operator()(const void* data, size_t numBytes);
  /// compute SHA256 of a string, excluding final zero
  std::string operator()(const std::string& text);

  /// add arbitrary number of bytes
  void add(const void* data, size_t numBytes);

  /// return latest hash as 64 hex characters
  std::string getHash();
  /// return latest hash as bytes
  void        getHash(unsigned char buffer[HashBytes]);

  /// restart
  void reset();

private:
  /// process 64 bytes
  void processBlock(const void* data);
  /// process everything left in the internal buffer
  void processBuffer();

  /// size of processed data in bytes
  uint64_t m_numBytes;
  /// valid bytes in m_buffer
  size_t   m_bufferSize;
  /// bytes not processed yet
  uint8_t  m_buffer[BlockSize];

  enum { HashValues = HashBytes / 4 };
  /// hash, stored as integers
  uint32_t m_hash[HashValues];
};

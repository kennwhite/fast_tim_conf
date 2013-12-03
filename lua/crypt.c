#if defined(__APPLE__) && defined(__MACH__)
  #define COMMON_DIGEST_FOR_OPENSSL
  #include <CommonCrypto/CommonDigest.h>
  #include <CommonCrypto/CommonCryptor.h>
#else
  #include <openssl/aes.h>
  #include <openssl/sha.h>
#endif

#include <stdio.h>
#include <lua.h>
    #include <lauxlib.h>
    #include <lualib.h>


void hash(unsigned char *output, const char *input, int length);
int encrypt(unsigned char *buffer, size_t bufferSize, char *data, size_t dataLen, char *key);
int decrypt(unsigned char *buffer, size_t bufferSize, char *data, size_t dataLen, char *key);


static int l_hash(lua_State *L) {
  size_t l;
  const char *str = luaL_checklstring(L, 1, &l);
  unsigned char encr[SHA256_DIGEST_LENGTH];

  hash(encr, str, l);

  luaL_Buffer b;
  luaL_buffinit(L, &b);
  luaL_addlstring(&b, (char *)encr, SHA256_DIGEST_LENGTH);
  luaL_pushresult(&b);

  return 1;
}

int main() {
//  unsigned char encr[SHA256_DIGEST_LENGTH];
//  hash(encr, "I am a thing", 13);
//  printf("hashed: %s\n", encr);
//
//  char keyPtr[kCCKeySizeAES256] = "password";
//  char data[] = "I am data";
//  size_t bufferSize = sizeof(data) + kCCBlockSizeAES128;
//  char buffer[bufferSize];
//
//
//  int result = encrypt(buffer, bufferSize, data, sizeof(data), keyPtr);
//  printf("Encrypt %s \n", buffer, result == kCCSuccess);
//
//  size_t decryptSize = bufferSize;
//  char decryptBuffer[decryptSize];
//
//  result = decrypt(decryptBuffer, decryptSize, buffer, bufferSize, keyPtr);
//  printf("Decrypt %s \n", decryptBuffer, result == kCCSuccess);
//
  return 0;
}

int encrypt(unsigned char *buffer, size_t bufferSize, char *data, size_t dataLen, char *key) {
  size_t outLength = 0;

  int result = CCCrypt(kCCEncrypt, // operation
      kCCAlgorithmAES128, // Algorithm
      kCCOptionPKCS7Padding, // options
      key, // key
      kCCKeySizeAES256, // keylength
      NULL,// iv
      data, // dataIn
      dataLen, // dataInLength,
      buffer, // dataOut
      bufferSize, // dataOutAvailable
      &outLength); // dataOutMoved

  return result;
}

int decrypt(unsigned char *buffer, size_t bufferSize, char *data, size_t dataLen, char *key) {
  size_t outLength = 0;

  int result = CCCrypt(kCCDecrypt, // operation
      kCCAlgorithmAES128, // Algorithm
      kCCOptionPKCS7Padding, // options
      key, // key
      kCCKeySizeAES256, // keylength
      NULL,// iv
      data, // dataIn
      dataLen, // dataInLength,
      buffer, // dataOut
      bufferSize, // dataOutAvailable
      &outLength); // dataOutMoved

  return result;

  //unsigned char indata[AES_BLOCK_SIZE];
  //unsigned char outdata[AES_BLOCK_SIZE];

  //unsigned char ckey[] =  "thiskeyisverybad";
  //unsigned char ivec[] = "dontusethisinput";

  //AES_KEY key;
  //AES_set_encrypt_key(ckey, 128, &key);
  //int num = 0;

  //AES_cfb128_encrypt(indata, outdata, 16, &key, ivec, &num, AES_ENCRYPT);

  //printf(outdata);

}

void hash(unsigned char *output, const char *input, int length) {
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, input, length);
  SHA256_Final(output, &sha256);
}

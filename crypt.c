#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>

void hash(unsigned char *output, const char *input, int length);
int encrypt(unsigned char *buffer, size_t bufferSize, const char *data, size_t dataLen, const char *key);
int decrypt(unsigned char *buffer, size_t bufferSize, const char *data, size_t dataLen, const char *key, size_t *outLen);

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

static int l_encrypt(lua_State *L) {
  size_t keyLen, valLen;

  // Key should be kCCKeySizeAES256
  //const char *key= luaL_checklstring(L, 1, &keyLen);
  const char *key = "01234567890123456789012345678901";
  const char *val= luaL_checklstring(L, 2, &valLen);

  size_t bufferSize = valLen + AES_BLOCK_SIZE;// + kCCBlockSizeAES128;
  unsigned char buffer[bufferSize];


  int result = encrypt((unsigned char *)buffer, bufferSize, val, valLen, key);

  luaL_Buffer b;
  luaL_buffinit(L, &b);
  luaL_addlstring(&b, (char *)buffer, bufferSize);
  luaL_pushresult(&b);

  return 1;
}

static int l_decrypt(lua_State *L) {
  size_t keyLen, dataLen, outLen;
  //const char *key = luaL_checklstring(L, 1, &keyLen);
  const char *key = "01234567890123456789012345678901";
  const char *data = luaL_checklstring(L, 2, &dataLen);

  char decryptBuffer[dataLen];

  int result = decrypt((unsigned char *)decryptBuffer, dataLen, data, dataLen, key, &outLen);

  luaL_Buffer b;
  luaL_buffinit(L, &b);
  luaL_addlstring(&b, decryptBuffer, outLen);
  luaL_pushresult(&b);

  return 1;
}

static const struct luaL_reg crypt[] = {
  {"encrypt", l_encrypt},
  {"decrypt", l_decrypt},
  {"hash", l_hash},
  {NULL, NULL}  /* sentinel */
};

int luaopen_crypt (lua_State *L) {
  luaL_openlib(L, "crypt", crypt, 0);
  return 1;
}

int main() {
  return 0;
}

int encrypt(unsigned char *buffer, size_t bufferSize, const char *data, size_t dataLen, const char *key) {
  size_t outLength = 0;

  EVP_CIPHER_CTX *ctx;
  unsigned char iv[16] = {0};
  int outlen1, outlen2;

  ctx = EVP_CIPHER_CTX_new();

  EVP_EncryptInit(ctx, EVP_aes_256_cbc(), key, iv);
  EVP_EncryptUpdate(ctx, buffer, &outlen1, data, dataLen);
  EVP_EncryptFinal(ctx, buffer + outlen1, &outlen2);
  return 0;
  
  /*
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
  */
  //int result = 0;
  //return result;
}

int decrypt(unsigned char *buffer, size_t bufferSize, const char *data, size_t dataLen, const char *key, size_t *outLen) {
  EVP_CIPHER_CTX *ctx;
  unsigned char iv[16] = {0};
  int outlen1, outlen2;

  ctx = EVP_CIPHER_CTX_new();

  EVP_DecryptInit(ctx, EVP_aes_256_cbc(), NULL, key, iv);
  EVP_DecryptUpdate(ctx, buffer, &outlen1, data, dataLen);
  EVP_DecryptFinal(ctx, buffer + outlen1, &outlen2);
  /*
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
      outLen); // dataOutMoved
  */
  return outlen1 + outlen2;
}

void hash(unsigned char *output, const char *input, int length) {
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, input, length);
  SHA256_Final(output, &sha256);
}

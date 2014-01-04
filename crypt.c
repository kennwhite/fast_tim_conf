#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>

int encrypt_str(unsigned char *buffer, const char *data, size_t dataLen, const char *key, size_t *outLen) {
  EVP_CIPHER_CTX *ctx;
  // TODO Bad
  unsigned char iv[16] = {0};
  int outlen1, outlen2;

  ctx = EVP_CIPHER_CTX_new();

  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
    return 0;
  if (EVP_EncryptUpdate(ctx, buffer, &outlen1, data, dataLen) != 1)
    return 0;
  if (EVP_EncryptFinal_ex(ctx, buffer + outlen1, &outlen2) != 1)
    return 0;

  *outLen = outlen1 + outlen2;
  return 1;
}

int decrypt_str(unsigned char *buffer, const char *data, size_t dataLen, const char *key, size_t *outLen) {
  EVP_CIPHER_CTX *ctx;
  // TODO Bad
  unsigned char iv[16] = {0};
  int outlen1, outlen2;

  if (!(ctx = EVP_CIPHER_CTX_new()))
    return 0;

  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
    return 2;
  if (EVP_DecryptUpdate(ctx, buffer, &outlen1, data, dataLen) != 1)
    return 3;
  if (EVP_DecryptFinal_ex(ctx, buffer + outlen1, &outlen2) != 1)
    return 4;

  *outLen = outlen1 + outlen2;
  return 1;
}

int hash_str(unsigned char *output, const char *input, int length) {
  SHA256_CTX sha256;

  if (SHA256_Init(&sha256) != 1)
    return 0;
  if (SHA256_Update(&sha256, input, length) != 1)
    return 0;
  if (SHA256_Final(output, &sha256) != 1)
    return 0;

  return 1;
}

void convert_from_hex(const char *hexStr, char *result, size_t resultSize) {
  unsigned char *dst = result;
  unsigned char *end = result + resultSize;
  unsigned int u;

  while (dst < end && sscanf(hexStr, "%2x", &u) == 1) {
    *dst++ = u;
    hexStr += 2;
  }
}

void convert_to_hex(char *str, size_t strLen, char *hexStr) {
  unsigned char *start = str;
  unsigned char *end = str + strLen;

  while(start < end) {
    sprintf(hexStr, "%02x", *start);
    start += 1;
    hexStr += 2;
  }
}

static int l_hash(lua_State *L) {
  size_t len;
  const char *str = luaL_checklstring(L, 1, &len);
  unsigned char encr[SHA256_DIGEST_LENGTH];

  if (hash_str(encr, str, len) != 1)
    return luaL_error(L, "Error hashing value");

  size_t hexOutLen = SHA256_DIGEST_LENGTH * 2;
  char hexStr[hexOutLen];

  convert_to_hex(encr, SHA256_DIGEST_LENGTH, hexStr);

  luaL_Buffer b;
  luaL_buffinit(L, &b);
  luaL_addlstring(&b, hexStr, hexOutLen);
  luaL_pushresult(&b);

  return 1;
}

static int l_encrypt(lua_State *L) {
  size_t keyLen, valLen, outLen, bufferSize;

  // TODO Key must be the correct key size
  const char *key = luaL_checklstring(L, 1, &keyLen);
  const char *val = luaL_checklstring(L, 2, &valLen);

  bufferSize = valLen + AES_BLOCK_SIZE;
  unsigned char buffer[bufferSize];

  if (encrypt_str(buffer, val, valLen, key, &outLen) != 1)
    return luaL_error(L, "Error encrypting value");

  size_t hexOutLen = outLen * 2;
  char hexStr[hexOutLen];

  convert_to_hex(buffer, outLen, hexStr);

  luaL_Buffer b;
  luaL_buffinit(L, &b);
  luaL_addlstring(&b, hexStr, hexOutLen);
  luaL_pushresult(&b);

  return 1;
}

static int l_decrypt(lua_State *L) {
  size_t keyLen, dataLen, outLen, hexDataLen;
  const char *key = luaL_checklstring(L, 1, &keyLen);
  const char *hexData = luaL_checklstring(L, 2, &hexDataLen);

  dataLen = hexDataLen/2;
  char data[dataLen];

  convert_from_hex(hexData, data, dataLen);

  char decryptBuffer[dataLen];

  int res = decrypt_str(decryptBuffer, data, dataLen, key, &outLen);
  if (res != 1)
    return luaL_error(L, "Error decrypting value %d, data:%s, dataLen: %d", res, data, dataLen);

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

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>

int encrypt_str(unsigned char *buffer, size_t bufferSize, const char *data, size_t dataLen, const char *key, size_t *outLen) {
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

int decrypt_str(unsigned char *buffer, size_t bufferSize, const char *data, size_t dataLen, const char *key, size_t *outLen) {
  EVP_CIPHER_CTX *ctx;
  // TODO Bad
  unsigned char iv[16] = {0};
  int outlen1, outlen2;

  ctx = EVP_CIPHER_CTX_new();

  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
    return 0;
  if (EVP_DecryptUpdate(ctx, buffer, &outlen1, data, dataLen) != 1)
    return 0;
  if (EVP_DecryptFinal_ex(ctx, buffer + outlen1, &outlen2) != 1)
    return 0;

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

static int l_hash(lua_State *L) {
  size_t len;
  const char *str = luaL_checklstring(L, 1, &len);
  unsigned char encr[SHA256_DIGEST_LENGTH];

  if (hash_str(encr, str, len) != 1)
    return luaL_error(L, "Error hashing value");

  luaL_Buffer b;
  luaL_buffinit(L, &b);
  luaL_addlstring(&b, (char *)encr, SHA256_DIGEST_LENGTH);
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

  if (encrypt_str(buffer, bufferSize, val, valLen, key, &outLen) != 1)
    return luaL_error(L, "Error encrypting value");

  luaL_Buffer b;
  luaL_buffinit(L, &b);
  luaL_addlstring(&b, (char *)buffer, bufferSize);
  luaL_pushresult(&b);

  return 1;
}

static int l_decrypt(lua_State *L) {
  size_t keyLen, dataLen, outLen;
  const char *key = luaL_checklstring(L, 1, &keyLen);
  const char *data = luaL_checklstring(L, 2, &dataLen);

  char decryptBuffer[dataLen];

  if (decrypt_str(decryptBuffer, dataLen, data, dataLen, key, &outLen) != 1)
    return luaL_error(L, "Error decrypting value");

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
  /*
  const char *key = "01234567890123456789012";
  const char *val= "this is a val   ";

  size_t bufferSize = 16 + AES_BLOCK_SIZE;// + kCCBlockSizeAES128;
  unsigned char buffer[bufferSize];


  int result = encrypt(buffer, bufferSize, val, 16, key);
 printf("%s hello\n", buffer);
        BIO_dump_fp(stdout, buffer, bufferSize);

  size_t keyLen, dataLen, outLen;
  //const char *key = luaL_checklstring(L, 1, &keyLen);
  key = "01234567890123456789012";
  const char *data = buffer;

  char decryptBuffer[result];

  decrypt((unsigned char *)decryptBuffer, dataLen, data, bufferSize, key, &outLen);
  printf("%s dec\n", decryptBuffer);
  */

  return 0;
}

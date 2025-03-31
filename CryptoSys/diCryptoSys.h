/* $Id: diCryptoSys.h $ */

/*	For `CryptoSys API`
	Requires:
	- `diCryptoSys.dll` and `diCryptoSys.lib` for Windows (32/64)
	- `libcryptosysapi.so` for i386 Linux,
	- `libcryptosysapi.dylib` for MacOSX.
*/

/* Copyright (C) 2001-24 DI Management Services Pty Limited. 
   All rights reserved. <www.di-mgt.com.au> <www.cryptosys.net>

   Last updated:
   $Date: 2024-01-05 12:53:00 $
   $Version: 6.22.1 $
*/

#ifndef DICRYPTOSYS_H_
#define DICRYPTOSYS_H_ 1

#if (_MSC_VER >= 1800) || (__STDC_VERSION >= 199901L) || defined(__linux__) || defined(__APPLE__) || defined(__MINGW32__)
#include <stdint.h>
#else
/** Default for signed 32-bit integer type if `int32_t` not defined */
typedef int int32_t;
#endif

/*************/
/* CONSTANTS */
/*************/
#define ENCRYPT 1
#define DECRYPT 0
/* Maximum number of bytes in hash digest byte array */
#define API_MAX_HASH_BYTES 64
#define API_SHA1_BYTES     20
#define API_SHA224_BYTES   28
#define API_SHA256_BYTES   32
#define API_SHA384_BYTES   48
#define API_SHA512_BYTES   64
#define API_MD5_BYTES      16
#define API_MD2_BYTES      16
#define API_RMD160_BYTES   20
#define API_ASCON_HASH_BYTES 32
/* Maximum number of hex characters in hash digest */
#define API_MAX_HASH_CHARS (2*API_MAX_HASH_BYTES)
#define API_SHA1_CHARS     (2*API_SHA1_BYTES)
#define API_SHA224_CHARS   (2*API_SHA224_BYTES)
#define API_SHA256_CHARS   (2*API_SHA256_BYTES)
#define API_SHA384_CHARS   (2*API_SHA384_BYTES)
#define API_SHA512_CHARS   (2*API_SHA512_BYTES)
#define API_MD5_CHARS      (2*API_MD5_BYTES)
#define API_MD2_CHARS      (2*API_MD2_BYTES)
#define API_RMD160_CHARS   (2*API_RMD160_BYTES)
#define API_ASCON_HASH_CHARS  (2*API_ASCON_HASH_BYTES)
/* Maximum lengths of MAC tags */
#define API_MAX_MAC_BYTES  64
#define API_MAX_HMAC_BYTES 64
#define API_MAX_CMAC_BYTES 16
#define API_MAX_GMAC_BYTES 16	/* Added [v4.2] */
#define API_POLY1305_BYTES 16	/* Added [v5.0] */
#define API_AEAD_TAG_MAX_BYTES 16 /* Added [v5.1] */
#define API_MAX_MAC_CHARS  (2*API_MAX_MAC_BYTES)
#define API_MAX_HMAC_CHARS (2*API_MAX_HMAC_BYTES)
#define API_MAX_CMAC_CHARS (2*API_MAX_CMAC_BYTES)
#define API_MAX_GMAC_CHARS (2*API_MAX_GMAC_BYTES)
#define API_POLY1305_CHARS (2*API_POLY1305_BYTES)
/* Synonyms retained for backwards compatibility */
#define API_MAX_SHA1_BYTES 20
#define API_MAX_SHA2_BYTES 32
#define API_MAX_MD5_BYTES  16
#define API_MAX_SHA1_CHARS (2*API_MAX_SHA1_BYTES)
#define API_MAX_SHA2_CHARS (2*API_MAX_SHA2_BYTES)
#define API_MAX_MD5_CHARS  (2*API_MAX_MD5_BYTES)
/* Encryption block sizes in bytes */
#define API_BLK_DES_BYTES  8
#define API_BLK_TDEA_BYTES 8
#define API_BLK_BLF_BYTES  8
#define API_BLK_AES_BYTES  16
/* Key size in bytes */
#define API_KEYSIZE_TDEA_BYTES     24
#define API_KEYSIZE_AES_MAX_BYTES  32
/* Required size for RNG seed file */
#define API_RNG_SEED_BYTES 128  /* Increased from 64 in [v6.22] */
/* Maximum number of characters in an error lookup message */
#define API_MAX_ERRORLOOKUP_CHARS 127

/***********/
/* OPTIONS */
/***********/
/* Options for HASH functions */
#define API_HASH_SHA1     0
#define API_HASH_MD5      1
#define API_HASH_MD2      2
#define API_HASH_SHA256   3
#define API_HASH_SHA384   4
#define API_HASH_SHA512   5
#define API_HASH_SHA224   6
#define API_HASH_RMD160   7
// --8 Reserved
// --9 Reserved
#define API_HASH_SHA3_224 0xA
#define API_HASH_SHA3_256 0xB
#define API_HASH_SHA3_384 0xC
#define API_HASH_SHA3_512 0xD
/* Added [v6.21] */
#define API_HASH_ASCON_HASH  0xAF
#define API_HASH_ASCON_HASHA 0xBF
#define API_HASH_MODE_TEXT 0x10000L

/* HMAC algorithms */
/* Added [v5.2] as convenient synonyms */
#define API_HMAC_SHA1     0
#define API_HMAC_SHA224   6
#define API_HMAC_SHA256   3
#define API_HMAC_SHA384   4
#define API_HMAC_SHA512   5
#define API_HMAC_SHA3_224 0xA
#define API_HMAC_SHA3_256 0xB
#define API_HMAC_SHA3_384 0xC
#define API_HMAC_SHA3_512 0xD

/* Options for MAC/XOF/PRF functions */
#define API_CMAC_TDEA     0x100	/* ) synonyms */
#define API_CMAC_DESEDE   0x100	/* ) synonyms */
#define API_CMAC_AES128   0x101
#define API_CMAC_AES192   0x102
#define API_CMAC_AES256   0x103
#define API_MAC_POLY1305  0x200
/* Added [v5.3] */
#define API_KMAC_128      0x201
#define API_KMAC_256      0x202
#define API_XOF_SHAKE128  0x203
#define API_XOF_SHAKE256  0x204
/* Added [v6.21] */
#define API_XOF_MGF1_SHA1   0x210
#define API_XOF_MGF1_SHA256 0x213
#define API_XOF_MGF1_SHA512 0x215
#define API_XOF_ASCON_XOF   0x20A
#define API_XOF_ASCON_XOFA  0x20B

/* Options for RNG functions */
#define API_RNG_STRENGTH_112  0x00L
#define API_RNG_STRENGTH_128  0x01L
#define API_RNG_STRENGTH_192  0x02L  // Added [v6.22]
#define API_RNG_STRENGTH_256  0x03L  // Added [v6.22]
#define API_RNG_NO_INTEL_DRNG    0x80000L  // Added [v6.22.1]

/* Block cipher (BC) algorithm options */
#define API_BC_TDEA     0x10L	// )
#define API_BC_3DES     0x10L	// ) equiv. synonyms for Triple DES
#define API_BC_DESEDE3  0x10L	// )
#define API_BC_AES128   0x20L
#define API_BC_AES192   0x30L
#define API_BC_AES256   0x40L

/* Block cipher mode options */
#define API_MODE_ECB  0x000L
#define API_MODE_CBC  0x100L
#define API_MODE_OFB  0x200L
#define API_MODE_CFB  0x300L
#define API_MODE_CTR  0x400L

/* Block cipher padding options */
#define API_PAD_DEFAULT 0x0
#define API_PAD_NOPAD  0x10000
#define API_PAD_PKCS5  0x20000
#define API_PAD_1ZERO  0x30000
#define API_PAD_AX923  0x40000
#define API_PAD_W3C    0x50000

/* Block cipher option flags */
#define API_IV_PREFIX 0x1000
#define API_PAD_LEAVE 0x2000

/* Stream cipher (SC) algorithm options (NB no zero default) */
#define API_SC_ARCFOUR  1
#define API_SC_SALSA20  2
#define API_SC_CHACHA20 3

/* AEAD algorithm options - added [v5.1] */
#define API_AEAD_AES_128_GCM       1
#define API_AEAD_AES_256_GCM       2
#define API_AEAD_CHACHA20_POLY1305 0x1d
/* Ascon aead added [v6.21] */
#define API_AEAD_ASCON_128  0x1A
#define API_AEAD_ASCON_128A 0x1B

/* Wipefile options - added [v5.3] */
#define API_WIPEFILE_DOD7    0x0	/* Default */
#define API_WIPEFILE_SIMPLE  0x1

/* Compression algorithm options - added [v6.20] */
#define API_COMPR_ZLIB	0x0	/* Default */
#define API_COMPR_ZSTD	0x1

/* General */
#define API_GEN_PLATFORM 0x40    

/*************/
/* FUNCTIONS */
/*************/
/* __stdcall convention required for Win32 DLL only */
#if __APPLE__
#define __stdcall __attribute__ ((visibility ("default")))
#elif (!( defined(_WIN32) || defined(WIN32) ))
#define __stdcall
#endif	

#ifdef __cplusplus
extern "C" {
#endif

/* GENERAL FUNCTIONS */
long __stdcall API_Version(void);
long __stdcall API_ErrorLookup(char *szOutput, long nMaxChars, long nErrCode);
long __stdcall API_CompileTime(char *szOutput, long nMaxChars);
long __stdcall API_ModuleName(char *szOutput, long nMaxChars, long nOptions);
long __stdcall API_PowerUpTests(long nOptions);
long __stdcall API_LicenceType(long nOptions);
long __stdcall API_ErrorCode(void);
/* New in [v6.21] */
long __stdcall API_Platform(char *szOutput, long nOutChars);
long __stdcall API_ModuleInfo(char *szOutput, long nOutChars, long nOptions);

/* AES-128 PROTOTYPES */
long __stdcall AES128_Bytes(unsigned char *lpOutput, const unsigned char *lpInput, long nBytes, const unsigned char *lpKey, int fEncrypt);
long __stdcall AES128_BytesMode(unsigned char *lpOutput, const unsigned char *lpInput, long nBytes, const unsigned char *lpKey, int fEncrypt, const char *szMode, const unsigned char *lpIV);
long __stdcall AES128_Hex(char *szOutput, const char *szInput, const char *szKey, int fEncrypt);
long __stdcall AES128_HexMode(char *szOutput, const char *szInput, const char *szKey, int fEncrypt, const char *szMode, const char *szIV);
long __stdcall AES128_B64Mode(char *szOutput, const char *szInput, const char *szKey, int fEncrypt, const char *szMode, const char *szIV);
long __stdcall AES128_File(const char *szFileOut, const char *szFileIn, const unsigned char *lpKey, int fEncrypt, const char *szMode, const unsigned char *lpIV);
long __stdcall AES128_FileExt(const char *szFileOut, const char *szFileIn, const unsigned char *lpKey, int fEncrypt, const char *szMode, const unsigned char *lpIV, long nOptions);
long __stdcall AES128_FileHex(const char *szFileOut, const char *szFileIn, const char *szKey, int fEncrypt, const char *szMode, const char *szIV);
long __stdcall AES128_Init(const unsigned char *lpKey, int fEncrypt, const char *szMode, const unsigned char *lpIV);
long __stdcall AES128_InitHex(const char *szKey, int fEncrypt, const char *szMode, const char *szIV);
long __stdcall AES128_Update(long hContext, unsigned char *lpData, long nDataLen);
long __stdcall AES128_UpdateHex(long hContext, char *szHexData);
long __stdcall AES128_Final(long hContext);
long __stdcall AES128_InitError(void);

/* AES-192 PROTOTYPES */
long __stdcall AES192_Bytes(unsigned char *lpOutput, const unsigned char *lpInput, long nBytes, const unsigned char *lpKey, int fEncrypt);
long __stdcall AES192_BytesMode(unsigned char *lpOutput, const unsigned char *lpInput, long nBytes, const unsigned char *lpKey, int fEncrypt, const char *szMode, const unsigned char *lpIV);
long __stdcall AES192_Hex(char *szOutput, const char *szInput, const char *szKey, int fEncrypt);
long __stdcall AES192_HexMode(char *szOutput, const char *szInput, const char *szKey, int fEncrypt, const char *szMode, const char *szIV);
long __stdcall AES192_B64Mode(char *szOutput, const char *szInput, const char *szKey, int fEncrypt, const char *szMode, const char *szIV);
long __stdcall AES192_File(const char *szFileOut, const char *szFileIn, const unsigned char *lpKey, int fEncrypt, const char *szMode, const unsigned char *lpIV);
long __stdcall AES192_FileExt(const char *szFileOut, const char *szFileIn, const unsigned char *lpKey, int fEncrypt, const char *szMode, const unsigned char *lpIV, long nOptions);
long __stdcall AES192_FileHex(const char *szFileOut, const char *szFileIn, const char *szKey, int fEncrypt, const char *szMode, const char *szIV);
long __stdcall AES192_Init(const unsigned char *lpKey, int fEncrypt, const char *szMode, const unsigned char *lpIV);
long __stdcall AES192_InitHex(const char *szKey, int fEncrypt, const char *szMode, const char *szIV);
long __stdcall AES192_Update(long hContext, unsigned char *lpData, long nDataLen);
long __stdcall AES192_UpdateHex(long hContext, char *szHexData);
long __stdcall AES192_Final(long hContext);
long __stdcall AES192_InitError(void);

/* AES-256 PROTOTYPES */
long __stdcall AES256_Bytes(unsigned char *lpOutput, const unsigned char *lpInput, long nBytes, const unsigned char *lpKey, int fEncrypt); 
long __stdcall AES256_BytesMode(unsigned char *lpOutput, const unsigned char *lpInput, long nBytes, const unsigned char *lpKey, int fEncrypt, const char *szMode, const unsigned char *lpIV);
long __stdcall AES256_Hex(char *szOutput, const char *szInput, const char *szKey, int fEncrypt);
long __stdcall AES256_HexMode(char *szOutput, const char *szInput, const char *szKey, int fEncrypt, const char *szMode, const char *szIV);
long __stdcall AES256_B64Mode(char *szOutput, const char *szInput, const char *szKey, int fEncrypt, const char *szMode, const char *szIV);
long __stdcall AES256_File(const char *szFileOut, const char *szFileIn, const unsigned char *lpKey, int fEncrypt, const char *szMode, const unsigned char *lpIV);
long __stdcall AES256_FileExt(const char *szFileOut, const char *szFileIn, const unsigned char *lpKey, int fEncrypt, const char *szMode, const unsigned char *lpIV, long nOptions);
long __stdcall AES256_FileHex(const char *szFileOut, const char *szFileIn, const char *szKey, int fEncrypt, const char *szMode, const char *szIV);
long __stdcall AES256_Init(const unsigned char *lpKey, int fEncrypt, const char *szMode, const unsigned char *lpIV);
long __stdcall AES256_InitHex(const char *szKey, int fEncrypt, const char *szMode, const char *szIV);
long __stdcall AES256_Update(long hContext, unsigned char *lpData, long nDataLen);
long __stdcall AES256_UpdateHex(long hContext, char *szHexData);
long __stdcall AES256_Final(long hContext);
long __stdcall AES256_InitError(void);

/* BLOWFISH PROTOTYPES */
long __stdcall BLF_Bytes(unsigned char *lpOutput, const unsigned char *lpInput, long nBytes, const unsigned char *lpKey, long keyBytes, int fEncrypt);
long __stdcall BLF_BytesMode(unsigned char *lpOutput, const unsigned char *lpInput, long nBytes, const unsigned char *lpKey, long keyBytes, int fEncrypt, const char *szMode, const unsigned char *lpIV);
long __stdcall BLF_Hex(char *szOutput, const char *szInput, const char *szKey, int fEncrypt);
long __stdcall BLF_HexMode(char *szOutput, const char *szInput, const char *szKey, int fEncrypt, const char *szMode, const char *szIV);
long __stdcall BLF_B64Mode(char *szOutput, const char *szInput, const char *szKey, int fEncrypt, const char *szMode, const char *szIV);
long __stdcall BLF_File(const char *szFileOut, const char *szFileIn, const unsigned char *lpKey, long keyBytes, int fEncrypt, const char *szMode, const unsigned char *lpIV);
long __stdcall BLF_FileExt(const char *szFileOut, const char *szFileIn, const unsigned char *lpKey, long keyBytes, int fEncrypt, const char *szMode, const unsigned char *lpIV, long nOptions);
long __stdcall BLF_FileHex(const char *szFileOut, const char *szFileIn, const char *szKey, int fEncrypt, const char *szMode, const char *sHexIV);
long __stdcall BLF_Init(const unsigned char *lpKey, long keyBytes, int fEncrypt, const char *szMode, const unsigned char *lpIV);
long __stdcall BLF_InitHex(const char *szKey, int fEncrypt, const char *szMode, const char *sHexIV);
long __stdcall BLF_Update(long hContext, unsigned char *lpData, long nDataLen);
long __stdcall BLF_UpdateHex(long hContext, char *szHexData);
long __stdcall BLF_Final(long hContext);
long __stdcall BLF_InitError(void);

/* DES PROTOTYPES */
long __stdcall DES_Bytes(unsigned char *lpOutput, const unsigned char *lpInput, long nBytes, const unsigned char *lpKey, int fEncrypt);
long __stdcall DES_BytesMode(unsigned char *lpOutput, const unsigned char *lpInput, long nBytes, const unsigned char *lpKey, int fEncrypt, const char *szMode, const unsigned char *lpIV);
long __stdcall DES_Hex(char *szOutput, const char *szInput, const char *szKey, int fEncrypt);
long __stdcall DES_HexMode(char *szOutput, const char *szInput, const char *szKey, int fEncrypt, const char *szMode, const char *szIV);
long __stdcall DES_B64Mode(char *szOutput, const char *szInput, const char *szKey, int fEncrypt, const char *szMode, const char *szIV);
long __stdcall DES_File(const char *szFileOut, const char *szFileIn, const unsigned char *lpKey, int fEncrypt, const char *szMode, const unsigned char *lpIV);
long __stdcall DES_FileExt(const char *szFileOut, const char *szFileIn, const unsigned char *lpKey, int fEncrypt, const char *szMode, const unsigned char *lpIV, long nOptions);
long __stdcall DES_FileHex(const char *szFileOut, const char *szFileIn, const char *szKey, int fEncrypt, const char *szMode, const char *szIV);
long __stdcall DES_Init(const unsigned char *lpKey, int fEncrypt, const char *szMode, const unsigned char *lpIV);
long __stdcall DES_InitHex(const char *szKey, int fEncrypt, const char *szMode, const char *szIV);
long __stdcall DES_Update(long hContext, unsigned char *lpData, long nDataLen);
long __stdcall DES_UpdateHex(long hContext, char *szHexData);
long __stdcall DES_Final(long hContext);
long __stdcall DES_InitError(void);
long __stdcall DES_CheckKey(const unsigned char *lpKey, long nKeyLen);
long __stdcall DES_CheckKeyHex(const char *szHexKey);

/* TRIPLE DES PROTOTYPES */
long __stdcall TDEA_Bytes(unsigned char *lpOutput, const unsigned char *lpInput, long nBytes, const unsigned char *lpKey, int fEncrypt);
long __stdcall TDEA_BytesMode(unsigned char *lpOutput, const unsigned char *lpInput, long nBytes, const unsigned char *lpKey, int fEncrypt, const char *szMode, const unsigned char *lpIV);
long __stdcall TDEA_Hex(char *szOutput, const char *szInput, const char *szKey, int fEncrypt);
long __stdcall TDEA_HexMode(char *szOutput, const char *szInput, const char *szKey, int fEncrypt, const char *szMode, const char *szIV);
long __stdcall TDEA_B64Mode(char *szOutput, const char *szInput, const char *szKey, int fEncrypt, const char *szMode, const char *szIV);
long __stdcall TDEA_File(const char *szFileOut, const char *szFileIn, const unsigned char *lpKey, int fEncrypt, const char *szMode, const unsigned char *lpIV);
long __stdcall TDEA_FileExt(const char *szFileOut, const char *szFileIn, const unsigned char *lpKey, int fEncrypt, const char *szMode, const unsigned char *lpIV, long nOptions);
long __stdcall TDEA_FileHex(const char *szFileOut, const char *szFileIn, const char *szKey, int fEncrypt, const char *szMode, const char *szIV);
long __stdcall TDEA_Init(const unsigned char *lpKey, int fEncrypt, const char *szMode, const unsigned char *lpIV);
long __stdcall TDEA_InitHex(const char *szKey, int fEncrypt, const char *szMode, const char *szIV);
long __stdcall TDEA_Update(long hContext, unsigned char *lpData, long nDataLen);
long __stdcall TDEA_UpdateHex(long hContext, char *szHexData);
long __stdcall TDEA_Final(long hContext);
long __stdcall TDEA_InitError(void);

/* KEY WRAP FUNCTIONS */
long __stdcall CIPHER_KeyWrap(unsigned char *lpOutput, long nOutBytes, const unsigned char *lpData, long nDataLen, const unsigned char *lpKEK, long nKekLen, long nOptions);
long __stdcall CIPHER_KeyUnwrap(unsigned char *lpOutput, long nOutBytes, const unsigned char *lpData, long nDataLen, const unsigned char *lpKEK, long nKekLen, long nOptions);

/* GENERIC BLOCK CIPHER FUNCTIONS */
/* Changed in [v6.20]: Renamed ~Bytes2 to ~Bytes */
long __stdcall CIPHER_EncryptBytes(unsigned char *lpOutput, long nOutBytes, const unsigned char *lpInput, long nInputLen, const unsigned char *lpKey, long nKeyLen, const unsigned char *lpIV, long nIvLen, const char *szAlgModePad, long nOptions);
long __stdcall CIPHER_DecryptBytes(unsigned char *lpOutput, long nOutBytes, const unsigned char *lpInput, long nInputLen, const unsigned char *lpKey, long nKeyLen, const unsigned char *lpIV, long nIvLen, const char *szAlgModePad, long nOptions);
/* Keep old ~Bytes2 for backwards compatibility [deprecated] */
long __stdcall CIPHER_EncryptBytes2(unsigned char *lpOutput, long nOutBytes, const unsigned char *lpInput, long nInputLen, const unsigned char *lpKey, long nKeyLen, const unsigned char *lpIV, long nIvLen, const char *szAlgModePad, long nOptions);
long __stdcall CIPHER_DecryptBytes2(unsigned char *lpOutput, long nOutBytes, const unsigned char *lpInput, long nInputLen, const unsigned char *lpKey, long nKeyLen, const unsigned char *lpIV, long nIvLen, const char *szAlgModePad, long nOptions);
long __stdcall CIPHER_FileEncrypt(const char *szFileOut, const char *szFileIn, const unsigned char *lpKey, long nKeyLen, const unsigned char *lpIV, long nIvLen, const char *szAlgModePad, long nOptions);
long __stdcall CIPHER_FileDecrypt(const char *szFileOut, const char *szFileIn, const unsigned char *lpKey, long nKeyLen, const unsigned char *lpIV, long nIvLen, const char *szAlgModePad, long nOptions);
/* New in [v6.0] */
long __stdcall CIPHER_EncryptHex(char *szOutput, long nOutChars, const char *szInputHex, const char *szKeyHex, const char *szIvHex, const char *szAlgModePad, long nOptions);
long __stdcall CIPHER_DecryptHex(char *szOutput, long nOutChars, const char *szInputHex, const char *szKeyHex, const char *szIvHex, const char *szAlgModePad, long nOptions);
/* Stateful CIPHER functions added in [v6.0] */
long __stdcall CIPHER_Init(int fEncrypt, const char *szAlgAndMode, const unsigned char *lpKey, long nKeyLen, const unsigned char *lpIV, long nIvLen, long nOptions);
long __stdcall CIPHER_InitHex(int fEncrypt, const char *szAlgAndMode, const char *szKeyHex, const char *szIvHex, long nOptions);
long __stdcall CIPHER_Update(long hContext, unsigned char *lpOutput, long nOutBytes, const unsigned char *lpData, long nDataLen);
long __stdcall CIPHER_UpdateHex(long hContext, char *szOutput, long nOutChars, const char *szDataHex);
long __stdcall CIPHER_Final(long hContext);

/* STREAM CIPHER FUNCTIONS */
// New in [v5.0]
long __stdcall CIPHER_StreamBytes(unsigned char *lpOutput, const unsigned char *lpData, long nDataLen, const unsigned char *lpKey, long nKeyLen, const unsigned char *lpIV, long nIvLen, long nCounter, long nOptions);
long __stdcall CIPHER_StreamHex(char *szOutput, long nOutChars, const char *szInputHex, const char *szKeyHex, const char *szIvHex, long nCounter, long nOptions);
long __stdcall CIPHER_StreamFile(const char *szFileOut, const char *szFileIn, const unsigned char *lpKey, long nKeyLen, const unsigned char *lpIV, long nIvLen, long nCounter, long nOptions);
long __stdcall CIPHER_StreamInit(const unsigned char *lpKey, long nKeyLen, const unsigned char *lpIV, long nIvLen, long nCounter, long nOptions);
long __stdcall CIPHER_StreamUpdate(long hContext, unsigned char *lpOutput, const unsigned char *lpData, long nDataLen);
long __stdcall CIPHER_StreamFinal(long hContext); 

/* RC4-COMPATIBLE PC1 PROTOTYPES */
// Superseded by CIPHER_Stream functions in [v5.0]
long __stdcall PC1_Bytes(unsigned char *lpOutput, unsigned char *lpInput, long nBytes, unsigned char *lpKey, long nKeyBytes);
long __stdcall PC1_File(char *szFileOut, char *szFileIn, unsigned char *lpKey, long nKeyBytes);
long __stdcall PC1_Hex(char *szOutput, long nMaxChars, const char *szInputHex, const char *szKeyHex);

/* GCM AUTHENTICATED EN/DECRYPTION FUNCTIONS */
// Partly superseded by AEAD functions in [v5.1]
long __stdcall GCM_Encrypt(unsigned char *lpOutput, long nOutLen, unsigned char *lpTagOut, long nTagLen, const unsigned char *lpData, long nDataLen, const unsigned char *lpKey, long nKeyLen, const unsigned char *lpIV, long nIvLen, const unsigned char *lpAAD, long nAadLen, long nOptions);
long __stdcall GCM_Decrypt(unsigned char *lpOutput, long nOutLen, const unsigned char *lpData, long nDataLen, const unsigned char *lpKey, long nKeyLen, const unsigned char *lpIV, long nIvLen, const unsigned char *lpAAD, long nAadLen, const unsigned char *lpTag, long nTagLen, long nOptions);
long __stdcall GCM_InitKey(const unsigned char *lpKey, long nKeyLen, long nOptions);
long __stdcall GCM_NextEncrypt(long hContext, unsigned char *lpOutput, long nOutLen, unsigned char *lpTagOut, long nTagLen, const unsigned char *lpData, long nDataLen, const unsigned char *lpIV, long nIvLen, const unsigned char *lpAAD, long nAadLen);
long __stdcall GCM_NextDecrypt(long hContext, unsigned char *lpOutput, long nOutLen, const unsigned char *lpData, long nDataLen, const unsigned char *lpIV, long nIvLen, const unsigned char *lpAAD, long nAadLen, const unsigned char *lpTag, long nTagLen);
long __stdcall GCM_FinishKey(long hContext);

/* AEAD FUNCTIONS */
long __stdcall AEAD_Encrypt(unsigned char *lpOutput, long nOutLen, unsigned char *lpTagOut, long nTagLen, const unsigned char *lpData, long nDataLen, const unsigned char *lpKey, long nKeyLen,const unsigned char *lpNonce, long nNonceLen, const unsigned char *lpAAD, long nAadLen, long nOptions);
long __stdcall AEAD_Decrypt(unsigned char *lpOutput, long nOutLen, const unsigned char *lpData, long nDataLen, const unsigned char *lpKey, long nKeyLen, const unsigned char *lpNonce, long nNonceLen,const unsigned char *lpAAD, long nAadLen, const unsigned char *lpTag, long nTagLen, long nOptions);
long __stdcall AEAD_InitKey(const unsigned char *lpKey, long nKeyLen, long nOptions);
long __stdcall AEAD_SetNonce(long hContext, const unsigned char *lpNonce, long nNonceLen);
long __stdcall AEAD_AddAAD(long hContext, const unsigned char *lpAAD, long nAadLen);
long __stdcall AEAD_StartEncrypt(long hContext);
long __stdcall AEAD_StartDecrypt(long hContext, const unsigned char *lpTagToCheck, long nTagLen);
long __stdcall AEAD_Update(long hContext, unsigned char *lpOutput, long nOutLen, const unsigned char *lpData, long nDataLen);
long __stdcall AEAD_FinishEncrypt(long hContext, unsigned char *lpTagOut, long nTagLen);
long __stdcall AEAD_FinishDecrypt(long hContext);
long __stdcall AEAD_Destroy(long hContext);
// Added in [v5.4]
long __stdcall AEAD_EncryptWithTag(unsigned char *lpOutput, long nOutLen, const unsigned char *lpData, long nDataLen, const unsigned char *lpKey, long nKeyLen, const unsigned char *lpNonce, long nNonceLen, const unsigned char *lpAAD, long nAadLen, long nOptions);
long __stdcall AEAD_DecryptWithTag(unsigned char *lpOutput, long nOutLen, const unsigned char *lpData, long nDataLen, const unsigned char *lpKey, long nKeyLen, const unsigned char *lpNonce, long nNonceLen, const unsigned char *lpAAD, long nAadLen, long nOptions);

/* GENERIC MESSAGE DIGEST HASH FUNCTIONS */
long __stdcall HASH_Bytes(unsigned char *lpOutput, long nOutLen, const void *lpMessage, long nMsgLen, long nOptions);
long __stdcall HASH_File(unsigned char *lpOutput, long nOutLen, const char *szFileName, long nOptions);
long __stdcall HASH_HexFromBytes(char *szOutput, long nMaxChars, const void *lpMessage, long nMsgLen, long nOptions);
long __stdcall HASH_HexFromFile(char *szOutput, long nMaxChars, const char *szFileName, long nOptions);
long __stdcall HASH_HexFromHex(char *szOutput, long nMaxChars, const char *szMsgHex, long nOptions);
long __stdcall HASH_HexFromBits(char *szOutput, long nMaxChars, const unsigned char *lpData, long nDataBitLen, long nOptions);
long __stdcall HASH_Length(long nAlgId);  /* New in [v6.21] */

/* Stateful HASH functions added in [v6.0] */
long __stdcall HASH_Init(long nAlg);
long __stdcall HASH_AddBytes(long hContext, const void *lpData, long nDataLen);
long __stdcall HASH_Final(unsigned char *lpOutput, long nOutLen, long hContext);
long __stdcall HASH_DigestLength(long hContext);
long __stdcall HASH_Reset(long hContext);

/* GENERIC MAC FUNCTIONS (HMAC, CMAC, KMAC) */
long __stdcall MAC_Bytes(unsigned char *lpOutput, long nOutLen, const void *lpMessage, long nMsgLen, const void *lpKey, long nKeyLen, long nOptions);
long __stdcall MAC_HexFromBytes(char *szOutput, long nMaxChars, const void *lpMessage, long nMsgLen, const void *lpKey, long nKeyLen, long nOptions);
long __stdcall MAC_HexFromHex(char *szOutput, long nMaxChars, const char *szMsgHex, const char *szKeyHex, long nOptions);
/* Stateful MAC functions added in [v6.0] (HMAC only) */
long __stdcall MAC_Init(const void *lpKey, long nKeyLen, long nAlg);
long __stdcall MAC_AddBytes(long hContext, const void *lpMessage, long nMsgLen);
long __stdcall MAC_Final(unsigned char *lpOutput, long nOutLen, long hContext);
long __stdcall MAC_CodeLength(long hContext);
long __stdcall MAC_Reset(long hContext);

/* SHA-1 PROTOTYPES */
long __stdcall SHA1_StringHexHash(char *szDigest, const char *szMessage);
long __stdcall SHA1_FileHexHash(char *szDigest, const char *szFileName, const char *szMode);
long __stdcall SHA1_BytesHexHash(char *szDigest, const unsigned char *lpData, long nDataLen);
long __stdcall SHA1_BytesHash(unsigned char *digest, const unsigned char *lpData, long nDataLen);
long __stdcall SHA1_Init(void);
long __stdcall SHA1_AddString(long hContext, const char *szMessage);
long __stdcall SHA1_AddBytes(long hContext, const unsigned char *lpData, long nDataLen);
long __stdcall SHA1_HexDigest(char *szDigest, long hContext);
long __stdcall SHA1_Reset(long hContext);
long __stdcall SHA1_Hmac(char *szDigest, const unsigned char *textBytes, long textLen, const unsigned char *lpKeyBytes, long keyLen);
long __stdcall SHA1_HmacHex(char *szDigest, const char *sHexText, const char *sHexKey);

/* SHA-256 PROTOTYPES */
long __stdcall SHA2_StringHexHash(char *szDigest, const char *szMessage);
long __stdcall SHA2_FileHexHash(char *szDigest, const char *szFileName, const char *szMode);
long __stdcall SHA2_BytesHexHash(char *szDigest, const unsigned char *lpData, long nDataLen);
long __stdcall SHA2_BytesHash(unsigned char *lpDigest, const unsigned char *lpData, long nDataLen);
long __stdcall SHA2_Init(void);
long __stdcall SHA2_AddString(long hContext, const char *szMessage);
long __stdcall SHA2_AddBytes(long hContext, const unsigned char *lpData, long nDataLen);
long __stdcall SHA2_HexDigest(char *szDigest, long hContext);
long __stdcall SHA2_Reset(long hContext);
long __stdcall SHA2_Hmac(char *szDigest, const unsigned char *textBytes, long textLen, const unsigned char *lpKeyBytes, long keyLen);
long __stdcall SHA2_HmacHex(char *szDigest, const char *sHexText, const char *sHexKey);

/* SHA-3 PROTOTYPES */
/* New stateful functions in [v5.3]. For stateless functions like _BytesHexHash, etc, use HASH_ or MAC_ */
long __stdcall SHA3_Init(long nHashBitLen);
long __stdcall SHA3_AddString(long hContext, const char *szMessage);
long __stdcall SHA3_AddBytes(long hContext, const unsigned char *lpData, long nDataLen);
long __stdcall SHA3_HexDigest(char *szOutput, long nMaxChars, long hContext);
long __stdcall SHA3_LengthInBytes(long hContext);
long __stdcall SHA3_Reset(long hContext);

/* MD5 PROTOTYPES */
long __stdcall MD5_StringHexHash(char *szDigest, const char *szMessage);
long __stdcall MD5_FileHexHash(char *szDigest, const char *szFileName, const char *szMode);
long __stdcall MD5_BytesHexHash(char *szDigest, const unsigned char *lpData, long nDataLen);
long __stdcall MD5_BytesHash(unsigned char *digest, const unsigned char *lpData, long nDataLen);
long __stdcall MD5_Init(void);
long __stdcall MD5_AddString(long hContext, const char *szMessage);
long __stdcall MD5_AddBytes(long hContext, const unsigned char *lpData, long nDataLen);
long __stdcall MD5_HexDigest(char *szDigest, long hContext);
long __stdcall MD5_Reset(long hContext);
long __stdcall MD5_Hmac(char *szDigest, const unsigned char *textBytes, long textLen, const unsigned char *lpKeyBytes, long keyLen);
long __stdcall MD5_HmacHex(char *szDigest, const char *szHexText, const char *szHexKey);

/* RNG PROTOTYPES */
long __stdcall RNG_KeyBytes(unsigned char *lpOutput, long nOutputLen, const void *lpSeed, long nSeedLen);
long __stdcall RNG_KeyHex(char *szOutput, long nMaxChars, long nBytes, const void *lpSeed, long nSeedLen);
long __stdcall RNG_NonceData(unsigned char *lpOutput, long nBytes);
long __stdcall RNG_NonceDataHex(char *szOutput, long nMaxChars, long nBytes);
long __stdcall RNG_Test(const char *szFileName);
int32_t __stdcall RNG_Number(int32_t nLower, int32_t nUpper);
long __stdcall RNG_BytesWithPrompt(unsigned char *lpOutput, long nOutputLen, const char *szPrompt, long nOptions);
long __stdcall RNG_HexWithPrompt(char *szOutput, long nMaxChars, long nBytes, const char *szPrompt, long nOptions);
long __stdcall RNG_Initialize(const char *szSeedFile, long nOptions);
long __stdcall RNG_MakeSeedFile( const char *szSeedFile, const char *szPrompt, long nOptions);
long __stdcall RNG_UpdateSeedFile(const char *szSeedFile, long nOptions);
/* Specialist DRBGVS test option */
long __stdcall RNG_TestDRBGVS(char *szOutput, long nMaxChars, long nReturnedBitsLen, const char *szEntropyInput, const char *szNonce, const char *szPersonalizationString, const char *szAdditionalInput1, const char *szEntropyReseed, const char *szAdditionalInputReseed, const char *szAdditionalInput2, long nOptions);

/* ZLIB COMPRESSION PROTOTYPES */
long __stdcall ZLIB_Deflate(unsigned char *lpOutput, long nOutBytes, const unsigned char *lpInput, long nBytes);
long __stdcall ZLIB_Inflate(unsigned char *lpOutput, long nOutBytes, const unsigned char *lpInput, long nBytes);

/* GENERIC COMPRESSION FUNCTIONS */
/* New in [v6.20] */
long __stdcall COMPR_Compress(unsigned char *lpOutput, long nOutBytes, const unsigned char *lpInput, long nInputLen, long nOptions);
long __stdcall COMPR_Uncompress(unsigned char *lpOutput, long nOutBytes, const unsigned char *lpInput, long nInputLen, long nOptions);

/* PASSWORD-BASED ENCRYPTION PROTOTYPES */
long __stdcall PBE_Kdf2(unsigned char *lpDerivedKey, long nKeyLen, const unsigned char *lpPwd, long nPwdLen, const unsigned char *lpSalt, long nSaltLen, long nCount, long nOptions);
long __stdcall PBE_Kdf2Hex(char *szOutput, long nMaxChars, long dkBytes, const char *szPwd, const char *szSaltHex, long nCount, long nOptions);
/* New in [v5.2] */
long __stdcall PBE_Scrypt(unsigned char *lpDerivedKey, long nKeyLen, const unsigned char *lpPwd, long nPwdLen, const unsigned char *lpSalt, long nSaltLen, long nParamN, long nParamR, long nParamP, long nOptions);
long __stdcall PBE_ScryptHex(char *szOutput, long nMaxChars, long dkBytes, const char *szPwd, const char *szSaltHex, long nParamN, long nParamR, long nParamP, long nOptions);

/* HEX CONVERSION PROTOTYPES */
long __stdcall CNV_HexStrFromBytes(char *szOutput, long nMaxChars, const unsigned char *lpInput, long nBytes);
long __stdcall CNV_BytesFromHexStr(unsigned char *lpOutput, long nOutputLen, const char *szInput);
long __stdcall CNV_HexFilter(char *szOutput, const char *szInput, long nInStrLen);

/* BASE64 CONVERSION PROTOTYPES */
long __stdcall CNV_B64StrFromBytes(char *szOutput, long nMaxChars, const unsigned char *lpInput, long nBytes);
long __stdcall CNV_BytesFromB64Str(unsigned char *lpOutput, long nOutputLen, const char *szInput);
long __stdcall CNV_B64Filter(char *szOutput, const char *szInput, long nInStrLen);

/* New in [v6.21] */
long __stdcall CNV_ShortPathName(char *szOut, long nOutChars, const wchar_t* wszPathName);

/* CRC-32 CHECKSUM PROTOTYPES */
int32_t __stdcall CRC_Bytes(const unsigned char *lpInput, long nBytes, long nOptions);
int32_t __stdcall CRC_String(const char *szInput, long nOptions);
int32_t __stdcall CRC_File(const char *szFileName, long nOptions);

/* WIPE PROTOTYPES */
long __stdcall WIPE_Data(void *lpData, long nDataLen);
long __stdcall WIPE_File(const char *szFileName, long nOptions);

/* PADDING PROTOTYPES */
long __stdcall PAD_BytesBlock(unsigned char *lpOutput, long nOutputLen, const unsigned char *lpInput, long nBytes, long nBlkLen, long nOptions);
long __stdcall PAD_UnpadBytes(unsigned char *lpOutput, long nOutputLen, const unsigned char *lpInput, long nBytes, long nBlkLen, long nOptions);
long __stdcall PAD_HexBlock(char *szOutput, long nMaxChars, const char *szInput, long nBlkLen, long nOptions);
long __stdcall PAD_UnpadHex(char *szOutput, long nMaxChars, const char *szInput, long nBlkLen, long nOptions);

/* XOF/PRF PROTOTYPES */
/* New in [v5.3] */
long __stdcall XOF_Bytes(unsigned char *lpOutput, long nOutBytes, const void *lpMessage, long nMsgLen, long nOptions);
long __stdcall PRF_Bytes(unsigned char *lpOutput, long nOutBytes, const void *lpMessage, long nMsgLen, const void *lpKey, long nKeyLen, const char *szCustom, long nOptions);

#ifdef __cplusplus
}
#endif

#endif /* end DICRYPTOSYS_H_ */

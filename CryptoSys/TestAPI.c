/*  $Id: TestAPI.c $
 *   Last updated:
 *   $Date: 2024-01-07 08:051:00 $
 *   $Version: 6.22.1 $
 */

// Formerly API_Examples.c

/*
This source code carries out a series of tests on the 
ANSI C functions in CryptoSys API (Version 6.22 or later). 

It needs to be compiled with the library file:

- `diCryptoSys.dll` and `diCryptoSys.lib` for Windows
- `libcryptosysapi.so` for i386 Linux, 
- `libcryptosysapi.dylib` for MacOSX.

The tests in themselves are pretty boring. Use the examples
as the basis for your hopefully-more-useful code.

It is not meant to be representative of good security coding.

There is minimal error checking here - we use assert as a blunt instrument -
and we make little or no effort to clean up passwords etc afterwards.


/******************************* LICENSE ***********************************
 * Copyright (C) 2001-24 David Ireland, DI Management Services Pty Limited.
 * All rights reserved. <www.di-mgt.com.au> <www.cryptosys.net>
 * The code in this module is licensed under the terms of the MIT license.
 * For a copy, see <http://opensource.org/licenses/MIT>
 ****************************************************************************
 */

#if _MSC_VER >= 1100
	/* Detect memory leaks in MSVC++ */ 
	#define _CRTDBG_MAP_ALLOC
	#include <stdlib.h>
	#include <crtdbg.h>
#else
	#include <stdlib.h>
#endif

#ifdef NDEBUG
	/* Make sure assertion testing is turned on */
	#undef NDEBUG
#endif
#include <assert.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <wchar.h>
#include "diCryptoSys.h"

typedef unsigned char BYTE;

/* Cope with case-insensitive string comparisons */
#if defined(_MSC_VER)
	#include <string.h>
	#define stricmp  _stricmp
	#define strnicmp _strnicmp
#elif (defined(__linux__) || defined (linux) || defined(__linux)) || defined(__APPLE__)
	#include <strings.h>
	#define stricmp  strcasecmp
	#define strnicmp strncasecmp
#else
	/* We just hope the function is available natively... */
#endif 


/* SYSTEM-SPECIFIC DIR FNS:
 * Used in `make_new_test_dir' and `remove_test_dir' only.
 */
#ifdef _WIN32
	#define DELCMD "DEL"
#else
	#define DELCMD "rm"
#endif
#ifdef _MSC_VER
	/* MSVC functions */
	#include <direct.h>
	#define MKDIR(d) _mkdir(d)
	#define CHDIR(d) _chdir(d)
	#define RMDIR(d) _rmdir(d)
	#define GETCWD(od, n) _getcwd(od, n)
#elif __BORLANDC__
	/* Borland functions */
	#include <dir.h>
	#define MKDIR(d) mkdir(d)
	#define CHDIR(d) chdir(d)
	#define RMDIR(d) rmdir(d)
	#define GETCWD(od, n) getcwd(od, n)
#elif (defined(__linux__) || defined (linux) || defined(__linux)) || defined(__APPLE__)
	/* Linux/macosx functions */
	#include <unistd.h>
	#include <sys/stat.h>
	#include <sys/types.h>
	#define MKDIR(d) mkdir(d, 0777)
	#define CHDIR(d) chdir(d)
	#define RMDIR(d) rmdir(d)
	#define GETCWD(od, n) getcwd(od, n)
#else
	/* Take a punt the compiler has inbuilt fns or die!
	   -- replace with your own here if necessary */
	#define MKDIR(d) mkdir(d)
	#define CHDIR(d) chdir(d)
	#define RMDIR(d) rmdir(d)
	#define GETCWD(od, n) getcwd(od, n)
#endif

#ifndef FALSE
#define FALSE (0)
#define TRUE (!FALSE)
#endif


/* FUNCTIONS TO CREATE AND REMOVE A TEST DIRECTORY */

/* Global variables */
char testdir[FILENAME_MAX];
char old_cwd[FILENAME_MAX];
char new_cwd[FILENAME_MAX];

int make_new_test_dir(void)
{
	/* 
	(1) Try and create a sub-dir in current working dir
	(2) If that fails, use _tempnam
	*/

	char hex[9];
	char *tempname = "";

	/* Use RNG to generate a 4-byte/8-hex char random address */
	RNG_NonceDataHex(hex, sizeof(hex)-1, 4);

	/* Create a test directory */
	sprintf(testdir, "./apitest.%s", hex);
	printf("Trying to create test directory '%s'...\n", testdir);
	
	/* Use MS-system-specific fns to create and set as default dir */
	if (MKDIR(testdir) != 0)
#ifdef _MSC_VER
	{	/* Check in case we run this where we don't have permission */
		printf("Unable to create test directory '%s'. Trying with _tempnam...\n", testdir);
		/* Now try using _tempnam (making a copy) */
		tempname = _tempnam("\\", "api");
		strncpy(testdir, tempname, FILENAME_MAX-1);
		free(tempname);	/* _tempnam uses malloc */
		if (MKDIR(testdir) != 0)
		{
			fprintf(stderr, "ERROR: unable to create a temp directory.");
			exit(EXIT_FAILURE);
		}
	}
#else	/* If not MSVC, we have just failed */
	{
		fprintf(stderr, "%s", tempname);	/* Fudge to avoid compiler warning */
		fprintf(stderr, "ERROR:unable to create a temp directory.");
		exit(EXIT_FAILURE);
	}
#endif
	printf("Created test directory '%s' OK.\n", testdir);

	/* Remember current working directory */
	GETCWD(old_cwd, FILENAME_MAX-1);

	/* Change CWD to our new temp dir */
	CHDIR(testdir);

	/* And check */
	GETCWD(new_cwd, FILENAME_MAX-1);
	printf("Current dir is '%s'\n", new_cwd);

	return 0;
}

void remove_test_dir(char *dirname, char *old_cwd)
{
	/* Use system commands to do the business 
	   --see DELCMD macro above (NB strings concatenate) */
	/* CAUTION: Use this carefully */
	int res;

	CHDIR(dirname);
	system (DELCMD" *.txt");
	system (DELCMD" *.dat");
	system (DELCMD" *.enc");
	system (DELCMD" *.ecb");
	system (DELCMD" *.chk");
	/* Go back to the CWD we stored at the start */
	if (!old_cwd)
		CHDIR("..");
	else
		CHDIR(old_cwd);
	res = RMDIR(dirname);
	if (res == 0)
		printf("Removed test directory OK.\n");
	else
		printf("ERROR: (%d) failed to remove test directory.\n", res);
}


/* UTILITIES USED IN THESE TESTS */

int create_hello_file(char *hello_file)
/* Create a 13-byte text file "hello world" plus CR-LF */
{
	FILE *fp;

	fp = fopen(hello_file, "wb");
	assert (fp != NULL);
	fprintf(fp, "hello world\r\n");
	fclose(fp);
	printf("Created 'hello.txt' as %s\n", hello_file);

	return 0;
}

int create_nowis_file(char *filename)
/* Create a 32-byte text file without a CR-LF at end */
{
	FILE *fp;

	fp = fopen(filename, "wb");
	assert (fp != NULL);
	fprintf(fp, "Now is the time for all good men");
	fclose(fp);
	printf("Created 'nowis.txt' as %s\n", filename);

	return 0;
}

int create_abc_file(const char *filename)
/* Create a 3-byte text file "abc" with no CR-LF */
{
	FILE *fp;

	fp = fopen(filename, "wb");
	assert(fp != NULL);
	fprintf(fp, "abc");
	fclose(fp);
	printf("Created 'abc.txt' as %s\n", filename);

	return 0;
}

int create_bin_file(char *bin_file)
/* Create a 512-byte binary file (0x00,0x01,0x02,...,0xFF)*2 */
{
	int i, k;
	FILE *fp;

	fp = fopen(bin_file, "wb");
	assert (fp != NULL);
	for (k = 0; k < 2; k++)
		for (i = 0; i < 256; i++)
			fputc(i, fp);
	fclose(fp);
	printf("Created 'test.bin' as %s\n", bin_file);

	return 0;
}

int file_exists(char *fname)
/* Returns true (1) if file exists or false (0) if it doesn't */
{
	FILE *fp;

	fp = fopen(fname, "rb");
	if (fp == NULL)
		return FALSE;

	fclose(fp);
	return TRUE;
}

long file_length(const char *fname)
/* Returns the length of file in bytes or -1 if error */
{
	FILE *fp;
	long flen;

	fp = fopen(fname, "rb");
	if (!fp) return -1L;
	fseek(fp, 0, SEEK_END);
	flen = ftell(fp);
	fclose(fp);

	return flen;
}

int cmp_files(const char *file1, const char *file2)
/* Compares two binary files: returns 0 if identical 
   or 1 if not identical or -1 if file error 
   [2006-06-20] modified to check lengths first. */
{
	FILE *fp1, *fp2;
	int c1, c2;
	long len1, len2;
	int result = 0;	/* Innocent until proven guilty */

	fp1 = fopen(file1, "rb");
	if (fp1 == NULL) 
		return -1;
	fp2 = fopen(file2, "rb");
	if (fp2 == NULL)
	{
		fclose(fp1);
		return -1;
	}

	/* Compare lengths */
	fseek(fp1, 0, SEEK_END);
	len1 = ftell(fp1);
	fseek(fp2, 0, SEEK_END);
	len2 = ftell(fp2);
	if (len1 != len2)
	{
		fclose(fp1);
		fclose(fp2);
		return 1;
	}

	rewind(fp1);
	rewind(fp2);

	while ((c1 = fgetc(fp1)) != EOF)
	{
		c2 = fgetc(fp2);
		if (c1 != c2)
		{	/* Found a mis-match */
			result = 1;
			break;
		}
	}

	fclose(fp1);
	fclose(fp2);

	return result;
}

int cmp_file_with_hex(char *file, const char *hex_ok)
/* Returns zero if file contains exactly the bytes in hex_ok */
{
	unsigned char *correct, *fbuf;
	const char *cp;
	long i, n, x, result;
	FILE *fp;
	char hex[3];

	/* Convert correct hex string to bytes */
	n = (long)strlen(hex_ok) / 2;
	correct = malloc(n);
	assert (correct != NULL);
	fbuf = malloc(n);
	assert (fbuf != NULL);

	for (cp = hex_ok, i = 0; i < n; i++)
	{
		hex[0] = *cp++;
		hex[1] = *cp++;
		hex[2] = 0;
		sscanf(hex, "%lx", &x);
		correct[i] = (unsigned char)x;
	}

	/* Read in file to buffer */
	fp = fopen(file, "rb");
	assert (fp != NULL);
	fread(fbuf, 1, n, fp);
	/* Make sure we are end of file */
	x = fgetc(fp);

	/* Do we have a match? */
	result = memcmp(fbuf, correct, n);

	/* Clean up */
	fclose(fp);
	free(correct);
	free(fbuf);

	if (x != EOF)
		return 1;

	return result;
}

static int convert_hex_to_bytes(unsigned char bytes[], size_t maxbytes, const char *hexstr)
/* Converts null-terminated string of hex chars to an array of bytes up to maxbytes long
   Returns # of bytes converted or -1 if error
*/
{
	size_t i;
	size_t len = strlen(hexstr) / 2;
	if (maxbytes < len) len = maxbytes;
 	for (i = 0; i < len; i++) 
	{
		int t, v;

		t = *hexstr++;
		if ((t >= '0') && (t <= '9')) v = (t - '0') << 4;
		else if ((t >= 'a') && (t <= 'f')) v = (t - 'a' + 10) << 4;
		else if ((t >= 'A') && (t <= 'F')) v = (t - 'A' + 10) << 4;
		else return -1;
		
		t = *hexstr++;
		if ((t >= '0') && (t <= '9')) v ^= (t - '0');
		else if ((t >= 'a') && (t <= 'f')) v ^= (t - 'a' + 10);
		else if ((t >= 'A') && (t <= 'F')) v ^= (t - 'A' + 10);
		else return -1;
		
		bytes[i] = (unsigned char)v;
	}
	return (int)i;
}

/* Various versions that print a byte array in hex format */

static void pr_hexbytes(const unsigned char *bytes, int nbytes)
/* Print bytes in hex format + newline */
{
	int i;

	for (i = 0; i < nbytes; i++)
		printf("%02X", bytes[i]);
	printf("\n");
}

static void pr_bytesmsg(const char *msg, const unsigned char *bytes, long nbytes)
/* Ditto but print an optional message beforehand */
{
	if (msg)
		printf("%s", msg);
	pr_hexbytes(bytes, nbytes);
}

static void pr_hexdump(const char *pre, const void *bytes, size_t nbytes, const char *post)
/* Print bytes as hex in blocks of 64 chars with optional "pre" and "post" strings */
{
	size_t i;
	const unsigned char *pb = (const unsigned char *)bytes;
	if (pre)
		printf("%s", pre);
	for (i = 0; i < nbytes; i++)
	{
		if (i && (i % 32) == 0)
			printf("\n");
		printf("%02x", *pb++);
	}
	if (post)
		printf("%s", post);
}

/** Display contents of binary file in hex. 
 * @returns length of file or -1 if error 
 */
static void pr_file_as_hex(const char *pre, const char *fname, const char *post)
{
	FILE *fp;
	unsigned char *buf;
	long flen = file_length(fname);
	if (flen <= 0)
	{
		printf("**OPEN ERROR**\n");
		return;
	}
	buf = calloc(flen, 1);
	assert(buf);
	fp = fopen(fname, "rb");
	if (fread(buf, 1, flen, fp) != flen)
	{
		printf("**READ ERROR**\n");
		return;
	}
	fclose(fp);
	pr_hexdump(pre, buf, flen, post);
	free(buf);
}

static void pr_byteshex16(const char *prefix, const unsigned char *b, size_t n, const char *suffix)
{
	size_t i;
	const size_t nline = 16;

	if (prefix) printf("%s", prefix);
	for (i = 0; i < n; i++)
	{
		if (i && (i % nline) == 0) printf("\n");
		printf("%02X", b[i]);
	}
	if (suffix) printf("%s", suffix);
}

static void pr_byteshexwrap(size_t linelen, const char *prefix, const unsigned char *b, size_t n, const char *suffix)
{
	size_t i;

	if (prefix) printf("%s", prefix);
	for (i = 0; i < n; i++)
	{
		if (i && (i % linelen) == 0) printf("\n");
		printf("%02X", b[i]);
	}
	if (suffix) printf("%s", suffix);
}

static void pr_textfile(const char *fname)
/* Print the contents of a text file */
{
	FILE *fp;
	int c;
	fp = fopen(fname, "rb");
	while ((c = fgetc(fp)) != EOF)
	{
		printf("%c", c);
	}
	fclose(fp);
}

static void pr_wrapstr(const char *prefix, const char *s, size_t linelen)
{
	size_t i;
	const char *cp = s;
	size_t nchars = strlen(s);

	if (prefix) printf("%s", prefix);
	for (i = 0; i < nchars; i++) {
		if (i && (i % linelen) == 0) printf("\n");
		printf("%c", s[i]);
	}
	printf("\n");
}

static int cmp_bytes2hex(unsigned char *bytes, size_t nbytes, const char *hex)
{
	int r;
	unsigned char *buf;
	size_t n = strlen(hex) / 2;
	if (n != nbytes) return -1;
	buf = malloc(n);
	n = convert_hex_to_bytes(buf, n, hex);
	r = memcmp(buf, bytes, nbytes);
	free(buf);
	return r;
}

static void pr_wordsmsg(const char *msg, wchar_t *w, size_t nw)
/* Print UTF-16 words in hex format */
{
	size_t i;
	if (msg)
		printf("%s", msg);

	for (i = 0; i < nw; i++)
		printf("%04X ", w[i]);
	printf("\n");
}

int create_file_unicode_name(wchar_t* wfname, wchar_t* text)
{
#if defined(_WIN32) || defined(WIN32) 
	FILE *fp;

	fp = _wfopen(wfname, L"wb");
	assert(fp != NULL);
	fwprintf(fp, text);
	fclose(fp);
	wprintf(L"Created '%s'\n", wfname);
	// Display UTF-16-encoded filename in hex
	pr_wordsmsg("HEX(wfname)=", wfname, wcslen(wfname));
#endif
	return 0;
}


static char *lookup_error(int errcode)
/* Looks up description of error msg and returns
   ptr to static string
*/
{
	static char errmsg[128];

	errmsg[0] = '\0';
	API_ErrorLookup(errmsg, sizeof(errmsg), errcode);

	return errmsg;
}

static void disp_error(long nRet)
{
	long errcode;

	errcode = API_ErrorCode();
	printf("ERROR Returned=%ld/Code=%ld: %s\n", nRet, errcode, lookup_error(errcode));
}



static const char *hashAlgName(long flags)
/* Returns a string describing the hash algorithm given the option flags */
{
	static const char *sret;
	switch (flags & 0xF)
	{
	case API_HASH_SHA1:
		sret = "sha-1";
		break;
	case API_HASH_MD5:
		sret = "md5";
		break;
	case API_HASH_MD2:
		sret = "md2";
		break;
	case API_HASH_SHA256:
		sret = "sha-256";
		break;
	case API_HASH_SHA384:
		sret = "sha-384";
		break;
	case API_HASH_SHA512:
		sret = "sha-512";
		break;
	case API_HASH_SHA224:
		sret = "sha-224";
		break;
	case API_HASH_RMD160:
		sret = "rmd160";
		break;

	default:
		sret = "**UNKNOWN**";
		break;
	}

	return sret;
}

/*************************************/
/* FINALLY, WE ACTUALLY DO THE TESTS */
/*************************************/


/* DES TESTS */

void test_DES_Hex(void)
{
    char *testfn = "DES_Hex()";
    char sHexKey[] = "0123456789abcdef";
	/* "Now is t" in hex */
    char sInput[] = "4E6F772069732074";
    char sCorrect[] = "3FA40E8A984D4815";
    char sOutput[sizeof(sInput)+1];
	long nRet;

	printf("\nTesting %s...\n", testfn);

    printf("KY=%s\n", sHexKey);
    printf("PT=%s\n", sInput);

    // Encrypt in one-off process
    nRet = DES_Hex(sOutput, sInput, sHexKey, ENCRYPT);
	assert (nRet == 0);
	/* Check */
    printf("CT=%s %ld\n", sOutput, nRet);
    printf("OK=%s\n", sCorrect);
	assert (strcmp(sCorrect, sOutput) == 0);

    // Now decrypt back to plain text using same buffer
    nRet = DES_Hex(sOutput, sOutput, sHexKey, DECRYPT);
	assert (nRet == 0);
    printf("P'=%s %ld\n", sOutput, nRet);
	assert (strcmp(sInput, sOutput) == 0);

	printf("...%s tested OK\n", testfn);
}

void test_DES_HexMode(void)
{
    char *testfn = "DES_HexMode()";
	long nRet;
	char sHexKey[] = "0123456789abcdef";
    char sHexIV[] = "1234567890abcdef";
    // "Now is the time for all good men"
    char sInput[] = "4E6F77206973207468652074696D6520666F7220616C6C20";
    char sCorrect[] = "E5C7CDDE872BF27C43E934008C389C0F683788499A7C05F6";
    // Set sOutput to be same length as sInput
    char sOutput[sizeof(sInput)+1];

	printf("\nTesting %s...\n", testfn);

    printf("KY=%s\n", sHexKey);
    printf("IV=%s\n", sHexIV);
    printf("PT=%s\n", sInput);

    // Encrypt in one-off process
    nRet = DES_HexMode(sOutput, sInput, sHexKey, ENCRYPT, "CBC", sHexIV);
	assert (nRet == 0);
    printf("CT=%s %ld\n", sOutput, nRet);
    printf("OK=%s\n", sCorrect);
	assert (strcmp(sOutput, sCorrect) == 0);

    // Now decrypt back to plain text
    nRet = DES_HexMode(sOutput, sOutput, sHexKey, DECRYPT, "cbc", sHexIV);
	assert (nRet == 0);
    printf("P'=%s %ld\n", sOutput, nRet);
	assert (strcmp(sOutput, sInput) == 0);

	printf("...%s tested OK\n", testfn);
}


void test_DES_UpdateHex(void)
{
	long hContext;
	long result;
	char sKey[] = "0123456789ABCDEF";
	char sInitV[] = "1234567890abcdef";
	char sHexString[33];
	char *correct;

	printf("Testing DES_UpdateHex() in CBC mode ...\n");
	hContext = DES_InitHex(sKey, ENCRYPT, "CBC", sInitV);
	if (hContext == 0)
		printf("DES_InitError=%ld\n", DES_InitError());
	assert (hContext != 0);

	/* First part: "Now is t" in hex (8 chars) */
	strcpy(sHexString, "4e6f772069732074");
	result = DES_UpdateHex(hContext, sHexString);
	assert (result == 0);
	correct = "E5C7CDDE872BF27C";
	printf("Result =%s\n", sHexString);
	printf("Correct=%s\n", correct);
	assert (strcmp(sHexString, correct) == 0);

    /* Second part: "he time for all " in hex (16 chars) */
    strcpy(sHexString, "68652074696d6520666f7220616c6c20");
    result = DES_UpdateHex(hContext, sHexString);
	assert (result == 0);
	correct = "43E934008C389C0F683788499A7C05F6";
	printf("Result =%s\n", sHexString);
	printf("Correct=%s\n", correct);
    assert (strcmp(sHexString, correct) == 0);

    result = DES_Final(hContext);
	assert (result == 0);

	/* Now decrypt */
	hContext = DES_InitHex(sKey, DECRYPT, "CBC", sInitV);
	if (hContext == 0)
		printf("DES_InitError=%ld\n", DES_InitError());
	assert (hContext != 0);

	strcpy(sHexString, "E5C7CDDE872BF27C43E934008C389C0F");
	result = DES_UpdateHex(hContext, sHexString);
	assert (result == 0);
	correct = "4E6F77206973207468652074696D6520";
	printf("Result =%s\n", sHexString);
	printf("Correct=%s\n", correct);
	assert (strcmp(sHexString, correct) == 0);

    strcpy(sHexString, "683788499A7C05F6");
    result = DES_UpdateHex(hContext, sHexString);
	assert (result == 0);
	correct = "666F7220616C6C20";
	printf("Result =%s\n", sHexString);
	printf("Correct=%s\n", correct);
    assert (strcmp(sHexString, correct) == 0);

    result = DES_Final(hContext);
	assert (result == 0);


	printf("...DES_UpdateHex() tested OK\n");
}

void test_DES_FileHex(void)
{
    char *testfn = "DES_FileHex()";
    long nRet;

    // Construct full path names to files
    char *strFileIn = "now.txt";
    char *strFileOut = "DESnow.enc";
    char *strFileChk = "DESnow.chk";

    // Encrypt plaintext file to cipher
    // WARNING: output file is just clobbered
    char sHexKey[] = "0123456789ABCDEF";

	printf("\nTesting %s...\n", testfn);

	create_nowis_file(strFileIn);

    nRet = DES_FileHex(strFileOut, strFileIn, sHexKey, 
        ENCRYPT, "ECB", 0);
    assert (nRet == 0);

	assert (cmp_file_with_hex(strFileOut, 
		"3FA40E8A984D48156A271787AB8883F9893D51EC4B563B53"
		"73C1ADB2171F7894086F9A1D74C94D4E")
		== 0);

    // Now decrypt it
    nRet = DES_FileHex(strFileChk, strFileOut, sHexKey, 
        DECRYPT, "ECB", 0);
    assert (nRet == 0);

	/* and check we got the plaintext we started with */
	assert (cmp_files(strFileChk, strFileIn) == 0);

	printf("...%s tested OK\n", testfn);
}

void test_DES_Bytes_rand(void)
/* Encrypt and decrypt random blocks with random keys */
{
    char *testfn = "DES_Bytes_rand()";

	unsigned char key[8];
	unsigned char plain[1024];
	unsigned char cipher[1024];
	int i, j, n, m;
	long result;

	srand((unsigned)time(NULL));

	printf("Testing DES_Bytes() with random blocks ...\n");
	for (i = 0; i < 10; i++)
	{
		/* Create a random key */
		for (j = 0; j < 8; j++)
			key[j] = rand() & 0xFF;

		/* Create some 'random' plaintext up to 1024 bytes long */
		/* in a multiple of block size */
		m = 1024 / 8;
		n = ((rand() % m) + 1) * 8; 
		assert (n <= sizeof(plain));

		for (j = 0; j < n; j++)
			plain[j] = rand() & 0xFF;
	
		/* Encrypt it into ciphertext */
		result = DES_Bytes(cipher, plain, n, key, ENCRYPT);
		assert (result == 0);

		/* Now decipher (use same variable) */
		result = DES_Bytes(cipher, cipher, n, key, DECRYPT);
		assert (result == 0);

		/* Check identical */
		assert (memcmp(plain, cipher, n) == 0);
		printf("%d(%d) ", i+1, n);
	}

	printf("...%s tested OK\n", testfn);
}



void test_DES_CheckKey(void)
{
    char *testfn = "DES_CheckKey()";
	long nRet;
	char *lpkey;
	
	printf("\nTesting %s...\n", testfn);
	/* Weak key */
	lpkey = "0101010101010101";
	nRet = DES_CheckKeyHex(lpkey);
	printf("%s is %s (%s)\n", lpkey, (nRet == 0 ? "OK" : "BAD"), lookup_error(nRet));
	assert(nRet != 0);

	/* Valid key by one bit */
	lpkey = "0101010101010102";
	nRet = DES_CheckKeyHex(lpkey);
	printf("%s is %s (%s)\n", lpkey, (nRet == 0 ? "OK" : "BAD"), lookup_error(nRet));
	assert(nRet == 0);

	/* Another weak key */
	lpkey = "01fe01fe01fe01fe";
	nRet = DES_CheckKeyHex(lpkey);
	printf("%s is %s (%s)\n", lpkey, (nRet == 0 ? "OK" : "BAD"), lookup_error(nRet));
	assert(nRet != 0);

	/* Weak double key in 1st half*/
	lpkey = "01010101010101010001112223334455";
	nRet = DES_CheckKeyHex(lpkey);
	printf("%s is %s (%s)\n", lpkey, (nRet == 0 ? "OK" : "BAD"), lookup_error(nRet));
	assert(nRet != 0);

	/* Weak triple key in 3rd part */
	lpkey = "000111222333444555666777888999aa0101010101010101";
	nRet = DES_CheckKeyHex(lpkey);
	printf("%s is %s (%s)\n", lpkey, (nRet == 0 ? "OK" : "BAD"), lookup_error(nRet));
	assert(nRet != 0);

	/* Valid key */
	lpkey = "000111222333444555666777888999aaabbbcccdddeeefff";
	nRet = DES_CheckKeyHex(lpkey);
	printf("%s is %s (%s)\n", lpkey, (nRet == 0 ? "OK" : "BAD"), lookup_error(nRet));
	assert(nRet == 0);

	/* Wrong key length (missing 'f' at end) */
	lpkey = "000111222333444555666777888999aaabbbcccdddeeeff";
	nRet = DES_CheckKeyHex(lpkey);
	printf("%s is %s (%s)\n", lpkey, (nRet == 0 ? "OK" : "BAD"), lookup_error(nRet));
	assert(nRet != 0);

	printf("...%s tested OK\n", testfn);
}



/* TRIPLE DES (TDEA, 3DES) TESTS */

void test_TDEA_Hex(void)
{
    char *testfn = "TDEA_Hex()";
    char sHexKey[] = "010101010101010101010101010101010101010101010101";
    char sInput[] = "8000000000000000";
    char sCorrect[] = "95F8A5E5DD31D900";
    char sOutput[sizeof(sInput)+1];
	long nRet;

	printf("\nTesting %s...\n", testfn);

    printf("KY=%s\n", sHexKey);
    printf("PT=%s\n", sInput);

    // Encrypt in one-off process
    nRet = TDEA_Hex(sOutput, sInput, sHexKey, ENCRYPT);
	assert (nRet == 0);
	/* Check */
    printf("CT=%s %ld\n", sOutput, nRet);
    printf("OK=%s\n", sCorrect);
	assert (strcmp(sCorrect, sOutput) == 0);

    // Now decrypt back to plain text using same buffer
    nRet = TDEA_Hex(sOutput, sOutput, sHexKey, DECRYPT);
	assert (nRet == 0);
    printf("P'=%s %ld\n", sOutput, nRet);
	assert (strcmp(sInput, sOutput) == 0);

	printf("...%s tested OK\n", testfn);
}

void test_TDEA_HexMode(void)
{
    char *testfn = "TDEA_HexMode()";
	long nRet;
    char sInput[] = "5468697320736F6D652073616D706520636F6E74656E742E0808080808080808";
    char sHexKey[] = "737C791F25EAD0E04629254352F7DC6291E5CB26917ADA32";
    char sHexIV[] = "B36B6BFB6231084E";
    char sCorrect[] = "D76FD1178FBD02F84231F5C1D2A2F74A4159482964F675248254223DAF9AF8E4";
    // Set sOutput to be same length as sInput
    char sOutput[sizeof(sInput)+1];

	printf("\nTesting %s...\n", testfn);

    printf("KY=%s\n", sHexKey);
    printf("IV=%s\n", sHexIV);
    printf("PT=%s\n", sInput);

    // Encrypt in one-off process
    nRet = TDEA_HexMode(sOutput, sInput, sHexKey, ENCRYPT, "CBC", sHexIV);
	assert (nRet == 0);
    printf("CT=%s %ld\n", sOutput, nRet);
    printf("OK=%s\n", sCorrect);
	assert (strcmp(sOutput, sCorrect) == 0);

    // Now decrypt back to plain text
    nRet = TDEA_HexMode(sOutput, sOutput, sHexKey, DECRYPT, "cbc", sHexIV);
	assert (nRet == 0);
    printf("P'=%s %ld\n", sOutput, nRet);
	assert (strcmp(sOutput, sInput) == 0);

	printf("...%s tested OK\n", testfn);
}



void test_TDEA_FileHex(void)
{
    char *testfn = "TDEA_FileHex()";
    long nRet;

    // Construct full path names to files
    char *strFileIn = "now.txt";
    char *strFileOut = "TDEAnow.enc";
    char *strFileChk = "TDEAnow.chk";

    // Encrypt plaintext file to cipher
    // WARNING: output file is just clobbered
    char sHexKey[] = "fedcba9876543210fedcba9876543210fedcba9876543210";

	printf("\nTesting %s...\n", testfn);

	create_nowis_file(strFileIn);

    nRet = TDEA_FileHex(strFileOut, strFileIn, sHexKey, 
        ENCRYPT, "ECB", 0);
    assert (nRet == 0);

    // Now decrypt it
    nRet = TDEA_FileHex(strFileChk, strFileOut, sHexKey, 
        DECRYPT, "ECB", 0);
    assert (nRet == 0);

	/* and check we got the plaintext we started with */
	assert (cmp_files(strFileChk, strFileIn) == 0);

	printf("...%s tested OK\n", testfn);
}

void test_TDEA_Bytes_rand(void)
/* Encrypt and decrypt random blocks with random keys */
{
    char *testfn = "TDEA_Bytes_rand()";

	unsigned char key[24];
	unsigned char plain[1024];
	unsigned char cipher[1024];
	int i, j, n, m;
	long result;

	srand((unsigned)time(NULL));

	printf("\nTesting %s...\n", testfn);
	for (i = 0; i < 10; i++)
	{
		/* Create a random key */
		for (j = 0; j < 24; j++)
			key[j] = rand() & 0xFF;

		/* Create some 'random' plaintext up to 1024 bytes long */
		/* in a multiple of block size */
		m = 1024 / 8;
		n = ((rand() % m) + 1) * 8; 
		assert (n <= sizeof(plain));

		for (j = 0; j < n; j++)
			plain[j] = rand() & 0xFF;
	
		/* Encrypt it into ciphertext */
		result = TDEA_Bytes(cipher, plain, n, key, ENCRYPT);
		assert (result == 0);

		/* Now decipher (use same variable) */
		result = TDEA_Bytes(cipher, cipher, n, key, DECRYPT);
		assert (result == 0);

		/* Check identical */
		assert (memcmp(plain, cipher, n) == 0);
		printf("%d(%d) ", i+1, n);
	}
	printf("\n");

	printf("...%s tested OK\n", testfn);
}

void test_TDEA_BytesMode_rand(void)
/* Encrypt and decrypt random blocks with random keys 
   in random modes 
*/
{
    char *testfn = "TDEA_BytesMode_rand()";

	unsigned char key[24];
	unsigned char plain[1024];
	unsigned char cipher[1024];
	unsigned char iv[8];
	char *modes[] = { "ECB", "CBC" };
	int i, j, n, m, im;
	long result;

	srand((unsigned)time(NULL));

	printf("\nTesting %s...\n", testfn);
	for (i = 0; i < 10; i++)
	{
		/* Create a random key and IV */
		for (j = 0; j < 24; j++)
			key[j] = rand() & 0xFF;
		for (j = 0; j < 8; j++)
			iv[j] = rand() & 0xFF;

		/* Create some 'random' plaintext up to 1024 bytes long */
		/* in a multiple of block size */
		m = 1024 / 8;
		n = ((rand() % m) + 1) * 8; 
		assert (n <= sizeof(plain));

		for (j = 0; j < n; j++)
			plain[j] = rand() & 0xFF;

		/* Select a mode index: 0 or 1 */
		im = rand() & 0x01;
	
		/* Encrypt it into ciphertext */
		result = TDEA_BytesMode(cipher, plain, n, key, ENCRYPT, modes[im], iv);
		assert (result == 0);

		/* Now decipher (use same variable) */
		result = TDEA_BytesMode(cipher, cipher, n, key, DECRYPT, modes[im], iv);
		assert (result == 0);

		/* Check identical */
		assert (memcmp(plain, cipher, n) == 0);
		printf("%d(%d) ", i+1, n);
	}
	printf("\n");

	printf("...%s tested OK\n", testfn);
}



/* HASH TESTS */

/* Correct message digest test vectors */
/* Hash('abc') */
#define OK_MD5_ABC "900150983cd24fb0d6963f7d28e17f72"
#define OK_MD2_ABC "da853b0d3f88d99b30283a69e6ded6bb"
#define OK_SHA1_ABC "a9993e364706816aba3e25717850c26c9cd0d89d"
#define OK_SHA224_ABC "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
#define OK_SHA256_ABC "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
#define OK_SHA384_ABC "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
#define OK_SHA512_ABC "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
#define OK_RMD160_ABC "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
/* Hash(empty-string) */
#define OK_SHA1_EMPTY "da39a3ee5e6b4b0d3255bfef95601890afd80709"
#define OK_SHA512_EMPTY "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"


void test_HASH_HexFromHex(void)
{
    char *testfn = "HASH_HexFromHex()";

	long result;
	char szDigest[API_MAX_HASH_CHARS+1]; /* NB extra one for terminating null character */
	char *szMsgHex = "616263";	/* = "abc" */

	printf("\nTesting %s...\n", testfn);

	/* Compute default SHA-1 digest */
	result = HASH_HexFromHex(szDigest, sizeof(szDigest)-1, szMsgHex, 0);
	assert(result > 0);
	printf("SHA1('abc')=%s\n", szDigest);
	assert(strcmp(szDigest, OK_SHA1_ABC) == 0);

	/* Compute MD5 digest */
	result = HASH_HexFromHex(szDigest, sizeof(szDigest)-1, szMsgHex, API_HASH_MD5);
	assert(result > 0);
	printf("MD5('abc')=%s\n", szDigest);
	assert(strcmp(szDigest, OK_MD5_ABC) == 0);

	/* Compute MD2 digest */
	result = HASH_HexFromHex(szDigest, sizeof(szDigest)-1, szMsgHex, API_HASH_MD2);
	assert(result > 0);
	printf("MD2('abc')=%s\n", szDigest);
	assert(strcmp(szDigest, OK_MD2_ABC) == 0);

	/* Compute SHA-224 digest */
	result = HASH_HexFromHex(szDigest, sizeof(szDigest)-1, szMsgHex, API_HASH_SHA224);
	assert(result > 0);
	printf("SHA224('abc')=%s\n", szDigest);
	assert(strcmp(szDigest, OK_SHA224_ABC) == 0);

	/* Compute SHA-256 digest */
	result = HASH_HexFromHex(szDigest, sizeof(szDigest)-1, szMsgHex, API_HASH_SHA256);
	assert(result > 0);
	printf("SHA256('abc')=%s\n", szDigest);
	assert(strcmp(szDigest, OK_SHA256_ABC) == 0);

	/* Compute SHA-384 digest */
	result = HASH_HexFromHex(szDigest, sizeof(szDigest)-1, szMsgHex, API_HASH_SHA384);
	assert(result > 0);
	printf("SHA384('abc')=%s\n", szDigest);
	assert(strcmp(szDigest, OK_SHA384_ABC) == 0);

	/* Compute SHA-512 digest */
	result = HASH_HexFromHex(szDigest, sizeof(szDigest)-1, szMsgHex, API_HASH_SHA512);
	assert(result > 0);
	printf("SHA512('abc')=%s\n", szDigest);
	assert(strcmp(szDigest, OK_SHA512_ABC) == 0);

	/* Compute RIPEMD-160 digest */
	result = HASH_HexFromHex(szDigest, sizeof(szDigest)-1, szMsgHex, API_HASH_RMD160);
	assert(result > 0);
	printf("RMD160('abc')=%s\n", szDigest);
	assert(strcmp(szDigest, OK_RMD160_ABC) == 0);

	/* Compute digest of empty string */
	result = HASH_HexFromHex(szDigest, sizeof(szDigest)-1, "", API_HASH_SHA1);
	assert(result > 0);
	printf("SHA1(e)=%s\n", szDigest);
	assert(strcmp(szDigest, OK_SHA1_EMPTY) == 0);
	
	result = HASH_HexFromHex(szDigest, sizeof(szDigest)-1, "", API_HASH_SHA512);
	assert(result > 0);
	printf("SHA512(e)=%s\n", szDigest);
	assert(strcmp(szDigest, OK_SHA512_EMPTY) == 0);
	
	printf("...%s tested OK\n", testfn);
}

void test_SHA1_StringHexHash(void)
{
    long result;
    char sDigest[41];	/* NB 1 extra char */
    char sCorrect[] = "a9993e364706816aba3e25717850c26c9cd0d89d";

	printf("Testing SHA1_StringHexHash()...\n");

    result = SHA1_StringHexHash(sDigest, "abc");

	assert (result == 0);
	printf("Result =%s\n", sDigest);
	printf("Correct=%s\n", sCorrect);
	assert (strcmp(sDigest, sCorrect) == 0);
	printf("...SHA1_StringHexHash() tested OK\n");
}

void test_SHA2_StringHexHash(void)
{
    char *testfn = "SHA2_StringHexHash()";
	long result;
    char sDigest[65];	/* NB 1 extra char */
    char sCorrect[] = 
"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

	printf("\nTesting %s...\n", testfn);

    result = SHA2_StringHexHash(sDigest, "abc");

	assert (result == 0);
	printf("Result =%s\n", sDigest);
	printf("Correct=%s\n", sCorrect);
	assert (strcmp(sDigest, sCorrect) == 0);
	printf("...%s tested OK\n", testfn);
}

void test_MD5_StringHexHash(void)
{
    long result;
    char sDigest[33];	/* NB 1 extra char */
    char sCorrect[] = "900150983cd24fb0d6963f7d28e17f72";

	printf("Testing MD5_StringHexHash()...\n");

    result = MD5_StringHexHash(sDigest, "abc");

	assert (result == 0);
	printf("Result =%s\n", sDigest);
	printf("Correct=%s\n", sCorrect);
	assert (strcmp(sDigest, sCorrect) == 0);
	printf("...MD5_StringHexHash() tested OK\n");
}

void test_SHA1_BytesHexHash(void)
{
    char *testfn = "SHA1_BytesHexHash()";
	long result;
    char sDigest[41];	/* NB 1 extra char */
    char sCorrect[] = "a9993e364706816aba3e25717850c26c9cd0d89d";
	unsigned char bytes[3];

	printf("\nTesting %s...\n", testfn);

	bytes[0] = 'a';
	bytes[1] = 'b';
	bytes[2] = 'c';
    result = SHA1_BytesHexHash(sDigest, bytes, 3);

	assert (result == 0);
	printf("Result =%s\n", sDigest);
	printf("Correct=%s\n", sCorrect);
	assert (strcmp(sDigest, sCorrect) == 0);
	printf("...%s tested OK\n", testfn);
}

void test_SHA2_BytesHexHash(void)
{
    char *testfn = "SHA2_BytesHexHash()";
	long result;
    char sDigest[65];	/* NB 1 extra char */
    char sCorrect[] = 
"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
	unsigned char bytes[3];

	printf("\nTesting %s...\n", testfn);

	bytes[0] = 'a';
	bytes[1] = 'b';
	bytes[2] = 'c';
    result = SHA2_BytesHexHash(sDigest, bytes, 3);

	assert (result == 0);
	printf("Result =%s\n", sDigest);
	printf("Correct=%s\n", sCorrect);
	assert (strcmp(sDigest, sCorrect) == 0);
	printf("...%s tested OK\n", testfn);
}

void test_MD5_BytesHexHash(void)
{
    char *testfn = "MD5_BytesHexHash()";
	long result;
    char sDigest[33];	/* NB 1 extra char */
    char sCorrect[] = "900150983cd24fb0d6963f7d28e17f72";
	unsigned char bytes[3];

	printf("\nTesting %s...\n", testfn);

	bytes[0] = 'a';
	bytes[1] = 'b';
	bytes[2] = 'c';
    result = MD5_BytesHexHash(sDigest, bytes, 3);

	assert (result == 0);
	printf("Result =%s\n", sDigest);
	printf("Correct=%s\n", sCorrect);
	assert (strcmp(sDigest, sCorrect) == 0);
	printf("...%s tested OK\n", testfn);
}

void test_SHA1_BytesHash(void)
{
    char *testfn = "SHA1_BytesHash()";
	long result;
    unsigned char digest[20];	/* NB minimum 20 bytes for SHA1 */
    unsigned char correct[] = {
		0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 
		0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
	};
	unsigned char bytes[3];

	printf("\nTesting %s...\n", testfn);

	bytes[0] = 'a';
	bytes[1] = 'b';
	bytes[2] = 'c';
    result = SHA1_BytesHash(digest, bytes, 3);

	assert (result == 0);
	printf("Result =");
	pr_hexbytes(digest, 20);
	printf("Correct=");
	pr_hexbytes(correct, 20);
	assert (memcmp(digest, correct, 20) == 0);
	printf("...%s tested OK\n", testfn);
}

void test_SHA2_BytesHash(void)
{
    char *testfn = "SHA2_BytesHash()";
	long result;
    unsigned char digest[32];	/* NB minimum 32 bytes for SHA256 */
    unsigned char correct[] = {
		0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
		0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
		0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 
		0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
	};
	unsigned char bytes[3];

	printf("\nTesting %s...\n", testfn);

	bytes[0] = 'a';
	bytes[1] = 'b';
	bytes[2] = 'c';
    result = SHA2_BytesHash(digest, bytes, 3);

	assert (result == 0);
	printf("Result =");
	pr_hexbytes(digest, 32);
	printf("Correct=");
	pr_hexbytes(correct, 32);
	assert (memcmp(digest, correct, 32) == 0);
	printf("...%s tested OK\n", testfn);
}

void test_MD5_BytesHash(void)
{
    char *testfn = "MD5_BytesHash()";
	long result;
    unsigned char digest[16];	/* NB minimum 16 bytes for MD5 */
    unsigned char correct[] = {
		0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96,
		0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72
	};
	unsigned char bytes[3];

	printf("\nTesting %s...\n", testfn);

	bytes[0] = 'a';
	bytes[1] = 'b';
	bytes[2] = 'c';
    result = MD5_BytesHash(digest, bytes, 3);

	assert (result == 0);
	printf("Result =");
	pr_hexbytes(digest, sizeof(digest));
	printf("Correct=");
	pr_hexbytes(correct, sizeof(digest));
	assert (memcmp(digest, correct, sizeof(digest)) == 0);
	printf("...%s tested OK\n", testfn);
}

void test_SHA1_HexDigest(void)
{
    char *testfn = "SHA1_HexDigest()";
	long result;
    char sDigest[41];	/* NB 1 extra char */
    char sCorrect[] = "a9993e364706816aba3e25717850c26c9cd0d89d";
	long hContext;
	unsigned char bytes[2];

	printf("\nTesting %s...\n", testfn);

	hContext = SHA1_Init();
	assert (hContext != 0);

	/* Combine _AddString and _AddBytes */

	result = SHA1_AddString(hContext, "a");
	assert (result == 0);

    bytes[0] = 'b';
	bytes[1] = 'c';
	result = SHA1_AddBytes(hContext, bytes, 2);
	assert (result == 0);

	result = SHA1_HexDigest(sDigest, hContext);

	assert (result == 0);
	printf("Result =%s\n", sDigest);
	printf("Correct=%s\n", sCorrect);
	assert (strcmp(sDigest, sCorrect) == 0);
	printf("...%s tested OK\n", testfn);
}

void test_SHA2_HexDigest(void)
{
    char *testfn = "SHA2_HexDigest()";
	long result;
    char sDigest[65];	/* NB 1 extra char */
    char sCorrect[] = 
"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
	long hContext;
	unsigned char bytes[2];

	printf("\nTesting %s...\n", testfn);

	hContext = SHA2_Init();
	assert (hContext != 0);

	/* Combine _AddString and _AddBytes */

	result = SHA2_AddString(hContext, "a");
	assert (result == 0);

    bytes[0] = 'b';
	bytes[1] = 'c';
	result = SHA2_AddBytes(hContext, bytes, 2);
	assert (result == 0);

	result = SHA2_HexDigest(sDigest, hContext);

	assert (result == 0);
	printf("Result =%s\n", sDigest);
	printf("Correct=%s\n", sCorrect);
	assert (strcmp(sDigest, sCorrect) == 0);
	printf("...%s tested OK\n", testfn);
}

void test_MD5_HexDigest(void)
{
    char *testfn = "MD5_HexDigest()";
	long result;
    char sDigest[33];	/* NB 1 extra char */
    char sCorrect[] = "900150983cd24fb0d6963f7d28e17f72";
	long hContext;
	unsigned char bytes[2];

	printf("\nTesting %s...\n", testfn);

	hContext = MD5_Init();
	assert (hContext != 0);

	/* Combine _AddString and _AddBytes */

	result = MD5_AddString(hContext, "a");
	assert (result == 0);

    bytes[0] = 'b';
	bytes[1] = 'c';
	result = MD5_AddBytes(hContext, bytes, 2);
	assert (result == 0);

	result = MD5_HexDigest(sDigest, hContext);

	assert (result == 0);
	printf("Result =%s\n", sDigest);
	printf("Correct=%s\n", sCorrect);
	assert (strcmp(sDigest, sCorrect) == 0);
	printf("...%s tested OK\n", testfn);
}



void test_SHA1_AddString(void)
{
    char *testfn = "SHA1_AddString()";
	long result;
    char sDigest[41];	/* NB 1 extra char */
    char sCorrect[] = "34aa973cd4c4daa4f61eeb2bdbad27316534016f";
	long hContext;
	char sA1000[1001];
	int i;

	printf("\nTesting %s...\n", testfn);

	hContext = SHA1_Init();
	assert (hContext != 0);

	/* Create a string of 1000 'a's */
	for (i = 0; i < 1000; i++)
		sA1000[i] = 'a';
	sA1000[i] = '\0';

	/* Add 1000 times => one million repetitions of "a" */

	for (i = 0; i < 1000; i++)
	{
		result = SHA1_AddString(hContext, sA1000);
		assert (result == 0);
	}

	/* Create final digest */

	result = SHA1_HexDigest(sDigest, hContext);

	assert (result == 0);
	printf("Result =%s\n", sDigest);
	printf("Correct=%s\n", sCorrect);
	assert (strcmp(sDigest, sCorrect) == 0);
	printf("...%s tested OK\n", testfn);
}

void test_SHA2_AddString(void)
{
    char *testfn = "SHA2_AddString()";
	long result;
    char sDigest[65];	/* NB 1 extra char */
    char sCorrect[] = 
"cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";
	long hContext;
	char sA1000[1001];
	int i;

	printf("\nTesting %s...\n", testfn);

	hContext = SHA2_Init();
	assert (hContext != 0);

	/* Create a string of 1000 'a's */
	for (i = 0; i < 1000; i++)
		sA1000[i] = 'a';
	sA1000[i] = '\0';

	/* Add 1000 times => one million repetitions of "a" */

	for (i = 0; i < 1000; i++)
	{
		result = SHA2_AddString(hContext, sA1000);
		assert (result == 0);
	}

	/* Create final digest */

	result = SHA2_HexDigest(sDigest, hContext);

	assert (result == 0);
	printf("Result =%s\n", sDigest);
	printf("Correct=%s\n", sCorrect);
	assert (strcmp(sDigest, sCorrect) == 0);
	printf("...%s tested OK\n", testfn);
}

void test_MD5_AddString(void)
{
    char *testfn = "MD5_AddString()";
	long result;
    char sDigest[41];	/* NB 1 extra char */
    char sCorrect[] = "7707d6ae4e027c70eea2a935c2296f21";
	long hContext;
	char sA1000[1001];
	int i;

	printf("\nTesting %s...\n", testfn);

	hContext = MD5_Init();
	assert (hContext != 0);

	/* Create a string of 1000 'a's */
	for (i = 0; i < 1000; i++)
		sA1000[i] = 'a';
	sA1000[i] = '\0';

	/* Add 1000 times => one million repetitions of "a" */

	for (i = 0; i < 1000; i++)
	{
		result = MD5_AddString(hContext, sA1000);
		assert (result == 0);
	}

	/* Create final digest */

	result = MD5_HexDigest(sDigest, hContext);

	assert (result == 0);
	printf("Result =%s\n", sDigest);
	printf("Correct=%s\n", sCorrect);
	assert (strcmp(sDigest, sCorrect) == 0);
	printf("...%s tested OK\n", testfn);
}


void test_SHA1_Hmac_KAT(void)
{
    char *testfn = "SHA1_Hmac_KAT()";
	/* Example from Wei Dai's Crypto++ test vectors 
	fipstest.cpp - written and placed in the public domain by Wei Dai
	*/
	long result;
    char sDigest[41];	/* NB 1 extra char */
    char sCorrect[] = "0922d3405faa3d194f82a45830737d5cc6c75d24";
	unsigned char key[] = {
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 
		0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 
		0x40, 0x41, 0x42, 0x43,
	};
	char data[] = "Sample #2";
	int key_len, data_len;

	printf("\nTesting %s...\n", testfn);

/* From http://trolocsis.com/crypto++/fipstest_8cpp-source.html
MAC_KnownAnswerTest<HMAC<SHA> >(
"303132333435363738393a3b3c3d3e3f40414243",
"Sample #2",
"0922d3405faa3d194f82a45830737d5cc6c75d24");
*/
	key_len = sizeof(key);
	data_len = (long)strlen(data);

	result = SHA1_Hmac(sDigest, (unsigned char*)data, data_len, key, key_len);

	assert (result == 0);
	printf("Result =%s\n", sDigest);
	printf("Correct=%s\n", sCorrect);
	assert (strcmp(sDigest, sCorrect) == 0);

	printf("...%s tested OK\n", testfn);
}

void test_SHA2_Hmac_KAT(void)
{
    char *testfn = "SHA2_Hmac_KAT()";
	/* Example from Wei Dai's Crypto++ test vectors 
	fipstest.cpp - written and placed in the public domain by Wei Dai
	*/
	long result;
    char sDigest[65];	/* NB 1 extra char */
    char sCorrect[] = 
"d28363f335b2dae468793a38680dea9f7fb8be1dceda197cdb3b1cb59a9f6422";
	unsigned char key[] = {
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 
		0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 
		0x40, 0x41, 0x42, 0x43,
	};
	char data[] = "abc";
	int key_len, data_len;

	printf("\nTesting %s...\n", testfn);

/* From http://trolocsis.com/crypto++/fipstest_8cpp-source.html
MAC_KnownAnswerTest<HMAC<SHA256> >(
"303132333435363738393a3b3c3d3e3f40414243",
"abc",
"D28363F335B2DAE468793A38680DEA9F7FB8BE1DCEDA197CDB3B1CB59A9F6422");	
*/
	key_len = sizeof(key);
	data_len = (long)strlen(data);

	result = SHA2_Hmac(sDigest, (unsigned char*)data, data_len, key, key_len);

	assert (result == 0);
	printf("Result =%s\n", sDigest);
	printf("Correct=%s\n", sCorrect);
	assert (strcmp(sDigest, sCorrect) == 0);

	printf("...%s tested OK\n", testfn);
}


void test_MD5_Hmac(void)
{
    char *testfn = "MD5_Hmac()";
	long result;
    char sDigest[33];	/* NB 1 extra char */
    char sCorrect1[] = "9294727a3638bb1c13f48ef8158bfc9d";
    char sCorrect2[] = "750c783e6ab0b503eaa86e310a5db738";
    char sCorrect3[] = "56be34521d144c88dbb8c733f0e8b3f6";
	int i;
	unsigned char key1[16];
	unsigned char key2[] = "Jefe";
	unsigned char key3[16];
	unsigned char data1[] = "Hi There";
	unsigned char data2[] = "what do ya want for nothing?";
	unsigned char data3[50];
	int key_len, data_len;

	printf("\nTesting %s...\n", testfn);

    /* Test No 1. from RFC 2104
	key =         0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
	key_len =     16 bytes
	data =        "Hi There"
	data_len =    8  bytes
	digest =      0x9294727a3638bb1c13f48ef8158bfc9d
	*/
	key_len = 16;
	for (i = 0; i < key_len; i++)
		key1[i] = 0x0b;

	data_len = 8;

	result = MD5_Hmac(sDigest, data1, data_len, key1, key_len);

	assert (result == 0);
	printf("Result =%s\n", sDigest);
	printf("Correct=%s\n", sCorrect1);
	assert (strcmp(sDigest, sCorrect1) == 0);

    /* Test No 2.
	key =         "Jefe"
	data =        "what do ya want for nothing?"
	data_len =    28 bytes
	digest =      0x750c783e6ab0b503eaa86e310a5db738
	*/
	key_len = 4;
	data_len = 28;

	result = MD5_Hmac(sDigest, data2, data_len, key2, key_len);

	assert (result == 0);
	printf("Result =%s\n", sDigest);
	printf("Correct=%s\n", sCorrect2);
	assert (strcmp(sDigest, sCorrect2) == 0);

    /* Test No 3.
	key =         0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
	key_len       16 bytes
	data =        0xDDDDDDDDDDDDDDDDDDDD...
				..DDDDDDDDDDDDDDDDDDDD...
				..DDDDDDDDDDDDDDDDDDDD...
				..DDDDDDDDDDDDDDDDDDDD...
				..DDDDDDDDDDDDDDDDDDDD
	data_len =    50 bytes
	digest =      0x56be34521d144c88dbb8c733f0e8b3f6
	*/
	key_len = 16;
	for (i = 0; i < key_len; i++)
		key3[i] = 0xAA;

	data_len = 50;
	for (i = 0; i < data_len; i++)
		data3[i] = 0xDD;

	result = MD5_Hmac(sDigest, data3, data_len, key3, key_len);

	assert (result == 0);
	printf("Result =%s\n", sDigest);
	printf("Correct=%s\n", sCorrect3);
	assert (strcmp(sDigest, sCorrect3) == 0);

	printf("...%s tested OK\n", testfn);
}


void test_SHA1_FileHexHash(void)
/* 'hello' and 'bin' are filenames */
{
	char *testfn = "SHA1_FileHexHash";
	long result;
	char sDigest[41];	/* NB 1 extra char */
    char sCorrectT[] = "22596363b3de40b06f981fb85d82312e8c0ed511";
    char sCorrectB[] = "88a5b867c3d110207786e66523cd1e4a484da697";
    char sCorrectBIN[] = "dbe649daba340bce7a44b809016d914839b99f10";
	char *hello = "hello$$.txt";
	char *bin = "bin$$.dat";

	printf("\nTesting %s...\n", testfn);

	create_hello_file(hello);
	create_bin_file(bin);

#ifdef _WIN32
	result = SHA1_FileHexHash(sDigest, hello, "t");

	assert (result == 0);
	printf("Result =%s\n", sDigest);
	printf("Correct=%s\n", sCorrectT);
	assert (strcmp(sDigest, sCorrectT) == 0);
#else
	result = (long)sCorrectT[0];	/* fudge to avoid compiler warning */
#endif

	result = SHA1_FileHexHash(sDigest, hello, "b");

	assert (result == 0);
	printf("Result =%s\n", sDigest);
	printf("Correct=%s\n", sCorrectB);
	assert (strcmp(sDigest, sCorrectB) == 0);

	result = SHA1_FileHexHash(sDigest, bin, "b");

	assert (result == 0);
	printf("Result =%s\n", sDigest);
	printf("Correct=%s\n",  sCorrectBIN);
	assert (strcmp(sDigest, sCorrectBIN) == 0);

	printf("...%s tested OK\n", testfn);
/*
C:\Test>sha1sum hello.txt
22596363b3de40b06f981fb85d82312e8c0ed511  hello.txt

C:\Test>sha1sum -b hello.txt
88a5b867c3d110207786e66523cd1e4a484da697 *hello.txt

C:\Test>sha1sum -b test.bin
dbe649daba340bce7a44b809016d914839b99f10 *test.bin
*/
}

void test_SHA2_FileHexHash(void)
{
	char *testfn = "SHA2_FileHexHash";
	long result;
	char sDigest[65];	/* NB 1 extra char */
    char sCorrectT[] = 
"a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447";
    char sCorrectB[] = 
"572a95fee9c0f320030789e4883707affe12482fbb1ea04b3ea8267c87a890fb";
    char sCorrectBIN[] = 
"110009dcee21620b166f3abfecb5eff7a873be729d1c2d53822e7acc5f34eb9b";
	char *hello = "hello$$2.txt";
	char *bin = "bin$$2.dat";

	printf("\nTesting %s...\n", testfn);

	create_hello_file(hello);
	create_bin_file(bin);

#ifdef _WIN32
	result = SHA2_FileHexHash(sDigest, hello, "t");

	assert (result == 0);
	printf("Result =%s\n", sDigest);
	printf("Correct=%s\n", sCorrectT);
	assert (strcmp(sDigest, sCorrectT) == 0);
#else
	result = (long)sCorrectT[0];	/* fudge to avoid compiler warning */
#endif

	result = SHA2_FileHexHash(sDigest, hello, "b");

	assert (result == 0);
	printf("Result =%s\n", sDigest);
	printf("Correct=%s\n", sCorrectB);
	assert (strcmp(sDigest, sCorrectB) == 0);

	result = SHA2_FileHexHash(sDigest, bin, "b");

	assert (result == 0);
	printf("Result =%s\n", sDigest);
	printf("Correct=%s\n",  sCorrectBIN);
	assert (strcmp(sDigest, sCorrectBIN) == 0);

	printf("...%s tested OK\n", testfn);
}

void test_MD5_FileHexHash(void)
/* 'hello' and 'bin' are filenames */
{
	char *testfn = "MD5_FileHexHash";
	long result;
	char sDigest[41];	/* NB 1 extra char */
    char sCorrectT[] = "6f5902ac237024bdd0c176cb93063dc4";
    char sCorrectB[] = "a0f2a3c1dcd5b1cac71bf0c03f2ff1bd";
    char sCorrectBIN[] = "f5c8e3c31c044bae0e65569560b54332";
	char *hello = "hello$$.txt";
	char *bin = "bin$$.dat";

	printf("\nTesting %s...\n", testfn);

	create_hello_file(hello);
	create_bin_file(bin);

#ifdef _WIN32
	result = MD5_FileHexHash(sDigest, hello, "t");

	assert (result == 0);
	printf("Result =%s\n", sDigest);
	printf("Correct=%s\n", sCorrectT);
	assert (strcmp(sDigest, sCorrectT) == 0);
#else
	result = (long)sCorrectT[0];	/* fudge to avoid compiler warning */
#endif

	result = MD5_FileHexHash(sDigest, hello, "b");

	assert (result == 0);
	printf("Result =%s\n", sDigest);
	printf("Correct=%s\n", sCorrectB);
	assert (strcmp(sDigest, sCorrectB) == 0);

	result = MD5_FileHexHash(sDigest, bin, "b");

	assert (result == 0);
	printf("Result =%s\n", sDigest);
	printf("Correct=%s\n",  sCorrectBIN);
	assert (strcmp(sDigest, sCorrectBIN) == 0);

	printf("...%s tested OK\n", testfn);
/*
C:\Test>md5sum -t hello.txt
6f5902ac237024bdd0c176cb93063dc4  hello.txt

C:\Test>md5sum -b hello.txt
a0f2a3c1dcd5b1cac71bf0c03f2ff1bd *hello.txt

C:\Test>md5sum -b test.bin
f5c8e3c31c044bae0e65569560b54332 *test.bin
*/
}

void test_MAC_HexFromBytes(void)
{
    char *testfn = "MAC_HexFromBytes()";

	long result;
	char szDigest[API_MAX_HASH_CHARS+1]; /* NB extra one for terminating null character */
	/* Test Case 2 RFC 2202 and RFC 4231 */
	char *key = "Jefe";
	char *data = "what do ya want for nothing?";

	printf("\nTesting %s...\n", testfn);

	/* Compute default HMAC-SHA-1 */
	result = MAC_HexFromBytes(szDigest, sizeof(szDigest)-1, 
		(unsigned char*)data, (long)strlen(data), (unsigned char*)key, (long)strlen(key), 0);
	assert(result > 0);
	printf("HMAC-SHA-1('Jefe', WDYWFN?)=%s\n", szDigest);
	assert(strcmp(szDigest, "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79") == 0);

	/* Compute HMAC-MD5 */
	result = MAC_HexFromBytes(szDigest, sizeof(szDigest)-1, 
		(unsigned char*)data, (long)strlen(data), (unsigned char*)key, (long)strlen(key), API_HASH_MD5);
	assert(result > 0);
	printf("HMAC-MD5('Jefe', WDYWFN?)=%s\n", szDigest);
	assert(strcmp(szDigest, "750c783e6ab0b503eaa86e310a5db738") == 0);

	/* Compute HMAC-SHA-224 */
	result = MAC_HexFromBytes(szDigest, sizeof(szDigest)-1, 
		(unsigned char*)data, (long)strlen(data), (unsigned char*)key, (long)strlen(key), API_HASH_SHA224);
	assert(result > 0);
	printf("HMAC-SHA-224('Jefe', WDYWFN?)=%s\n", szDigest);
	assert(strcmp(szDigest, 
	"a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44") == 0);

	/* Compute HMAC-SHA-256 */
	result = MAC_HexFromBytes(szDigest, sizeof(szDigest)-1, 
		(unsigned char*)data, (long)strlen(data), (unsigned char*)key, (long)strlen(key), API_HASH_SHA256);
	assert(result > 0);
	printf("HMAC-SHA-256('Jefe', WDYWFN?)=%s\n", szDigest);
	assert(strcmp(szDigest, 
	"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843") == 0);

	/* Compute HMAC-SHA-384 */
	result = MAC_HexFromBytes(szDigest, sizeof(szDigest)-1, 
		(unsigned char*)data, (long)strlen(data), (unsigned char*)key, (long)strlen(key), API_HASH_SHA384);
	assert(result > 0);
	printf("HMAC-SHA-384('Jefe', WDYWFN?)=%s\n", szDigest);
	assert(strcmp(szDigest, 
	"af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649") == 0);

	/* Compute HMAC-SHA-512 */
	result = MAC_HexFromBytes(szDigest, sizeof(szDigest)-1, 
		(unsigned char*)data, (long)strlen(data), (unsigned char*)key, (long)strlen(key), API_HASH_SHA512);
	assert(result > 0);
	printf("HMAC-SHA-512('Jefe', WDYWFN?)=%s\n", szDigest);
	assert(strcmp(szDigest, 
	"164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737") == 0);

	
	printf("...%s tested OK\n", testfn);
}

void test_CMAC_HexFromBytes(void)
{
    char *testfn = "CMAC_HexFromBytes()";

	long r;
	char szOutput[API_MAX_CMAC_CHARS+1];
	unsigned char *data;
	long key_len, data_len;
	unsigned char *key;
	unsigned char key128[] = {
		0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 
		0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
	};
	unsigned char key3des[] = {
		0x8A, 0xA8, 0x3B, 0xF8, 0xCB, 0xDA, 0x10, 0x62, 
		0x0B, 0xC1, 0xBF, 0x19, 0xFB, 0xB6, 0xCD, 0x58, 
		0xBC, 0x31, 0x3D, 0x4A, 0x37, 0x1C, 0xA8, 0xB5,
	};
	unsigned char M1[] = {
		0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 
		0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
	};

	printf("\nTesting %s...\n", testfn);

	key = key128;
	key_len = sizeof(key128);
	/* Test 1. */
	data = M1;
	data_len = sizeof(M1);
	/* Check required size */
	r = MAC_HexFromBytes(NULL, 0, data, data_len, key, key_len, API_CMAC_AES128);
	printf("MAC_HexFromBytes(NULL, 0,..,AES) returns %ld\n", r);
	assert(r > 0);
	r = MAC_HexFromBytes(szOutput, sizeof(szOutput)-1, data, data_len, key, key_len, API_CMAC_AES128);
	assert(r > 0);
	printf("CMAC-AES-128(Ex1)=%s\n", szOutput);
	assert(strcmp(szOutput, "070a16b46b4d4144f79bdd9dd04a287c") == 0);

	/* Compute CMAC-DES-EDE */
	key = key3des;
	key_len = sizeof(key3des);

	/* Test 0 = empty string */
	data = NULL;
	data_len = 0;
	/* Check required size */
	r = MAC_HexFromBytes(NULL, 0, data, data_len, key, key_len, API_CMAC_TDEA);
	printf("MAC_HexFromBytes(NULL, 0,..,TDEA) returns %ld\n", r);
	assert(r > 0);
	r = MAC_HexFromBytes(szOutput, sizeof(szOutput)-1, data, data_len, key, key_len, API_CMAC_DESEDE);
	assert(r > 0);
	printf("CMAC-DES-EDE(<empty>)=%s\n", szOutput);
	assert(strcmp(szOutput, "b7a688e122ffaf95") == 0);

	printf("...%s tested OK\n", testfn);
}

void test_CMAC_HexFromHex(void)
{
    char *testfn = "CMAC_HexFromHex()";

	long r;
	char szDigest[API_MAX_CMAC_CHARS+1]; /* NB extra one for terminating null character */
	/* SP800-38B D.1 AES-128 */
	char *szKeyHex = "2b7e151628aed2a6abf7158809cf4f3c";
	char *szMsgHex = "6bc1bee22e409f96e93d7e117393172a";
	char *lpszOK;

	printf("\nTesting %s...\n", testfn);

	/* Compute CMAC_AES-128 on empty string */
	r = MAC_HexFromHex(szDigest, sizeof(szDigest)-1, "", szKeyHex, API_CMAC_AES128);
	assert(r > 0);
	printf("CMAC-AES-128(K128, e)=%s\n", szDigest);
	lpszOK = "bb1d6929e95937287fa37d129b756746";
	assert(strcmp(szDigest, lpszOK) == 0);

	/* Compute CMAC_AES-128 on Example 2: Mlen = 128 */
	r = MAC_HexFromHex(szDigest, sizeof(szDigest)-1, szMsgHex, szKeyHex, API_CMAC_AES128);
	assert(r > 0);
	printf("CMAC-AES-128(K128, M128)=%s\n", szDigest);
	lpszOK = "070a16b46b4d4144f79bdd9dd04a287c";
	assert(strcmp(szDigest, lpszOK) == 0);

	/* CMAC_AES-256 on Example 12: Mlen = 512 */
	szKeyHex = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
	szMsgHex = "6bc1bee22e409f96e93d7e117393172a"
		"ae2d8a571e03ac9c9eb76fac45af8e51"
		"30c81c46a35ce411e5fbc1191a0a52ef"
		"f69f2445df4f9b17ad2b417be66c3710";
	r = MAC_HexFromHex(szDigest, sizeof(szDigest)-1, szMsgHex, szKeyHex, API_CMAC_AES256);
	assert(r > 0);
	printf("CMAC-AES-256(K256, M512)=%s\n", szDigest);
	lpszOK = "e1992190549f6ed5696a2c056c315410";
	assert(strcmp(szDigest, lpszOK) == 0);

	/* CMAC_TDEA on Example 16: Mlen = 256 */
	szKeyHex = "8aa83bf8cbda10620bc1bf19fbb6cd58bc313d4a371ca8b5";
	szMsgHex = "6bc1bee22e409f96e93d7e117393172a"
		"ae2d8a571e03ac9c9eb76fac45af8e51";
	r = MAC_HexFromHex(szDigest, sizeof(szDigest)-1, szMsgHex, szKeyHex, API_CMAC_DESEDE);
	assert(r > 0);
	printf("CMAC-DES-EDE(K192, M256)=%s\n", szDigest);
	lpszOK = "33e6b1092400eae5";
	assert(strcmp(szDigest, lpszOK) == 0);

	printf("Test with invalid parameters...\n");
	/* CMAC_AES-128 on an invalid hex string */
	r = MAC_HexFromHex(szDigest, sizeof(szDigest)-1, "A", szKeyHex, API_CMAC_AES128);
	printf("CMAC-AES-128(key, 0xA) returns %ld (expected -ve error)\n\t%s\n", r, lookup_error(r));
	assert(r < 0);

	/* CMAC_DES_EDE on an invalid key */
	r = MAC_HexFromHex(szDigest, sizeof(szDigest)-1, szMsgHex, "", API_CMAC_DESEDE);
	printf("CMAC-DES_EDE(BADKEY, M) returns %ld (expected -ve error)\n\t%s\n", r, lookup_error(r));
	assert(r < 0);

	
	printf("...%s tested OK\n", testfn);
}

void test_PBE_Kdf2(void)
{
    char *testfn = "PBE_Kdf2()";
	/* Use des-ede3-cbc example from test vectors by 
	   Dr. Stephen Henson using PBKDF2 defined in PKCS #5 v2.0.
	*/
	unsigned char dk[24];
	char pwd[] = "password";
	unsigned char salt[] = { 0x78, 0x57, 0x8E, 0x5A, 0x5D, 0x63, 0xCB, 0x06 };
	long dkLen, pwdLen, saltLen, count;
	long result;
	unsigned char correct[] = {
		0xBF, 0xDE, 0x6B, 0xE9, 0x4D, 0xF7, 0xE1, 0x1D, 0xD4, 0x09, 0xBC, 0xE2, 
		0x0A, 0x02, 0x55, 0xEC, 0x32, 0x7C, 0xB9, 0x36, 0xFF, 0xE9, 0x36, 0x43
	};

	printf("\nTesting %s...\n", testfn);

	// Compute the derived key DK given the password, salt and iteration count
	dkLen = sizeof(dk);
	pwdLen = (long)strlen(pwd);
	saltLen = sizeof(salt);
	count = 2048;

	result = PBE_Kdf2(dk, dkLen, (unsigned char*)pwd, pwdLen, salt, saltLen, count, 0);

	assert (result == 0);
	assert (result == 0);
	printf("Result =");
	pr_hexbytes(dk, dkLen);
	printf("Correct=");
	pr_hexbytes(correct, dkLen);
	assert (memcmp(dk, correct, dkLen) == 0);
	printf("...%s tested OK\n", testfn);

	return;
}

void test_PBE_Kdf2_SHA2(void)
{
    char *testfn = "PBE_Kdf2_SHA2()";
	/* Same as above but uses SHA-2 hash functions in HMAC.
	*/
	long result;
	char pwd[] = "password";
	char *salthex = "78578e5a5d63cb06";
	char *correcthex256 = "97B5A91D35AF542324881315C4F849E327C4707D1BC9D322";
	char *correcthex224 = "10CFFEDFB13503519969151E466F587028E0720B387F9AEF";
	char *pcorrecthex;
	long count = 2048;
	long dkLen = 24;
	char dkhex[2*24+1] = { 0 };

	printf("\nTesting %s...\n", testfn);

	printf("Using HMAC-SHA-256...\n");
	pcorrecthex = correcthex256;
	result = PBE_Kdf2Hex(dkhex, sizeof(dkhex)-1, dkLen, pwd, salthex, count, API_HASH_SHA256);
	printf("PBE_Kdf2Hex returns %ld\n", result);
	assert(result == 0);
	printf("Result =%s\n", dkhex);
	printf("Correct=%s\n", pcorrecthex);
	assert(strcmp(dkhex, pcorrecthex) == 0);

	printf("Using HMAC-SHA-224...\n");
	pcorrecthex = correcthex224;
	result = PBE_Kdf2Hex(dkhex, sizeof(dkhex)-1, dkLen, pwd, salthex, count, API_HASH_SHA224);
	printf("PBE_Kdf2Hex returns %ld\n", result);
	assert(result == 0);
	printf("Result =%s\n", dkhex);
	printf("Correct=%s\n", pcorrecthex);
	assert(strcmp(dkhex, pcorrecthex) == 0);

	printf("...%s tested OK\n", testfn);
	return;
}


void test_BLF_Hex(void)
{
	long result;
    char sInputHex[] = "0123456789ABCDEF";
    char sKeyHex[] = "FEDCBA9876543210";
    char sCorrectHex[] = "0ACEAB0FC6A0A28D";
	/* NB Output for Hex requires an extra byte */
	char sOutputHex[sizeof(sInputHex)+1];

	printf("Testing BLF_Hex()...\n");
	result = BLF_Hex(sOutputHex, sInputHex, sKeyHex, 1);
	assert (result == 0);
	printf("Result =%s\n", sOutputHex);
	printf("Correct=%s\n", sCorrectHex);
	assert (strcmp(sOutputHex, sCorrectHex) == 0);
	printf("...BLF_Hex() tested OK\n");
}

void test_BLF_HexMode(void)
{
    char *testfn = "BLF_HexMode()";
	long nRet;
    // "7654321 Now is the time for " padded to 32 bytes with 4 nulls
    char sInput[] = "37363534333231204E6F77206973207468652074696D6520666F722000000000";
    char sCorrect[] = "6B77B4D63006DEE605B156E27403979358DEB9E7154616D959F1652BD5FF92CC";
    char sHexKey[] = "0123456789ABCDEFF0E1D2C3B4A59687";
    char sHexIV[] = "FEDCBA9876543210";
    // Set sOutput to be same length as sInput
    char sOutput[sizeof(sInput)+1];

	printf("\nTesting %s...\n", testfn);

    printf("KY=%s\n", sHexKey);
    printf("IV=%s\n", sHexIV);
    printf("PT=%s\n", sInput);

    // Encrypt in one-off process
    nRet = BLF_HexMode(sOutput, sInput, sHexKey, ENCRYPT, "CBC", sHexIV);
	assert (nRet == 0);
    printf("CT=%s %ld\n", sOutput, nRet);
    printf("OK=%s\n", sCorrect);
	assert (strcmp(sOutput, sCorrect) == 0);

    // Now decrypt back to plain text
    nRet = BLF_HexMode(sOutput, sOutput, sHexKey, DECRYPT, "cbc", sHexIV);
	assert (nRet == 0);
    printf("P'=%s %ld\n", sOutput, nRet);
	assert (strcmp(sOutput, sInput) == 0);

	printf("...%s tested OK\n", testfn);
}


void test_BLF_UpdateHex(void)
{
	long hContext;
	long result;
	char sKey[] = "0123456789ABCDEF";
	char sHexString[33];
	char *correct;

	printf("Testing BLF_UpdateHex() in ECB mode ...\n");
	hContext = BLF_InitHex(sKey, 1, "ECB", NULL);
	if (hContext == 0)
		printf("BLF_InitError=%ld\n", BLF_InitError());
	assert (hContext != 0);

	/* First part: "Now is t" in hex (8 chars) */
	strcpy(sHexString, "4e6f772069732074");
	result = BLF_UpdateHex(hContext, sHexString);
	assert (result == 0);
	correct = "CB08E682C67E32E2";
	printf("Result =%s\n", sHexString);
	printf("Correct=%s\n", correct);
	assert (strcmp(sHexString, correct) == 0);

    /* Second part: "he time for all " in hex (16 chars) */
    strcpy(sHexString, "68652074696d6520666f7220616c6c20");
    result = BLF_UpdateHex(hContext, sHexString);
	assert (result == 0);
	correct = "8FCB010AC2CE9B1D9C4538762E33B52F";
	printf("Result =%s\n", sHexString);
	printf("Correct=%s\n", correct);
    assert (strcmp(sHexString, correct) == 0);

    result = BLF_Final(hContext);
	assert (result == 0);

	/* Now decrypt */
	hContext = BLF_InitHex(sKey, 0, "ECB", NULL);
	if (hContext == 0)
		printf("BLF_InitError=%ld\n", BLF_InitError());
	assert (hContext != 0);

	strcpy(sHexString, "CB08E682C67E32E2");
	result = BLF_UpdateHex(hContext, sHexString);
	assert (result == 0);
	correct = "4E6F772069732074";
	printf("Result =%s\n", sHexString);
	printf("Correct=%s\n", correct);
	assert (strcmp(sHexString, correct) == 0);

    strcpy(sHexString, "8FCB010AC2CE9B1D9C4538762E33B52F");
    result = BLF_UpdateHex(hContext, sHexString);
	assert (result == 0);
	correct = "68652074696D6520666F7220616C6C20";
	printf("Result =%s\n", sHexString);
	printf("Correct=%s\n", correct);
    assert (strcmp(sHexString, correct) == 0);

    result = BLF_Final(hContext);
	assert (result == 0);


	printf("...BLF_UpdateHex() tested OK\n");
}


void test_BLF_Bytes_rand(void)
/* Encrypt and decrypt random blocks */
{
	unsigned char key[8] = { 
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
	unsigned char plain[512];
	unsigned char cipher[512];
	int i, j, n;
	long result;

	srand((unsigned)time(NULL));

	printf("Testing BLF_Bytes() with random blocks ...\n");
	for (i = 0; i < 10; i++)
	{
		/* Create some 'random' plaintext up to 512 bytes long */
		n = ((rand() & 0x2F) + 1) * 8; /* in multiple of 8 */
		assert (n <= 512);

		for (j = 0; j < n; j++)
			plain[j] = rand() & 0xFF;
	
		/* Encrypt it into ciphertext */
		result = BLF_Bytes(cipher, plain, n, key, 8, 1);
		assert (result == 0);

		/* Now decipher (use same variable) */
		result = BLF_Bytes(cipher, cipher, n, key, 8, 0);
		assert (result == 0);

		/* Check identical */
		assert (memcmp(plain, cipher, n) == 0);
		printf("%d(%d) ", i+1, n);
	}
	printf("\n...BLF_Bytes() tested OK\n");
}

void test_BLF_BytesMode_rkeys(void)
/* Encrypt and decrypt with random keys */
{
	unsigned char key[56];
	/* NB we don't want the trailing NUL here! */
	unsigned char plain[32] = "Now is the time for all good men";
	unsigned char cipher[sizeof(plain)];
	unsigned char iv[8];
	int i, j, n;
	long result;

	srand((unsigned)time(NULL));

	printf("Testing BLF_BytesMode() with random keys and IV ...\n");
	for (i = 0; i < 10; i++)
	{
		/* Create some 'random' keys from 1 to 56 bytes long */
		n = (rand() % 56) + 1;
		for (j = 0; j < n; j++)
			key[j] = rand() & 0xFF;
		for (j = 0; j < 8; j++)
			iv[j] = rand() & 0xFF;
	
		/* Encrypt it into ciphertext in CBC mode */
		result = BLF_BytesMode(cipher, plain, sizeof(plain), key, n, 1,
			"CBC", iv);
		assert (result == 0);

		/* Now decipher (use same variable for result) */
		result = BLF_BytesMode(cipher, cipher, sizeof(cipher), key, n, 0,
			"CBC", iv);
		assert (result == 0);

		/* Check identical */
		assert (memcmp(plain, cipher, sizeof(plain)) == 0);
		printf("%d(%d) ", i+1, n);
	}
	printf("\n...BLF_BytesMode() tested OK\n");
}

void test_BLF_BytesMode_rmode(void)
/* Encrypt and decrypt random blocks and modes */
{
	unsigned char key[8] = { 
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
	unsigned char iv[8] = { 
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF }; 
	unsigned char plain[512];
	unsigned char cipher[512];
	int i, j, n;
	long result;
	char *mode[] = { "ECB", "CBC", "CFB", "OFB" };
	int m;

	srand((unsigned)time(NULL));

	printf("Testing BLF_BytesMode() with random modes ...\n");
	for (i = 0; i < 10; i++)
	{
		/* Create some 'random' plaintext up to 512 bytes long */
		n = ((rand() & 0x2F) + 1) * 8; /* in multiple of 8 */
		assert (n <= 512);

		for (j = 0; j < n; j++)
			plain[j] = rand() & 0xFF;

		/* And pick a random mode */
		m = rand() & 0x3;
	
		printf("%d-%s(%d) ", i+1, mode[m], n);

		/* Encrypt it into ciphertext */
		result = BLF_BytesMode(cipher, plain, n, key, 8, 1,
			mode[m], iv);
		assert (result == 0);

		/* Now decipher (use same variable) */
		result = BLF_BytesMode(cipher, cipher, n, key, 8, 0,
			mode[m], iv);
		assert (result == 0);

		/* Check identical */
		assert (memcmp(plain, cipher, n) == 0);
	}
	printf("\n...BLF_BytesMode() tested OK\n");
}


void test_BLF_File(void)
{
	char sFileIn[]  = "test$.txt";
	char sFileOut[] = "test$.ecb";
	char sFileChk[] = "test$.chk";
	unsigned char key[8] = { 
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
	unsigned char correct[] = { 
		0x1a, 0xa1, 0x51, 0xb7, 0x7a, 0x5a, 0x33, 0x5c, 
		0x4e, 0x7e, 0xdc, 0x84, 0xa3, 0x86, 0xdc, 0x96 };
	long result;
	FILE *fp;
	char buf[128], *cp;
	int c, n;
	
	/* Create a test file in current dir */
	fp = fopen(sFileIn, "wb");
	assert(fp != NULL);
	fprintf(fp, "hello world\r\n");
	fclose(fp);

	printf("Testing BLF_File()...\n");

	/* Encrypt it and create output file */
	result = BLF_File(sFileOut, sFileIn, key, sizeof(key), 1, "ECB", NULL);
	assert (result == 0);

	/* Read this ciphertext file to a buffer and see if correct */
	fp = fopen(sFileOut, "rb");
	assert (fp != NULL);
	printf("Result =");
	for (n = 0, cp = buf; (c = fgetc(fp)) != EOF && n < sizeof(buf); n++)
	{
		*cp++ = c;
		printf("%02X", (unsigned char)c);
	}
	fclose(fp);
	printf("\n");

	printf("Correct=");
	pr_hexbytes(correct, sizeof(correct));

	assert (memcmp(buf, correct, n) == 0);

	/* Now decrypt back to plaintext */
	result = BLF_File(sFileChk, sFileOut, key, sizeof(key), 0, "ECB", NULL);
	assert (result == 0);

	/* and check we got the plaintext we started with */
	assert (cmp_files(sFileChk, sFileIn) == 0);

	printf("...BLF_File() tested OK\n");
}

void test_ZLIB(void)
{
    char *testfn = "ZLIB_De/Inflate()";
	char *input = 
		"hello, hello, hello. This is a 'hello world' message "
        "for the world, repeat, for the world.";
	unsigned char *pcomp, *pcheck;
	long uncomp_len, comp_len, result;

	printf("\nTesting %s...\n", testfn);

	/* Find out compressed length of ascii input
	   NB don't use (long)strlen for binary data */
	uncomp_len = (long)strlen(input);
	printf("Input length = %ld bytes\n", uncomp_len);
	comp_len = ZLIB_Deflate(NULL, 0, (unsigned char*)input, uncomp_len);
	assert (comp_len > 0);
	printf("Compressed length = %ld bytes\n", comp_len);
	/* Alloc buffer storage */
	pcomp = (unsigned char*)malloc(comp_len);
	assert (pcomp != NULL);
	/* Do compression */
	result = ZLIB_Deflate(pcomp, comp_len, (unsigned char*)input, uncomp_len);
	assert (result > 0);

	/* Now uncompress and check */
	pcheck = (unsigned char*)malloc(uncomp_len);
	assert(pcheck != NULL);
	result = ZLIB_Inflate(pcheck, uncomp_len, pcomp, comp_len);
	assert (result > 0);
	printf("Inflated length = %ld\n", result);

	/* Do we have the same as we started with? */
	assert (memcmp(pcheck, input, uncomp_len) == 0);

	free(pcomp);
	free(pcheck);

	printf("...%s tested OK\n", testfn);
}

void test_RNG_Initialize(void)
{
    char *testfn = "RNG_Initialize()";
	char *sfname = "seed.dat";
	long result;

	printf("\nTesting %s...\n", testfn);

	/* Initialize the RNG generator from seed file
	   or [new in v4.7] create new seed file for later use
	 */

	result = RNG_Initialize(sfname, 0);
	printf("RNG_Initialize returns %ld (expecting 0)\n", result);
	assert (result == 0);
	pr_file_as_hex("Contents of seed file :\n", sfname, "\n");

	/* Now update this seed file */
	result = RNG_UpdateSeedFile(sfname, 0);
	printf("RNG_UpdateSeedFile returns %ld (expecting 0)\n", result);
	assert (result == 0);
	pr_file_as_hex("Contents of seed file after update :\n", sfname, "\n");


	printf("...%s tested OK\n", testfn);
}


void test_RNG_KeyBytes(void)
{
    char *testfn = "RNG_KeyBytes()";
	unsigned char key[8], prevkey[8] = { 0 };
	long result;
	int i;

	printf("\nTesting %s...\n", testfn);

	/* Generate 3 random keys with no seed */

	for (i = 0; i < 3; i++)
	{
		result = RNG_KeyBytes(key, sizeof(key), NULL, 0);
		assert (result == 0);
		pr_hexbytes(key, sizeof(key));
		// Make sure NOT the same as last time
		assert (memcmp(key, prevkey, sizeof(key)) != 0);
		memcpy(prevkey, key, sizeof(key));
	}

	printf("...%s tested OK\n", testfn);
}

void test_RNG_KeyHex(void)
{
    char *testfn = "RNG_KeyHex()";
	char hexkey[17], prevhexkey[17] = "";
	long result;
	int i;
	int nbytes;

	printf("\nTesting %s...\n", testfn);

	/* Generate 3 random keys with no seed */

	nbytes = sizeof(hexkey) / 2 - 1;
	for (i = 0; i < 3; i++)
	{
		/* Deliberately write too few or too many bytes */
		result = RNG_KeyHex(hexkey, sizeof(hexkey), nbytes++, NULL, 0);
		assert (result == 0);
		printf("%s\n", hexkey);
		// Make sure NOT the same as last time
		assert (strcmp(hexkey, prevhexkey) != 0);
		strcpy(prevhexkey, hexkey);
	}

	printf("...%s tested OK\n", testfn);
}

void test_RNG_NonceData(void)
{
    char *testfn = "RNG_NonceData()";
	long result;
	unsigned char nonce[32];
	char hex[33];
	int i;

	printf("\nTesting %s...\n", testfn);

	/* Generate nonce bytes */
	for (i = 0; i < 4; i++)
	{
		result = RNG_NonceData(nonce, sizeof(nonce));
		assert (result == 0);
		pr_hexbytes(nonce, sizeof(nonce));
	}

	/* And in hex - deliberately too long! */
	for (i = 0; i < 4; i++)
	{
		result = RNG_NonceDataHex(hex, sizeof(hex)-1, sizeof(hex) /*!!*/);
		assert (result == 0);
		printf("%s\n", hex);
	}

	printf("...%s tested OK\n", testfn);
}

void test_RNG_Number(void)
{
    char *testfn = "RNG_Number()";
	int32_t myvar;
	int32_t mymin = 256;
	int32_t mymax = 0x0fffffff;
	int i;

	printf("\nTesting %s...\n", testfn);

	/* Generate set of random longs */
	for (i = 0; i < 8; i++)
	{
		myvar = RNG_Number(mymin, mymax);
		printf("%08x ", myvar);
		assert (myvar > mymin || myvar > mymax);
	}
	printf("\n");

	printf("...%s tested OK\n", testfn);

}

void test_RNG_Test(void)
{
    char *testfn = "RNG_Test()";
	long result;
	char *filename = "RNGtest.txt";

	printf("\nTesting %s...\n", testfn);

	result = RNG_Test(filename);
	assert (result == 0);

	printf("...%s tested OK\n", testfn);
}



/* NEW AES FUNCTION TESTS */
void test_AES128_Hex(void)
{
    char *testfn = "AES128_Hex()";
    char sHexKey[] = "00000000000000000000000000000000";
    char sInput[] = "80000000000000000000000000000000";
    char sCorrect[] = "3AD78E726C1EC02B7EBFE92B23D9EC34";
    char sOutput[sizeof(sInput)+1];
	long nRet;

	printf("\nTesting %s...\n", testfn);

    printf("KY=%s\n", sHexKey);
    printf("PT=%s\n", sInput);

    // Encrypt in one-off process
    nRet = AES128_HexMode(sOutput, sInput, sHexKey, ENCRYPT, "ECB", NULL);
	assert (nRet == 0);
	/* Check */
    printf("CT=%s %ld\n", sOutput, nRet);
    printf("OK=%s\n", sCorrect);
	assert (strcmp(sCorrect, sOutput) == 0);

    // Now decrypt back to plain text using same buffer
    nRet = AES128_HexMode(sOutput, sOutput, sHexKey, DECRYPT, "ECB", NULL);
	assert (nRet == 0);
    printf("P'=%s %ld\n", sOutput, nRet);
	assert (strcmp(sInput, sOutput) == 0);

	printf("...%s tested OK\n", testfn);
}

void test_AES128_HexMode(void)
{
    char *testfn = "AES128_HexMode()";
	long nRet;
	char sHexKey[] = "0123456789ABCDEFF0E1D2C3B4A59687";
    char sHexIV[] = "FEDCBA9876543210FEDCBA9876543210";
    // "Now is the time for all good men"
    char sInput[] = "4E6F77206973207468652074696D6520666F7220616C6C20676F6F64206D656E";
    char sCorrect[] = "C3153108A8DD340C0BCB1DFE8D25D2320EE0E66BD2BB4A313FB75C5638E9E177";
    // Set sOutput to be same length as sInput
    char sOutput[sizeof(sInput)+1];

	printf("\nTesting %s...\n", testfn);

    printf("KY=%s\n", sHexKey);
    printf("IV=%s\n", sHexIV);
    printf("PT=%s\n", sInput);

    // Encrypt in one-off process
    nRet = AES128_HexMode(sOutput, sInput, sHexKey, ENCRYPT, "CBC", sHexIV);
	assert (nRet == 0);
    printf("CT=%s %ld\n", sOutput, nRet);
    printf("OK=%s\n", sCorrect);
	assert (strcmp(sOutput, sCorrect) == 0);

    // Now decrypt back to plain text
    nRet = AES128_HexMode(sOutput, sOutput, sHexKey, DECRYPT, "cbc", sHexIV);
	assert (nRet == 0);
    printf("P'=%s %ld\n", sOutput, nRet);
	assert (strcmp(sOutput, sInput) == 0);

	printf("...%s tested OK\n", testfn);
}

void test_AES128_HexModeError(void)
{
    char *testfn = "AES128_HexModeError()";
	long nRet;
	char sHexKey[] = "0123456789ABCDEFF0E1D2C3B4A59687";
    char sHexIV[] = "FEDCBA9876543210FEDCBA9876543210";
    // "Now is the time for all good men"
    char sInput[] = "4E6F77206973207468652074696D6520666F7220616C6C20676F6F64206D656E";
    //char sCorrect[] = "C3153108A8DD340C0BCB1DFE8D25D2320EE0E66BD2BB4A313FB75C5638E9E177";
    // Set sOutput to be same length as sInput
    char sOutput[sizeof(sInput)+1];
	char badhex[] = "THIS IS NOT HEX!";

	printf("\nTesting %s...\n", testfn);

	// nRet = AES128_HexMode(sOutput, sInput, sHexKey, ENCRYPT, "CBC", sHexIV);

	/* Call with null output */
    nRet = AES128_HexMode(NULL, sInput, sHexKey, ENCRYPT, "CBC", sHexIV);
	printf("AES128_HexMode returns %ld (%s)\n", nRet, lookup_error(nRet));
	assert (nRet != 0);

	/* Call with null input */
    nRet = AES128_HexMode(sOutput, NULL, sHexKey, ENCRYPT, "CBC", sHexIV);
	printf("AES128_HexMode returns %ld (%s)\n", nRet, lookup_error(nRet));
	assert (nRet != 0);

	/* Call with empty input */
    nRet = AES128_HexMode(sOutput, "", sHexKey, ENCRYPT, "CBC", sHexIV);
	printf("AES128_HexMode returns %ld (%s)\n", nRet, lookup_error(nRet));
	assert (nRet != 0);

	/* Call with invalid input */
    nRet = AES128_HexMode(sOutput, badhex, sHexKey, ENCRYPT, "CBC", sHexIV);
	printf("AES128_HexMode returns %ld (%s)\n", nRet, lookup_error(nRet));
	assert (nRet != 0);

	/* Call with null key */
    nRet = AES128_HexMode(sOutput, sInput, NULL, ENCRYPT, "CBC", sHexIV);
	printf("AES128_HexMode returns %ld (%s)\n", nRet, lookup_error(nRet));
	assert (nRet != 0);

	/* Call with empty key */
    nRet = AES128_HexMode(sOutput, sInput, "", ENCRYPT, "CBC", sHexIV);
	printf("AES128_HexMode returns %ld (%s)\n", nRet, lookup_error(nRet));
	assert (nRet != 0);

	/* Call with invalid key */
    nRet = AES128_HexMode(sOutput, sInput, badhex, ENCRYPT, "CBC", sHexIV);
	printf("AES128_HexMode returns %ld (%s)\n", nRet, lookup_error(nRet));
	assert (nRet != 0);

	/* Call with null mode */
    nRet = AES128_HexMode(sOutput, sInput, sHexKey, ENCRYPT, NULL, sHexIV);
	printf("AES128_HexMode returns %ld (%s)\n", nRet, lookup_error(nRet));
	assert (nRet != 0);

	/* Call with empty mode */
    nRet = AES128_HexMode(sOutput, sInput, sHexKey, ENCRYPT, "", sHexIV);
	printf("AES128_HexMode returns %ld (%s)\n", nRet, lookup_error(nRet));
	assert (nRet != 0);

	/* Call with invalid mode */
    nRet = AES128_HexMode(sOutput, sInput, sHexKey, ENCRYPT, "XBAD", sHexIV);
	printf("AES128_HexMode returns %ld (%s)\n", nRet, lookup_error(nRet));
	assert (nRet != 0);

	/* Call with null IV */
    nRet = AES128_HexMode(sOutput, sInput, sHexKey, ENCRYPT, "CBC", NULL);
	printf("AES128_HexMode returns %ld (%s)\n", nRet, lookup_error(nRet));
	assert (nRet != 0);

	/* Call with empty IV */
    nRet = AES128_HexMode(sOutput, sInput, sHexKey, ENCRYPT, "CBC", "");
	printf("AES128_HexMode returns %ld (%s)\n", nRet, lookup_error(nRet));
	assert (nRet != 0);

	/* Call with invalid IV */
    nRet = AES128_HexMode(sOutput, sInput, sHexKey, ENCRYPT, "CBC", badhex);
	printf("AES128_HexMode returns %ld (%s)\n", nRet, lookup_error(nRet));
	assert (nRet != 0);


	printf("...%s tested OK\n", testfn);
}



void test_AES128_HexMode_CBC(void)
{
    char *testfn = "AES128_HexMode_CBC()";
	long nRet;
    // NIST SP800-38a F.2.1 CBC-AES128.Encrypt
	char sHexKey[] = "2b7e151628aed2a6abf7158809cf4f3c";
    char sHexIV[] = "000102030405060708090a0b0c0d0e0f";
    char sInput[] = "6BC1BEE22E409F96E93D7E117393172A";
    char sCorrect[] = "7649ABAC8119B246CEE98E9B12E9197D";
    // Set sOutput to be same length as sInput
    char sOutput[sizeof(sInput)+1];

	printf("\nTesting %s...\n", testfn);

    printf("KY=%s\n", sHexKey);
    printf("IV=%s\n", sHexIV);
    printf("PT=%s\n", sInput);

    // Encrypt in one-off process
    nRet = AES128_HexMode(sOutput, sInput, sHexKey, ENCRYPT, "CBC", sHexIV);
	assert (nRet == 0);
    printf("CT=%s %ld\n", sOutput, nRet);
    printf("OK=%s\n", sCorrect);
	assert (strcmp(sOutput, sCorrect) == 0);

    // Now decrypt back to plain text
    nRet = AES128_HexMode(sOutput, sOutput, sHexKey, DECRYPT, "cbc", sHexIV);
	assert (nRet == 0);
    printf("P'=%s %ld\n", sOutput, nRet);
	assert (strcmp(sOutput, sInput) == 0);

	printf("...%s tested OK\n", testfn);
}

void test_AES128_BytesMode_CBC(void)
{
    char *testfn = "AES128_BytesMode_CBC()";
	long nRet, nbytes;
    // NIST SP800-38a F.2.1 CBC-AES128.Encrypt
	unsigned char key[16], iv[16], input[16], output[16], correct[16];
	convert_hex_to_bytes(key, sizeof(key), "2b7e151628aed2a6abf7158809cf4f3c");
	convert_hex_to_bytes(iv, sizeof(iv), "000102030405060708090a0b0c0d0e0f");
	nbytes = convert_hex_to_bytes(input, sizeof(input), "6BC1BEE22E409F96E93D7E117393172A");
	convert_hex_to_bytes(correct, sizeof(correct), "7649ABAC8119B246CEE98E9B12E9197D");

	printf("\nTesting %s...\n", testfn);

    printf("KY="); pr_hexbytes(key, sizeof(key));
    printf("IV="); pr_hexbytes(iv, sizeof(iv));
    printf("PT="); pr_hexbytes(input, sizeof(input));

    // Encrypt in one-off process
    nRet = AES128_BytesMode(output, input, nbytes, key, ENCRYPT, "CBC", iv);
	assert (nRet == 0);
    printf("CT="); pr_hexbytes(output, sizeof(output));
    printf("OK="); pr_hexbytes(correct, sizeof(correct));
	assert (memcmp(output, correct, nbytes) == 0);

    // Now decrypt back to plain text
    nRet = AES128_BytesMode(output, output, nbytes, key, DECRYPT, "cbc", iv);
	assert (nRet == 0);
    printf("P'="); pr_hexbytes(output, sizeof(output));
	assert (memcmp(output, input, nbytes) == 0);

	printf("...%s tested OK\n", testfn);
}

void test_AES192_HexMode_CBC(void)
{
    char *testfn = "AES192_HexMode_CBC()";
	long nRet;
    // NIST SP800-38a F.2.3 CBC-AES192.Encrypt
	char sHexKey[] = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
    char sHexIV[] = "000102030405060708090a0b0c0d0e0f";
    char sInput[] = "6BC1BEE22E409F96E93D7E117393172A";
    char sCorrect[] = "4F021DB243BC633D7178183A9FA071E8";
    // Set sOutput to be same length as sInput
    char sOutput[sizeof(sInput)+1];

	printf("\nTesting %s...\n", testfn);

    printf("KY=%s\n", sHexKey);
    printf("IV=%s\n", sHexIV);
    printf("PT=%s\n", sInput);

    // Encrypt in one-off process
    nRet = AES192_HexMode(sOutput, sInput, sHexKey, ENCRYPT, "CBC", sHexIV);
	assert (nRet == 0);
    printf("CT=%s %ld\n", sOutput, nRet);
    printf("OK=%s\n", sCorrect);
	assert (strcmp(sOutput, sCorrect) == 0);

    // Now decrypt back to plain text
    nRet = AES192_HexMode(sOutput, sOutput, sHexKey, DECRYPT, "cbc", sHexIV);
	assert (nRet == 0);
    printf("P'=%s %ld\n", sOutput, nRet);
	assert (strcmp(sOutput, sInput) == 0);

	printf("...%s tested OK\n", testfn);
}

void test_AES256_HexMode_CBC(void)
{
    char *testfn = "AES256_HexMode_CBC()";
	long nRet;
    // NIST SP800-38a F.2.5 CBC-AES256.Encrypt
	char sHexKey[] = 
		"603deb1015ca71be2b73aef0857d7781"
		"1f352c073b6108d72d9810a30914dff4";
    char sHexIV[] = "000102030405060708090a0b0c0d0e0f";
    char sInput[] = "6BC1BEE22E409F96E93D7E117393172A";
    char sCorrect[] = "F58C4C04D6E5F1BA779EABFB5F7BFBD6";
    // Set sOutput to be same length as sInput
    char sOutput[sizeof(sInput)+1];

	printf("\nTesting %s...\n", testfn);

    printf("KY=%s\n", sHexKey);
    printf("IV=%s\n", sHexIV);
    printf("PT=%s\n", sInput);

    // Encrypt in one-off process
    nRet = AES256_HexMode(sOutput, sInput, sHexKey, ENCRYPT, "CBC", sHexIV);
	assert (nRet == 0);
    printf("CT=%s %ld\n", sOutput, nRet);
    printf("OK=%s\n", sCorrect);
	assert (strcmp(sOutput, sCorrect) == 0);

    // Now decrypt back to plain text
    nRet = AES256_HexMode(sOutput, sOutput, sHexKey, DECRYPT, "cbc", sHexIV);
	assert (nRet == 0);
    printf("P'=%s %ld\n", sOutput, nRet);
	assert (strcmp(sOutput, sInput) == 0);

	printf("...%s tested OK\n", testfn);
}

void test_AES128_Hex_Monte(void)
{
	int i;
	long nRet;
	char sBlock[] = "00000000000000000000000000000000";
    char sKey[] = "00000000000000000000000000000000";
    char sCorrect[] = "C34C052CC0DA8D73451AFE5F03BE297F";

    char *testfn = "AES128_Hex_Monte()";

	printf("\nTesting %s...\n", testfn);

    printf("AES Monte Carlo TECB Mode Encrypt:\n");
    printf("KY=%s\n", sKey);
    printf("PT=%s\n", sBlock);
    // Do 10,000 times
    for (i = 0; i < 10000; i++)
	{
        nRet = AES128_HexMode(sBlock, sBlock, sKey, ENCRYPT, "ECB", "");
		assert (nRet == 0);
	}
    printf("CT=%s\n", sBlock);
    printf("OK=%s\n", sCorrect);
	assert (strcmp(sBlock, sCorrect) == 0);

	printf("...%s tested OK\n", testfn);
}


void test_AES128_FileHex(void)
{
    char *testfn = "AES128_FileHex()";
    long nRet;

    // Construct full path names to files
    char *strFileIn = "now.txt";
    char *strFileOut = "aesnow.enc";
    char *strFileChk = "aesnow.chk";

    char sHexKey[] = "0123456789ABCDEFF0E1D2C3B4A59687";
	char sCorrect[] = 
		"F0D1AD6F901FFFAE5572A6928DAB52B0"
		"64B25C79F876730321E36DC01011ACCE"
		"9C68DA6958A93ADFDECD9A1418D61EFD";

	printf("\nTesting %s...\n", testfn);

	create_nowis_file(strFileIn);

    // Encrypt plaintext file to cipher (with padding)
    // WARNING: output file is just clobbered
    nRet = AES128_FileHex(strFileOut, strFileIn, sHexKey, ENCRYPT, "ECB", 0);
    assert (nRet == 0);

	// Check we got the correct ciphertext 
	assert (cmp_file_with_hex(strFileOut, sCorrect) == 0);

    // Now decrypt it
    nRet = AES128_FileHex(strFileChk, strFileOut, sHexKey, DECRYPT, "ECB", 0);
    assert (nRet == 0);

	/* and check we got the plaintext we started with */
	assert (cmp_files(strFileChk, strFileIn) == 0);

	printf("...%s tested OK\n", testfn);
}

void test_AESnnn_BytesMode_rand(void)
/* Encrypt and decrypt random blocks with random keys
   and random modes */
{
    char *testfn = "AESnnn_BytesMode_rand()";

	unsigned char key[32];
	unsigned char plain[1024];
	unsigned char cipher[1024];
	long keybits;
	unsigned char iv[16];
	char *modes[] = { "ECB", "CBC" };
	int i, j, n, im;
	long result;

	srand((unsigned)time(NULL));

	printf("Testing AESnnn_BytesMode() with random blocks and modes...\n");
	for (i = 0; i < 10; i++)
	{
		/* Select a random key size: 128|192|256 */
		keybits = ((rand() % 3) + 2) * 64;

		/* Create a random key */
		for (j = 0; j < keybits / 8; j++)
			key[j] = rand() & 0xFF;

		/* and a random IV */
		for (j = 0; j < sizeof(iv); j++)
			iv[j] = rand() & 0xFF;

		/* Select a mode index: 0 or 1 */
		im = rand() & 0x01;

		/* Create some 'random' plaintext up to 1024 bytes long */
		/* in a multiple of block size */
		n = ((rand() % 16) + 1) * 16; 
		assert (n <= sizeof(plain));

		for (j = 0; j < n; j++)
			plain[j] = rand() & 0xFF;
	
		printf("%d %ld-%s(%d) ", i+1, keybits, modes[im], n);

		/* Encrypt it into ciphertext */
		switch (keybits)
		{
		case 128:
			result = AES128_BytesMode(cipher, plain, n, key, ENCRYPT, modes[im], iv);
			break;
		case 192:
			result = AES192_BytesMode(cipher, plain, n, key, ENCRYPT, modes[im], iv);
			break;
		case 256:
			result = AES256_BytesMode(cipher, plain, n, key, ENCRYPT, modes[im], iv);
			break;
		}
		assert (result == 0);

		/* Now decipher (use same variable) */
		switch (keybits)
		{
		case 128:
			result = AES128_BytesMode(cipher, cipher, n, key, DECRYPT, modes[im], iv);
			break;
		case 192:
			result = AES192_BytesMode(cipher, cipher, n, key, DECRYPT, modes[im], iv);
			break;
		case 256:
			result = AES256_BytesMode(cipher, cipher, n, key, DECRYPT, modes[im], iv);
			break;
		}
		assert (result == 0);

		/* Check identical */
		//printf("KY="); pr_hexbytes(key, keybits / 8);
		//if (im > 0) { printf("IV="); pr_hexbytes(iv, sizeof(iv)); }
		//printf("PT="); pr_hexbytes(plain, n);
		//printf("P'="); pr_hexbytes(cipher, n);
		assert (memcmp(plain, cipher, n) == 0);
	}

	printf("...%s tested OK\n", testfn);
}

void test_AESnnn_InitUpdate_rand(void)
/* Encrypt and decrypt random blocks with random keys
   and random modes and random direction (encrypt/decrypt first) */
{
    char *testfn = "AESnnn_InitUpdate_rand()";

	unsigned char key[32];
	unsigned char plain[1024];
	unsigned char block[1024];
	long keybits;
	unsigned char iv[16];
	char *modes[] = { "ECB", "CBC" };
	int i, j, n, m, im;
	long result;
	long hContext;
	int dir;

	srand((unsigned)time(NULL));

	printf("Testing AESnnn_InitUpdate_rand() with random blocks and modes...\n");
	for (i = 0; i < 10; i++)
	{
		/* Select a random key size: 128|192|256 */
		keybits = ((rand() % 3) + 2) * 64;

		/* Create a random key */
		for (j = 0; j < keybits / 8; j++)
			key[j] = rand() & 0xFF;

		/* and a random IV */
		for (j = 0; j < sizeof(iv); j++)
			iv[j] = rand() & 0xFF;

		/* Select a mode index: 0 or 1 */
		im = rand() & 0x01;

		/* select a direction to encrypt or decrypt first */
		dir = rand() & 0x01;

		/* Create some 'random' plaintext up to 1024 bytes long */
		/* in a multiple of block size */
		n = ((rand() % 16) + 1) * 16; 
		assert (n <= sizeof(plain));

		for (j = 0; j < n; j++)
			plain[j] = rand() & 0xFF;
	
		printf("%d %ld-%s-%s(%d) ", i+1, keybits, modes[im], (dir ? "ENCRYPT" : "DECRYPT"), n);

		/* Initialise the AESnnn context */
		switch (keybits)
		{
		case 128:
			hContext = AES128_Init(key, dir, modes[im], iv);
			break;
		case 192:
			hContext = AES192_Init(key, dir, modes[im], iv);
			break;
		case 256:
			hContext = AES256_Init(key, dir, modes[im], iv);
			break;
		}
		assert (hContext != 0);	/* Context should not be zero */

		/* Encrypt it into ciphertext in two parts */
		m = rand() % n;
		m = (m / 16) * 16;

		memcpy(block, plain, n);
		switch (keybits)
		{
		case 128:
			result = AES128_Update(hContext, block, m);
			result = AES128_Update(hContext, &block[m], n-m);
			break;
		case 192:
			result = AES192_Update(hContext, block, m);
			result = AES192_Update(hContext, &block[m], n-m);
			break;
		case 256:
			result = AES256_Update(hContext, block, m);
			result = AES256_Update(hContext, &block[m], n-m);
			break;
		}
		assert (result == 0);

		/* Now decipher (use same variable) */
		switch (keybits)
		{
		case 128:
			result = AES128_BytesMode(block, block, n, key, !dir, modes[im], iv);
			break;
		case 192:
			result = AES192_BytesMode(block, block, n, key, !dir, modes[im], iv);
			break;
		case 256:
			result = AES256_BytesMode(block, block, n, key, !dir, modes[im], iv);
			break;
		}
		assert (result == 0);

		/* Check identical */
		//printf("KY="); pr_hexbytes(key, keybits / 8);
		//if (im > 0) { printf("IV="); pr_hexbytes(iv, sizeof(iv)); }
		//printf("PT="); pr_hexbytes(plain, n);
		//printf("P'="); pr_hexbytes(block, n);
		assert (memcmp(plain, block, n) == 0);
	}

	printf("...%s tested OK\n", testfn);
}



void test_ArcFour(void)
{
	char *testfn = "ARCFOUR()";

	// Way back in the day, we used the made-up name 'PC1' to refer to 'RC4'
	// The new [v4.8] CIPHER_Stream functions use the more recent pseudonym 'ARCFOUR'

	long result;
	unsigned char key[] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef 
	};
	unsigned char input[] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef 
	};
	unsigned char output[sizeof(input)];
	unsigned char correct[] = {
		0x75, 0xb7, 0x87, 0x80, 0x99, 0xe0, 0xc5, 0x96 
	};
	FILE *fp;
	char *infile = "testpc1.dat";
	char *outfile = "testpc1.enc";
	char *chkfile = "testpc1.chk";
	unsigned char buf[512];
	unsigned char correctfile[] = {
		0x75, 0x95, 0xc3, 0xe6, 0x11, 0x4a, 0x09, 0x78
	};

	printf("\nTesting %s...\n", testfn);

	printf("Encrypt and decrypt byte arrays ... \n");
	printf("Key:       ");
	pr_hexbytes(key, sizeof(key));
	printf("Input:     ");
	pr_hexbytes(input, sizeof(input));

	/* Encrypt with (old) PC1 function */
	result = PC1_Bytes(output, input, sizeof(input), key, sizeof(key));
	printf("PC1_Bytes returns %ld (expecting 0)\n", result);
	assert (result == 0);
	pr_hexdump("Encrypted: ", output, sizeof(output), "\n");

	assert (memcmp(output, correct, sizeof(correct)) == 0);

	/* Now decrypt - i.e. just do it again */
	result = PC1_Bytes(output, output, sizeof(output), key, sizeof(key));
	assert (result == 0);
	pr_hexdump("Decrypted: ", output, sizeof(output), "\n");

	assert (memcmp(output, input, sizeof(input)) == 0);

	printf("... passed OK\n");

	// Repeat with newer CIPHER_StreamBytes + ARCFOUR

	printf("Same again with CIPHER_StreamBytes(ARCFOUR) ... \n");
	result = CIPHER_StreamBytes(output, input, sizeof(input), key, sizeof(key), NULL, 0, 0, API_SC_ARCFOUR);
	printf("CIPHER_StreamBytes(ARCFOUR) returns %ld (expecting 0)\n", result);
	assert (result == 0);
	pr_hexdump("Encrypted: ", output, sizeof(output), "\n");

	assert (memcmp(output, correct, sizeof(correct)) == 0);

	printf("Encrypt and decrypt a file ... \n");

	/* Create a file of 512 0x01 bytes */
	fp = fopen(infile, "wb");
	assert (fp != NULL);
	memset(buf, 0x01, 512);
	fwrite(buf, 1, 512, fp);
	fclose(fp);
	printf("File PT [0..%d]: ", sizeof(correctfile)-1);
	pr_hexbytes(buf, sizeof(correctfile));

	/* encrypt it with same key as before */
	result = PC1_File(outfile, infile, key, sizeof(key));
	assert (result == 0);

	/* get first few bytes and compare with correct answer */
	fp = fopen(outfile, "rb");
	assert (fp != NULL);
	fread(buf, 1, sizeof(correctfile), fp);
	fclose(fp);

	printf("File CT [0..%d]: ", sizeof(correctfile)-1);
	pr_hexbytes(buf, sizeof(correctfile));
	printf("Correct [0..%d]: ", sizeof(correctfile)-1);
	pr_hexbytes(correctfile, sizeof(correctfile));
	
	
	/* Now decrypt by doing it again */
	result = PC1_File(chkfile, outfile, key, sizeof(key));
	assert (result == 0);
	assert (cmp_files(chkfile, infile) == 0);

	/* And again using newer CIPHER_StreamFile function... */
	result = CIPHER_StreamFile(chkfile, outfile, key, sizeof(key), NULL, 0, 0, API_SC_ARCFOUR);
	printf("CIPHER_StreamFile(ARCFOUR) returns %ld (expecting 0)\n", result);
	assert (result == 0);
	assert (cmp_files(chkfile, infile) == 0);

	printf("... passed OK\n");

}


/* CRC FUNCTIONS */
void test_CRC_Bytes(void)
{
    char *testfn = "CRC_Bytes()";

	char *msg = "123456789";
	int32_t crc;

	printf("\nTesting %s...\n", testfn);

	crc = CRC_Bytes((unsigned char*)msg, (long)strlen(msg), 0);
	printf("CRC32(\"%s\")=%08x\n", msg, crc);
	assert (crc == 0xCBF43926);

	printf("...%s tested OK\n", testfn);
}

void test_CRC_String(void)
{
    char *testfn = "CRC_String()";

	char *msg = "123456789";
	char *hello = "hello world\x0d\x0a";
	int32_t crc;

	printf("\nTesting %s...\n", testfn);

	crc = CRC_String(msg, 0);
	printf("CRC32(\"%s\")=%08x\n", msg, crc);
	assert (crc == 0xCBF43926);

	crc = CRC_String(hello, 0);
	printf("CRC32(\"%s\")=%08x\n", hello, crc);
	assert (crc == 0x38e6c41a);

	printf("...%s tested OK\n", testfn);
}

void test_CRC_File(void)
{
    char *testfn = "CRC_File()";

	char *fname = "hello.txt";
	int32_t crc;

	printf("\nTesting %s...\n", testfn);

	/* Create a test file  */
	create_hello_file(fname);

	crc = CRC_File(fname, 0);
	printf("CRC32('%s')=%08x\n", fname, crc);
	assert (crc == 0x38e6c41a);


	printf("...%s tested OK\n", testfn);
}

/* WIPE FUNCTIONS */

void test_WIPE_Data(void)
{
    char *testfn = "WIPE_Data()";
	long ret;

	char data[] = "123456789";

	printf("\nTesting %s...\n", testfn);

	printf("Before WIPE_Data=[%s]\n", data);
	ret = WIPE_Data(data, (long)strlen(data));
	printf("After WIPE_Data=[%s]\n", data);
	assert (ret == 0);

	printf("...%s tested OK\n", testfn);
}

void test_WIPE_File(void)
{
    char *testfn = "WIPE_File()";
	long ret;

	char *fname = "tobewiped.dat";

	printf("\nTesting %s...\n", testfn);

	create_hello_file(fname);

	printf("Before WIPE_File=[%s]\n", (file_exists(fname) ? "File exists" : "File not there"));
	ret = WIPE_File(fname, 0);
	printf("WIPE_File returns %ld\n", ret);
	printf("After WIPE_File=[%s]\n", (file_exists(fname) ? "File exists" : "File not there"));
	assert (ret == 0);

	printf("...%s tested OK\n", testfn);
}

/* HEX ENCODING FUNCTIONS */

void test_CNV_BytesFromHexStr(void)
{
    char *testfn = "CNV_BytesFromHexStr()";

	char *hexdata = "FEDCBA9876543210";
	long nbytes, nchars;
	unsigned char *bp;
	char *cp;

	printf("\nTesting %s...\n", testfn);

	printf("Hexdata %s -> ", hexdata);
	nbytes = CNV_BytesFromHexStr(NULL, 0, hexdata);
	printf("up to %ld bytes\n", nbytes);
	assert(nbytes > 0);

	bp = malloc(nbytes);
	assert(bp != NULL);

	nbytes = CNV_BytesFromHexStr(bp, nbytes, hexdata);
	assert(nbytes == 8);
	printf("...actually %ld bytes\n", nbytes);
	pr_hexbytes(bp, nbytes);

	// Now convert back to hex
	nchars = CNV_HexStrFromBytes(NULL, 0, bp, nbytes);
	printf("%ld hex chars\n", nchars);
	assert(nchars > 0);
	// NB allocate one extra for terminating null
	cp = malloc(nchars + 1);
	assert(cp != NULL);

	nchars = CNV_HexStrFromBytes(cp, nchars, bp, nbytes);
	assert(nchars == 16);
	printf("Converts back to '%s' (%ld chars)\n", cp, nchars);
	assert(strcmp(cp, hexdata) == 0);

	free(bp);
	free(cp);
	printf("...%s tested OK\n", testfn);
}

void test_CNV_HexFilter(void)
{
    char *testfn = "CNV_HexFilter()";

	char badhexdata[] = " FE DC BA \n 98 \x00 76\r\n54321 0 ";
	char goodhexdata[] = "fedcba9876543210";
	char after[sizeof(badhexdata)];
	long nchars;

	printf("\nTesting %s...\n", testfn);

	nchars = sizeof(badhexdata) - 1;
	printf("Filtering a string of %ld chars...\n", nchars);

	nchars = CNV_HexFilter(after, badhexdata, nchars);
	printf("...returned %ld chars: %s\n", nchars, after);
	assert (nchars == 16);

	nchars = (long)strlen(goodhexdata);
	printf("Filtering a string of %ld chars...\n", nchars);

	nchars = CNV_HexFilter(after, goodhexdata, nchars);
	printf("...returned %ld chars: %s\n", nchars, after);
	assert (nchars == 16);
	printf("...%s tested OK\n", testfn);
}

/* KEY WRAP FUNCTIONS */

void test_CIPHER_KeyWrap(void)
{
    char *testfn = "CIPHER_KeyWrap()";

	unsigned char kek_aes[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
	};
	unsigned char kdata_aes[] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	};
	unsigned char kdata_tdea[] = {
		0x29, 0x23, 0xBF, 0x85, 0xE0, 0x6D, 0xD6, 0xAE, 
		0x52, 0x91, 0x49, 0xF1, 0xF1, 0xBA, 0xE9, 0xEA, 
		0xB3, 0xA7, 0xDA, 0x3D, 0x86, 0x0D, 0x3E, 0x98,
	};
	unsigned char kek_tdea[] = {
		0x25, 0x5E, 0x0D, 0x1C, 0x07, 0xB6, 0x46, 0xDF, 
		0xB3, 0x13, 0x4C, 0xC8, 0x43, 0xBA, 0x8A, 0xA7, 
		0x1F, 0x02, 0x5B, 0x7C, 0x08, 0x38, 0x25, 0x1F,
	};
	unsigned char ok_128aes128[] = {
		0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47, 
		0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B, 0x82, 
		0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5,
	};
	unsigned char ok_256aes256[] = {
		0x28, 0xC9, 0xF4, 0x04, 0xC4, 0xB8, 0x10, 0xF4, 
		0xCB, 0xCC, 0xB3, 0x5C, 0xFB, 0x87, 0xF8, 0x26, 
		0x3F, 0x57, 0x86, 0xE2, 0xD8, 0x0E, 0xD3, 0x26, 
		0xCB, 0xC7, 0xF0, 0xE7, 0x1A, 0x99, 0xF4, 0x3B, 
		0xFB, 0x98, 0x8B, 0x9B, 0x7A, 0x02, 0xDD, 0x21,
	};
	unsigned char cdata[sizeof(kdata_aes) + 16] = { 0 };
	unsigned char check[sizeof(kdata_aes) + 16] = { 0 };
	unsigned char *pkek, *pkdata, *pbok;
	unsigned keklen, kdlen, cdlen, oklen;
	int nlen;
	
	printf("\nTesting %s...\n", testfn);

	pkek = kek_aes;
	pkdata = kdata_aes;
	/* 4.1 Wrap 128 bits of Key Data with a 128-bit KEK */
	printf("4.1 Wrap 128 bits of Key Data with a 128-bit KEK\n");
	pbok = ok_128aes128;
	oklen = sizeof(ok_128aes128);
	keklen = 16;
	kdlen = 16;
	cdlen = kdlen + 8;
	pr_bytesmsg("KEK    =", pkek, keklen);
	pr_bytesmsg("KeyData=", pkdata, kdlen);
	nlen = CIPHER_KeyWrap(cdata, cdlen, pkdata, kdlen, pkek, keklen, API_BC_AES128);
	printf("CIPHER_KeyWrap returns %d\n", nlen);
	if (nlen > 0) pr_bytesmsg("Cipher =", cdata, nlen);
	assert(nlen > 0);
	pr_bytesmsg("OK     =", pbok, oklen);
	assert (memcmp(cdata, pbok, cdlen) == 0);
	nlen = CIPHER_KeyUnwrap(check, sizeof(check), cdata, cdlen, pkek, keklen, API_BC_AES128);
	printf("CIPHER_KeyUnwrap returns %d\n", nlen);
	if (nlen > 0) pr_bytesmsg("KeyMat =", check, nlen);
	assert(nlen == (long)kdlen);
	assert(memcmp(check, pkdata, kdlen) == 0);
	pr_bytesmsg("OK     =", pkdata, kdlen);

	/* 4.6 Wrap 256 bits of Key Data with a 256-bit KEK */
	printf("4.6 Wrap 256 bits of Key Data with a 256-bit KEK\n");
	pbok = ok_256aes256;
	oklen = sizeof(ok_256aes256);
	keklen = 32;
	kdlen = 32;
	cdlen = kdlen + 8;
	pr_bytesmsg("KEK    =", pkek, keklen);
	pr_bytesmsg("KeyData=", pkdata, kdlen);
	nlen = CIPHER_KeyWrap(cdata, cdlen, pkdata, kdlen, pkek, keklen, API_BC_AES256);
	printf("CIPHER_KeyWrap returns %d\n", nlen);
	if (nlen > 0) pr_bytesmsg("Cipher =", cdata, nlen);
	assert(nlen > 0);
	pr_bytesmsg("OK     =", pbok, oklen);
	assert (memcmp(cdata, pbok, cdlen) == 0);
	nlen = CIPHER_KeyUnwrap(check, sizeof(check), cdata, cdlen, pkek, keklen, API_BC_AES256);
	printf("CIPHER_KeyUnwrap returns %d\n", nlen);
	if (nlen > 0) pr_bytesmsg("KeyMat =", check, nlen);
	assert(nlen == (long)kdlen);
	assert(memcmp(check, pkdata, kdlen) == 0);
	pr_bytesmsg("OK     =", pkdata, kdlen);

	/* 	RFC3217 3.4  Triple-DES Key Wrap Example */
	printf("RFC3217 3.4  Triple-DES Key Wrap Example\n");
	pkek = kek_tdea;
	pkdata = kdata_tdea;
	keklen = 24;
	kdlen = 24;
	cdlen = 40;
	pr_bytesmsg("KEK    =", pkek, keklen);
	pr_bytesmsg("KeyData=", pkdata, kdlen);
	nlen = CIPHER_KeyWrap(cdata, cdlen, pkdata, kdlen, pkek, keklen, API_BC_TDEA);
	printf("CIPHER_KeyWrap returns %d\n", nlen);
	if (nlen > 0) pr_bytesmsg("Cipher =", cdata, nlen);
	assert(nlen > 0);
	// we don't have an OK result because the random IV used
	nlen = CIPHER_KeyUnwrap(check, sizeof(check), cdata, cdlen, pkek, keklen, API_BC_TDEA);
	printf("CIPHER_KeyUnwrap returns %d\n", nlen);
	if (nlen > 0) pr_bytesmsg("KeyMat =", check, nlen);
	assert(nlen == (long)kdlen);
	assert(memcmp(check, pkdata, kdlen) == 0);
	pr_bytesmsg("OK     =", pkdata, kdlen);

	printf("...%s tested OK\n", testfn);
}

/* GCM AUTHENTICATED ENCRYPTION */

static int do_gcm_test(const char *title, 
				const unsigned char *key, long keylen, 
				const unsigned char *pt, long ptlen, 
				const unsigned char *iv, long ivlen,
				const unsigned char *adata, long alen,
				const unsigned char *ok_ct, long okctlen,
				const unsigned char *ok_tag, long oktaglen
				)
{	/* Generic test bed for GCM_Encrypt */
	unsigned char tag[16];
	unsigned char *ct;
	unsigned char *p1;
	long taglen, ctlen, p1len;
	long r;

	ctlen = ptlen;
	p1len = ptlen;
	taglen = sizeof(tag);

	/* Provide output */
	ct = malloc(ctlen);
	assert(ct);
	p1 = malloc(ptlen);
	assert(p1);

	printf("%s", title);
	pr_hexdump("K =", key, keylen, "\n");
	pr_hexdump("PT=", pt, ptlen, "\n");
	pr_hexdump("A =", adata, alen, "\n");
	pr_hexdump("IV=", iv, ivlen, "\n");
	r = GCM_Encrypt(ct, ctlen, tag, taglen, pt, ptlen, key, keylen, iv, ivlen, adata, alen, 0);
	pr_hexdump("CT=", ct, ctlen, "\n");
	assert(memcmp(ct, ok_ct, okctlen) == 0);
	pr_hexdump("T =", tag, taglen, "\n");
	assert(memcmp(tag, ok_tag, oktaglen) == 0);
	r = GCM_Decrypt(p1, p1len, ct, ctlen, key, keylen, iv, ivlen, adata, alen, tag, taglen, 0);
	pr_hexdump("P'=", p1, p1len, "\n");
	assert(memcmp(pt, p1, p1len) == 0);

	free(ct);
	free(p1);

	return 0;
}

void test_GCM_Encrypt(void)
{
    char *testfn = "GCM_Encrypt()";

	const char *title = "Test case 6:\n";
	unsigned char key[] = {
		0xFE, 0xFF, 0xE9, 0x92, 0x86, 0x65, 0x73, 0x1C, 
		0x6D, 0x6A, 0x8F, 0x94, 0x67, 0x30, 0x83, 0x08,
	};
	unsigned char pt[] = {
		0xD9, 0x31, 0x32, 0x25, 0xF8, 0x84, 0x06, 0xE5, 
		0xA5, 0x59, 0x09, 0xC5, 0xAF, 0xF5, 0x26, 0x9A, 
		0x86, 0xA7, 0xA9, 0x53, 0x15, 0x34, 0xF7, 0xDA, 
		0x2E, 0x4C, 0x30, 0x3D, 0x8A, 0x31, 0x8A, 0x72, 
		0x1C, 0x3C, 0x0C, 0x95, 0x95, 0x68, 0x09, 0x53, 
		0x2F, 0xCF, 0x0E, 0x24, 0x49, 0xA6, 0xB5, 0x25, 
		0xB1, 0x6A, 0xED, 0xF5, 0xAA, 0x0D, 0xE6, 0x57, 
		0xBA, 0x63, 0x7B, 0x39,
	};
	unsigned char adata[] = {
		0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF, 
		0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF, 
		0xAB, 0xAD, 0xDA, 0xD2,
	};
	unsigned char iv[] = {
		0x93, 0x13, 0x22, 0x5D, 0xF8, 0x84, 0x06, 0xE5, 
		0x55, 0x90, 0x9C, 0x5A, 0xFF, 0x52, 0x69, 0xAA, 
		0x6A, 0x7A, 0x95, 0x38, 0x53, 0x4F, 0x7D, 0xA1, 
		0xE4, 0xC3, 0x03, 0xD2, 0xA3, 0x18, 0xA7, 0x28, 
		0xC3, 0xC0, 0xC9, 0x51, 0x56, 0x80, 0x95, 0x39, 
		0xFC, 0xF0, 0xE2, 0x42, 0x9A, 0x6B, 0x52, 0x54, 
		0x16, 0xAE, 0xDB, 0xF5, 0xA0, 0xDE, 0x6A, 0x57, 
		0xA6, 0x37, 0xB3, 0x9B,
	};
	unsigned char ok_ct[] = {
		0x8C, 0xE2, 0x49, 0x98, 0x62, 0x56, 0x15, 0xB6, 
		0x03, 0xA0, 0x33, 0xAC, 0xA1, 0x3F, 0xB8, 0x94, 
		0xBE, 0x91, 0x12, 0xA5, 0xC3, 0xA2, 0x11, 0xA8, 
		0xBA, 0x26, 0x2A, 0x3C, 0xCA, 0x7E, 0x2C, 0xA7, 
		0x01, 0xE4, 0xA9, 0xA4, 0xFB, 0xA4, 0x3C, 0x90, 
		0xCC, 0xDC, 0xB2, 0x81, 0xD4, 0x8C, 0x7C, 0x6F, 
		0xD6, 0x28, 0x75, 0xD2, 0xAC, 0xA4, 0x17, 0x03, 
		0x4C, 0x34, 0xAE, 0xE5,
	};
	unsigned char ok_tag[] = {
		0x61, 0x9C, 0xC5, 0xAE, 0xFF, 0xFE, 0x0B, 0xFA, 
		0x46, 0x2A, 0xF4, 0x3C, 0x16, 0x99, 0xD0, 0x50,
	};

	printf("\nTesting %s...\n", testfn);

	do_gcm_test(title, key, sizeof(key), pt, sizeof(pt), iv, sizeof(iv), adata, sizeof(adata),
		ok_ct, sizeof(ok_ct), ok_tag, sizeof(ok_tag));

	printf("...%s tested OK\n", testfn);
}

void test_GCM_Decrypt(void)
{
    char *testfn = "GCM_Decrypt()";

	unsigned char key[16] = { 0 };
	unsigned char pt[16] =  { 0 };
	unsigned char iv[12] =  { 0 };
	unsigned char ct[] = {
		0x03, 0x88, 0xDA, 0xCE, 0x60, 0xB6, 0xA3, 0x92, 
		0xF3, 0x28, 0xC2, 0xB9, 0x71, 0xB2, 0xFE, 0x78,
	};
	unsigned char tag[] = {
		0xAB, 0x6E, 0x47, 0xD4, 0x2C, 0xEC, 0x13, 0xBD, 
		0xF5, 0x3A, 0x67, 0xB2, 0x12, 0x57, 0xBD, 0xDF,
	};
	unsigned char p1[16] = { 0xfa };
	unsigned char *adata = NULL;
	long alen = 0;
	long keylen = sizeof(key);
	long ptlen = sizeof(pt);
	long ivlen = sizeof(iv);
	long taglen = sizeof(tag);
	long ctlen = sizeof(ct);
	long p1len = sizeof(p1);

	long r;
	
	printf("\nTesting %s...\n", testfn);

	r = GCM_Decrypt(p1, p1len, ct, ctlen, key, keylen, iv, ivlen, adata, alen, tag, taglen, 0);
	printf("GCM_Decrypt returns %ld\n", r);
	pr_hexdump("P'=", p1, p1len, "\n");
	assert(memcmp(pt, p1, ptlen) == 0);

	printf("Now expect an error..\n");
	memset(p1, 0xfa, p1len);
	pr_hexdump("Correct tag  =", tag, taglen, "\n");
	tag[0] = ~tag[0];
	pr_hexdump("Corrupted tag=", tag, taglen, "\n");
	r = GCM_Decrypt(p1, p1len, ct, ctlen, key, keylen, iv, ivlen, adata, alen, tag, taglen, 0);
	printf("GCM_Decrypt returns %ld: %s\n", r, lookup_error(r));
	assert(r != 0);
	pr_hexdump("P'=", p1, p1len, "\n");
	printf("..end of deliberate errors.\n");

	
	printf("...%s tested OK\n", testfn);
}

void test_GCM_GMAC(void)
{
    char *testfn = "GCM_GMAC()";
	/* Test case 13 - 256-bit key, GMAC only */
	unsigned char key[32] = { 0 };
	unsigned char iv[12] =  { 0 };
	unsigned char tag[16];
	unsigned char ok_tag[] = {
		0x53, 0x0F, 0x8A, 0xFB, 0xC7, 0x45, 0x36, 0xB9, 
		0xA9, 0x63, 0xB4, 0xF1, 0xC4, 0xCB, 0x73, 0x8B,
	};
	unsigned char *adata = NULL;
	long alen = 0;
	long keylen = sizeof(key);
	long ivlen = sizeof(iv);
	long taglen = sizeof(tag);
	long oktaglen = sizeof(ok_tag);
	long r;

	printf("\nTesting %s...\n", testfn);

	printf("Test case 13 = GMAC only, 256-bit key, empty message string.\n");
	pr_hexdump("K =", key, keylen, "\n");
	pr_hexdump("A =", adata, alen, "\n");
	pr_hexdump("IV=", iv, ivlen, "\n");
	r = GCM_Encrypt(NULL, 0, tag, taglen, NULL, 0, key, keylen, iv, ivlen, adata, alen, 0);
	pr_hexdump("GMAC('')=", tag, taglen, "\n");
	assert(memcmp(tag, ok_tag, oktaglen) == 0);
	
	printf("...%s tested OK\n", testfn);
}

/* CHANGED COMPLETELY IN [v6.22] */
void test_RNG_TestDRBGVS(void)
{
#define NRETBITS 2048
	char *testfn = "RNG_TestDRBGVS()";
	long result;
	char hexoutput[2048 * 2 / 8 + 1];
	const char *correct;

	printf("Testing %s...\n", testfn);

	/* drbgtestvectors/drbgvectors_pr_false/HMAC_DRBG.txt (line 22654)
	# CAVS 14.3
	# DRBG800-90A information for "drbg_pr"
	# Generated on Tue Apr 02 15:32:12 2013
	# 01d07d7a6b06314a6cb25c1230a8b28c10a17763fa0bb6674f1a0a126d4a267f5b34877ec693b66a03b46b505ed6de19c6180d0ade97a6a7832b5f3bc5169466

	[SHA-512]
	[PredictionResistance = False]
	[EntropyInputLen = 256]
	[NonceLen = 128]
	[PersonalizationStringLen = 256]
	[AdditionalInputLen = 256]
	[ReturnedBitsLen = 2048]

	COUNT = 0
	EntropyInput = da740cbc36057a8e282ae717fe7dfbb245e9e5d49908a0119c5dbcf0a1f2d5ab
	Nonce = 46561ff612217ba3ff91baa06d4b5440
	PersonalizationString = fc227293523ecb5b1e28c87863626627d958acc558a672b148ce19e2abd2dde4
	AdditionalInput = b7998998eaf9e5d34e64ff7f03de765b31f407899d20535573e670c1b402c26a
	EntropyInputReseed = 1d61d4d8a41c3254b92104fd555adae0569d1835bb52657ec7fbba0fe03579c5
	AdditionalInputReseed = b9ed8e35ad018a375b61189c8d365b00507cb1b4510d21cac212356b5bbaa8b2
	AdditionalInput = 2089d49d63e0c4df58879d0cb1ba998e5b3d1a7786b785e7cf13ca5ea5e33cfd
	ReturnedBits = 5b70f3e4da95264233efbab155b828d4e231b67cc92757feca407cc9615a660871cb07ad1a2e9a99412feda8ee34dc9c57fa08d3f8225b30d29887d20907d12330fffd14d1697ba0756d37491b0a8814106e46c8677d49d9157109c402ad0c247a2f50cd5d99e538c850b906937a05dbb8888d984bc77f6ca00b0e3bc97b16d6d25814a54aa12143afddd8b2263690565d545f4137e593bb3ca88a37b0aadf79726b95c61906257e6dc47acd5b6b7e4b534243b13c16ad5a0a1163c0099fce43f428cd27c3e6463cf5e9a9621f4b3d0b3d4654316f4707675df39278d5783823049477dcce8c57fdbd576711c91301e9bd6bb0d3e72dc46d480ed8f61fd63811
	*/

	result = RNG_TestDRBGVS(hexoutput, sizeof(hexoutput), NRETBITS,
		"da740cbc36057a8e282ae717fe7dfbb245e9e5d49908a0119c5dbcf0a1f2d5ab",
		"46561ff612217ba3ff91baa06d4b5440",
		"fc227293523ecb5b1e28c87863626627d958acc558a672b148ce19e2abd2dde4",
		"b7998998eaf9e5d34e64ff7f03de765b31f407899d20535573e670c1b402c26a",
		"1d61d4d8a41c3254b92104fd555adae0569d1835bb52657ec7fbba0fe03579c5",
		"b9ed8e35ad018a375b61189c8d365b00507cb1b4510d21cac212356b5bbaa8b2",
		"2089d49d63e0c4df58879d0cb1ba998e5b3d1a7786b785e7cf13ca5ea5e33cfd", 0);
	correct = "5b70f3e4da95264233efbab155b828d4e231b67cc92757feca407cc9615a660871cb07ad1a2e9a99412feda8ee34dc9c57fa08d3f8225b30d29887d20907d12330fffd14d1697ba0756d37491b0a8814106e46c8677d49d9157109c402ad0c247a2f50cd5d99e538c850b906937a05dbb8888d984bc77f6ca00b0e3bc97b16d6d25814a54aa12143afddd8b2263690565d545f4137e593bb3ca88a37b0aadf79726b95c61906257e6dc47acd5b6b7e4b534243b13c16ad5a0a1163c0099fce43f428cd27c3e6463cf5e9a9621f4b3d0b3d4654316f4707675df39278d5783823049477dcce8c57fdbd576711c91301e9bd6bb0d3e72dc46d480ed8f61fd63811";
	printf("RNG_TestDRBGVS returns %ld\n", result);
	assert(result > 0);
	printf("ReturnedBits = %s\n", hexoutput);
	assert(strcmp(hexoutput, correct) == 0);

	printf("...%s tested OK\n", testfn);
}


void test_HASH_HexFromBits(void)
{
    char *testfn = "HASH_HexFromBits()";

	long r;
	char szDigest[API_MAX_HASH_CHARS+1];
	unsigned char data_33[] = { 0x94, 0x09, 0xFF, 0xD0, 0x00, };
	unsigned char data_1[] = { 0x00, };
	unsigned char data_9[] = { 0x43, 0x00 };
	unsigned char data_31[] = { 0x8C, 0xCB, 0x08, 0xD2, };

	printf("\nTesting %s...\n", testfn);

	// SHA-1
	//	nerrs += process_bits_hash(33, "9409ffd000", "ba5704635712dd2e5ff5e7d5de0c66d5c21d6f3e");
	r = HASH_HexFromBits(szDigest, sizeof(szDigest)-1, data_33, 33, API_HASH_SHA1);
	assert(r > 0);
	printf("SHA1(9409ffd000:33)=%s\n", szDigest);
	assert(strcmp(szDigest, "ba5704635712dd2e5ff5e7d5de0c66d5c21d6f3e") == 0);

	// SHA-256
	// 	nerrs += process_bits_hash256(9, "4300", "b0f025fe6e4ac8fddd6e0fb2bf37b3c5773c9d3311d1aa2ce860d0fbef842f7f");
	r = HASH_HexFromBits(szDigest, sizeof(szDigest)-1, data_9, 9, API_HASH_SHA256);
	assert(r > 0);
	printf("SHA256(4300:9)=%s\n", szDigest);
	assert(strcmp(szDigest, "b0f025fe6e4ac8fddd6e0fb2bf37b3c5773c9d3311d1aa2ce860d0fbef842f7f") == 0);

	// SHA-512
	r = HASH_HexFromBits(szDigest, sizeof(szDigest)-1, data_31, 31, API_HASH_SHA512);
	assert(r > 0);
	printf("SHA512(8ccb08d2:31)=%s\n", szDigest);
	assert(strcmp(szDigest, "23661b4c1183789eb687e73a776ba07c88e71675914ee9740ce8ec6ac06370306f7849f6fcfea2c60484459910fe194df964f2f45435c94645fbff2cd60eafdc") == 0);

	
	printf("...%s tested OK\n", testfn);
}

void test_Stream_ChaCha20()
{
    char *testfn = "Stream_ChaCha20()";

	// ref: Nir & Langley
	BYTE key_chacha_sun[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
	};
	BYTE iv_chacha_sun[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4A, 
		0x00, 0x00, 0x00, 0x00,
	};
	BYTE *plain_chacha_sun = 
		"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

	BYTE correct_chacha_sun[] = {
		0x6E, 0x2E, 0x35, 0x9A, 0x25, 0x68, 0xF9, 0x80, 
		0x41, 0xBA, 0x07, 0x28, 0xDD, 0x0D, 0x69, 0x81, 
		0xE9, 0x7E, 0x7A, 0xEC, 0x1D, 0x43, 0x60, 0xC2, 
		0x0A, 0x27, 0xAF, 0xCC, 0xFD, 0x9F, 0xAE, 0x0B, 
		0xF9, 0x1B, 0x65, 0xC5, 0x52, 0x47, 0x33, 0xAB, 
		0x8F, 0x59, 0x3D, 0xAB, 0xCD, 0x62, 0xB3, 0x57, 
		0x16, 0x39, 0xD6, 0x24, 0xE6, 0x51, 0x52, 0xAB, 
		0x8F, 0x53, 0x0C, 0x35, 0x9F, 0x08, 0x61, 0xD8, 
		0x07, 0xCA, 0x0D, 0xBF, 0x50, 0x0D, 0x6A, 0x61, 
		0x56, 0xA3, 0x8E, 0x08, 0x8A, 0x22, 0xB6, 0x5E, 
		0x52, 0xBC, 0x51, 0x4D, 0x16, 0xCC, 0xF8, 0x06, 
		0x81, 0x8C, 0xE9, 0x1A, 0xB7, 0x79, 0x37, 0x36, 
		0x5A, 0xF9, 0x0B, 0xBF, 0x74, 0xA3, 0x5B, 0xE6, 
		0xB4, 0x0B, 0x8E, 0xED, 0xF2, 0x78, 0x5E, 0x42, 
		0x87, 0x4D,
	};
	long counter_chacha_sun = 1;
	long r, nbytes;
	BYTE *output;
	
	printf("\nTesting %s...\n", testfn);

	nbytes = (long)strlen(plain_chacha_sun); // NB we are using byte arrays, so no terminating zero
	output = malloc(nbytes);

	pr_hexdump("Key: ", key_chacha_sun, sizeof(key_chacha_sun), "\n");
	pr_hexdump("IV : ", iv_chacha_sun, sizeof(iv_chacha_sun), "\n");
	pr_hexdump("Plaintext:\n", plain_chacha_sun, nbytes, "\n");

	r = CIPHER_StreamBytes(output, plain_chacha_sun, nbytes, key_chacha_sun, sizeof(key_chacha_sun),
		iv_chacha_sun, sizeof(iv_chacha_sun), counter_chacha_sun, API_SC_CHACHA20);

	pr_hexdump("Ciphertext:\n", output, nbytes, "\n");

	printf("CIPHER_StreamBytes returns %ld (expecting 0)\n", r);
	assert(0 == memcmp(output, correct_chacha_sun, sizeof(correct_chacha_sun)));

	free(output);

	printf("...%s tested OK\n", testfn);

}

void test_MAC_Poly1305()
{

    char *testfn = "MAC_Poly1305()";

	/* Ref: draft-irtf-cfrg-chacha20-poly1305-06.txt */

	BYTE key1[] = {	// 2.5.2.  Poly1305 Example and Test Vector
		0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 
		0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8, 
		0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 
		0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b
	};
	BYTE msg1[] = { //Cryptographic Forum Research Group
		0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x67, 0x72, 
		0x61, 0x70, 0x68, 0x69, 0x63, 0x20, 0x46, 0x6f, 
		0x72, 0x75, 0x6d, 0x20, 0x52, 0x65, 0x73, 0x65, 
		0x61, 0x72, 0x63, 0x68, 0x20, 0x47, 0x72, 0x6f, 
		0x75, 0x70
	};
	BYTE tag1_ok[] = {
		0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 
		0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9	
	};

	long r;
	BYTE mac[API_POLY1305_BYTES];
	const int taglen = API_POLY1305_BYTES;

	printf("\nTesting %s...\n", testfn);

	pr_hexdump("Key: ", key1, sizeof(key1), "\n");
	pr_hexdump("Message to be authenticated:\n", msg1, sizeof(msg1), "\n");

	r = MAC_Bytes(mac, sizeof(mac), msg1, sizeof(msg1), key1, sizeof(key1), API_MAC_POLY1305);
	printf("MAC_Bytes(POLY1305) returns %ld (expecting %ld)\n", r, taglen);
	assert(taglen == r);
	pr_hexdump("Tag: ", mac, taglen, "\n");
	assert(0 == memcmp(mac, tag1_ok, taglen));

	printf("...%s tested OK\n", testfn);
}

void test_CIPHER_EncryptBytes()
{

    char *testfn = "CIPHER_EncryptBytes()";

	unsigned char key[] =  {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 
		0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87,
	};
	unsigned char iv[] = {
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
	};
	unsigned char plain[] = "Now is the time for all good men to";
	unsigned char correct_cbc[] = { // For "aes128/cbc/pkcs5padding"
		0xC3, 0x15, 0x31, 0x08, 0xA8, 0xDD, 0x34, 0x0C, 
		0x0B, 0xCB, 0x1D, 0xFE, 0x8D, 0x25, 0xD2, 0x32, 
		0x0E, 0xE0, 0xE6, 0x6B, 0xD2, 0xBB, 0x4A, 0x31, 
		0x3F, 0xB7, 0x5C, 0x56, 0x38, 0xE9, 0xE1, 0x77, 
		0x53, 0xC7, 0xE8, 0xDF, 0x59, 0x75, 0xA3, 0x66, 
		0x77, 0x35, 0x5F, 0x5C, 0x65, 0x84, 0x22, 0x8B,
	};
	unsigned char correct_ecb[] = {
		0xF0, 0xD1, 0xAD, 0x6F, 0x90, 0x1F, 0xFF, 0xAE, 
		0x55, 0x72, 0xA6, 0x92, 0x8D, 0xAB, 0x52, 0xB0, 
		0x64, 0xB2, 0x5C, 0x79, 0xF8, 0x76, 0x73, 0x03, 
		0x21, 0xE3, 0x6D, 0xC0, 0x10, 0x11, 0xAC, 0xCE, 
		0x7F, 0x1D, 0xBB, 0x0C, 0x8B, 0xC4, 0x95, 0x28, 
		0x48, 0xD3, 0x82, 0x49, 0x0E, 0x52, 0x0F, 0x60,
	};
	unsigned char correct_ctr[] = {
		0x3F, 0xAC, 0x68, 0xCB, 0xAE, 0x6D, 0x77, 0x41, 
		0x51, 0x30, 0x6E, 0x9D, 0xB1, 0x6C, 0xE0, 0x19, 
		0x1C, 0x51, 0xE9, 0x19, 0x59, 0xDA, 0x4F, 0x08, 
		0x2B, 0x7C, 0xE3, 0x49, 0x8C, 0x2D, 0x20, 0xD7, 
		0x84, 0x37, 0xEC,
	};
	unsigned char *pcipher;
	long plen, clen, dlen;

	printf("\nTesting %s...\n", testfn);

	pr_bytesmsg("KY=", key, sizeof(key));
	pr_bytesmsg("IV=", iv, sizeof(iv));
	printf("PT='%s'\n", plain);
	plen = (long)strlen(plain);
	printf("LEN(PT)=%d\n", plen);
	pr_bytesmsg("PT=", plain, plen);
	/* 1. Encrypt it into ciphertext */
	/* 1.1 Get required length */
	clen = CIPHER_EncryptBytes(NULL, 0, plain, plen, key, sizeof(key), iv, sizeof(iv), "aes128/cbc/pkcs5padding", 0);
	if (clen < 0) printf("Error code %ld\n", clen);
	assert (clen > 0);
	printf("AES128/CBC/PKCS5:\n");
	printf("LEN(PAD(PT))=%d\n", clen);
	/* 1.2 Allocate memory */
	pcipher = malloc(clen);
	/* 1.3 Do the business */
	clen = CIPHER_EncryptBytes(pcipher, clen, plain, plen, key, sizeof(key), iv, sizeof(iv), "aes128/cbc/pkcs5padding", 0);
	if (clen < 0) printf("Error code %ld\n", clen);
	pr_bytesmsg("CT=", pcipher, clen);
	pr_bytesmsg("OK=", correct_cbc, clen);
	assert (memcmp(correct_cbc, pcipher, sizeof(correct_cbc)) == 0);

	/* Now decipher (use same variable) */
	/* No need to check lengths before deciphering: output is never longer than input */
	dlen = CIPHER_DecryptBytes(pcipher, clen, pcipher, clen, key, sizeof(key), iv, sizeof(iv), "aes128/cbc/pkcs5padding", 0);
	assert (dlen == plen);
	pr_bytesmsg("P'=", pcipher, dlen);

	/* Check identical */
	assert (memcmp(plain, pcipher, dlen) == 0);
	free(pcipher);

	// SAME AGAIN USING FLAGS INSTEAD OF STRING

	printf("AES128/CBC/PKCS5 (flags):\n");
	clen = CIPHER_EncryptBytes(NULL, 0, plain, plen, key, sizeof(key), iv, sizeof(iv), "", API_BC_AES128 | API_MODE_CBC | API_PAD_PKCS5);
	if (clen < 0) printf("Error code %ld\n", clen);
	assert (clen > 0);
	printf("LEN(PAD(PT))=%d\n", clen);
	/* 1.2 Allocate memory */
	pcipher = malloc(clen);
	/* 1.3 Do the business */
	clen = CIPHER_EncryptBytes(pcipher, clen, plain, plen, key, sizeof(key), iv, sizeof(iv), "", API_BC_AES128 | API_MODE_CBC | API_PAD_PKCS5);
	if (clen < 0) printf("Error code %ld\n", clen);
	pr_bytesmsg("CT=", pcipher, clen);
	pr_bytesmsg("OK=", correct_cbc, clen);
	assert (memcmp(correct_cbc, pcipher, sizeof(correct_cbc)) == 0);

	/* Now decipher (use same variable) */
	/* No need to check lengths before deciphering: output is never longer than input */
	dlen = CIPHER_DecryptBytes(pcipher, clen, pcipher, clen, key, sizeof(key), iv, sizeof(iv), "", API_BC_AES128 | API_MODE_CBC | API_PAD_PKCS5);
	assert (dlen == plen);
	pr_bytesmsg("P'=", pcipher, dlen);

	/* Check identical */
	assert (memcmp(plain, pcipher, dlen) == 0);
	free(pcipher);

	// SAME AGAIN USING ECB MODE AND MIXED STRING AND FLAGS

	printf("AES128/ECB/PKCS5:\n");
	clen = CIPHER_EncryptBytes(NULL, 0, plain, plen, key, sizeof(key), iv, sizeof(iv), "", API_BC_AES128 | API_MODE_ECB | API_PAD_PKCS5);
	if (clen < 0) printf("Error code %ld\n", clen);
	assert (clen > 0);
	printf("LEN(PAD(PT))=%d\n", clen);
	/* 1.2 Allocate memory */
	pcipher = malloc(clen);
	/* 1.3 Do the business */
	clen = CIPHER_EncryptBytes(pcipher, clen, plain, plen, key, sizeof(key), iv, sizeof(iv), "aes128/ecb/pkcs5padding", 0);
	if (clen < 0) printf("Error code %ld\n", clen);
	pr_bytesmsg("CT=", pcipher, clen);
	pr_bytesmsg("OK=", correct_ecb, clen);
	assert (memcmp(correct_ecb, pcipher, sizeof(correct_ecb)) == 0);

	/* Now decipher (use same variable) */
	/* No need to check lengths before deciphering: output is never longer than input */
	dlen = CIPHER_DecryptBytes(pcipher, clen, pcipher, clen, key, sizeof(key), iv, sizeof(iv), "aes128/ecb/pkcs5padding", 0);
	assert (dlen == plen);
	pr_bytesmsg("P'=", pcipher, dlen);

	/* Check identical */
	assert (memcmp(plain, pcipher, dlen) == 0);
	free(pcipher);

	/* Encrypt with padding, decrypt without... */
	pcipher = malloc(clen);
	clen = CIPHER_EncryptBytes(pcipher, clen, plain, plen, key, sizeof(key), iv, sizeof(iv), "aes128/ecb/pkcs5padding", 0);
	if (clen < 0) printf("Error code %ld\n", clen);
	pr_bytesmsg("CT=", pcipher, clen);
	dlen = CIPHER_DecryptBytes(pcipher, clen, pcipher, clen, key, sizeof(key), iv, sizeof(iv), "aes128/ecb/nopadding", 0);
	pr_bytesmsg("P(nopad)=\n", pcipher, dlen);
	free(pcipher);


	// CHECK DEFAULT IS ECB/PKCS5PADDING

	printf("AES128 (+defaults):\n");
	clen = CIPHER_EncryptBytes(NULL, 0, plain, plen, key, sizeof(key), iv, sizeof(iv), "", API_BC_AES128);
	if (clen < 0) printf("Error code %ld\n", clen);
	assert (clen > 0);
	printf("LEN(PAD(PT))=%d\n", clen);
	/* 1.2 Allocate memory */
	pcipher = malloc(clen);
	/* 1.3 Do the business */
	clen = CIPHER_EncryptBytes(pcipher, clen, plain, plen, key, sizeof(key), iv, sizeof(iv), "aes128", 0);
	if (clen < 0) printf("Error code %ld\n", clen);
	pr_bytesmsg("CT=", pcipher, clen);
	pr_bytesmsg("OK=", correct_ecb, clen);
	assert (memcmp(correct_ecb, pcipher, sizeof(correct_ecb)) == 0);
	/* Decipher */
	dlen = CIPHER_DecryptBytes(pcipher, clen, pcipher, clen, key, sizeof(key), iv, sizeof(iv), "aes128", 0);
	assert (dlen == plen);
	pr_bytesmsg("P'=", pcipher, dlen);
	assert (memcmp(plain, pcipher, dlen) == 0);
	free(pcipher);

	// USE CTR MODE WITH DEFAULT PADDING (NOPADDING)

	clen = CIPHER_EncryptBytes(NULL, 0, plain, plen, key, sizeof(key), iv, sizeof(iv), "", API_BC_AES128 | API_MODE_CTR | API_PAD_DEFAULT);
	if (clen < 0) printf("Error code %ld\n", clen);
	assert (clen > 0);
	printf("AES128/CTR:\n");
	printf("LEN(PAD(PT))=%d\n", clen);
	/* 1.2 Allocate memory */
	pcipher = malloc(clen);
	/* 1.3 Do the business */
	clen = CIPHER_EncryptBytes(pcipher, clen, plain, plen, key, sizeof(key), iv, sizeof(iv), "aes128/ctr", 0);
	if (clen < 0) printf("Error code %ld\n", clen);
	pr_bytesmsg("CT=", pcipher, clen);
	pr_bytesmsg("OK=", correct_ctr, sizeof(correct_ctr));
	assert (memcmp(correct_ctr, pcipher, sizeof(correct_ctr)) == 0);

	/* Now decipher (use same variable) */
	/* No need to check lengths before deciphering: output is never longer than input */
	dlen = CIPHER_DecryptBytes(pcipher, clen, pcipher, clen, key, sizeof(key), iv, sizeof(iv), "aes128/ctr", 0);
	assert (dlen == plen);
	pr_bytesmsg("P'=", pcipher, dlen);

	/* Check identical */
	assert (memcmp(plain, pcipher, dlen) == 0);
	free(pcipher);

	printf("...%s tested OK\n", testfn);
}

/* AEAD FUNCTIONS */

void test_AEAD_Encrypt()
{

    char *testfn = "AEAD_Encrypt()";

	const char *title = "\nIEEE P802.1 MACsec 2.6.2 61-byte Packet Encryption Using GCM-AES-256:\n";

	int algo = API_AEAD_AES_256_GCM;
	BYTE key[] = {
		0x83, 0xC0, 0x93, 0xB5, 0x8D, 0xE7, 0xFF, 0xE1, 
		0xC0, 0xDA, 0x92, 0x6A, 0xC4, 0x3F, 0xB3, 0x60, 
		0x9A, 0xC1, 0xC8, 0x0F, 0xEE, 0x1B, 0x62, 0x44, 
		0x97, 0xEF, 0x94, 0x2E, 0x2F, 0x79, 0xA8, 0x23,
	};
	BYTE pt[] = {
		0x08, 0x00, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 
		0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 
		0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 
		0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 
		0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 
		0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x00, 
		0x06,
	};
	BYTE aad[] = {
		0x84, 0xC5, 0xD5, 0x13, 0xD2, 0xAA, 0xF6, 0xE5, 
		0xBB, 0xD2, 0x72, 0x77, 0x88, 0xE5, 0x2F, 0x00, 
		0x89, 0x32, 0xD6, 0x12, 0x7C, 0xFD, 0xE9, 0xF9, 
		0xE3, 0x37, 0x24, 0xC6,
	};
	BYTE nonce[] = {
		0x7C, 0xFD, 0xE9, 0xF9, 0xE3, 0x37, 0x24, 0xC6, 
		0x89, 0x32, 0xD6, 0x12,
	};
	BYTE ct_ok[] = {
		0x11, 0x02, 0x22, 0xFF, 0x80, 0x50, 0xCB, 0xEC, 
		0xE6, 0x6A, 0x81, 0x3A, 0xD0, 0x9A, 0x73, 0xED, 
		0x7A, 0x9A, 0x08, 0x9C, 0x10, 0x6B, 0x95, 0x93, 
		0x89, 0x16, 0x8E, 0xD6, 0xE8, 0x69, 0x8E, 0xA9, 
		0x02, 0xEB, 0x12, 0x77, 0xDB, 0xEC, 0x2E, 0x68, 
		0xE4, 0x73, 0x15, 0x5A, 0x15, 0xA7, 0xDA, 0xEE, 
		0xD4,
	};
	BYTE tag_ok[] = {
		0xA1, 0x0F, 0x4E, 0x05, 0x13, 0x9C, 0x23, 0xDF, 
		0x00, 0xB3, 0xAA, 0xDC, 0x71, 0xF0, 0x59, 0x6A,
	};

	BYTE tag[16];
	BYTE *ct;
	long klen, nlen, alen, ptlen; 
	long taglen, ctlen;
	long r;

	printf("\nTesting %s...\n", testfn);

	/* Get and set lengths of byte arrays */
	klen = sizeof(key);
	nlen = sizeof(nonce);
	alen = sizeof(aad);
	ptlen = sizeof(pt);
	ctlen = ptlen;
	taglen = sizeof(tag);

	/* Allocate output */
	ct = malloc(ctlen);
	assert(ct);

	/* Display input info */
	printf("%s", title);
	pr_hexdump("K: ", key, klen, "\n");
	pr_hexdump("N: ", nonce, alen, "\n");
	pr_hexdump("A: ", aad, alen, "\n");
	pr_hexdump("P:\n", pt, ptlen, "\n");

	/* Encrypt: PT + AAD -> CT + Tag */
	r = AEAD_Encrypt(ct, ctlen, tag, taglen, pt, ptlen, 
		key, klen, nonce, nlen, aad, alen, API_AEAD_AES_256_GCM);

	printf("AEAD_Encrypt(API_AEAD_AES_256_GCM) returns %ld (expecting 0)\n", r);
	assert(0 == r);
	pr_hexdump("C:\n", ct, ctlen, "\n");
	pr_hexdump("T: ", tag, taglen, "\n");

	/* Check we got the expected results */
	assert (memcmp(ct, ct_ok, ctlen) == 0);
	assert (memcmp(tag, tag_ok, taglen) == 0);

	/* Free resources */
	free(ct);

	printf("...%s tested OK\n", testfn);

}

void test_AEAD_Decrypt(void)
{
    char *testfn = "AEAD_Decrypt()";
	// Ref: RFC 7539 Appendix A.5

	BYTE key[] = {
		0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
		0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0,	
	};
	BYTE ct[] = {
		0x64, 0xa0, 0x86, 0x15, 0x75, 0x86, 0x1a, 0xf4, 0x60, 0xf0, 0x62, 0xc7, 0x9b, 0xe6, 0x43, 0xbd,
		0x5e, 0x80, 0x5c, 0xfd, 0x34, 0x5c, 0xf3, 0x89, 0xf1, 0x08, 0x67, 0x0a, 0xc7, 0x6c, 0x8c, 0xb2,
		0x4c, 0x6c, 0xfc, 0x18, 0x75, 0x5d, 0x43, 0xee, 0xa0, 0x9e, 0xe9, 0x4e, 0x38, 0x2d, 0x26, 0xb0,
		0xbd, 0xb7, 0xb7, 0x3c, 0x32, 0x1b, 0x01, 0x00, 0xd4, 0xf0, 0x3b, 0x7f, 0x35, 0x58, 0x94, 0xcf,
		0x33, 0x2f, 0x83, 0x0e, 0x71, 0x0b, 0x97, 0xce, 0x98, 0xc8, 0xa8, 0x4a, 0xbd, 0x0b, 0x94, 0x81,
		0x14, 0xad, 0x17, 0x6e, 0x00, 0x8d, 0x33, 0xbd, 0x60, 0xf9, 0x82, 0xb1, 0xff, 0x37, 0xc8, 0x55,
		0x97, 0x97, 0xa0, 0x6e, 0xf4, 0xf0, 0xef, 0x61, 0xc1, 0x86, 0x32, 0x4e, 0x2b, 0x35, 0x06, 0x38,
		0x36, 0x06, 0x90, 0x7b, 0x6a, 0x7c, 0x02, 0xb0, 0xf9, 0xf6, 0x15, 0x7b, 0x53, 0xc8, 0x67, 0xe4,
		0xb9, 0x16, 0x6c, 0x76, 0x7b, 0x80, 0x4d, 0x46, 0xa5, 0x9b, 0x52, 0x16, 0xcd, 0xe7, 0xa4, 0xe9,
		0x90, 0x40, 0xc5, 0xa4, 0x04, 0x33, 0x22, 0x5e, 0xe2, 0x82, 0xa1, 0xb0, 0xa0, 0x6c, 0x52, 0x3e,
		0xaf, 0x45, 0x34, 0xd7, 0xf8, 0x3f, 0xa1, 0x15, 0x5b, 0x00, 0x47, 0x71, 0x8c, 0xbc, 0x54, 0x6a,
		0x0d, 0x07, 0x2b, 0x04, 0xb3, 0x56, 0x4e, 0xea, 0x1b, 0x42, 0x22, 0x73, 0xf5, 0x48, 0x27, 0x1a,
		0x0b, 0xb2, 0x31, 0x60, 0x53, 0xfa, 0x76, 0x99, 0x19, 0x55, 0xeb, 0xd6, 0x31, 0x59, 0x43, 0x4e,
		0xce, 0xbb, 0x4e, 0x46, 0x6d, 0xae, 0x5a, 0x10, 0x73, 0xa6, 0x72, 0x76, 0x27, 0x09, 0x7a, 0x10,
		0x49, 0xe6, 0x17, 0xd9, 0x1d, 0x36, 0x10, 0x94, 0xfa, 0x68, 0xf0, 0xff, 0x77, 0x98, 0x71, 0x30,
		0x30, 0x5b, 0xea, 0xba, 0x2e, 0xda, 0x04, 0xdf, 0x99, 0x7b, 0x71, 0x4d, 0x6c, 0x6f, 0x2c, 0x29,
		0xa6, 0xad, 0x5c, 0xb4, 0x02, 0x2b, 0x02, 0x70, 0x9b,
	};
	BYTE nonce[] = {
		0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,	
	};
	BYTE aad[] = {
		0xf3, 0x33, 0x88, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4e, 0x91,
	};
	BYTE tag[] = {
		0xee, 0xad, 0x9d, 0x67, 0x89, 0x0c, 0xbb, 0x22, 0x39, 0x23, 0x36, 0xfe, 0xa1, 0x85, 0x1f, 0x38,
	};
	BYTE pt_ok[] = {
		0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2d, 0x44, 0x72, 0x61, 0x66, 0x74, 0x73, 0x20,
		0x61, 0x72, 0x65, 0x20, 0x64, 0x72, 0x61, 0x66, 0x74, 0x20, 0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65,
		0x6e, 0x74, 0x73, 0x20, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x61, 0x20,
		0x6d, 0x61, 0x78, 0x69, 0x6d, 0x75, 0x6d, 0x20, 0x6f, 0x66, 0x20, 0x73, 0x69, 0x78, 0x20, 0x6d,
		0x6f, 0x6e, 0x74, 0x68, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x6d, 0x61, 0x79, 0x20, 0x62, 0x65,
		0x20, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x2c, 0x20, 0x72, 0x65, 0x70, 0x6c, 0x61, 0x63,
		0x65, 0x64, 0x2c, 0x20, 0x6f, 0x72, 0x20, 0x6f, 0x62, 0x73, 0x6f, 0x6c, 0x65, 0x74, 0x65, 0x64,
		0x20, 0x62, 0x79, 0x20, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x20, 0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65,
		0x6e, 0x74, 0x73, 0x20, 0x61, 0x74, 0x20, 0x61, 0x6e, 0x79, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x2e,
		0x20, 0x49, 0x74, 0x20, 0x69, 0x73, 0x20, 0x69, 0x6e, 0x61, 0x70, 0x70, 0x72, 0x6f, 0x70, 0x72,
		0x69, 0x61, 0x74, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x75, 0x73, 0x65, 0x20, 0x49, 0x6e, 0x74, 0x65,
		0x72, 0x6e, 0x65, 0x74, 0x2d, 0x44, 0x72, 0x61, 0x66, 0x74, 0x73, 0x20, 0x61, 0x73, 0x20, 0x72,
		0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x20, 0x6d, 0x61, 0x74, 0x65, 0x72, 0x69, 0x61,
		0x6c, 0x20, 0x6f, 0x72, 0x20, 0x74, 0x6f, 0x20, 0x63, 0x69, 0x74, 0x65, 0x20, 0x74, 0x68, 0x65,
		0x6d, 0x20, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x20, 0x74, 0x68, 0x61, 0x6e, 0x20, 0x61, 0x73, 0x20,
		0x2f, 0xe2, 0x80, 0x9c, 0x77, 0x6f, 0x72, 0x6b, 0x20, 0x69, 0x6e, 0x20, 0x70, 0x72, 0x6f, 0x67,
		0x72, 0x65, 0x73, 0x73, 0x2e, 0x2f, 0xe2, 0x80, 0x9d,
	};

	// We are decrypting
	unsigned char pt[sizeof(ct)];
	long plen, klen, nlen, alen, clen, tlen;
	long r;

	printf("\nTesting %s...\n", testfn);

	clen = sizeof(ct);
	klen = sizeof(key);
	nlen = sizeof(nonce);
	alen = sizeof(aad);
	tlen = sizeof(tag);

	plen = clen;

	printf("\nDECRYPTING...\n");
	pr_hexdump("K: ", key, klen, "\n");
	pr_hexdump("N: ", nonce, nlen, "\n");
	pr_hexdump("A: ", aad, alen, "\n");
	pr_hexdump("C:\n", ct, clen, "\n");

	r = AEAD_Decrypt(pt, plen, ct, clen,
		key, klen, nonce, nlen, aad, alen, tag, tlen, API_AEAD_CHACHA20_POLY1305);

	printf("AEAD_Decrypt(AEAD_CHACHA20_POLY1305) returns %ld (expected 0)\n", r);
	assert(0 == r);	// Tag is valid

	pr_hexdump("P:\n", pt, plen, "\n");
	assert (memcmp(pt, pt_ok, clen) == 0);
	
	printf("...%s tested OK\n", testfn);
}

void test_AEAD_InitKey(void)
{
    char *testfn = "AEAD_InitKey()";

	unsigned char key[32];
	unsigned char nonce[12];
	unsigned char aad[12];
	unsigned char tag[16];
	unsigned char *pt, *ct;
	long klen, nlen, alen, ptlen, ctlen, taglen;
	long r, hContext;
	long n, offset, nleft;
	char *pthex = "4C616469657320616E642047656E746C656D656E206F662074686520636C617373206F66202739393A204966204920636F756C64206F6666657220796F75206F6E6C79206F6E652074697020666F7220746865206675747572652C2073756E73637265656E20776F756C642062652069742E";
	unsigned char tag_ok[] = {
		0x1A, 0xE1, 0x0B, 0x59, 0x4F, 0x09, 0xE2, 0x6A, 
		0x7E, 0x90, 0x2E, 0xCB, 0xD0, 0x60, 0x06, 0x91,
	};
	
	printf("\nTesting %s...\n", testfn);

	printf("RFC7739 ChaCha20_Poly1305 Sunscreen test:\n");

	// Set byte arrays and lengths from hex strings
	klen = convert_hex_to_bytes(key, sizeof(key), "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F");
	nlen = convert_hex_to_bytes(nonce, sizeof(nonce), "070000004041424344454647");
	alen = convert_hex_to_bytes(aad, sizeof(aad), "50515253C0C1C2C3C4C5C6C7");

	// Allocate memory for plaintext
	ptlen = (long)strlen(pthex) / 2;
	pt = malloc(ptlen);
	assert(pt);
	ptlen = convert_hex_to_bytes(pt, ptlen, pthex);

	// Display input
	pr_hexdump("K: ", key, klen, "\n");
	pr_hexdump("N: ", nonce, nlen, "\n");
	pr_hexdump("A: ", aad, alen, "\n");
	pr_hexdump("P-all:\n", pt, ptlen, "\n");

	// Allocate memory for output
	ctlen = ptlen;
	ct = malloc(ctlen);
	assert(ct);
	taglen = sizeof(tag);

	// Do authenticated encryption using AEAD_CHACHA20_POLY1305
	// 1.1 Initialize with the key and AEAD algorithm
	hContext = AEAD_InitKey(key, klen, API_AEAD_CHACHA20_POLY1305);
	printf("AEAD_InitKey returns %#08X (expecting nonzero)\n", hContext);
	assert(hContext != 0);

	// 1.2 Set the nonce
	r = AEAD_SetNonce(hContext, nonce, nlen);
	assert(0 == r);

	// 1.3 Add the AAD (simulate adding in two parts)
	n = alen / 2;
	offset = 0;
	r = AEAD_AddAAD(hContext, &aad[offset], n);
	assert(0 == r);
	offset = n;
	n = alen - n;
	r = AEAD_AddAAD(hContext, &aad[offset], n);
	assert(0 == r);

	// 1.4 Start Encrypting
	r = AEAD_StartEncrypt(hContext);
	assert(0 == r);

	// 1.5 Update plaintext -> ciphertext (simulate adding in chunks)
	printf("Updating plaintext in chunks...\n");
	n = 17;
	nleft = ptlen;
	offset = 0;
	while (nleft > 0) {
		if (nleft < n) n = nleft;
		// Update another chunk of plaintext
		pr_hexdump("P-chunk: ", &pt[offset], n, "\n");
		r = AEAD_Update(hContext, &ct[offset], n, &pt[offset], n);
		assert(0 == r);
		pr_hexdump("C-chunk: ", &ct[offset], n, "\n");
		offset += n;
		nleft -= n;
	}

	// 1.6 Finish encrypting and output Tag
	r = AEAD_FinishEncrypt(hContext, tag, taglen);
	assert(0 == r);
	pr_hexdump("C-all:\n", ct, ctlen, "\n");
	pr_hexdump("T: ", tag, taglen, "\n");
	assert (memcmp(tag, tag_ok, taglen) == 0);

	// NOW DECRYPT...
	printf("DECRYPTING...\n");
	// 2.1 Use key we initialized with in step 1.1
	// 2.2 Set Nonce
	r = AEAD_SetNonce(hContext, nonce, nlen);
	assert(0 == r);
	// 2.3 Add AAD (this time in one go)
	r = AEAD_AddAAD(hContext, aad, alen);
	assert(0 == r);
	// 2.4 Start decrypting using Tag we just made
	r = AEAD_StartDecrypt(hContext, tag, taglen);
	assert(0 == r);

	// 2.5 Update with ciphertext -> plaintext (simulate adding in chunks)
	printf("Updating ciphertext in chunks...\n");
	n = 13;
	nleft = ptlen;
	offset = 0;
	while (nleft > 0) {
		if (nleft < n) n = nleft;
		// Update chunk of ciphertext in situ
		pr_hexdump("C-chunk: ", &ct[offset], n, "\n");
		r = AEAD_Update(hContext, &ct[offset], n, &ct[offset], n);
		assert(0 == r);
		pr_hexdump("P-chunk: ", &ct[offset], n, "\n");
		offset += n;
		nleft -= n;
	}
	// Note: treat plaintext output as suspect until authenticated by FinishDecrypt
	pr_hexdump("P-all:\n", ct, ctlen, "\n");

	// 2.6 Finish decrypting and check OK|FAIL
	r = AEAD_FinishDecrypt(hContext);
	printf("AEAD_FinishDecrypt returns %ld (0 => OK)\n", r);
	assert(0 == r);

	// 3. We are done with the key so destroy it
	r = AEAD_Destroy(hContext);
	printf("AEAD_Destroy returns %ld (expecting 0)\n", r);
	assert(0 == r);

	// Clean up
	free(pt);
	free(ct);

	printf("...%s tested OK\n", testfn);
}

/* GENERIC CIPHER FUNCTIONS */

void test_CIPHER_FileEncrypt(void)
{
	char *testfn = "CIPHER_FileEncrypt()";
	long r;
	char *filein, *fileenc, *filechk, *fileckn;
	BYTE key[] = {
		0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
		0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
	};
	BYTE badkey[] = {
		0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
		0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0xFF,
	};
	BYTE iv[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	};
	char *amps[] = {
		"Aes128/CBC",
		"Aes128/CBC/pkcs5",
		"Aes128/CBC/oneandzeroes",
		"Aes128/CBC/ansix923",
		"Aes128/CBC/w3cpadding",
	};
	char *algmodepad2 = "Aes128/CBC/NoPad";
	char *algmodepad;
	int i, nelems;
	long flen;

	printf("\nTesting %s...\n", testfn);

	filein = "abc.txt";
	fileenc = "file-enc.dat";
	filechk = "file-chk.dat";
	fileckn = "file-ckn.dat";
	create_abc_file(filein);


	nelems = sizeof(amps) / sizeof(amps[0]);
	printf("Tests=%d\n", nelems);
	for (i = 0; i < nelems; i++) {
		algmodepad = amps[i];
		printf("\n%s:\n", algmodepad);
		r = CIPHER_FileEncrypt(fileenc, filein, key, sizeof(key), iv, sizeof(iv), algmodepad, 0);
		printf("CIPHER_FileEncrypt() returns %ld\n", r);
		assert(0 == r);
		flen = file_length(fileenc);
		printf("Enc file length = %ld\n", flen);

		// Decrypt with expected padding
		r = CIPHER_FileDecrypt(filechk, fileenc, key, sizeof(key), iv, sizeof(iv), algmodepad, 0);
		printf("CIPHER_FileDecrypt() returns %ld\n", r);
		assert(0 == r);
		pr_file_as_hex("Decrypt unpad: '", filechk, "'\n");

		// Decrypt with NoPadding
		r = CIPHER_FileDecrypt(fileckn, fileenc, key, sizeof(key), iv, sizeof(iv), algmodepad2, 0);
		printf("CIPHER_FileDecrypt() returns %ld\n", r);
		assert(0 == r);
		pr_file_as_hex("Decrypt NoPad: ", fileckn, "\n");

		// Decrypt with the wrong key and catch the error
		r = CIPHER_FileDecrypt(filechk, fileenc, badkey, sizeof(badkey), iv, sizeof(iv), algmodepad, 0);
		printf("CIPHER_FileDecrypt(badkey) returns %ld (expecting error)\n", r);
		disp_error(r);
		assert(r != 0);

		// Encrypt and prepend the IV
		r = CIPHER_FileEncrypt(fileenc, filein, key, sizeof(key), iv, sizeof(iv), algmodepad, API_IV_PREFIX);
		printf("CIPHER_FileEncrypt(IV_PREFIX) returns %ld\n", r);
		assert(0 == r);
		flen = file_length(fileenc);
		printf("Enc file length = %ld\n", flen);

		// Decrypt with expected padding, using the prepended IV (and passing a NULL IV parameter)
		r = CIPHER_FileDecrypt(filechk, fileenc, key, sizeof(key), NULL, 0, algmodepad, API_IV_PREFIX);
		printf("CIPHER_FileDecrypt(IV_PREFIX) returns %ld\n", r);
		assert(0 == r);
		pr_file_as_hex("Decrypt unpad: '", filechk, "'\n");


	}

	printf("...%s tested OK\n", testfn);
}

static int scrypt_test(unsigned char *dk, long dkLen, const unsigned char *pwd, long pwdLen,
	unsigned char *salt, long saltLen, long N, long r, long p, const unsigned char *correct)
{
	long result;

	printf("scrypt (P=\"%s\", S=\"%s\", N=%d, r=%d, p=%d, dkLen=%d) =\n", pwd, salt, N, r, p, dkLen);

	result = PBE_Scrypt(dk, dkLen, pwd, pwdLen, salt, saltLen, N, r, p, 0);
	if (result != 0) {
		printf("ERROR: scrypt returns %ld\n", result);
		return 0;	// FAIL
	}
	pr_hexdump("", dk, dkLen, "\n");
	pr_hexdump("Correct=\n", correct, dkLen, "\n");
	result = (memcmp(dk, correct, dkLen) == 0);
	if (!result) {
		printf("<==ERROR!\n");
		return 0;
	}
	return 1;
}

/* SCRYPT TESTS */

void test_PBE_Scrypt()
{
	char *testfn = "PBE_Scrypt()";
	unsigned char dk[64];
	unsigned char *pwd;
	unsigned char *salt;
	long dkLen, pwdLen, saltLen;
	long N, r, p;
	int ret;

	// TEST 1
	/*
	scrypt (P="", S="",
	N=16, r=1, p=1, dklen=64) =
	77 d6 57 62 38 65 7b 20 3b 19 ca 42 c1 8a 04 97
	f1 6b 48 44 e3 07 4a e8 df df fa 3f ed e2 14 42
	fc d0 06 9d ed 09 48 f8 32 6a 75 3a 0f c8 1f 17
	e8 d3 e0 fb 2e 0d 36 28 cf 35 e2 0c 38 d1 89 06
	*/
	unsigned char correct1[] = {
		0x77, 0xD6, 0x57, 0x62, 0x38, 0x65, 0x7B, 0x20,
		0x3B, 0x19, 0xCA, 0x42, 0xC1, 0x8A, 0x04, 0x97,
		0xF1, 0x6B, 0x48, 0x44, 0xE3, 0x07, 0x4A, 0xE8,
		0xDF, 0xDF, 0xFA, 0x3F, 0xED, 0xE2, 0x14, 0x42,
		0xFC, 0xD0, 0x06, 0x9D, 0xED, 0x09, 0x48, 0xF8,
		0x32, 0x6A, 0x75, 0x3A, 0x0F, 0xC8, 0x1F, 0x17,
		0xE8, 0xD3, 0xE0, 0xFB, 0x2E, 0x0D, 0x36, 0x28,
		0xCF, 0x35, 0xE2, 0x0C, 0x38, 0xD1, 0x89, 0x06,
	};

	printf("Testing %s...\n", testfn);

	dkLen = sizeof(dk);
	pwd = "";
	salt = "";
	N = 16;
	r = 1;
	p = 1;
	pwdLen = (long)strlen(pwd);
	saltLen = (long)strlen(salt);
	ret = scrypt_test(dk, dkLen, pwd, pwdLen, salt, saltLen, N, r, p, correct1);
	assert(ret);
	assert(0 == memcmp(dk, correct1, sizeof(correct1)));

	// TEST 2
	/*
	scrypt (P="password", S="NaCl",
	N=1024, r=8, p=16, dkLen=64) =
	fd ba be 1c 9d 34 72 00 78 56 e7 19 0d 01 e9 fe
	7c 6a d7 cb c8 23 78 30 e7 73 76 63 4b 37 31 62
	2e af 30 d9 2e 22 a3 88 6f f1 09 27 9d 98 30 da
	c7 27 af b9 4a 83 ee 6d 83 60 cb df a2 cc 06 40
	*/
	unsigned char correct2[] = {
		0xFD, 0xBA, 0xBE, 0x1C, 0x9D, 0x34, 0x72, 0x00,
		0x78, 0x56, 0xE7, 0x19, 0x0D, 0x01, 0xE9, 0xFE,
		0x7C, 0x6A, 0xD7, 0xCB, 0xC8, 0x23, 0x78, 0x30,
		0xE7, 0x73, 0x76, 0x63, 0x4B, 0x37, 0x31, 0x62,
		0x2E, 0xAF, 0x30, 0xD9, 0x2E, 0x22, 0xA3, 0x88,
		0x6F, 0xF1, 0x09, 0x27, 0x9D, 0x98, 0x30, 0xDA,
		0xC7, 0x27, 0xAF, 0xB9, 0x4A, 0x83, 0xEE, 0x6D,
		0x83, 0x60, 0xCB, 0xDF, 0xA2, 0xCC, 0x06, 0x40,
	};
	dkLen = sizeof(dk);
	pwd = "password";
	salt = "NaCl";
	N = 1024;
	r = 8;
	p = 16;
	pwdLen = (long)strlen(pwd);
	saltLen = (long)strlen(salt);
	ret = scrypt_test(dk, dkLen, pwd, pwdLen, salt, saltLen, N, r, p, correct2);
	assert(ret);
	assert(0 == memcmp(dk, correct2, sizeof(correct2)));

	// TEST 3
	/*
	scrypt (P="pleaseletmein", S="SodiumChloride",
	N=16384, r=8, p=1, dkLen=64) =
	70 23 bd cb 3a fd 73 48 46 1c 06 cd 81 fd 38 eb
	fd a8 fb ba 90 4f 8e 3e a9 b5 43 f6 54 5d a1 f2
	d5 43 29 55 61 3f 0f cf 62 d4 97 05 24 2a 9a f9
	e6 1e 85 dc 0d 65 1e 40 df cf 01 7b 45 57 58 87
	*/
	unsigned char correct3[] = {
		0x70, 0x23, 0xBD, 0xCB, 0x3A, 0xFD, 0x73, 0x48,
		0x46, 0x1C, 0x06, 0xCD, 0x81, 0xFD, 0x38, 0xEB,
		0xFD, 0xA8, 0xFB, 0xBA, 0x90, 0x4F, 0x8E, 0x3E,
		0xA9, 0xB5, 0x43, 0xF6, 0x54, 0x5D, 0xA1, 0xF2,
		0xD5, 0x43, 0x29, 0x55, 0x61, 0x3F, 0x0F, 0xCF,
		0x62, 0xD4, 0x97, 0x05, 0x24, 0x2A, 0x9A, 0xF9,
		0xE6, 0x1E, 0x85, 0xDC, 0x0D, 0x65, 0x1E, 0x40,
		0xDF, 0xCF, 0x01, 0x7B, 0x45, 0x57, 0x58, 0x87,
	};
	dkLen = sizeof(dk);
	pwd = "pleaseletmein";
	salt = "SodiumChloride";
	N = 16384;
	r = 8;
	p = 1;
	pwdLen = (long)strlen(pwd);
	saltLen = (long)strlen(salt);
	ret = scrypt_test(dk, dkLen, pwd, pwdLen, salt, saltLen, N, r, p, correct3);
	assert(ret);
	assert(0 == memcmp(dk, correct3, sizeof(correct3)));

#if 0
	// These take a long time...
	// TEST 4
	/*
	scrypt (P="pleaseletmein", S="SodiumChloride",
	N=1048576, r=8, p=1, dkLen=64) =
	21 01 cb 9b 6a 51 1a ae ad db be 09 cf 70 f8 81
	ec 56 8d 57 4a 2f fd 4d ab e5 ee 98 20 ad aa 47
	8e 56 fd 8f 4b a5 d0 9f fa 1c 6d 92 7c 40 f4 c3
	37 30 40 49 e8 a9 52 fb cb f4 5c 6f a7 7a 41 a4
	*/
	unsigned char correct4[] = {
		0x21, 0x01, 0xCB, 0x9B, 0x6A, 0x51, 0x1A, 0xAE,
		0xAD, 0xDB, 0xBE, 0x09, 0xCF, 0x70, 0xF8, 0x81,
		0xEC, 0x56, 0x8D, 0x57, 0x4A, 0x2F, 0xFD, 0x4D,
		0xAB, 0xE5, 0xEE, 0x98, 0x20, 0xAD, 0xAA, 0x47,
		0x8E, 0x56, 0xFD, 0x8F, 0x4B, 0xA5, 0xD0, 0x9F,
		0xFA, 0x1C, 0x6D, 0x92, 0x7C, 0x40, 0xF4, 0xC3,
		0x37, 0x30, 0x40, 0x49, 0xE8, 0xA9, 0x52, 0xFB,
		0xCB, 0xF4, 0x5C, 0x6F, 0xA7, 0x7A, 0x41, 0xA4,
	};
	dkLen = sizeof(dk);
	pwd = "pleaseletmein";
	salt = "SodiumChloride";
	N = 1048576;
	r = 8;
	p = 1;
	pwdLen = (long)strlen(pwd);
	saltLen = (long)strlen(salt);
	ret = scrypt_test(dk, dkLen, pwd, pwdLen, salt, saltLen, N, r, p, correct4);
	assert(ret);
	assert(0 == memcmp(dk, correct4, sizeof(correct4)));

	// TEST 5
	/*
	The password is "Rabbit" (without the quotes) with N=1048576, r=8 and
	p=1.  The salt is "Mouse" and the encryption algorithm used is
	aes256-CBC.  The derived key is: E2 77 EA 2C AC B2 3E DA-FC 03 9D 22
	9B 79 DC 13 EC ED B6 01 D9 9B 18 2A-9F ED BA 1E 2B FB 4F 58.
	*/
	unsigned char correct5[] = {
		0xE2, 0x77, 0xEA, 0x2C, 0xAC, 0xB2, 0x3E, 0xDA,
		0xFC, 0x03, 0x9D, 0x22, 0x9B, 0x79, 0xDC, 0x13,
		0xEC, 0xED, 0xB6, 0x01, 0xD9, 0x9B, 0x18, 0x2A,
		0x9F, 0xED, 0xBA, 0x1E, 0x2B, 0xFB, 0x4F, 0x58,
	};
	dkLen = 32;
	pwd = "Rabbit";
	salt = "Mouse";
	N = 1048576;
	r = 8;
	p = 1;
	pwdLen = (long)strlen(pwd);
	saltLen = (long)strlen(salt);
	ret = scrypt_test(dk, dkLen, pwd, pwdLen, salt, saltLen, N, r, p, correct5);
	assert(ret);
	assert(0 == memcmp(dk, correct5, sizeof(correct5)));
#endif

	printf("...%s tested OK\n", testfn);

}

void test_PBE_ScryptHex()
{
	char *testfn = "PBE_ScryptHex()";
	long N, r, p, dkLen;
	const char *P = "password";
	char *salthex = "4E61436C";	// "NaCl"
	char *correcthex = "FDBABE1C9D3472007856E7190D01E9FE7C6AD7CBC8237830E77376634B3731622EAF30D92E22A3886FF109279D9830DAC727AFB94A83EE6D8360CBDFA2CC0640";
	char dkhex[64 * 2 + 1] = { 0 };
	int result;

	/*
	scrypt (P="password", S="NaCl",
	N=1024, r=8, p=16, dkLen=64) =
	fd ba be 1c 9d 34 72 00 78 56 e7 19 0d 01 e9 fe
	7c 6a d7 cb c8 23 78 30 e7 73 76 63 4b 37 31 62
	2e af 30 d9 2e 22 a3 88 6f f1 09 27 9d 98 30 da
	c7 27 af b9 4a 83 ee 6d 83 60 cb df a2 cc 06 40
	*/

	printf("Testing %s...\n", testfn);

	N = 1024;
	r = 8;
	p = 16;
	dkLen = 64;

	/* Now test the hex version */
	result = PBE_ScryptHex(dkhex, sizeof(dkhex) - 1, dkLen, P, salthex, N, r, p, 0);
	printf("PBE_ScryptHex returns %ld\n", result);
	assert(result == 0);
	printf("Result =%s\n", dkhex);
	printf("Correct=%s\n", correcthex);
	assert(stricmp(dkhex, correcthex) == 0);

	/*
	scrypt (P="pleaseletmein", S="SodiumChloride",
	N=16384, r=8, p=1, dkLen=64) =
	70 23 bd cb 3a fd 73 48 46 1c 06 cd 81 fd 38 eb
	fd a8 fb ba 90 4f 8e 3e a9 b5 43 f6 54 5d a1 f2
	d5 43 29 55 61 3f 0f cf 62 d4 97 05 24 2a 9a f9
	e6 1e 85 dc 0d 65 1e 40 df cf 01 7b 45 57 58 87
	*/
	P = "pleaseletmein";
	salthex = "536F6469756D43686C6F72696465";	// "SodiumChloride"
	N = 16384;
	r = 8;
	p = 1;
	dkLen = 64;
	correcthex = "7023BDCB3AFD7348461C06CD81FD38EBFDA8FBBA904F8E3EA9B543F6545DA1F2D5432955613F0FCF62D49705242A9AF9E61E85DC0D651E40DFCF017B45575887";
	result = PBE_ScryptHex(dkhex, sizeof(dkhex) - 1, dkLen, P, salthex, N, r, p, 0);
	printf("PBE_ScryptHex returns %ld\n", result);
	assert(result == 0);
	printf("Result =%s\n", dkhex);
	printf("Correct=%s\n", correcthex);
	assert(stricmp(dkhex, correcthex) == 0);

	printf("...%s tested OK\n", testfn);
}

/* PADDING TESTS */

void test_PAD_BytesBlock(void)
{
	char *testfn = "PAD_BytesBlock()";

	unsigned char input[] = { 0xFF, 0xFF, 0xFF };
	unsigned char *output;
	long inlen, outlen, blklen;
	long pads[] = { 0, API_PAD_AX923, API_PAD_1ZERO };
	long padopts;
	int pi;
	int npads = sizeof(pads) / sizeof(pads[0]);

	printf("Testing %s...\n", testfn);

	for (pi = 0; pi < npads; pi++) {
		padopts = pads[pi];
		printf("PADDING=%#x\n", padopts);

		blklen = 8;
		inlen = sizeof(input);
		outlen = PAD_BytesBlock(NULL, 0, input, inlen, blklen, padopts);
		printf("PAD_BytesBlock(%ld) returns %2ld :", inlen, outlen);
		output = malloc(outlen);
		outlen = PAD_BytesBlock(output, outlen, input, inlen, blklen, padopts);
		pr_hexbytes(output, outlen);
		/* Now unpad */
		outlen = PAD_UnpadBytes(output, outlen, output, outlen, blklen, padopts);
		printf("PAD_UnpadBytes(%ld) returns %2ld :", inlen, outlen);
		pr_hexbytes(output, outlen);
		free(output);


		blklen = 16;
		inlen = sizeof(input);
		outlen = PAD_BytesBlock(NULL, 0, input, inlen, blklen, padopts);
		printf("PAD_BytesBlock(%ld) returns %2ld :", inlen, outlen);
		output = malloc(outlen);
		outlen = PAD_BytesBlock(output, outlen, input, inlen, blklen, padopts);
		pr_hexbytes(output, outlen);
		/* Now unpad */
		outlen = PAD_UnpadBytes(output, outlen, output, outlen, blklen, padopts);
		printf("PAD_UnpadBytes(%ld) returns %2ld :", inlen, outlen);
		pr_hexbytes(output, outlen);
		free(output);
		
	}


	printf("...%s tested OK\n", testfn);
}

void test_PAD_HexBlock(void)
{
	char *testfn = "PAD_HexBlock()";

	char *szInput = "FFFFFFFFFF";
	char *lpszOutput;
	long inlen, outlen, blklen;
	long pads[] = { 0, API_PAD_AX923, API_PAD_1ZERO };
	long padopts;
	int pi;
	int npads = sizeof(pads) / sizeof(pads[0]);

	printf("Testing %s...\n", testfn);

	inlen = (long)strlen(szInput) / 2;
	for (pi = 0; pi < npads; pi++) {
		padopts = pads[pi];
		printf("PADDING=%#x\n", padopts);

		blklen = 8;

		outlen = PAD_HexBlock(NULL, 0, szInput, blklen, padopts);
		printf("PAD_HexBlock(%ld) returns %2ld :", inlen, outlen);
		lpszOutput = malloc(outlen + 1);
		outlen = PAD_HexBlock(lpszOutput, outlen, szInput, blklen, padopts);
		printf("%s\n", lpszOutput);
		assert(outlen > 0);
		/* Now unpad */
		outlen = PAD_UnpadHex(lpszOutput, outlen, lpszOutput, blklen, padopts);
		printf("PAD_UnpadHex(%ld) returns %2ld :", inlen, outlen);
		printf("%s\n", lpszOutput);
		assert(outlen == inlen * 2);	/* NB hex-encoded 2 chars per byte */
		free(lpszOutput);

		blklen = 16;
		outlen = PAD_HexBlock(NULL, 0, szInput, blklen, padopts);
		printf("PAD_HexBlock(%ld) returns %2ld :", inlen, outlen);
		lpszOutput = malloc(outlen + 1);
		outlen = PAD_HexBlock(lpszOutput, outlen, szInput, blklen, padopts);
		printf("%s\n", lpszOutput);
		/* Now unpad */
		outlen = PAD_UnpadHex(lpszOutput, outlen, lpszOutput, blklen, padopts);
		printf("PAD_UnpadHex(%ld) returns %2ld :", inlen, outlen);
		printf("%s\n", lpszOutput);
		free(lpszOutput);

	}

	printf("...%s tested OK\n", testfn);
}

/* SHA-3 FAMILY */
void test_SHA3(void)
{
	char *testfn = "test_SHA3()";

	long lRet;
	char szDigest[API_MAX_HASH_CHARS + 1]; /* NB extra one for terminating null character */
	char *szMsgHex = "616263";	// ="abc"
	long h;
	unsigned char *b;
	long nbits;
	char *ok;

	printf("Testing %s...\n", testfn);

	lRet = HASH_HexFromHex(szDigest, sizeof(szDigest) - 1, szMsgHex, API_HASH_SHA3_224);
	assert(lRet > 0);
	printf("SHA3-224('abc')=%s\n", szDigest);
	assert(strcmp(szDigest, "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf") == 0);
	lRet = HASH_HexFromHex(szDigest, sizeof(szDigest) - 1, szMsgHex, API_HASH_SHA3_256);
	assert(lRet > 0);
	printf("SHA3-256('abc')=%s\n", szDigest);
	assert(strcmp(szDigest, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532") == 0);
	lRet = HASH_HexFromHex(szDigest, sizeof(szDigest) - 1, szMsgHex, API_HASH_SHA3_384);
	assert(lRet > 0);
	printf("SHA3-384('abc')=%s\n", szDigest);
	assert(strcmp(szDigest, "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25") == 0);
	lRet = HASH_HexFromHex(szDigest, sizeof(szDigest) - 1, szMsgHex, API_HASH_SHA3_512);
	assert(lRet > 0);
	printf("SHA3-512('abc')=%s\n", szDigest);
	assert(strcmp(szDigest, "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0") == 0);

	// Using stateful context
	h = SHA3_Init(256);
	assert(h != 0);
	SHA3_AddString(h, "ab");
	b = (unsigned char*)"c";
	SHA3_AddBytes(h, b, 1);
	SHA3_HexDigest(szDigest, sizeof(szDigest) - 1, h);
	printf("SHA3-256('abc')=%s\n", szDigest);
	assert(strcmp(szDigest, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532") == 0);

	// Directly from a file
	lRet = HASH_HexFromFile(szDigest, sizeof(szDigest) - 1, "abc.txt", API_HASH_SHA3_256);
	assert(lRet > 0);
	printf("SHA3-256('abc')=%s\n", szDigest);
	assert(strcmp(szDigest, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532") == 0);

	// Bitwise
	b = "\x25\x90\xa0";	// NIST version 259028 => API version 2590A0
	nbits = 22;
	ok = "d5863d4b1ff41551c92a9e08c52177e32376c9bd100c611c607db840096eb22f";
	lRet = HASH_HexFromBits(szDigest, sizeof(szDigest) - 1, b, nbits, API_HASH_SHA3_256);
	assert(lRet > 0);
	printf("SHA3-256(0x259028/22)=%s\n", szDigest);
	assert(strcmp(szDigest, ok) == 0);

	// Reset
	h = SHA3_Init(384);
	printf("SHA3_Init() returns 0x%08X (nonzero - different each time)\n", h);
	assert(h != 0);
	printf("SHA_LengthInBytes()=%ld\n", SHA3_LengthInBytes(h));
	lRet = SHA3_Reset(h);
	printf("SHA3_Reset() returns %d\n", lRet);
	lRet = SHA3_LengthInBytes(h);
	printf("Expecting error...\n");
	printf("After reset, SHA_LengthInBytes()=%ld\n", lRet);
	assert(lRet < 0);
	disp_error(lRet);


	printf("...%s tested OK\n", testfn);
}

void test_SHA3_HMAC(void)
{
	char *testfn = "test_SHA3_HMAC()";

	long lRet;
	char szDigest[API_MAX_HASH_CHARS + 1]; /* NB extra one for terminating null character */
	unsigned char *data;
	unsigned char key1[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
	};
	unsigned char key3[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
		0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
		0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
		0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
		0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
		0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
		0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
		0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
		0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
		0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
		0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
		0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
		0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
		0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
	};
	long dlen;
	char *ok;

	printf("Testing %s...\n", testfn);

	/* NIST: "Keyed-Hash Message Authentication Code (HMAC) using SHA3-256" (HMAC_SHA3-256.pdf) */

	printf("Sample #1\n");
	data = (unsigned char*)"Sample message for keylen<blocklen";
	dlen = (long)strlen(data);
	ok = "4fe8e202c4f058e8dddc23d8c34e467343e23555e24fc2f025d598f558f67205";
	printf("DATA='%s'\n", data);

	lRet = MAC_HexFromBytes(szDigest, sizeof(szDigest) - 1, data, dlen, key1, sizeof(key1), API_HMAC_SHA3_256);
	assert(lRet > 0);
	printf("HMAC-SHA-3-256()=%s\n", szDigest);
	assert(strcmp(szDigest, ok) == 0);

	printf("Sample #3\n");
	data = (unsigned char*)"Sample message for keylen>blocklen";
	dlen = (long)strlen(data);
	ok = "9bcf2c238e235c3ce88404e813bd2f3a97185ac6f238c63d6229a00b07974258";
	printf("DATA='%s'\n", data);

	lRet = MAC_HexFromBytes(szDigest, sizeof(szDigest) - 1, data, dlen, key3, sizeof(key3), API_HMAC_SHA3_256);
	assert(lRet > 0);
	printf("HMAC-SHA-3-256()=%s\n", szDigest);
	assert(strcmp(szDigest, ok) == 0);

	printf("...%s tested OK\n", testfn);
}

void test_SHA3_KMAC(void)
{
	char *testfn = "test_SHA3_KMAC()";

	long r;
	unsigned char key[] = {
		0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
		0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
		0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
		0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
	};
	unsigned char datashort[] = { 0x00, 0x01, 0x02, 0x03, };
	unsigned char datalong[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
		0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
		0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
		0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
		0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
		0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
		0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
		0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
		0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
		0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
		0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
		0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
		0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
		0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
		0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
		0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
		0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
		0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
	};
	unsigned char output[1024];
	unsigned char *pdata;
	long dlen, klen, olen;
	char *okhex;
	long flag;
	char szOut[1024];
	long nchars;
	char *keyhex, *datahex;

	printf("Testing %s...\n", testfn);

	// Sample #1
	//kmac_test(128, "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F", "00010203",
	//	256, "", "E5780B0D3EA6F7D3A429C5706AA43A00FADBD7D49628839E3187243F456EE14E");


	// Ref: `KMAC_samples.pdf` "Secure Hashing - KMAC-Samples" 2017-02-27
	// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMAC_samples.pdf>

	printf("Sample #1\n");
	flag = API_KMAC_128;
	pdata = datashort;
	dlen = sizeof(datashort);
	klen = sizeof(key);
	//olen = 256 / 8;
	okhex = "E5780B0D3EA6F7D3A429C5706AA43A00FADBD7D49628839E3187243F456EE14E";

	olen = MAC_Bytes(NULL, 0, pdata, dlen, key, klen, flag);
	printf("MAC_Bytes(NULL) returns %ld\n", olen);
	assert(olen > 0);

	printf("Security Strength: %d-bits\n", (API_KMAC_256 == flag ? 256 : 128));
	printf("Length of Key is %d bits\n", klen * 8);
	pr_byteshex16("KEY:\n", key, klen, "\n");
	printf("Length of data is %d bits\n", dlen * 8);
	pr_byteshex16("DATA:\n", pdata, dlen, "\n");
	printf("Requested output length is %d bits\n", olen * 8);

	r = MAC_Bytes(output, olen, pdata, dlen, key, klen, flag);
	assert(r > 0);
	pr_byteshex16("OUTPUT:\n", output, olen, "\n");
	pr_wrapstr("OK:\n", okhex, 32);
	assert(0 == cmp_bytes2hex(output, olen, okhex));


	printf("Sample #5\n");
	flag = API_KMAC_256;
	pdata = datalong;
	dlen = sizeof(datalong);
	klen = sizeof(key);
	//olen = 512 / 8;
	okhex = "75358CF39E41494E949707927CEE0AF20A3FF553904C86B08F21CC414BCFD691589D27CF5E15369CBBFF8B9A4C2EB17800855D0235FF635DA82533EC6B759B69";

	olen = MAC_Bytes(NULL, 0, pdata, dlen, key, klen, flag);
	printf("MAC_Bytes(NULL) returns %ld\n", olen);
	assert(olen > 0);

	printf("Security Strength: %d-bits\n", (API_KMAC_256 == flag ? 256 : 128));
	printf("Length of Key is %d bits\n", klen * 8);
	pr_byteshex16("KEY:\n", key, klen, "\n");
	printf("Length of data is %d bits\n", dlen * 8);
	pr_byteshex16("DATA:\n", pdata, dlen, "\n");
	printf("Requested output length is %d bits\n", olen * 8);

	r = MAC_Bytes(output, olen, pdata, dlen, key, klen, flag);
	assert(r > 0);
	pr_byteshex16("OUTPUT:\n", output, olen, "\n");
	pr_wrapstr("OK:\n", okhex, 32);
	assert(0 == cmp_bytes2hex(output, olen, okhex));

	// HexFromBytes
	nchars = MAC_HexFromBytes(NULL, 0, pdata, dlen, key, klen, flag);
	printf("MAC_HexFromBytes(NULL) returns %ld\n", nchars);
	assert(nchars > 0);
	r = MAC_HexFromBytes(szOut, nchars, pdata, dlen, key, klen, flag);
	printf("MAC_HexFromBytes returns %ld\n", r);
	assert(r > 0);
	pr_wrapstr("OUTPUT:\n", szOut, 32);
	assert(0 == stricmp(okhex, szOut));

	// HexFromHex
	flag = API_KMAC_128;
	olen = 256 / 8;
	//nchars = olen * 2;
	keyhex = "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F";
	datahex = "00010203";
	okhex = "E5780B0D3EA6F7D3A429C5706AA43A00FADBD7D49628839E3187243F456EE14E";
	nchars = MAC_HexFromHex(NULL, 0, datahex, keyhex, flag);
	printf("MAC_HexFromHex(NULL) returns %ld\n", nchars);
	assert(nchars > 0);
	r = MAC_HexFromHex(szOut, nchars, datahex, keyhex, flag);
	printf("MAC_HexFromHex returns %ld\n", r);
	assert(r > 0);
	pr_wrapstr("OUTPUT:\n", szOut, 32);
	assert(0 == stricmp(okhex, szOut));

	flag = API_KMAC_256;
	olen = 512 / 8;
	nchars = olen * 2;
	keyhex = "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F";
	datahex = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7";
	okhex = "75358CF39E41494E949707927CEE0AF20A3FF553904C86B08F21CC414BCFD691589D27CF5E15369CBBFF8B9A4C2EB17800855D0235FF635DA82533EC6B759B69";
	r = MAC_HexFromHex(szOut, nchars, datahex, keyhex, flag);
	printf("MAC_HexFromHex returns %ld\n", r);
	assert(r > 0);
	pr_wrapstr("OUTPUT:\n", szOut, 32);
	assert(0 == stricmp(okhex, szOut));

	flag = API_KMAC_128;
	olen = 256 / 8;
	nchars = olen * 2;
	keyhex = "";
	datahex = "";
	okhex = "5C135C615152FB4D9784DD1155F9B6034E013FD77165C327DFA4D36701983EF7";
	r = MAC_HexFromHex(szOut, nchars, datahex, keyhex, flag);
	printf("MAC_HexFromHex returns %ld\n", r);
	assert(r > 0);
	pr_wrapstr("OUTPUT:\n", szOut, 32);
	assert(0 == stricmp(okhex, szOut));

	printf("...%s tested OK\n", testfn);
}

void test_XOF(void)
{
	char *testfn = "test_XOF()";

	long r;
	unsigned char msg1[] = {
		0x59, 0xFA, 0x3D, 0x70, 0x91, 0xED, 0xD1, 0xAE,
		0x28, 0x74, 0x94, 0x9A, 0x0B, 0x18, 0xFF, 0x95,
	};
	unsigned char msg2[] = {
		0xC6, 0x1A, 0x91, 0x88, 0x81, 0x2A, 0xE7, 0x39,
		0x94, 0xBC, 0x0D, 0x6D, 0x40, 0x21, 0xE3, 0x1B,
		0xF1, 0x24, 0xDC, 0x72, 0x66, 0x97, 0x49, 0x11,
		0x12, 0x32, 0xDA, 0x7A, 0xC2, 0x9E, 0x61, 0xC4,
	};
	unsigned char msg3[] = {
		0x6A, 0xE2, 0x3F, 0x05, 0x8F, 0x0F, 0x22, 0x64,
		0xA1, 0x8C, 0xD6, 0x09, 0xAC, 0xC2, 0x6D, 0xD4,
		0xDB, 0xC0, 0x0F, 0x5C, 0x3E, 0xE9, 0xE1, 0x3E,
		0xCA, 0xEA, 0x2B, 0xB5, 0xA2, 0xF0, 0xBB, 0x6B,
	};
	unsigned char output[1024];
	unsigned char *pmsg;
	long mlen, olen;
	char *okhex;
	long flag;

	printf("Testing %s...\n", testfn);

	flag = API_XOF_SHAKE128;
	pmsg = msg1;
	mlen = sizeof(msg1);
	olen = 464 / 8;
	okhex = "7b27fd12ce28aadd5fe136cd26fadb9e26b0ec0858c5599bd599a17ba36f032d5fb55b50effa08fd423b9e28e780c16066bc9b806a7f646db20e";
	printf("SHAKE%d\n", (API_XOF_SHAKE256 == flag ? 256 : 128));
	pr_byteshexwrap(32, "Msg =\n", pmsg, mlen, "\n");
	printf("Outputlen = %d\n", olen * 8);

	r = XOF_Bytes(output, olen, pmsg, mlen, flag);
	assert(r > 0);
	pr_byteshexwrap(32, "Output =\n", output, olen, "\n");
	pr_wrapstr("OK:\n", okhex, 64);
	assert(0 == cmp_bytes2hex(output, olen, okhex));

	flag = API_XOF_SHAKE256;
	pmsg = msg2;
	mlen = sizeof(msg2);
	olen = 16 / 8;
	okhex = "23ce";
	printf("SHAKE%d\n", (API_XOF_SHAKE256 == flag ? 256 : 128));
	pr_byteshexwrap(32, "Msg =\n", pmsg, mlen, "\n");
	printf("Outputlen = %d\n", olen * 8);

	r = XOF_Bytes(output, olen, pmsg, mlen, flag);
	assert(r > 0);
	pr_byteshexwrap(32, "Output =\n", output, olen, "\n");
	pr_wrapstr("OK:\n", okhex, 64);
	assert(0 == cmp_bytes2hex(output, olen, okhex));

	flag = API_XOF_SHAKE256;
	pmsg = msg3;
	mlen = sizeof(msg3);
	olen = 2000 / 8;
	okhex = "b9b92544fb25cfe4ec6fe437d8da2bbe00f7bdaface3de97b8775a44d753c3adca3f7c6f183cc8647e229070439aa9539ae1f8f13470c9d3527fffdeef6c94f9f0520ff0c1ba8b16e16014e1af43ac6d94cb7929188cce9d7b02f81a2746f52ba16988e5f6d93298d778dfe05ea0ef256ae3728643ce3e29c794a0370e9ca6a8bf3e7a41e86770676ac106f7ae79e67027ce7b7b38efe27d253a52b5cb54d6eb4367a87736ed48cb45ef27f42683da140ed3295dfc575d3ea38cfc2a3697cc92864305407369b4abac054e497378dd9fd0c4b352ea3185ce1178b3dc1599df69db29259d4735320c8e7d33e8226620c9a1d22761f1d35bdff79a";
	printf("SHAKE%d\n", (API_XOF_SHAKE256 == flag ? 256 : 128));
	pr_byteshexwrap(32, "Msg =\n", pmsg, mlen, "\n");
	printf("Outputlen = %d\n", olen * 8);

	r = XOF_Bytes(output, olen, pmsg, mlen, flag);
	assert(r > 0);
	pr_byteshexwrap(32, "Output =\n", output, olen, "\n");
	pr_wrapstr("OK:\n", okhex, 64);
	assert(0 == cmp_bytes2hex(output, olen, okhex));

}

void test_PRF(void)
{
	char *testfn = "test_PRF()";

	long r;
	unsigned char key[] = {
		0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
		0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
		0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
		0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
	};
	unsigned char datashort[] = { 0x00, 0x01, 0x02, 0x03, };
	unsigned char datalong[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
		0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
		0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
		0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
		0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
		0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
		0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
		0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
		0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
		0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
		0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
		0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
		0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
		0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
		0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
		0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
		0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
		0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
	};
	unsigned char output[1024];
	unsigned char *pdata;
	long dlen, klen, olen;
	char *okhex;
	long flag;
	char *customstring;

	printf("Testing %s...\n", testfn);


	// Ref: `KMAC_samples.pdf` "Secure Hashing - KMAC-Samples" 2017-02-27
	// <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMAC_samples.pdf>

	printf("Sample #2\n");
	flag = API_KMAC_128;
	pdata = datashort;
	dlen = sizeof(datashort);
	klen = sizeof(key);
	olen = 256 / 8;
	customstring = "My Tagged Application";
	okhex = "3B1FBA963CD8B0B59E8C1A6D71888B7143651AF8BA0A7070C0979E2811324AA5";

	printf("Security Strength: %d-bits\n", (API_KMAC_256 == flag ? 256 : 128));
	printf("Length of Key is %d bits\n", klen * 8);
	pr_byteshex16("KEY:\n", key, klen, "\n");
	printf("Length of data is %d bits\n", dlen * 8);
	pr_byteshex16("DATA:\n", pdata, dlen, "\n");
	printf("Requested output length is %d bits\n", olen * 8);
	printf("S (as a character string) is\n\"%s\"\n", customstring);

	/* To use a customization string with KMAC, use PRF_Bytes*/
	r = PRF_Bytes(output, olen, pdata, dlen, key, klen, customstring, flag);
	assert(r > 0);
	pr_byteshex16("OUTPUT:\n", output, olen, "\n");
	pr_wrapstr("OK:\n", okhex, 32);
	assert(0 == cmp_bytes2hex(output, olen, okhex));

	// Ask for longer output
	olen = 1600 / 8;
	customstring = "";
	okhex = "38158A1CAE4E1A25D85F2031246ADE697B3292FEF88B0923A59A02D1D53B704653EE7242662A10796BA20779D300D52D7432018741233D587252D31DC48BDB8233285D4A4ACD65848509B051A448D873649228B6626E5EF817C7AF2DEDC91F120F8CA535A1EE301FAE8186FDEDE5A76181A472A32CFAD1DDD1391E162F124D4A7572AD8A20076601BCF81E4B0391F3E95AEFFA708C33C1217C96BE6A4F02FBBC2D3B3B6FFAEB5BFD3BE4A2E02B75993FCC04DA6FAC4BFCB2A9F05792A1A5CC80CA34186243EFDB31";
	printf("Requested output length is %d bits\n", olen * 8);
	printf("S (as a character string) is\n\"%s\"\n", customstring);
	r = PRF_Bytes(output, olen, pdata, dlen, key, klen, customstring, flag);
	assert(r > 0);
	pr_byteshex16("OUTPUT:\n", output, olen, "\n");
	//pr_wrapstr("OK:\n", okhex, 32);
	assert(0 == cmp_bytes2hex(output, olen, okhex));

}

void test_CIPHER_EncryptBytesPad2_aes_iv_prefix(void)
{
	char *testfn = "CIPHER_EncryptBytesPad2_aes_iv_prefix()";

	unsigned char key[] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87,
	};
	unsigned char iv[] = {
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
	};
	unsigned char plain[] = "Now is the time for all good men to";
	unsigned char correct_cbc[] = { // For "aes128/cbc/pkcs5padding" WITH IV PREFIX
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
		0xC3, 0x15, 0x31, 0x08, 0xA8, 0xDD, 0x34, 0x0C,
		0x0B, 0xCB, 0x1D, 0xFE, 0x8D, 0x25, 0xD2, 0x32,
		0x0E, 0xE0, 0xE6, 0x6B, 0xD2, 0xBB, 0x4A, 0x31,
		0x3F, 0xB7, 0x5C, 0x56, 0x38, 0xE9, 0xE1, 0x77,
		0x53, 0xC7, 0xE8, 0xDF, 0x59, 0x75, 0xA3, 0x66,
		0x77, 0x35, 0x5F, 0x5C, 0x65, 0x84, 0x22, 0x8B,
	};
	unsigned char correct_ecb[] = {
		0xF0, 0xD1, 0xAD, 0x6F, 0x90, 0x1F, 0xFF, 0xAE,
		0x55, 0x72, 0xA6, 0x92, 0x8D, 0xAB, 0x52, 0xB0,
		0x64, 0xB2, 0x5C, 0x79, 0xF8, 0x76, 0x73, 0x03,
		0x21, 0xE3, 0x6D, 0xC0, 0x10, 0x11, 0xAC, 0xCE,
		0x7F, 0x1D, 0xBB, 0x0C, 0x8B, 0xC4, 0x95, 0x28,
		0x48, 0xD3, 0x82, 0x49, 0x0E, 0x52, 0x0F, 0x60,
	};
	unsigned char correct_ctr[] = {
		0x3F, 0xAC, 0x68, 0xCB, 0xAE, 0x6D, 0x77, 0x41,
		0x51, 0x30, 0x6E, 0x9D, 0xB1, 0x6C, 0xE0, 0x19,
		0x1C, 0x51, 0xE9, 0x19, 0x59, 0xDA, 0x4F, 0x08,
		0x2B, 0x7C, 0xE3, 0x49, 0x8C, 0x2D, 0x20, 0xD7,
		0x84, 0x37, 0xEC,
	};
	unsigned char correct_empty[] = {
		0xCB, 0x5A, 0x18, 0x9F, 0x98, 0xD0, 0x69, 0x31,
		0x03, 0x32, 0x6C, 0x34, 0x46, 0x65, 0x38, 0x5E,
	};
	unsigned char *pcipher, *pdeciph;
	long plen, clen, dlen;

	printf("\nTesting %s...\n", testfn);

	pr_bytesmsg("KY=", key, sizeof(key));
	pr_bytesmsg("IV=", iv, sizeof(iv));
	printf("PT='%s'\n", plain);
	plen = (long)strlen(plain);
	printf("LEN(PT)=%d\n", plen);
	pr_bytesmsg("PT=", plain, plen);
	/* 1. Encrypt it into ciphertext */
	/* 1.1 Get required length */
	clen = CIPHER_EncryptBytes(NULL, 0, plain, plen, key, sizeof(key), iv, sizeof(iv), "aes128/cbc/pkcs5padding", API_IV_PREFIX);
	if (clen < 0) printf("Error code %ld\n", clen);
	assert(clen > 0);
	printf("AES128/CBC/PKCS5:\n");
	printf("LEN(IV||PAD(PT))=%d\n", clen);
	/* 1.2 Allocate memory */
	pcipher = malloc(clen);
	/* 1.3 Do the business */
	clen = CIPHER_EncryptBytes(pcipher, clen, plain, plen, key, sizeof(key), iv, sizeof(iv), "aes128/cbc/pkcs5padding", API_IV_PREFIX);
	if (clen < 0) printf("Error code %ld\n", clen);
	pr_bytesmsg("CT=", pcipher, clen);
	pr_bytesmsg("OK=", correct_cbc, clen);
	assert(memcmp(correct_cbc, pcipher, sizeof(correct_cbc)) == 0);

	/* Now decipher */
	/* No need to check lengths before deciphering: output is never longer than input */
	// NB IV is not required with IV_PREFIX
	pdeciph = malloc(clen);
	dlen = CIPHER_DecryptBytes(pdeciph, clen, pcipher, clen, key, sizeof(key), NULL, 0, "aes128/cbc/pkcs5padding", API_IV_PREFIX);
	printf("dlen=%d\n", dlen);
	assert(dlen <= plen);
	pr_bytesmsg("P'=", pdeciph, dlen);

	/* Check identical */
	assert(memcmp(plain, pdeciph, dlen) == 0);

	/* Leave padding in place */
	printf("Leave padding in place...\n");
	dlen = CIPHER_DecryptBytes(pdeciph, clen, pcipher, clen, key, sizeof(key), NULL, 0, "aes128/cbc/nopad", API_IV_PREFIX);
	printf("dlen=%d\n", dlen);
	pr_bytesmsg("PT||PAD=", pdeciph, dlen);
	/* Check first plen bytes are identical */
	assert(memcmp(plain, pdeciph, plen) == 0);
	/* and that output is a multiple of block size */
	assert(dlen % API_BLK_AES_BYTES == 0);

	free(pdeciph);

	/* New behaviour [v5.4] CIPHER_DecryptBytes will return actual decrypted length with NULL lpOutput */
	printf("[v5.4] behaviour...\n");
	dlen = CIPHER_DecryptBytes(NULL, 0, pcipher, clen, key, sizeof(key), NULL, 0, "aes128/cbc/pkcs5padding", API_IV_PREFIX);
	printf("dlen=%d\n", dlen);
	assert(dlen >= 0);
	pdeciph = malloc(dlen);
	dlen = CIPHER_DecryptBytes(pdeciph, dlen, pcipher, clen, key, sizeof(key), NULL, 0, "aes128/cbc/pkcs5padding", API_IV_PREFIX);
	printf("dlen=%d\n", dlen);
	assert(dlen >= 0);
	pr_bytesmsg("P'=", pdeciph, dlen);
	assert(dlen <= plen);
	assert(memcmp(plain, pdeciph, plen) == 0);

	free(pdeciph);

	dlen = CIPHER_DecryptBytes(NULL, 0, pcipher, clen, key, sizeof(key), NULL, 0, "aes128/cbc/nopad", API_IV_PREFIX);
	printf("dlen=%d\n", dlen);
	assert(dlen >= 0);
	pdeciph = malloc(dlen);
	dlen = CIPHER_DecryptBytes(pdeciph, dlen, pcipher, clen, key, sizeof(key), NULL, 0, "aes128/cbc/nopad", API_IV_PREFIX);
	printf("dlen=%d\n", dlen);
	assert(dlen >= 0);
	pr_bytesmsg("P'=", pdeciph, dlen);
	assert(memcmp(plain, pdeciph, plen) == 0);
	assert(dlen % API_BLK_AES_BYTES == 0);

	free(pdeciph);

	free(pcipher);


	printf("...%s tested OK\n", testfn);
}

void test_AEAD_EncryptWithTag(void)
{
	char *testfn = "test_AEAD_EncryptWithTag()";

	long nbytes, ctlen;
	// gcm-test-vectors: vec-03
	BYTE key[] = {
		0xFE, 0xFF, 0xE9, 0x92, 0x86, 0x65, 0x73, 0x1C,
		0x6D, 0x6A, 0x8F, 0x94, 0x67, 0x30, 0x83, 0x08,
	};
	BYTE pt[] = {
		0xD9, 0x31, 0x32, 0x25, 0xF8, 0x84, 0x06, 0xE5,
		0xA5, 0x59, 0x09, 0xC5, 0xAF, 0xF5, 0x26, 0x9A,
		0x86, 0xA7, 0xA9, 0x53, 0x15, 0x34, 0xF7, 0xDA,
		0x2E, 0x4C, 0x30, 0x3D, 0x8A, 0x31, 0x8A, 0x72,
		0x1C, 0x3C, 0x0C, 0x95, 0x95, 0x68, 0x09, 0x53,
		0x2F, 0xCF, 0x0E, 0x24, 0x49, 0xA6, 0xB5, 0x25,
		0xB1, 0x6A, 0xED, 0xF5, 0xAA, 0x0D, 0xE6, 0x57,
		0xBA, 0x63, 0x7B, 0x39, 0x1A, 0xAF, 0xD2, 0x55,
	};
	BYTE iv[] = {
		0xCA, 0xFE, 0xBA, 0xBE, 0xFA, 0xCE, 0xDB, 0xAD,
		0xDE, 0xCA, 0xF8, 0x88,
	};
	BYTE ctok[] = { /* including tag */
		0x42, 0x83, 0x1E, 0xC2, 0x21, 0x77, 0x74, 0x24,
		0x4B, 0x72, 0x21, 0xB7, 0x84, 0xD0, 0xD4, 0x9C,
		0xE3, 0xAA, 0x21, 0x2F, 0x2C, 0x02, 0xA4, 0xE0,
		0x35, 0xC1, 0x7E, 0x23, 0x29, 0xAC, 0xA1, 0x2E,
		0x21, 0xD5, 0x14, 0xB2, 0x54, 0x66, 0x93, 0x1C,
		0x7D, 0x8F, 0x6A, 0x5A, 0xAC, 0x84, 0xAA, 0x05,
		0x1B, 0xA3, 0x0B, 0x39, 0x6A, 0x0A, 0xAC, 0x97,
		0x3D, 0x58, 0xE0, 0x91, 0x47, 0x3F, 0x59, 0x85,
		0x4D, 0x5C, 0x2A, 0xF3, 0x27, 0xCD, 0x64, 0xA6,
		0x2C, 0xF3, 0x5A, 0xBD, 0x2B, 0xA6, 0xFA, 0xB4,
	};
	BYTE key256zero[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	BYTE ivzero[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	};

	// NB fixed length
	BYTE ct[256];
	BYTE p1[256];

	printf("\nTesting %s...\n", testfn);

	pr_bytesmsg("KY: ", key, sizeof(key));
	pr_bytesmsg("IV: ", iv, sizeof(iv));
	pr_bytesmsg("PT:\n", pt, sizeof(pt));

	nbytes = AEAD_EncryptWithTag(NULL, 0, pt, sizeof(pt), key, sizeof(key), iv, sizeof(iv), NULL, 0, API_AEAD_AES_128_GCM);
	printf("AEAD_EncryptWithTag() returns %ld\n", nbytes);
	if (nbytes < 0) disp_error(nbytes);
	assert(nbytes > 0);
	nbytes = AEAD_EncryptWithTag(ct, nbytes, pt, sizeof(pt), key, sizeof(key), iv, sizeof(iv), NULL, 0, API_AEAD_AES_128_GCM);
	if (nbytes < 0) disp_error(nbytes);
	assert(nbytes > 0);
	pr_bytesmsg("CT:\n", ct, nbytes);
	//pr_bytesmsg("OK:\n", ctok, nbytes);
	assert(0 == memcmp(ct, ctok, nbytes) && sizeof(ctok) == nbytes);

	ctlen = nbytes;
	nbytes = AEAD_DecryptWithTag(NULL, 0, ct, ctlen, key, sizeof(key), iv, sizeof(iv), NULL, 0, API_AEAD_AES_128_GCM);
	printf("AEAD_Decrypt() returns %ld\n", nbytes);
	if (nbytes < 0) disp_error(nbytes);
	assert(nbytes >= 0);
	nbytes = AEAD_DecryptWithTag(p1, nbytes, ct, ctlen, key, sizeof(key), iv, sizeof(iv), NULL, 0, API_AEAD_AES_128_GCM);
	if (nbytes < 0) disp_error(nbytes);
	assert(nbytes >= 0);
	pr_bytesmsg("PT:\n", p1, nbytes);
	assert(0 == memcmp(pt, p1, nbytes) && sizeof(pt) == nbytes);

	// Same again but prefixing the IV
	nbytes = AEAD_EncryptWithTag(NULL, 0, pt, sizeof(pt), key, sizeof(key), iv, sizeof(iv), NULL, 0, API_AEAD_AES_128_GCM | API_IV_PREFIX);
	printf("AEAD_EncryptWithTag(PREFIX) returns %ld\n", nbytes);
	if (nbytes < 0) disp_error(nbytes);
	assert(nbytes > 0);
	nbytes = AEAD_EncryptWithTag(ct, nbytes, pt, sizeof(pt), key, sizeof(key), iv, sizeof(iv), NULL, 0, API_AEAD_AES_128_GCM | API_IV_PREFIX);
	if (nbytes < 0) disp_error(nbytes);
	assert(nbytes > 0);
	pr_bytesmsg("CT:\n", ct, nbytes);

	ctlen = nbytes;
	nbytes = AEAD_DecryptWithTag(NULL, 0, ct, ctlen, key, sizeof(key), NULL, 0, NULL, 0, API_AEAD_AES_128_GCM | API_IV_PREFIX);
	printf("AEAD_Decrypt(PREFIX) returns %ld\n", nbytes);
	if (nbytes < 0) disp_error(nbytes);
	assert(nbytes >= 0);
	nbytes = AEAD_DecryptWithTag(p1, nbytes, ct, ctlen, key, sizeof(key), NULL, 0, NULL, 0, API_AEAD_AES_128_GCM | API_IV_PREFIX);
	if (nbytes < 0) disp_error(nbytes);
	assert(nbytes >= 0);
	pr_bytesmsg("PT:\n", p1, nbytes);
	assert(0 == memcmp(pt, p1, nbytes) && sizeof(pt) == nbytes);

	printf("Decrypt error:\n");	// wrong key
	memset(p1, 0, sizeof(p1));
	nbytes = AEAD_DecryptWithTag(p1, nbytes, ct, ctlen, key256zero, sizeof(key), NULL, 0, NULL, 0, API_AEAD_AES_128_GCM | API_IV_PREFIX);
	if (nbytes < 0) disp_error(nbytes);
	//assert(nbytes >= 0);
	pr_bytesmsg("PT:\n", p1, sizeof(pt));


	printf("...%s tested OK\n", testfn);
}

void test_HASH_Init(void)
{
	char *testfn = "test_HASH_Init()";
	long h, r, dlen;
	BYTE digest[API_MAX_HASH_BYTES];
	char *okhex;

	printf("\nTesting %s...\n", testfn);

	printf("SHA-256...\n");
	// Initialize context...
	h = HASH_Init(API_HASH_SHA256);
	printf("HASH_Init returns 0x%08X\n", h);
	assert(h != 0);
	printf("HASH_DigestLength=%ld\n", HASH_DigestLength(h));
	// Add string "abc" in parts...
	r = HASH_AddBytes(h, (unsigned char*)"a", 1);
	r = HASH_AddBytes(h, (unsigned char*)"bc", 2);
	// Compute final digest...
	dlen = HASH_Final(digest, sizeof(digest), h);
	printf("HASH_Final returns %ld\n", dlen);
	pr_bytesmsg("DIG=", digest, dlen);
	okhex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
	printf("OK= %s\n", okhex);
	assert(0 == cmp_bytes2hex(digest, dlen, okhex));

	printf("...%s tested OK\n", testfn);
}

void test_MAC_Init(void)
{
	char *testfn = "test_MAC_Init()";
	long h, r, dlen;
	BYTE digest[API_MAX_MAC_BYTES];
	BYTE key[] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19,
	};
	BYTE block_cd_10[] = {
		0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
		0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
	};
	int i;
	char *s;

	printf("\nTesting %s...\n", testfn);

	// Test case 4 from RFC 2202 and RFC 4231
	// key =           0x0102030405060708090a0b0c0d0e0f10111213141516171819
	// key_len         25
	// data =          0xcd repeated 50 times
	// data_len =      50
	printf("HMAC-SHA-1...\n");
	h = MAC_Init(key, sizeof(key), API_HMAC_SHA1);
	assert(h != 0);
	printf("MAC_CodeLength=%ld\n", MAC_CodeLength(h));
	// Add data in parts...
	for (i = 0; i < 5; i++){
		r = MAC_AddBytes(h, block_cd_10, sizeof(block_cd_10));
		assert(0 == r);
	}

	dlen = MAC_Final(digest, sizeof(digest), h);
	printf("MAC_Final returns %ld\n", dlen);
	pr_bytesmsg("DIG=", digest, dlen);
	assert(0 == cmp_bytes2hex(digest, dlen, "4c9007f4026250c6bc8414f9bf50c86c2d7235da"));

	printf("HMAC-SHA-256...\n");
	h = MAC_Init(key, sizeof(key), API_HMAC_SHA256);
	assert(h != 0);

	for (i = 0; i < 5; i++){
		r = MAC_AddBytes(h, block_cd_10, sizeof(block_cd_10));
		assert(0 == r);
	}

	dlen = MAC_Final(digest, sizeof(digest), h);
	printf("MAC_Final returns %ld\n", dlen);
	pr_bytesmsg("DIG=", digest, dlen);
	assert(0 == cmp_bytes2hex(digest, dlen, "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"));

	/* Test case 2 from RFC 2202 and RFC 4231
	Key =          4a656665                          ("Jefe")
	Data =         7768617420646f2079612077616e7420  ("what do ya want ")
	               666f72206e6f7468696e673f          ("for nothing?")
	*/
	printf("HMAC-SHA-384...\n");
	h = MAC_Init((unsigned char*)"Jefe", 4, API_HMAC_SHA384);
	assert(h != 0);
	// Pass input as string, typecast as unsigned char*
	s = "what do ya want ";
	r = MAC_AddBytes(h, (unsigned char*)s, (long)strlen(s));
	assert(0 == r);
	s = "for nothing?";
	r = MAC_AddBytes(h, (unsigned char*)s, (long)strlen(s));
	assert(0 == r);
	dlen = MAC_Final(digest, sizeof(digest), h);
	printf("MAC_Final returns %ld\n", dlen);
	pr_bytesmsg("DIG=", digest, dlen);
	assert(0 == cmp_bytes2hex(digest, dlen, "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"));

	printf("...%s tested OK\n", testfn);
}

void test_CIPHER_Init(void)
{
	char *testfn = "test_CIPHER_Init()";
	long h, r;
	BYTE *key;
	BYTE *iv;
	BYTE *pt, *ct;
	long keylen, ivlen, dlen;
	const char *okhex;

	unsigned char plain[] = "Now is the time for all good men to";
	// For CTR mode, input must be in blocks of multiples of 16, except the last one.
	unsigned char plain1[] = "Now is the time ";
	unsigned char plain2[] = "for all good men";
	unsigned char plain3[] = " to";
	unsigned char key_128[] = { // 0123456789ABCDEFF0E1D2C3B4A59687
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87,
	};
	unsigned char iv_128[] = {	// FEDCBA9876543210FEDCBA9876543210
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
	};
	unsigned char correct_ctr[] = { // For "aes128/ctr
		0x3F, 0xAC, 0x68, 0xCB, 0xAE, 0x6D, 0x77, 0x41,
		0x51, 0x30, 0x6E, 0x9D, 0xB1, 0x6C, 0xE0, 0x19,
		0x1C, 0x51, 0xE9, 0x19, 0x59, 0xDA, 0x4F, 0x08,
		0x2B, 0x7C, 0xE3, 0x49, 0x8C, 0x2D, 0x20, 0xD7,
		0x84, 0x37, 0xEC,
	};
	char *ok_128_ctr = "3FAC68CBAE6D774151306E9DB16CE0191C51E91959DA4F082B7CE3498C2D20D78437EC";
	const char *ok_128_ctr_parts = "3FAC68CBAE6D774151306E9DB16CE019" "\n"
		"1C51E91959DA4F082B7CE3498C2D20D7" "\n"
		"8437EC";
	char *buf;

	printf("\nTesting %s...\n", testfn);


	key = key_128;
	keylen = sizeof(key_128);
	iv = iv_128;
	ivlen = sizeof(iv_128);

	okhex = ok_128_ctr_parts;
	h = CIPHER_Init(ENCRYPT, "aes128/ctr", key, keylen, iv, ivlen, 0);
	printf("CIPHER_Init returns 0x%08X\n", h);
	assert(h != 0);

	pt = plain1;
	dlen = (long)strlen(pt);
	printf("dlen=%ld: '%s'\n", dlen, pt);
	buf = malloc(dlen);
	ct = buf;
	r = CIPHER_Update(h, ct, dlen, pt, dlen);
	printf("CIPHER_Update returns %ld\n", r);
	pr_bytesmsg("CT=", ct, dlen);
	free(buf);

	pt = plain2;
	dlen = (long)strlen(pt);
	printf("dlen=%ld: '%s'\n", dlen, pt);
	buf = malloc(dlen);
	ct = buf;
	r = CIPHER_Update(h, ct, dlen, pt, dlen);
	printf("CIPHER_Update returns %ld\n", r);
	pr_bytesmsg("CT=", ct, dlen);
	free(buf);

	pt = plain3;
	dlen = (long)strlen(pt);
	printf("dlen=%ld: '%s'\n", dlen, pt);
	buf = malloc(dlen);
	ct = buf;
	r = CIPHER_Update(h, ct, dlen, pt, dlen);
	printf("CIPHER_Update returns %ld\n", r);
	pr_bytesmsg("CT=", ct, dlen);
	free(buf);

	printf("OK=%s\n", okhex);
	printf("...%s tested OK\n", testfn);
}


void test_CIPHER_InitHex(void)
{
	char *testfn = "test_CIPHER_InitHex()";
	long h, r;
	const char *okhex;
	char *pt, *ct;
	long nchars;

	// SP800-38a F.1.5
	//algstr = "Aes256-ECB-nopad";
	//sHexKey = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
	//sHexIV = NULL;
	//sPlain = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
	okhex = "f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7";

	printf("\nTesting %s...\n", testfn);

	h = CIPHER_InitHex(ENCRYPT, "aes256/ecb", "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "", 0);
	assert(h != 0);

	pt = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
	nchars = (long)strlen(pt);
	ct = malloc(nchars + 1);	// NB Plus one
	r = CIPHER_UpdateHex(h, ct, nchars, pt);
	printf("CT=%s\n", ct);
	assert(0 == r);
	free(ct);

	r = CIPHER_Final(h);
	printf("OK=%s\n", okhex);

	// In parts
	h = CIPHER_InitHex(ENCRYPT, "aes256/ecb", "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "", 0);
	assert(h != 0);

	pt = "6bc1bee22e409f96e93d7e117393172a";
	nchars = (long)strlen(pt);
	ct = malloc(nchars + 1);	// NB Plus one
	r = CIPHER_UpdateHex(h, ct, nchars, pt);
	printf("CT=%s\n", ct);
	free(ct);
	pt = "ae2d8a571e03ac9c9eb76fac45af8e51";
	nchars = (long)strlen(pt);
	ct = malloc(nchars + 1);	// NB Plus one
	r = CIPHER_UpdateHex(h, ct, nchars, pt);
	printf("CT=%s\n", ct);
	assert(0 == r);
	free(ct);
	pt = "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
	nchars = (long)strlen(pt);
	ct = malloc(nchars + 1);	// NB Plus one
	r = CIPHER_UpdateHex(h, ct, nchars, pt);
	printf("CT=%s\n", ct);
	assert(0 == r);
	free(ct);

	r = CIPHER_Final(h);
	okhex = "f3eed1bdb5d2a03c064b5a7e3db181f8" "\n"
		"591ccb10d410ed26dc5ba74a31362870" "\n"
		"b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7";
	printf("OK=%s\n", okhex);

	printf("...%s tested OK\n", testfn);
}

void test_CIPHER_EncryptHex(void)
{
	char *testfn = "test_CIPHER_EncryptHex()";
	long nchars;
	// Section 8.1 of [SMIME-EX]
	char *algstr = "tdea-cbc";
	char *sHexKey = "737C791F25EAD0E04629254352F7DC6291E5CB26917ADA32";
	char *sHexIV = "B36B6BFB6231084E";
	char *sPlain = "5468697320736F6D652073616D706520636F6E74656E742E";
	//              T h i s _ s o m e _ s a m p e _ c o n t e n t .
	char *sCorrect = "d76fd1178fbd02f84231f5c1d2a2f74a4159482964f675248254223daf9af8e4";
	char *cthex, *chkhex;

	printf("\nTesting %s...\n", testfn);

	printf("KY=%s\n", sHexKey);
	printf("IV=%s\n", sHexIV);
	printf("PT=%s\n", sPlain);
	printf("ALG=%s\n", algstr);

	nchars = CIPHER_EncryptHex(NULL, 0, sPlain, sHexKey, sHexIV, algstr, 0);
	printf("CIPHER_EncryptHex returns %ld\n", nchars);
	if (nchars < 0) disp_error(nchars);
	assert(nchars >= 0);

	cthex = malloc(nchars + 1);
	nchars = CIPHER_EncryptHex(cthex, nchars, sPlain, sHexKey, sHexIV, algstr, 0);

	printf("CT=%s\n", cthex);
	printf("OK=%s\n", sCorrect);
	assert(stricmp(cthex, sCorrect) == 0);

	// Now decrypt back to plain text
	nchars = CIPHER_DecryptHex(NULL, 0, cthex, sHexKey, sHexIV, algstr, 0);
	printf("CIPHER_DecryptHex returns %ld\n", nchars);
	if (nchars < 0) disp_error(nchars);
	assert(nchars >= 0);
	chkhex = malloc(nchars + 1);
	nchars = CIPHER_DecryptHex(chkhex, nchars, cthex, sHexKey, sHexIV, algstr, 0);
	printf("P'=%s\n", chkhex, nchars);
	assert(stricmp(chkhex, sPlain) == 0);

	free(cthex);
	free(chkhex);

	printf("...%s tested OK\n", testfn);

}

static void do_compr(const char *msg, unsigned char *input, long in_len, long opt, int istext)
{
	unsigned char *pcomp, *pcheck;
	long uncomp_len, comp_len, result;

	printf("%s\n", msg);
	uncomp_len = in_len;
	printf("Input length = %ld bytes\n", uncomp_len);

	comp_len = COMPR_Compress(NULL, 0, input, uncomp_len, opt);
	assert(comp_len > 0);
	printf("Compressed length = %ld bytes\n", comp_len);
	/* Alloc buffer storage */
	pcomp = (unsigned char*)malloc(comp_len);
	assert(pcomp != NULL);
	/* Do compression */
	result = COMPR_Compress(pcomp, comp_len, input, uncomp_len, opt);
	assert(result > 0);
	pr_hexbytes(pcomp, comp_len);

	/* Now uncompress and check */
	uncomp_len = COMPR_Uncompress(NULL, 0, pcomp, comp_len, opt);
	printf("Uncompressed length = %ld bytes\n", uncomp_len);
	assert(uncomp_len > 0);
	pcheck = (unsigned char*)malloc(uncomp_len);
	assert(pcheck != NULL);
	result = COMPR_Uncompress(pcheck, uncomp_len, pcomp, comp_len, opt);
	assert(result > 0);
	printf("Inflated length = %ld\n", result);
	// Only print if "small"
	if (uncomp_len < 256) {
		pr_hexbytes(pcheck, uncomp_len);
		if (istext) printf("[%s]\n", pcheck);
	}

	/* Do we have the same as we started with? */
	assert(memcmp(pcheck, input, uncomp_len) == 0);
	free(pcheck);
	free(pcomp);

}

void test_COMPR(void)
{
	char *testfn = "COMPR_Compress";
	unsigned char *input =
		"hello, hello, hello. This is a 'hello world' message "
		"for the world, repeat, for the world.";
	unsigned char bindata[2048] = { 0 };
	unsigned char block16[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	};
	long inlen;
	int i, nb;

	printf("Testing %s...\n", testfn);

	/* Find out compressed length of string input, then add one
	NB don't use strlen for binary data */
	inlen = (long)strlen(input) + 1;
	printf("Input length = %ld bytes\n", inlen);

	do_compr("Using ZLIB", input, inlen, API_COMPR_ZLIB, 1);
	do_compr("Using ZSTD", input, inlen, API_COMPR_ZSTD, 1);

	// Generate binary data
	nb = sizeof(bindata) / sizeof(block16);
	for (i = 0; i < nb; i++) {
		memcpy(&bindata[i * 16], block16, 16);
	}
	pr_byteshexwrap(120, "bindata=(", block16, sizeof(block16), ") x 128\n");
	inlen = sizeof(bindata);

	do_compr("Using ZLIB", bindata, inlen, API_COMPR_ZLIB, 0);
	do_compr("Using ZSTD", bindata, inlen, API_COMPR_ZSTD, 0);


	printf("...%s tested OK\n", testfn);
}

void test_HASH_Length(void)
{
	char *testfn = "test_HASH_Length()";
	long nbytes;

	printf("\nTesting %s...\n", testfn);
	nbytes = HASH_Length(API_HASH_SHA1);
	printf("HASH_Length(SHA-1) returns %ld\n", nbytes);
	assert(nbytes == 20);

	nbytes = HASH_Length(API_HASH_SHA256);
	printf("HASH_Length(SHA-256) returns %ld\n", nbytes);
	assert(nbytes == 32);

	nbytes = HASH_Length(API_HASH_SHA512);
	printf("HASH_Length(SHA-512) returns %ld\n", nbytes);
	assert(nbytes == 64);

	nbytes = HASH_Length(API_HASH_ASCON_HASH);
	printf("HASH_Length(ASCON_HASH) returns %ld\n", nbytes);
	assert(nbytes ==32);


	printf("...%s tested OK\n", testfn);
}

void test_AEAD_EncryptWithTag_ascon(void)
{
	char *testfn = "test_AEAD_EncryptWithTag_ascon()";

	long nbytes, ctlen, dtlen;

	const char *ref = "ascon128v12/LWC_AEAD_KAT_128_128.txt, Count = 303";
	BYTE key[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	};
	BYTE pt[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08,
	};
	BYTE iv[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	};
	BYTE aad[] = {
		0x00, 0x01, 0x02, 0x03, 0x04,
	};
	BYTE ctok[] = { /* including tag */
		0x0E, 0x6A, 0x8B, 0x0C, 0xA5, 0x17, 0xF5, 0x3D,
		0x3D, 0x37, 0x56, 0x23, 0xAC, 0x11, 0xC8, 0x52,
		0xFF, 0x0A, 0x98, 0x09, 0x8C, 0xCB, 0x74, 0x29,
		0xF2,
	};

	// NB fixed length
	BYTE ct[256] = { 0 };
	BYTE dt[256] = { 0 };

	printf("\nTesting %s...\n", testfn);

	printf("Ref=\"%s\"\n", ref);
	pr_bytesmsg("KY: ", key, sizeof(key));
	pr_bytesmsg("IV: ", iv, sizeof(iv));
	pr_bytesmsg("AD: ", aad, sizeof(aad));
	pr_bytesmsg("PT: ", pt, sizeof(pt));

	nbytes = AEAD_EncryptWithTag(NULL, 0, pt, sizeof(pt), key, sizeof(key), iv, sizeof(iv), aad, sizeof(aad), API_AEAD_ASCON_128);
	printf("AEAD_EncryptWithTag(NULL) returns %ld\n", nbytes);
	if (nbytes < 0) disp_error(nbytes);
	assert(nbytes > 0);
	nbytes = AEAD_EncryptWithTag(ct, nbytes, pt, sizeof(pt), key, sizeof(key), iv, sizeof(iv), aad, sizeof(aad), API_AEAD_ASCON_128);
	printf("AEAD_EncryptWithTag() returns %ld\n", nbytes);
	if (nbytes < 0) disp_error(nbytes);
	assert(nbytes > 0);
	pr_bytesmsg("CT: ", ct, nbytes);
	pr_bytesmsg("OK: ", ctok, nbytes);
	assert(0 == memcmp(ct, ctok, nbytes) && sizeof(ctok) == nbytes);

	ctlen = nbytes;
	dtlen = AEAD_DecryptWithTag(NULL, 0, ct, ctlen, key, sizeof(key), iv, sizeof(iv), aad, sizeof(aad), API_AEAD_ASCON_128);
	printf("AEAD_DecryptWithTag(NULL) returns %ld\n", dtlen);
	if (dtlen < 0) disp_error(dtlen);
	assert(dtlen >= 0);
	nbytes = AEAD_DecryptWithTag(dt, dtlen, ct, ctlen, key, sizeof(key), iv, sizeof(iv), aad, sizeof(aad), API_AEAD_ASCON_128);
	printf("AEAD_DecryptWithTag() returns %ld\n", nbytes);
	if (nbytes < 0) disp_error(nbytes);
	assert(nbytes >= 0);
	pr_bytesmsg("DT: ", dt, nbytes);
	assert(0 == memcmp(pt, dt, nbytes) && sizeof(pt) == nbytes);

	printf("...%s tested OK\n", testfn);
}

test_HASH_Bytes_ascon(void)
{
	char *testfn = "HASH_Bytes_ascon()";

	long lRet;
	unsigned char digest[API_MAX_HASH_BYTES];
	const char *ref = "asconhashv12/LWC_HASH_KAT_256.txt; Count = 513";
	char msghex[] = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627"
		"28292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F"
		"505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F7071727374757677"
		"78797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F"
		"A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7"
		"C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEF"
		"F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF000102030405060708090A0B0C0D0E0F1011121314151617"
		"18191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
		"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F6061626364656667"
		"68696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F"
		"909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7"
		"B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"
		"E0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF";
	char *msgok = "7039284FA1CB4C798250B1A62E2378718040E10F206527BFCEB2FF3887884484";
	char *msgemptyok = "7346BC14F036E87AE03D0997913088F5F68411434B3CF8B54FA796A80D251F91";
	unsigned char message[1024];
	unsigned char digestok[32];
	long msglen;
	char digesthex[API_MAX_HASH_CHARS + 1];

	printf("Testing %s...\n", testfn);

	printf("%s\n", ref);
	msglen = CNV_BytesFromHexStr(message, sizeof(message), msghex);
	pr_bytesmsg("Msg=", message, msglen);
	lRet = HASH_Bytes(digest, sizeof(digest), message, msglen, API_HASH_ASCON_HASH);
	assert(lRet > 0);
	pr_bytesmsg("MD=", digest, API_ASCON_HASH_BYTES);
	CNV_BytesFromHexStr(digestok, sizeof(digestok), msgok);
	pr_bytesmsg("OK=", digestok, API_ASCON_HASH_BYTES);
	assert(memcmp(digest, digestok, API_ASCON_HASH_BYTES) == 0);

	printf("Use HASH_HexFromHex...\n");
	lRet = HASH_HexFromHex(digesthex, sizeof(digesthex) - 1, msghex, API_HASH_ASCON_HASH);
	printf("HASH_HexFromHex returns %ld\n", lRet);
	assert(lRet > 0);
	printf("MD = %s\n", digesthex);
	printf("OK = %s\n", msgok);
	assert(0 == stricmp(digesthex, msgok));

	printf("Use HASH_HexFromBytes...\n");
	lRet = HASH_HexFromBytes(digesthex, sizeof(digesthex) - 1, message, msglen, API_HASH_ASCON_HASH);
	printf("HASH_HexFromBytes returns %ld\n", lRet);
	assert(lRet > 0);
	printf("MD = %s\n", digesthex);
	printf("OK = %s\n", msgok);
	assert(0 == stricmp(digesthex, msgok));

	printf("...%s tested OK\n", testfn);
}

void test_XOF_ascon(void)
{
	char *testfn = "test_XOF_ascon()";

	long r;
	unsigned char msg1[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	};
	unsigned char output[1024];
	unsigned char *pmsg;
	long mlen, olen;
	char *okhex;
	long flag;

	printf("Testing %s...\n", testfn);

	// Ref: asconxofv12/LWC_HASH_KAT_256.txt, Count = 17
	flag = API_XOF_ASCON_XOF;
	pmsg = msg1;
	mlen = sizeof(msg1);
	olen = 32;
	okhex = "C861A89CFB1335F278C96CF7FFC9753C290CBE1A4E186D2923B496BB4EA5E519";
	printf("ASCON-XOF%c\n", (API_XOF_ASCON_XOFA == flag ? 'A' : ' '));
	pr_byteshexwrap(32, "Msg =", pmsg, mlen, "\n");
	r = XOF_Bytes(output, olen, pmsg, mlen, flag);
	if (r < 0) disp_error(r);
	assert(r > 0);
	pr_byteshexwrap(80, "MD = ", output, olen, "\n");
	pr_wrapstr("OK = ", okhex, 64);
	assert(0 == cmp_bytes2hex(output, olen, okhex));

	// Ask for more than 32
	olen = 40;
	r = XOF_Bytes(output, olen, pmsg, mlen, flag);
	if (r < 0) disp_error(r);
	assert(r > 0);
	pr_byteshexwrap(80, "MD = ", output, olen, "\n");
	// Ask for less
	olen = 20;
	r = XOF_Bytes(output, olen, pmsg, mlen, flag);
	if (r < 0) disp_error(r);
	assert(r > 0);
	pr_byteshexwrap(80, "MD = ", output, olen, "\n");

	// ASCON-XOFA of empty string
	// Ref: asconxofav12/LWC_HASH_KAT_256.txt, Count = 1
	flag = API_XOF_ASCON_XOFA;
	pmsg = NULL;
	mlen = 0;
	olen = 32;
	okhex = "7C10DFFD6BB03BE262D72FBE1B0F530013C6C4EADAABDE278D6F29D579E3908D";
	printf("ASCON-XOF%c\n", (API_XOF_ASCON_XOFA == flag ? 'A' : ' '));
	pr_byteshexwrap(32, "Msg =", pmsg, mlen, "\n");
	r = XOF_Bytes(output, olen, pmsg, mlen, flag);
	if (r < 0) disp_error(r);
	assert(r > 0);
	pr_byteshexwrap(32, "MD = ", output, olen, "\n");
	pr_wrapstr("OK = ", okhex, 64);
	assert(0 == cmp_bytes2hex(output, olen, okhex));

	printf("...%s tested OK\n", testfn);
}

void test_XOF_MGF1(void)
{
	char *testfn = "test_XOF_MGF1()";

	long r;
	unsigned char input1[] = {
		0x3B, 0x5C, 0x05, 0x6A, 0xF3, 0xEB, 0xBA, 0x70,
		0xD4, 0xC8, 0x05, 0x38, 0x04, 0x20, 0x58, 0x55,
		0x62, 0xB3, 0x24, 0x10, 0xA7, 0x78, 0xF5, 0x58,
		0xFF, 0x95, 0x12, 0x52, 0x40, 0x76, 0x47, 0xE3,
	};
	unsigned char input2[] = {
		0x01, 0x23, 0x45, 0xFF,
	};
	unsigned char output[1024];
	unsigned char *pmsg;
	long mlen, olen;
	char *okhex;
	long flag;

	printf("Testing %s...\n", testfn);


	flag = API_XOF_MGF1_SHA256;
	pmsg = input1;
	mlen = sizeof(input1);
	olen = 34;
	okhex = "5b7eb772aecf04c74af07d9d9c1c1f8d3a90dcda00d5bab1dc28daecdc86eb87611e";
	pr_byteshexwrap(32, "Msg =\n", pmsg, mlen, "\n");
	printf("Outputlen = %d bytes\n", olen);

	r = XOF_Bytes(output, olen, pmsg, mlen, flag);
	assert(r > 0);
	pr_byteshexwrap(36, "Output =\n", output, olen, "\n");
	pr_wrapstr("OK:\n", okhex, 72);
	assert(0 == cmp_bytes2hex(output, olen, okhex));

	/*
	print("mgf1_sha1:", mgf1sha1(bytes.fromhex("012345ff"), 24).hex())
	# mgf1_sha1: 242fb2e7a338ae07e580047f82b7acff83a41ec5d8ff9bab
	*/
	flag = API_XOF_MGF1_SHA1;
	pmsg = input2;
	mlen = sizeof(input2);
	olen = 24;
	okhex = "242fb2e7a338ae07e580047f82b7acff83a41ec5d8ff9bab";
	pr_byteshexwrap(32, "Msg =\n", pmsg, mlen, "\n");
	printf("Outputlen = %d bytes\n", olen);
	r = XOF_Bytes(output, olen, pmsg, mlen, flag);
	assert(r > 0);
	pr_byteshexwrap(32, "Output =\n", output, olen, "\n");
	pr_wrapstr("OK:\n", okhex, 64);
	assert(0 == cmp_bytes2hex(output, olen, okhex));

	printf("...%s tested OK\n", testfn);
}

void test_CNV_ShortPathName(void)
{
	char *testfn = "test_CNV_ShortPathName()";
	long nchars;
	wchar_t *wfname;
	char *shortname;
	char *encfile, *decfile;
	long r;
	BYTE key[] = {
		0x71, 0x90, 0x42, 0x42, 0x0F, 0xF3, 0x99, 0x05,
		0x4A, 0xA8, 0xB8, 0x9F, 0xB6, 0xE5, 0x57, 0x6F,
	};
	BYTE iv[] = {
		0x5A, 0xD7, 0xD5, 0x26, 0xFF, 0xB5, 0x53, 0x63,
		0x7C, 0xBF, 0x62, 0xAC, 0x66, 0xCA, 0x5B, 0x47,
	};

	printf("\nTesting %s...\n", testfn);
#if defined(_WIN32) || defined(WIN32) 


	wfname = L"你好.txt"; // nihao.txt U+4F60 U+597D U+002E U+0074 U+0078 U+0074
	// Create a test file
	create_file_unicode_name(wfname, L"你好世界目录");
	nchars = CNV_ShortPathName(NULL, 0, wfname);
	printf("CNV_ShortPathName returns %ld\n", nchars);
	if (nchars < 0) disp_error(nchars);
	assert(nchars > 0);
	shortname = malloc(nchars + 1);
	nchars = CNV_ShortPathName(shortname, nchars, wfname);
	if (nchars < 0) disp_error(nchars);
	assert(nchars > 0);
	printf("ShortPath='%s'\n", shortname);
	printf("File '%s' is %ld bytes\n", shortname, file_length(shortname));

	// Make sure this short filename works with, say, the CIPHER_FileEncrypt function

	encfile = "nihao.enc";
	r = CIPHER_FileEncrypt(encfile, shortname, key, sizeof(key), iv, sizeof(iv), "aes128/ctr", API_IV_PREFIX);
	printf("CIPHER_FileEncrypt returns %ld\n", r);
	if (r != 0) disp_error(r);
	printf("File %s is %ld bytes\n", encfile, file_length(encfile));

	decfile = "nihao.dec.txt";
	r = CIPHER_FileDecrypt(decfile, encfile, key, sizeof(key), NULL, 0, "aes128/ctr", API_IV_PREFIX);
	printf("CIPHER_FileDecrypt returns %ld\n", r);
	if (r != 0) disp_error(r);
	printf("File %s is %ld bytes\n", decfile, file_length(decfile));
	pr_file_as_hex("", decfile, "\n");

	free(shortname);
#else
	printf("CNV_ShortPathName only works on Windows");
#endif

	printf("...%s tested OK\n", testfn);
}

void test_RNG_Intel(void)
{
	char *testfn = "test_RNG_Intel()";
	long n;

	printf("\nTesting %s...\n", testfn);

	n = RNG_Initialize("", 0);	// Check for Intel(R) DRNG support
	printf("RNG_Initialize('') returns %ld (If > 0 Intel(R) DRNG support available)\n", n);


	// NB this is just a demonstration. You woud not do this under normal circumstances.
	n = RNG_Initialize("", API_RNG_NO_INTEL_DRNG);	// Explicitly turn support off
	printf("RNG_Initialize('', RNG_NO_INTEL_DRNG) returns %ld (expected -ve)\n", n);
	if (n < 0) disp_error(n);
	n = RNG_Initialize("", 0);	// Now query again - it should be turned off
	printf("RNG_Initialize('') returns %ld (expected -ve)\n", n);

	printf("...%s tested OK\n", testfn);
}

/* GENERAL FUNCTIONS */

void test_API_Version(void)
{
    char *testfn = "API_Version()";
	long nRet;
	char timestamp[256];
	char platform[6];
	
	printf("\nTesting %s...\n", testfn);
	nRet = API_Version();
	printf("API_Version returns %ld.\n", nRet);
	nRet = API_CompileTime(timestamp, sizeof(timestamp)-1);
	printf("Compiled [%s]\n", timestamp);
	nRet = API_LicenceType(0);
	printf("Licence Type=%c\n", (char)nRet);
	/* What platform are we on? */
	nRet = API_LicenceType(API_GEN_PLATFORM);
	printf("IsWin64=%ld\n", nRet);
	nRet = API_ModuleName(platform, sizeof(platform)-1, API_GEN_PLATFORM);
	printf("Platform=[%s]\n", platform);

	printf("...%s tested OK\n", testfn);
}

void test_API_ModuleName(void)
{
    char *testfn = "API_ModuleName()";
	long nRet, len;
	char *buf;
	
	printf("\nTesting %s...\n", testfn);
	len = API_ModuleName(NULL, 0, 0);
	assert (len > 0);

	buf = malloc(len + 1);
	assert(buf);

	nRet = API_ModuleName(buf, len, 0);
	assert(nRet > 0);
	printf("API_ModuleName=[%s]\n", buf);
	free(buf);

	printf("...%s tested OK\n", testfn);
}

void test_API_PowerUpTests(void)
{
    char *testfn = "API_PowerUpTests()";
	long nRet;
	
	printf("\nTesting %s...\n", testfn);
	nRet = API_PowerUpTests(0);
	printf("API_PowerUpTests returns %ld\n", nRet);

	printf("...%s tested OK\n", testfn);
}

void test_API_ErrorLookup(void)
{
    char *testfn = "test_API_ErrorLookup()";
	long nRet;
	char errmsg[128];
	int i;
	
	printf("\nTesting %s...\n", testfn);
	for (i = 0; i < 10000; i++)
	{
		nRet = API_ErrorLookup(errmsg, sizeof(errmsg)-1, i);
		if (nRet > 0)
			printf("%d = %s\n", i, errmsg);
	}

	printf("...%s tested OK\n", testfn);
}

void test_API_VersionQuick(void)
{
	char *testfn = "API_VersionQuick()";
	long ver;
	char modname[512];
	char comptime[32];
	char platform[6];
	char info[128];

	printf("\n");
	ver = API_Version();
	// Get platform 
	API_Platform(platform, sizeof(platform) - 1);
	API_ModuleInfo(info, sizeof(info) - 1, 0);
	API_CompileTime(comptime, sizeof(comptime) - 1);
	printf("API_Version=%ld [%s] Lic=%c Compiled=[%s]\n", ver, platform, API_LicenceType(0), comptime);
	printf("[%s]\n", info);
	API_ModuleName(modname, sizeof(modname) - 1, 0);
	printf("[%s]\n", modname);
}

	
void do_all_tests(void)
{
	test_API_Version();
	test_API_ModuleName();
	test_AES128_BytesMode_CBC();
	test_AES128_FileHex();
	test_AES128_Hex();
	test_AES128_HexMode();
	test_AES128_HexModeError();
	test_AES128_HexMode_CBC();
	test_AES128_Hex_Monte();
	test_AES192_HexMode_CBC();
	test_AES256_HexMode_CBC();
	test_AESnnn_BytesMode_rand();
	test_AESnnn_InitUpdate_rand();
	test_API_ErrorLookup();
	test_API_PowerUpTests();
	test_BLF_BytesMode_rkeys();
	test_BLF_BytesMode_rmode();
	test_BLF_Bytes_rand();
	test_BLF_File();
	test_BLF_Hex();
	test_BLF_HexMode();
	test_BLF_UpdateHex();
	test_CIPHER_KeyWrap();
	test_CNV_BytesFromHexStr();
	test_CNV_HexFilter();
	test_CRC_Bytes();
	test_CRC_File();
	test_CRC_String();
	test_DES_Bytes_rand();
	test_DES_CheckKey();
	test_DES_FileHex();
	test_DES_Hex();
	test_DES_HexMode();
	test_DES_UpdateHex();
	test_HASH_HexFromHex();
	test_MAC_HexFromBytes();
	test_CMAC_HexFromBytes();
	test_CMAC_HexFromHex();
	test_MD5_AddString();
	test_MD5_BytesHash();
	test_MD5_BytesHexHash();
	test_MD5_FileHexHash();
	test_MD5_HexDigest();
	test_MD5_Hmac();
	test_MD5_StringHexHash();
	test_PBE_Kdf2();
	test_PBE_Kdf2_SHA2();
	test_RNG_Initialize();
	test_RNG_KeyBytes();
	test_RNG_KeyHex();
	test_RNG_Number();
	test_RNG_NonceData();
	test_RNG_Test();
	test_RNG_TestDRBGVS();
	test_SHA1_AddString();
	test_SHA1_BytesHash();
	test_SHA1_BytesHexHash();
	test_SHA1_FileHexHash();
	test_SHA1_HexDigest();
	test_SHA1_Hmac_KAT();
	test_SHA1_StringHexHash();
	test_SHA2_AddString();
	test_SHA2_BytesHash();
	test_SHA2_BytesHexHash();
	test_SHA2_FileHexHash();
	test_SHA2_HexDigest();
	test_SHA2_Hmac_KAT();
	test_SHA2_StringHexHash();
	test_TDEA_BytesMode_rand();
	test_TDEA_Bytes_rand();
	test_TDEA_FileHex();
	test_TDEA_Hex();
	test_TDEA_HexMode();
	test_WIPE_Data();
	test_WIPE_File();
	test_ZLIB();
	test_GCM_Encrypt();
	test_GCM_Decrypt();
	test_GCM_GMAC();
	test_HASH_HexFromBits();
	test_ArcFour();
	test_Stream_ChaCha20();
	test_MAC_Poly1305();
	test_AEAD_Encrypt();
	test_AEAD_Decrypt();
	test_AEAD_InitKey();
	test_CIPHER_EncryptBytes();
	test_CIPHER_FileEncrypt();
	test_PBE_Scrypt();
	test_PBE_ScryptHex();
	test_PAD_BytesBlock();
	test_PAD_HexBlock();
	test_SHA3();
	test_SHA3_HMAC();
	test_SHA3_KMAC();
	test_XOF();
	test_PRF();
	test_CIPHER_EncryptBytesPad2_aes_iv_prefix();
	test_AEAD_EncryptWithTag();
	test_HASH_Init();
	test_MAC_Init();
	test_CIPHER_Init();
	test_CIPHER_InitHex();
	test_CIPHER_EncryptHex();
	test_COMPR();
	test_HASH_Length();
	test_AEAD_EncryptWithTag_ascon();
	test_HASH_Bytes_ascon();
	test_XOF_ascon();
	test_XOF_MGF1();
	test_CNV_ShortPathName();
	test_RNG_Intel();

	/* Do this last so we can see which version we are using */
	test_API_VersionQuick();
}


int main(int argc, char *argv[])
{
	int c;

/* MSVC memory leak checking stuff */
#if _MSC_VER >= 1100
	_CrtSetDbgFlag( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
	_CrtSetReportMode( _CRT_WARN, _CRTDBG_MODE_FILE );
	_CrtSetReportFile( _CRT_WARN, _CRTDBG_FILE_STDOUT );
	_CrtSetReportMode( _CRT_ERROR, _CRTDBG_MODE_FILE );
	_CrtSetReportFile( _CRT_ERROR, _CRTDBG_FILE_STDOUT );
	_CrtSetReportMode( _CRT_ASSERT, _CRTDBG_MODE_FILE );
	_CrtSetReportFile( _CRT_ASSERT, _CRTDBG_FILE_STDOUT );
#endif

	printf("Version=%ld\n", API_Version());
	make_new_test_dir();

	do_all_tests();

	printf("ALL DONE. \n");

	// Clean up test directory by default unless first command line argument is exactly "--prompt"
	if (argc > 1 && 0 == strcmp(argv[1], "--prompt")) {
		/* Option to clean up */
		printf("The temp directory '%s' has been created by this test program.\n"
			"Do you want to remove this directory? [Y]/N: ", testdir);
		c = getchar();
		if (!(c == 'N' || c == 'n'))
			remove_test_dir(testdir, old_cwd);
	}
	else {
		remove_test_dir(testdir, old_cwd);
	}

	return 0;
}

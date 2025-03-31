/* ERROR CODES (C/C++) */
// For CryptoSys API v6.22 <https://www.cryptosys.net/api/>
#ifndef API_ERRORCODES_H_
#define API_ERRORCODES_H_

#define SUCCESS_NO_ERROR         0   /* OK, success, no error */
#define OPEN_ERROR               1   /* Cannot open input file */
#define CREATE_ERROR             2   /* Cannot create output file */
#define READ_ERROR               3   /* File read error */
#define WRITE_ERROR              4   /* File write error */
#define MEMORY_ERROR             5   /* Not enough memory */
#define BAD_PARAM_ERROR          6   /* Parameter is wrong or missing */
#define BAD_FORMAT_ERROR         7   /* Data is in wrong format */
#define INVALID_DATA_ERROR       8   /* Invalid data */
#define EOF_ERROR                9   /* Unexpected end of file found */
#define OUT_OF_RANGE_ERROR      11   /* Value out of range */
#define DUP_ERROR               12   /* Duplicate data or filename */
#define NULL_ERROR              14   /* Unexpected NULL value */
#define DECRYPT_ERROR           15   /* Decryption error */
#define BAD_FLAG_ERROR          17   /* Invalid option */
#define WIPE_ERROR              18   /* Failed to wipe data */
#define NOT_SUPPORTED_ERROR     19   /* Item is not supported */
#define TEST_FAILED_ERROR       23   /* Failed a test e.g. known answer test */
#define BAD_LENGTH_ERROR        26   /* Data not a valid length */
#define SHORT_BUF_ERROR         30   /* Not enough room in output buffer */
#define ZLIB_COMPR_ERROR        31   /* Zlib compression error */
#define BAD_KEY_LEN_ERROR       33   /* Invalid key length */
#define BAD_BLK_LEN_ERROR       34   /* Invalid block length */
#define BAD_MODE_ERROR          35   /* Invalid mode */
#define BAD_KEY_ERROR           36   /* Invalid key */
#define BAD_IV_ERROR            37   /* Invalid initialization vector */
#define BAD_IV_LEN_ERROR        38   /* Invalid IV length */
#define ENCODING_ERROR          39   /* Unable to encode */
#define AUTH_FAIL_ERROR         40   /* Authentication failed */
#define MISUSE_ERROR            41   /* Function called out of sequence */
#define WEAK_KEY_ERROR          52   /* Weak key */
#define INVALID_HANDLE_ERROR    64   /* Invalid context handle */
#define PRNG_ERR_FILE_OPEN     201   /* PRNG: Cannot open input file */
#define PRNG_ERR_FILE_CREATE   202   /* PRNG: Cannot create output file */
#define PRNG_ERR_FILE_READ     203   /* PRNG: File read error */
#define PRNG_ERR_FILE_WRITE    204   /* PRNG: File write error */
#define PRNG_ERR_FILE_LOCK     205   /* PRNG: File locking error */
#define PRNG_ERR_UNINST        210   /* PRNG: Uninstantiation failed */
#define PRNG_ERR_TOOBIG        211   /* PRNG: Requested length is too large */
#define PRNG_ERR_FAILURE       212   /* PRNG: Function failed */
#define PRNG_ERR_BADPARAM      213   /* PRNG: Invalid input parameter */
#define PRNG_ERR_NOTAVAIL      214   /* PRNG: Function is not available */
#define PRNG_ERR_CATASTROPHIC  299   /* PRNG: Catastrophic failure */
#define INTERNAL_ERROR        9745   /* Something not expected to happen has happened */
#define MISC_ERROR            9999   /* Miscellaneous error */

#endif /*API_ERRORCODES_H_*/

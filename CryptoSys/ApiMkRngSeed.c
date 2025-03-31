/* $Id: ApiMkRngSeed.c $ 
* Create a seed file suitable for the CryptoSys API function RNG_Initialize.
*   Last updated:
*   $Date: 2024-01-05 13:23 $
*   $Version: 2.1.0 $
*/
/******************************* LICENSE ***********************************
* Copyright (C) 2004-24 David Ireland, DI Management Services Pty Limited.
* All rights reserved. <www.di-mgt.com.au> <www.cryptosys.net>
* The code in this module is licensed under the terms of the MIT license.
* For a copy, see <http://opensource.org/licenses/MIT>
****************************************************************************/
/* Changelog:
	[2008-05-13] Updated to create a default file `seed.dat` after prompt.
	[2023-12-06] Added options to change strength.
	[2024-01-05] Added option to use Intel(R) DRNG, if available.
*/
/* Requires CryptoSys API to be installed available from <https://www.cryptosys.net/api.html> */

#include <stdio.h>
#include <stdlib.h>
#include "diCryptoSys.h"

/* Link to library in MSVC and Borland */
#if _MSC_VER >= 1400 
/* This should work in MS VS2005 and above */
#if _WIN64
	#if _DEBUG
	#define MYLIBDIR "../x64/Debug/"
	#else
	#define MYLIBDIR "../x64/Release/"
	#endif
#else
	#if _DEBUG
	#define MYLIBDIR "../Debug/"
	#else
	#define MYLIBDIR "../Release/"
	#endif
#endif	/* END _WIN64 */
#pragma comment(lib, MYLIBDIR "diCryptoSys.lib")
#elif (defined(_MSC_VER) && _MSC_VER < 1400) || defined(__BORLANDC__)
/* Link to library in same dir as this source.
 * This works in old MSVC++ and Borland.
 */
#pragma comment(lib, ".\\diCryptoSys.lib")
#endif	/* END _MSC_VER >= 1400 */

#define PROG_NAME "ApiMkRngSeed"
#define PROG_VERSION "v2.1"

const char *copyright =
"Copyright (C) 2004-24 DI Management Services Pty Ltd.";

#define SEEDFILE "seed.dat"

void usage(int n)
{
	fprintf(stderr,
		"Usage: %s [OPTION]... [FILENAME] [\"ALTPROMPT\"]\n"
		"Generate a new RNG seed file with random keyboard entries.\n"
		"OPTIONS:\n"
		"  -s {112|[128]|192|256} required security strength in bits\n"
		"  -r use Intel(R) DRNG, if available, instead of keystrokes\n"
		"  -h display this help and exit\n"
		"  -v display version information and exit\n"
		"FILENAME  Name of seedfile to be created (default='%s')\n"
		"ALTPROMPT Alternative prompt to use in dialog box\n"
		"* Requires CryptoSys API <https://www.cryptosys.net/api.html>\n"
		, PROG_NAME, SEEDFILE);
	exit(n);
}

int main(int argc, char *argv[])
{
	long ver, r;
	char errmsg[128];
	char *prompt;
	char *fname = SEEDFILE;
	int c;
	int strength = 128;  // Default strength
	long opts = API_RNG_STRENGTH_128;
	int intel_features = 0;
	int use_intel = 0;

	ver = API_Version();
	intel_features = RNG_Initialize("", 0);

	// Parse any options
	while (argc > 1 && argv[1][0] == '-') {
		int c = argv[1][1];
		switch (c)
		{
		case 's':
			if (argc > 2) {
				// Expecting an integer 112|128|192|256
				strength = atoi(argv[2]);
				argc--;
				argv++;
			}
			else {
				fprintf(stderr, "missing argument for -s option\n");
				usage(1);
			}
			break;
		case 'r':
			if (intel_features <= 0) {
				printf("Sorry, Intel(R) DRNG is not available on this system. The -r option cannot be used.\n");
				exit(1);
			}
			use_intel = 1;
			break;
		case 'h':
			usage(0);
			break;
		case 'v':
			printf("%s %s [api:%03ld] (%s)\n%s\n", PROG_NAME, PROG_VERSION, ver, __DATE__" "__TIME__, copyright);
			printf("[Intel(R) DRNG is%savailable]\n", (intel_features > 0 ? " " : " NOT "));
			exit(0);
			break;
		default:
			fprintf(stderr, "Invalid option -%c\n", c);
			usage(1);
			break;
		}
		argc--;
		argv++;
	}

	switch (strength) {
	case 112:
		opts = API_RNG_STRENGTH_112;
		break;
	case 128:
		opts = API_RNG_STRENGTH_128;
		break;
	case 192:
		opts = API_RNG_STRENGTH_192;
		break;
	case 256:
		opts = API_RNG_STRENGTH_256;
		break;
	default:
		fprintf(stderr, "Invalid argument for -s expected {112|128|192|256}\n");
		usage(1);
	}

	printf("%s %s [api:%03ld]%s\n", PROG_NAME, PROG_VERSION, ver, (intel_features > 0 ? " (Have Intel DRNG)" : ""));
	if (argc > 1)
		fname = argv[1];

	if (use_intel && intel_features > 0) {
		printf("Using Intel(R) DRNG to generate secure seed file...\n");
		r = RNG_Initialize("", 0);	// Do again for good measure
		r = RNG_UpdateSeedFile(fname, 0);
		if (0 == r) {
			printf("Created seed file '%s' with estimated security strength 256 bits.\n", fname);
			exit(0);
		}
		else {
			printf("Failed to create seed file '%s'\n", fname);
		}

	}


	printf("This will create a new seed file '%s' with estimated security strength %d bits. Continue Y/N: ", fname, strength);
	c = getchar();
	if (c != 'Y' && c != 'y')
		exit(EXIT_FAILURE);

	if (argc > 2)
		prompt = argv[2];
	else
		prompt = NULL;

	printf("Prompting user to type random characters on keyboard...\n");
	r = RNG_MakeSeedFile(fname, prompt, opts);
	if (r == 0)
		printf("Created seed file '%s'\n", fname);
	else
	{
		API_ErrorLookup(errmsg, sizeof(errmsg)-1, r);
		printf("ERROR: %s\n", errmsg);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}


/* $Id: APICheck.c $ */

/* A simple Windows program to display the details of the CryptoSys API core DLL */

/* $ $Date: 2010-08-09 21:12:00 $ */

#define WIN32_LEAN_AND_MEAN
#define STRICT
#include <windows.h>
#include "diCryptoSys.h"

// Compiler-specific explicit link to library
// This pragma trick works in (old) MSVC and Borland for LIB in current dir.
#if (_MSC_VER < 1400)
#pragma comment(lib, ".\\diCryptoSys.lib")
#endif
// For MSVC 2005+, set a Linker dependency in Properties to diCryptoSys.lib:
// Configuration Properties > Linker > Input > Additional Dependencies.

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
				   LPSTR lpszCmdLine, int nCmdShow)
{
	char msg[2048];
	char compiled[255];
	char modname[MAX_PATH];
	long ver, lic, iswin64;

	/* Get details from API */
	ver = API_Version();
	API_CompileTime(compiled, sizeof(compiled)-1);
	API_ModuleName(modname, sizeof(modname)-1, 0);
	lic = API_LicenceType(0);
	/* New in version 4.3: check if DLL is compiled for Win64 */
	iswin64 = API_LicenceType(API_GEN_PLATFORM);	/* Returns 1 if X64 or 0 if Win32 */

	/* Compose into a string */
	wsprintf(msg, "Version=%ld\r\nLicence Type=%c\r\nModule=%s\r\nPlatform=%s\r\nCompiled=%s", 
		ver, lic, modname, (iswin64 ? "X64" : "Win32"), compiled);
	
	/* Display */
	MessageBox(NULL, msg, "CryptoSys API Check", 0);

	return 0;
}

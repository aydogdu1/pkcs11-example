
#ifndef PKCS11_COMMON_HPP
#define PKCS11_COMMON_HPP

#include <cryptoki.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>


void *libHandle = 0; 
CK_FUNCTION_LIST *p11Func = NULL;
CK_SLOT_ID slotId = 146688163;
CK_SESSION_HANDLE hSession = 0;
CK_BYTE *slotPin = NULL;

using namespace std;


// This function loads a pkcs11 library. Path of the pkcs11 library is read using P11_LIB environment variable.
void loadHSMLibrary()
{
        char libPath[] ="/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so";
        
        libHandle = dlopen(libPath,RTLD_NOW);
        
	if(!libHandle)
	{
		cout << "Failed to load P11 library. " << libPath << endl;
		exit(1);
	}
	CK_C_GetFunctionList C_GetFunctionList = (CK_C_GetFunctionList)dlsym(libHandle,"C_GetFunctionList");
     
	C_GetFunctionList(&p11Func);
           
	if(!p11Func)
	{
		cout << "Failed to load P11 Functions." << endl;
		exit(1);
	}
}


// Before exiting, this functions performs some memory cleanup.
void freeResource()
{
        dlclose(libHandle);
        p11Func = NULL;
        slotPin = NULL;
}


// This function checks if a requested PKCS #11 operation was a success or a failure. 
void checkOperation(CK_RV rv, const char *message)
{
	if(rv!=CKR_OK)
	{
		cout << message << " failed with : " << rv << endl;
		printf("RV : %#08lx", rv);
		freeResource();
		exit(1);
	}
}

// This function connects this sample to a token. It initializes the library, opens a new session and performs login.
void connectToSlot(const char *password){
    	slotPin = new CK_BYTE[strlen(password)];
	slotPin = (CK_BYTE_PTR)password;
    
	checkOperation(p11Func->C_Initialize(NULL_PTR),"C_Initialize");
	checkOperation(p11Func->C_OpenSession(slotId, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession),"C_OpenSession");
	checkOperation(p11Func->C_Login(hSession, CKU_USER, slotPin, strlen((const char*)slotPin)),"C_Login");
}



// This function disconnects this sample from a token. It first logs out of the slot, closes the session and then finalizes the library.
void disconnectFromSlot()
{
	checkOperation(p11Func->C_Logout(hSession),"C_Logout");
	checkOperation(p11Func->C_CloseSession(hSession),"C_CloseSesion");
	checkOperation(p11Func->C_Finalize(NULL_PTR),"C_Finalize");
}


// Converts a byte data to hex.
void printHex(unsigned char *data, int size)
{
	for(int ctr = 0; ctr<size; ctr++)
	{
		printf("%02x", data[ctr]);
	}
	cout << endl;
}

#endif /* PKCS11_COMMON_HPP */


/*++
Copyright (c) Microsoft Corporation.  All rights reserved.

    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
    KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
    PURPOSE.

Module Name:

    regfltr.h

Abstract: 

    Header file for the sample driver

Environment:

    Kernel mode only


--*/

/*
	Daniel 5/22/2018

	This header file contains the functions that return the time the registry operation was intercepted and
	the user SID:
		1. GetTimestamp() -> Returns time (in UNIX Epoch time)
		2. GetUserSID() -> Returns the user SID

	The functions are all the way at the bottom of this file

	This header file also contains the declaration of the functions in the "tool.c" file:
		1. extern NTSTATUS GetUserID(_Inout_ PUNICODE_STRING userId);

		2. extern NTSTATUS LoadRegistryConfigKey(_In_ const PWCHAR Value, _Inout_ CHAR *Variable);

		3. extern NTSTATUS LoadActiveName(_In_ const PWCHAR Value, _Inout_ CHAR Variable[256]);

	Any function that you code in a ".c" file should have an external declaration just like the above in
	a header file. This way, you can call that function in another ".c" file by "#include <header.h>"
*/

#pragma once

#include <ntifs.h>
#include <ntstrsafe.h>
#include <wdmsec.h>
#include "common.h"
#include <time.h>
#include <fltKernel.h>

//#include <io.h>
//#include <winsock2.h>

#define BUFFER 8192

//
// Pool tags
//

#define REGFLTR_CONTEXT_POOL_TAG          '0tfR'
#define REGFLTR_CAPTURE_POOL_TAG          '1tfR'

//Ticks
#define WINDOWS_TICK 10000
#define SEC_TO_UNIX_EPOCH 11644473600000LL

//
// Logging macros
//

#define InfoPrint(str, ...)                 \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID,         \
               DPFLTR_INFO_LEVEL,           \
               "%S: "##str"\n",             \
               DRIVER_NAME,                 \
               __VA_ARGS__)

#define ErrorPrint(str, ...)                \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID,         \
               DPFLTR_ERROR_LEVEL,          \
               "%S: %d: "##str"\n",         \
               DRIVER_NAME,                 \
               __LINE__,                    \
               __VA_ARGS__)


//
// The root key used in the samples
//
extern HANDLE g_RootKey;

//Defining the GetUserID function in Util.c
extern NTSTATUS GetUserID(_Inout_ PUNICODE_STRING userId);

extern NTSTATUS LoadRegistryConfigKey(_In_ const PWCHAR Value, _Inout_ CHAR *Variable);

extern NTSTATUS LoadActiveName(_In_ const PWCHAR Value, _Inout_ CHAR Variable[256]);

extern NTSTATUS LoadRegistryValue(_In_ ULONG Value, _In_ UNICODE_STRING KeyPath, _Inout_ CHAR Variable[256]);

//
// Pointer to the device object used to register registry callbacks
//
extern PDEVICE_OBJECT g_DeviceObj;


//
// Registry callback version
//
extern ULONG g_MajorVersion;
extern ULONG g_MinorVersion;


//
// Set to TRUE if TM and RM were successfully created and the transaction
// callback was successfully enabled. 
//
extern BOOLEAN g_RMCreated;


//
// Flag that indicates if the system is win8 or higher. This is set on
// driver entry by calling RtlVerifyVersionInfo.
//
extern BOOLEAN g_IsWin8OrGreater;


//
// The following are variables used to manage callback contexts handed
// out to user mode.
//

#define MAX_CALLBACK_CTX_ENTRIES            10

//
// The fast mutex guarding the callback context list
//
extern FAST_MUTEX g_CallbackCtxListLock;

//
// The list head
//
extern LIST_ENTRY g_CallbackCtxListHead;

//
// Count of entries in list
//
extern USHORT g_NumCallbackCtxListEntries;

//
// Context data structure for the transaction callback RMCallback
//

typedef struct _RMCALLBACK_CONTEXT {

    //
    // A bit mask of all transaction notifications types that the RM Callback is 
    // notified of.
    //
    ULONG Notification;

    //
    // The handle to an enlistment
    //
    HANDLE Enlistment;
    
} RMCALLBACK_CONTEXT, *PRMCALLBACK_CONTEXT;


//
// The context data structure for the registry callback. It will be passed 
// to the callback function every time it is called. 
//

typedef struct _CALLBACK_CONTEXT {

    //
    // List of callback contexts currently active
    //
    LIST_ENTRY CallbackCtxList;

    //
    // Specifies which callback helper method to use
    //
    CALLBACK_MODE CallbackMode;

    //
    // Records the current ProcessId to filter out registry operation from
    // other processes.
    //
    HANDLE ProcessId;

    //
    // Records the altitude that the callback was registered at
    //
    UNICODE_STRING Altitude; 
    WCHAR AltitudeBuffer[MAX_ALTITUDE_BUFFER_LENGTH];
        
    //
    // Records the cookie returned by the registry when the callback was 
    // registered
    //
    LARGE_INTEGER Cookie;

    //
    // A pointer to the context for the transaction callback. 
    // Used to enlist on a transaction. Only used in the transaction samples.
    //
    PRMCALLBACK_CONTEXT RMCallbackCtx;

    //
    // These fields record information for verifying the behavior of the
    // certain samples. They are not used in all samples
    //
    
    //
    // Number of times the RegNtCallbackObjectContextCleanup 
    // notification was received
    //
    LONG ContextCleanupCount;

    //
    // Number of times the callback saw a notification with the call or
    // object context set correctly.
    //
    LONG NotificationWithContextCount;

    //
    // Number of times callback saw a notirication without call or without
    // object context set correctly
    //
    LONG NotificationWithNoContextCount;

    //
    // Number of pre-notifications received
    //
    LONG PreNotificationCount;

    //
    // Number of post-notifications received
    //
    LONG PostNotificationCount;
    
} CALLBACK_CONTEXT, *PCALLBACK_CONTEXT;


//
// The registry and transaction callback routines
//

EX_CALLBACK_FUNCTION Callback;

NTSTATUS  
RMCallback(
    _In_ PKENLISTMENT EnlistmentObject,
    _In_ PVOID RMContext,    
    _In_ PVOID TransactionContext,    
    _In_ ULONG TransactionNotification,    
    _Inout_ PLARGE_INTEGER TMVirtualClock,
    _In_ ULONG ArgumentLength,
    _In_ PVOID Argument
    );

//
// The samples and their corresponding callback helper methods
//

NTSTATUS 
CallbackPreNotificationBlock(
    _In_ PCALLBACK_CONTEXT CallbackCtx,
    _In_ REG_NOTIFY_CLASS NotifyClass,
    _Inout_ PVOID Argument2
    );

BOOLEAN 
PreNotificationBlockSample();

NTSTATUS 
CallbackPreNotificationBlock(
    _In_ PCALLBACK_CONTEXT CallbackCtx,
    _In_ REG_NOTIFY_CLASS NotifyClass,
    _Inout_ PVOID Argument2
    );

BOOLEAN 
PreNotificationBypassSample();

NTSTATUS 
CallbackPreNotificationBypass(
    _In_ PCALLBACK_CONTEXT CallbackCtx,
    _In_ REG_NOTIFY_CLASS NotifyClass,
    _Inout_ PVOID Argument2
    );

BOOLEAN 
PostNotificationOverrideSuccessSample();

NTSTATUS 
CallbackPostNotificationOverrideSuccess(
    _In_ PCALLBACK_CONTEXT CallbackCtx,
    _In_ REG_NOTIFY_CLASS NotifyClass,
    _Inout_ PVOID Argument2
    );

BOOLEAN 
PostNotificationOverrideErrorSample();

NTSTATUS 
CallbackPostNotificationOverrideError(
    _In_ PCALLBACK_CONTEXT CallbackCtx,
    _In_ REG_NOTIFY_CLASS NotifyClass,
    _Inout_ PVOID Argument2
    );

BOOLEAN
TransactionEnlistSample();

NTSTATUS
CallbackTransactionEnlist(
    _In_ PCALLBACK_CONTEXT CallbackCtx,
    _In_ REG_NOTIFY_CLASS NotifyClass,
    _Inout_ PVOID Argument2
    );

BOOLEAN
TransactionReplaySample();

NTSTATUS
CallbackTransactionReplay(
    _In_ PCALLBACK_CONTEXT CallbackCtx,
    _In_ REG_NOTIFY_CLASS NotifyClass,
    _Inout_ PVOID Argument2
    );

BOOLEAN
SetObjectContextSample();

NTSTATUS
CallbackSetObjectContext(
    _In_ PCALLBACK_CONTEXT CallbackCtx,
    _In_ REG_NOTIFY_CLASS NotifyClass,
    _Inout_ PVOID Argument2
    );

BOOLEAN
SetCallContextSample();

NTSTATUS
CallbackSetCallContext(
    _In_ PCALLBACK_CONTEXT CallbackCtx,
    _In_ REG_NOTIFY_CLASS NotifyClass,
    _Inout_ PVOID Argument2
    );

BOOLEAN
MultipleAltitudeBlockDuringPreSample();

BOOLEAN
MultipleAltitudeInternalInvocationSample();

NTSTATUS
CallbackMonitor(
    _In_ PCALLBACK_CONTEXT CallbackCtx,
    _In_ REG_NOTIFY_CLASS NotifyClass,
    _Inout_ PVOID Argument2
    );

NTSTATUS
CallbackMultipleAltitude(
    _In_ PCALLBACK_CONTEXT CallbackCtx,
    _In_ REG_NOTIFY_CLASS NotifyClass,
    _Inout_ PVOID Argument2
    );

NTSTATUS
CallbackCapture(
    _In_ PCALLBACK_CONTEXT CallbackCtx,
    _In_ REG_NOTIFY_CLASS NotifyClass,
    _Inout_ PVOID Argument2
    );

VOID
BugCheckSample();

NTSTATUS
CallbackBugcheck(
    _In_ PCALLBACK_CONTEXT CallbackCtx,
    _In_ REG_NOTIFY_CLASS NotifyClass,
    _Inout_ PVOID Argument2
    );

BOOLEAN 
CreateOpenV1Sample();

NTSTATUS
CallbackCreateOpenV1(
    _In_ PCALLBACK_CONTEXT CallbackCtx,
    _In_ REG_NOTIFY_CLASS NotifyClass,
    _Inout_ PVOID Argument2
    );

//
// Driver dispatch functions
//

NTSTATUS
DoCallbackSamples(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    );

NTSTATUS
RegisterCallback(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    );

NTSTATUS
UnRegisterCallback(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    );

NTSTATUS
GetCallbackVersion(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    );

//
// Transaction related routines
//

NTSTATUS
CreateKTMResourceManager(
    _In_ PTM_RM_NOTIFICATION CallbackRoutine,
    _In_opt_ PVOID RMKey
    );

NTSTATUS
EnlistInTransaction(
    _Out_ PHANDLE EnlistmentHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PVOID Transaction,
    _In_ NOTIFICATION_MASK NotificationMask,
    _In_opt_ PVOID EnlistmentKey
    );

VOID
DeleteKTMResourceManager(
    );


//
// Capture methods
//

NTSTATUS
CaptureBuffer(
    _Outptr_result_maybenull_ PVOID *CapturedBuffer,
    _In_reads_bytes_(Length)PVOID Buffer, 
    _In_ SIZE_T Length, 
    _In_ ULONG PoolTag
    );

VOID
FreeCapturedBuffer(
    _In_ PVOID Buffer, 
    _In_ ULONG PoolTag
    );

NTSTATUS
CaptureUnicodeString(
    _Inout_ UNICODE_STRING * DestString, 
    _In_ PCUNICODE_STRING SourceString, 
    _In_ ULONG PoolTag
    );

VOID
FreeCapturedUnicodeString(
    _In_ UNICODE_STRING * String, 
    _In_ ULONG PoolTag
    );


//
// Utility methods
//

PVOID
CreateCallbackContext(
    _In_ CALLBACK_MODE CallbackMode, 
    _In_ PCWSTR AltitudeString
    );

BOOLEAN
InsertCallbackContext(
    _In_ PCALLBACK_CONTEXT CallbackCtx
    );

PCALLBACK_CONTEXT
FindCallbackContext(
    _In_ LARGE_INTEGER Cookie
    );

PCALLBACK_CONTEXT
FindAndRemoveCallbackContext(
    _In_ LARGE_INTEGER Cookie
    );

VOID
DeleteCallbackContext(
    _In_ PCALLBACK_CONTEXT CallbackCtx
    );


ULONG 
ExceptionFilter (
    _In_ PEXCEPTION_POINTERS ExceptionPointers
    );
    
//This function gets the timestamp of the registry operation interception
inline time_t GetTimestamp() {
	/*
		Daniel May 2018
		
		In this function, 2 things are done
		
		1. Getting of the Windows system time
		2. Converting the Windows system time to Linux Epoch time
	*/
	LARGE_INTEGER ret;

	KeQuerySystemTimePrecise(&ret);

	// From https://stackoverflow.com/questions/6161776/convert-windows-filetime-to-second-in-unix-linux

	long long secs;
	time_t t;

	secs = (ret.QuadPart / WINDOWS_TICK - SEC_TO_UNIX_EPOCH);

	t = (time_t)secs;

	if (secs != (long long)t)    // checks for truncation/overflow/underflow
		return (time_t)-1;   // value not representable as a POSIX time

	return t;
}

//This function handles the getting of the user SID based on the registry operation intercepted
inline NTSTATUS GetUserSID(_Inout_ PUNICODE_STRING SidString) {
	/*
		Daniel May 2018
		
		In this function, 3 things are done
		
		1. Opening the token of the registry operation thread -> ZwOpenThreadTokenEx()
		2. Query token information -> ZwQueryInformationToken()
		3. Query token information again to get user token data -> ZwQueryInformationToken()
	*/
	PTOKEN_USER pUser;
	HANDLE token;
	ULONG len;
	NTSTATUS status;

	status = ZwOpenThreadTokenEx(NtCurrentThread(), GENERIC_READ, TRUE, OBJ_KERNEL_HANDLE, &token);

	if (!NT_SUCCESS(status)) {
		status = ZwOpenProcessTokenEx(NtCurrentProcess(), GENERIC_READ, OBJ_KERNEL_HANDLE, &token);
	}

	if (!NT_SUCCESS(status)) {
		return status;
	}

	ZwQueryInformationToken(token, TokenUser, NULL, 0, &len);

	pUser = ExAllocatePoolWithTag(PagedPool, len, 'REGF');

	if (!pUser) {
		ZwClose(token);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	status = ZwQueryInformationToken(token, TokenUser, pUser, len, &len);

	if (!NT_SUCCESS(status)) {
		ZwClose(token);
		ExFreePoolWithTag(pUser, 'REGF');
		return status;
	}

	status = RtlConvertSidToUnicodeString(SidString, pUser->User.Sid, FALSE);

	ZwClose(token);
	ExFreePoolWithTag(pUser, 'REGF');

	return status;
}

//inline char GetHostName() {
//	char hostname[1024];
//	hostname[1023] = '\0';
//	gethostname(hostname, 1023);
//	//printf("Hostname: %s\n", hostname);
//	struct hostent* h;
//	h = gethostbyname(hostname);
//	//printf("h_name: %s\n", h->h_name);
//
//	return h->h_name;
//}

//inline PVOID GetValueRoot() {
//	char value[255];
//	DWORD BufferSize = BUFFER;
//	RegGetValue(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "SystemRoot", RRF_RT_ANY, NULL, (PVOID)&value, &BufferSize);
//	
//	return value;
//}
//
//inline PVOID GetValueUser() {
//	char value[255];
//	DWORD BufferSize = BUFFER;
//	RegGetValue(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "SystemRoot", RRF_RT_ANY, NULL, (PVOID)&value, &BufferSize);
//
//	return value;
//}

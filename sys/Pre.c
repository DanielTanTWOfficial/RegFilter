/*++
Copyright (c) Microsoft Corporation.  All rights reserved.

    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
    KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
    PURPOSE.

Module Name:

    Pre.c

Abstract: 

    Samples that show what callbacks can do during the pre-notification
    phase.

Environment:

    Kernel mode only

--*/

/*
	Daniel 5/22/2018

	This file is the main file for this whole pre-notification registry operation interception process

	Pre-notification = The registry operations intercepted have not taken place in the registry yet - Google it.

	This file contains the PreNotificationBypassSample() function which registers and unregisters the callback
	routine we are using to intercept the registry operations.

	The registering and unregistering functions are called:
		- CmRegisterCallbackEx() -> To register
		- CmUnRegisterCallback() -> To unregister

	The callback routine itself is in the function CallbackPreNotificationBypass() -> Go read what is written
	there.
*/

#define _CRT_SECURE_NO_WARNINGS
#include <stdlib.h>
#include "regfltr.h"
#include <stdio.h>
#include <conio.h>
#include <ntifs.h>
#include "tools.h"
#include <wchar.h>
#include <tchar.h>
#include "log.h"
#include <string.h> 

#define BUFFER 8192

BOOLEAN
PreNotificationBlockSample(
    )
/*++

Routine Description:

    This sample shows how to block a registry operation in the
    pre-notification phase. 

    Two keys are created. The create operations should succeed, but one
    is intercepted by the callback and failed with STATUS_ACCESS_DENIED.
    The same is done for two values.

Return Value:

    TRUE if the sample completed successfully.

--*/
{
    PCALLBACK_CONTEXT CallbackCtx = NULL;
    NTSTATUS Status;
    OBJECT_ATTRIBUTES KeyAttributes;
    UNICODE_STRING Name;
    HANDLE Key = NULL;
    HANDLE NotModifiedKey = NULL;
    DWORD ValueData = 0; 
    BOOLEAN Success = FALSE;

    InfoPrint("");
    InfoPrint("=== Pre-Notification Block Sample ====");
    
    //
    // Create the callback context
    //

    CallbackCtx = CreateCallbackContext(CALLBACK_MODE_PRE_NOTIFICATION_BLOCK,
                                        CALLBACK_ALTITUDE);
    if (CallbackCtx == NULL) {
        goto Exit;
    }
    
    //
    // Register callback
    //

    Status = CmRegisterCallbackEx(Callback,
                                  &CallbackCtx->Altitude,
                                  g_DeviceObj->DriverObject,
                                  (PVOID) CallbackCtx,
                                  &CallbackCtx->Cookie, 
                                  NULL);
    if (!NT_SUCCESS(Status)) {
        ErrorPrint("CmRegisterCallback failed. Status 0x%x", Status);
        goto Exit;
    }

    Success = TRUE;
    
    //
    // Create two keys.
    // Creating the "not modified" key will succeed.
    // Creating the other key will fail with STATUS_ACCESS_DENIED
    //

    RtlInitUnicodeString(&Name, NOT_MODIFIED_KEY_NAME);
    InitializeObjectAttributes(&KeyAttributes,
                               &Name,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               g_RootKey,
                               NULL);

    Status = ZwCreateKey(&NotModifiedKey,
                         KEY_ALL_ACCESS,
                         &KeyAttributes,
                         0,
                         NULL,
                         0,
                         NULL);

    if (Status != STATUS_SUCCESS) {
        ErrorPrint("ZwCreateKey returned unexpected status 0x%x", Status);
        Success = FALSE;
    }

    RtlInitUnicodeString(&Name, KEY_NAME);
    InitializeObjectAttributes(&KeyAttributes,
                               &Name,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               g_RootKey,
                               NULL);

    Status = ZwCreateKey(&Key,
                         KEY_ALL_ACCESS,
                         &KeyAttributes,
                         0,
                         NULL,
                         0,
                         NULL);

    if (Status != STATUS_ACCESS_DENIED) {
        ErrorPrint("ZwCreateKey returned unexpected status 0x%x", Status);
        Success = FALSE;
    }


    //
    // Set two values. 
    // Setting the "not modified" value will succeed.
    // Setting the other value will fail with STATUS_ACCESS_DENIED.
    //

    RtlInitUnicodeString(&Name, NOT_MODIFIED_VALUE_NAME);
    Status = ZwSetValueKey(g_RootKey,
                           &Name,
                           0,
                           REG_DWORD,
                           &ValueData,
                           sizeof(ValueData));
    
    if(Status != STATUS_SUCCESS) {
        ErrorPrint("ZwSetValue return unexpected status 0x%x", Status);
        Success = FALSE;
    }

    RtlInitUnicodeString(&Name, VALUE_NAME);
    Status = ZwSetValueKey(g_RootKey,
                           &Name,
                           0,
                           REG_DWORD,
                           &ValueData,
                           sizeof(ValueData));
    
    if(Status != STATUS_ACCESS_DENIED) {
        ErrorPrint("ZwSetValue return unexpected status 0x%x", Status);
        Success = FALSE;
    }
    
    //
    // Unregister the callback
    //

    Status = CmUnRegisterCallback(CallbackCtx->Cookie);

    if (!NT_SUCCESS(Status)) {
        ErrorPrint("CmUnRegisterCallback failed. Status 0x%x", Status);
        Success = FALSE;
    }

  Exit:

    //
    // Clean up
    //

    if (Key != NULL) {
        ZwDeleteKey(Key);
        ZwClose(Key);
    }

    if (NotModifiedKey != NULL) {
        ZwDeleteKey(NotModifiedKey);
        ZwClose(NotModifiedKey);
    }

    RtlInitUnicodeString(&Name, VALUE_NAME);
    ZwDeleteValueKey(g_RootKey, &Name);
    RtlInitUnicodeString(&Name, NOT_MODIFIED_VALUE_NAME);
    ZwDeleteValueKey(g_RootKey, &Name);

    if (CallbackCtx != NULL) {
        ExFreePoolWithTag(CallbackCtx, REGFLTR_CONTEXT_POOL_TAG);
    }

    if (Success) {
        InfoPrint("Pre-Notification Block Sample succeeded.");
    } else {
        ErrorPrint("Pre-Notification Block Sample FAILED.");
    }

    return Success;
    
}


NTSTATUS 
CallbackPreNotificationBlock(
    _In_ PCALLBACK_CONTEXT CallbackCtx,
    _In_ REG_NOTIFY_CLASS NotifyClass,
    _Inout_ PVOID Argument2
    )
/*++

Routine Description:

    This helper callback routine shows hot to fail a registry operation
    in the pre-notification phase.
    
Arguments:

    CallbackContext - The value that the driver passed to the Context parameter
        of CmRegisterCallbackEx when it registers this callback routine.

    NotifyClass - A REG_NOTIFY_CLASS typed value that identifies the type of 
        registry operation that is being performed and whether the callback
        is being called in the pre or post phase of processing.

    Argument2 - A pointer to a structure that contains information specific
        to the type of the registry operation. The structure type depends
        on the REG_NOTIFY_CLASS value of Argument1. 

Return Value:

    NTSTATUS

--*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    PREG_CREATE_KEY_INFORMATION PreCreateInfo;
    PREG_SET_VALUE_KEY_INFORMATION PreSetValueInfo;
    UNICODE_STRING Name;

    UNREFERENCED_PARAMETER(CallbackCtx);
    
    switch(NotifyClass) {
        case RegNtPreCreateKeyEx:
            
            PreCreateInfo = (PREG_CREATE_KEY_INFORMATION) Argument2;

            //
            // Only intercept the operation if the key being created has the 
            // name KEY_NAME.
            //
            
            RtlInitUnicodeString(&Name, KEY_NAME);
            if (RtlEqualUnicodeString((PCUNICODE_STRING) &Name, 
                                      (PCUNICODE_STRING) PreCreateInfo->CompleteName, 
                                      TRUE)) {
                //
                // By returning an error status, we block the operation.
                //
				InfoPrint("&Name: %p", (PCUNICODE_STRING)&Name);
				InfoPrint("Complete name: %p", &((PUNICODE_STRING)PreCreateInfo->CompleteName));
                InfoPrint("\tCallback: Create key %wZ blocked.", 
                          PreCreateInfo->CompleteName);
                Status = STATUS_ACCESS_DENIED;
            }
            break;
            
        case RegNtPreSetValueKey:
            
            PreSetValueInfo = (PREG_SET_VALUE_KEY_INFORMATION) Argument2;

            //
            // Only intercept the operation if the value being set has the 
            // name VALUE_NAME.
            //
            
            RtlInitUnicodeString(&Name, VALUE_NAME);
            if (RtlEqualUnicodeString((PCUNICODE_STRING) &Name, 
                                      (PCUNICODE_STRING) PreSetValueInfo->ValueName, 
                                      TRUE)) {
                //
                // By returning an error status, we block the operation.
                //
               
                InfoPrint("\tCallback: Set value %wZ blocked.", 
                          PreSetValueInfo->ValueName);
                Status = STATUS_ACCESS_DENIED;
            }
            break;
            
        default:
            //
            // Do nothing for other notifications
            //
            break;
    }

    return Status;
}



BOOLEAN
PreNotificationBypassSample(
    )
/*++

Routine Description:

    This sample shows how to bypass a registry operation so that the CM does
    not process the operation. Unlike block, an operation that is bypassed
    is still considered successful so the callback must provide the caller
    with what the CM would have provided.

    A key and a value are created. However both operations are bypassed by the
    callback so that the key and value actually created have different names
    than would is expected.
    
Return Value:

    TRUE if the sample completed successfully.

--*/
{
    PCALLBACK_CONTEXT CallbackCtx = NULL;
    NTSTATUS Status;
    OBJECT_ATTRIBUTES KeyAttributes;
    UNICODE_STRING Name;
    HANDLE Key = NULL;
    DWORD ValueData = 0; 
    BOOLEAN Success = FALSE;

    InfoPrint("");
    InfoPrint("=== Pre-Notification Bypass Sample ====");

    //
    // Create the callback context
    //

    CallbackCtx = CreateCallbackContext(CALLBACK_MODE_PRE_NOTIFICATION_BYPASS,
                                        CALLBACK_ALTITUDE);
    if (CallbackCtx == NULL) {
        goto Exit;
    }

    //
    // Register the callback
    //

    Status = CmRegisterCallbackEx(Callback,
                                  &CallbackCtx->Altitude,
                                  g_DeviceObj->DriverObject,
                                  (PVOID) CallbackCtx,
                                  &CallbackCtx->Cookie, 
                                  NULL);
    if (!NT_SUCCESS(Status)) {
        ErrorPrint("CmRegisterCallback failed. Status 0x%x", Status);
        goto Exit;
    }

    Success = TRUE;
    
    //
    // Create a key and set a value. Both should succeed
    //

    RtlInitUnicodeString(&Name, KEY_NAME);
    InitializeObjectAttributes(&KeyAttributes,
                               &Name,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               g_RootKey,
                               NULL);

    Status = ZwCreateKey(&Key,
                         KEY_ALL_ACCESS,
                         &KeyAttributes,
                         0,
                         NULL,
                         0,
                         NULL);

    if (!NT_SUCCESS(Status)) {
        ErrorPrint("ZwCreateKey failed. Status 0x%x", Status);
        Success = FALSE;
    }

    RtlInitUnicodeString(&Name, VALUE_NAME);
    Status = ZwSetValueKey(g_RootKey,
                           &Name,
                           0,
                           REG_DWORD,
                           &ValueData,
                           sizeof(ValueData));
    
    if(!NT_SUCCESS(Status)) {
        ErrorPrint("ZwSetValue failed. Status 0x%x", Status);
        Success = FALSE;
    }

    //
    // Unregister the callback
    //

    Status = CmUnRegisterCallback(CallbackCtx->Cookie);

    if (!NT_SUCCESS(Status)) {
        ErrorPrint("CmUnRegisterCallback failed. Status 0x%x", Status);
        Success = FALSE;
    }

    
    //
    // Check that a key with the expected name KEY_NAME cannot be found 
    // but a key with the "modified" name can be found. 
    //

    if (Key != NULL) {
        ZwClose(Key);
    }

    RtlInitUnicodeString(&Name, KEY_NAME);
    InitializeObjectAttributes(&KeyAttributes,
                               &Name,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               g_RootKey,
                               NULL);
    
    Status = ZwOpenKey(&Key,
                       KEY_ALL_ACCESS,
                       &KeyAttributes);

    if (Status != STATUS_OBJECT_NAME_NOT_FOUND) {
        ErrorPrint("ZwOpenKey on key returned unexpected status: 0x%x", Status);
        if (Key != NULL) {
            ZwDeleteKey(Key);
            ZwClose(Key);
            Key = NULL;
        }
        Success = FALSE;
    }

    RtlInitUnicodeString(&Name, MODIFIED_KEY_NAME);
    InitializeObjectAttributes(&KeyAttributes,
                               &Name,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               g_RootKey,
                               NULL);

    Status = ZwOpenKey(&Key,
                       KEY_ALL_ACCESS,
                       &KeyAttributes);

    if (!NT_SUCCESS(Status)) {
        ErrorPrint("ZwOpenKey on modified key path failed. Status: 0x%x", Status);
        Success = FALSE;
    }
        

    //
    // Do the same check by trying to delete a value with VALUE_NAME and
    // with the "modified" name. 
    //

    RtlInitUnicodeString(&Name, VALUE_NAME);
    Status = ZwDeleteValueKey(g_RootKey, &Name);

    if (Status != STATUS_OBJECT_NAME_NOT_FOUND) {
        ErrorPrint("ZwDeleteValueKey on original value returned unexpected status: 0x%x", 
                   Status);
        Success = FALSE;
    }

    RtlInitUnicodeString(&Name, MODIFIED_VALUE_NAME);
    Status = ZwDeleteValueKey(g_RootKey, &Name);

    if (!NT_SUCCESS(Status)) {
        ErrorPrint("ZwDeleteValueKey on modified value failed. Status: 0x%x", 
                   Status);
        Success = FALSE;
    }

  Exit:

    //
    // Clean up
    //

    if (Key != NULL) {
        ZwDeleteKey(Key);
        ZwClose(Key);
    }

    if (CallbackCtx != NULL) {
        ExFreePoolWithTag(CallbackCtx, REGFLTR_CONTEXT_POOL_TAG);
    }

    if (Success) {
        InfoPrint("Pre-Notification Bypass Sample succeeded.");
    } else {
        ErrorPrint("Pre-Notification Bypass Sample FAILED.");
    }

    return Success;
}



NTSTATUS 
CallbackPreNotificationBypass(
    _In_ PCALLBACK_CONTEXT CallbackCtx,
    _In_ REG_NOTIFY_CLASS NotifyClass,
    _Inout_ PVOID Argument2
)
/*++

Routine Description:

    This helper callback routine is the most complex part of the sample. 
    Here we actually manipulate the registry inside the callback to modify the 
    outcome and the behavior of the registry operation. 

    In the pre-notification phase, we bypass the call but create a key or set 
    a value with a different name. 

    In the post-notification phase we delete the key or value that was 
    created by the registry and tell the registry to return the bad error 
    status to the caller.
    
Arguments:

    CallbackContext - The value that the driver passed to the Context parameter
        of CmRegisterCallbackEx when it registers this callback routine.

    NotifyClass - A REG_NOTIFY_CLASS typed value that identifies the type of 
        registry operation that is being performed and whether the callback
        is being called in the pre or post phase of processing.

    Argument2 - A pointer to a structure that contains information specific
        to the type of the registry operation. The structure type depends
        on the REG_NOTIFY_CLASS value of Argument1. 

Return Value:

    NTSTATUS

--*/
{

    NTSTATUS Status = STATUS_SUCCESS;
	NTSTATUS status = STATUS_SUCCESS;
	//PCALLBACK_CONTEXT CallbackCtx = NULL;

	/*
		Daniel 5/22/2018

		All structures of the registry operations intercepted are declared here
		For example, if you want to intercept a RegNtPreCreateKeyEx registry operation:
			- Declare PREG_CREATE_KEY_INFORMATION PreCreateInfo;
		
		A sample registry operation structure declaration has been done below and commented out
	*/
    PREG_CREATE_KEY_INFORMATION PreCreateInfo;
    PREG_SET_VALUE_KEY_INFORMATION PreSetValueInfo;
	PREG_DELETE_VALUE_KEY_INFORMATION PreDeleteValueInfo;
	PREG_RENAME_KEY_INFORMATION PreRenameInfo;
	PREG_OPEN_KEY_INFORMATION PreOpenInfo;
	PREG_QUERY_VALUE_KEY_INFORMATION PreQueryValueInfo;
	PREG_DELETE_KEY_INFORMATION PreDeleteKeyInfo;
	PREG_QUERY_KEY_INFORMATION PreQueryKeyInfo;
	PREG_SET_KEY_SECURITY_INFORMATION PreSetSecurityInfo;
	PREG_ENUMERATE_KEY_INFORMATION PreEnumerateInfo;
	PREG_ENUMERATE_VALUE_KEY_INFORMATION PreEnumerateValueInfo;
	PREG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION PreQueryMultipleValueInfo;
	PREG_SET_INFORMATION_KEY_INFORMATION PreSetInformationInfo;
	//PREG_KEY_HANDLE_CLOSE_INFORMATION PreKeyHandleCloseInfo;

    UNICODE_STRING LocalClass = {0};
    PUNICODE_STRING Class = NULL;
    HANDLE Key = NULL;
    //HANDLE RootKey = NULL;
    //PVOID Object;
    PVOID LocalData = NULL;
    PVOID Data = NULL;
    KPROCESSOR_MODE Mode = KernelMode;
	HANDLE ProcessID = NULL;
	CHAR *RegOp = NULL;
	CHAR * ProcessName = NULL;
	UNICODE_STRING userSid;
	unsigned long long t;
	UNICODE_STRING username;
	PCUNICODE_STRING ObjectName = NULL;
	UNICODE_STRING CapturedObjectName = { 0 };
	ULONG_PTR ObjectValueName = 0;
	char hostname[256] = { 2 };
	char activename[256] = { 2 };
    UNREFERENCED_PARAMETER(CallbackCtx);
    

	/* for loop execution */

	//for (int a = 0; a < 10; a = a + 1) {

	//CHAR* t1 = "GoodExample";
	//CHAR t2[] = "GoodExample";


	//WriteLog(t1, sizeof(t2));
	//}


	//union ExampleUnion data = { { 10000 } };
	//WriteLog(data.string, sizeof(data.string));

	/*
		Daniel 5/22/2018

		The identification and extraction of information from intercepted registry operations are done in this
		switch case.

		To add more registry operations to be intercepted, add new cases:
			- E.g. case RegNtPreKeyHandleClose:
			- Current problem faced is that the test machine will freeze if any more registry operation types are
			added to be intercepted on top of the existing operations intercepted here (Memory issue?)

		All the possible registry operation types can be found in Microsoft's documentation page:
			- https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/ne-wdm-_reg_notify_class

		Currently, only registry operations in the pre-notification stage - operations have not taken place in
		the registry yet - are intercepted. A possible future work would be to also intercept registry operations
		in the post-notification stage - after they have taken place in the registry.

		Possible way to do this:
			- Create a new case for a post-notification operation (E.g. case RegNtPostCreateKeyEx:)
			- Modify the Callback Context (E.g. CallbackCtx = CreateCallbackContext(CALLBACK_MODE_POST_NOTIFICATION_BYPASS,
				CALLBACK_ALTITUDE);

		In each of the switch cases here, a standard set of function calls and routines are performed to collect
		information about the registry operations that are intercepted.
		
		A list of these information collected:
			1. Type of registry operation (This is hard-coded depending on which case the operation falls into)
			2. Time the registry operation is intercepted -> Using function GetTimestamp()
			3. Process name (What process initiated the operation) -> Using function GetProcessNameFromPid()
			4. Process ID (ID of process that initiates the operation) -> This is based on the CallbackCtx
			5. User SID (SID of user responsible for operation) -> Using function GetUserSID()
			6. User ID (ID of user responsible for operation) -> Using function GetUserID()
			7. Full path to registry key referenced by operation -> Using function CmCallbackGetKeyObjectIDEx()
			8. Key value affected (if any) -> This value is acquired from the registry operation's information
			   structure, if it exists. Example: PreSetValueInfo->ValueName, PreCreateInfo->CompleteName.

		Remember, the aim of collecting these information is to provide users with useful information to create
		a picture of the events taking place in their registry during a certain time period (forensic purposes).

		The information collected for each registry operation intercepted are printed onto the console using
		InfoPrint().

		In each case below, comments have been made to help locate portions of code collecting each piece of
		information.
	*/
    switch(NotifyClass) {

        case RegNtPreCreateKeyEx:
			//This case handles registry operations regarding key creation

            PreCreateInfo = (PREG_CREATE_KEY_INFORMATION) Argument2;
			CallbackCtx = CreateCallbackContext(CALLBACK_MODE_PRE_NOTIFICATION_BYPASS,
				CALLBACK_ALTITUDE);

            Mode = ExGetPreviousMode();

            if (!g_IsWin8OrGreater && Mode == UserMode) {
                status = CaptureUnicodeString(&LocalClass, 
                                              PreCreateInfo->Class, 
                                              REGFLTR_CAPTURE_POOL_TAG);
                if (!NT_SUCCESS(status)) {
                    break;
                }
                Class = &LocalClass;
                
            } else {
                Class = PreCreateInfo->Class;
            }

			//Gets time of registry event
			t = (unsigned long long)GetTimestamp();

			InfoPrint("Time: %llu", t);

			//Gets the name of the process making the registry operation
			ProcessName = GetProcessNameFromPid(CallbackCtx->ProcessId);

			InfoPrint("Process Name: %s", ProcessName);

			//Gets the SID of user logged into the computer
			userSid.MaximumLength = 256;
			userSid.Buffer = ExAllocatePoolWithTag(PagedPool, userSid.MaximumLength, 'REGF');

			RtlZeroMemory(userSid.Buffer, userSid.MaximumLength);

			status = GetUserSID(&userSid);

			if (!NT_SUCCESS(status)) {
				ErrorPrint("GetUserSID failed. Status 0x%x", status);
				break;
			}

			//Gets the username of user logged into the computer 
			username.MaximumLength = 1024;
			username.Buffer = ExAllocatePoolWithTag(PagedPool, username.MaximumLength, 'REGF');

			if (!username.Buffer) {
				return STATUS_INSUFFICIENT_RESOURCES;
			}

			RtlZeroMemory(username.Buffer, username.MaximumLength);

			status = GetUserID(&username);

			if (!NT_SUCCESS(status)) {

				ExFreePoolWithTag(username.Buffer, 'REGF');

				return STATUS_UNSUCCESSFUL;
			}

			//Get the full path of the registry key referenced in the operation
			Status = CmCallbackGetKeyObjectIDEx(&CallbackCtx->Cookie,
				PreCreateInfo->RootObject,
				NULL,
				&ObjectName,
				0);           // Flag: reserved for future

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("CmCallbackGetKeyObjectIDEx failed. Status 0x%x", Status);
				break;
			}

			CapturedObjectName.Length = ObjectName->Length;
			CapturedObjectName.MaximumLength = ObjectName->MaximumLength;
			CapturedObjectName.Buffer = ObjectName->Buffer;

			//Get computer's hostname
			Status = LoadRegistryConfigKey(L"ComputerName", hostname);

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("LoadRegistryConfigKey failed. Status 0x%x", Status);
				break;
			}

			//Get computer's active hostname
			Status = LoadActiveName(L"ComputerName", activename);

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("LoadActiveName failed. Status 0x%x", Status);
				break;
			}

			//Setting the type of registry operation (Refer to the documentation for acronym meanings)
			RegOp = "KCO";

			PUNICODE_STRING CreateCN = (PUNICODE_STRING)PreCreateInfo->CompleteName;
			PVOID CreateRO = (PVOID)PreCreateInfo->RootObject;
			PVOID CreateOT = (PVOID)PreCreateInfo->ObjectType;
			ULONG CreateCO = (ULONG)PreCreateInfo->CreateOptions;
			PUNICODE_STRING CreateClass = (PUNICODE_STRING)PreCreateInfo->Class;        
			PVOID CreateSD = (PVOID)PreCreateInfo->SecurityDescriptor;
			PVOID CreateQS = (PVOID)PreCreateInfo->SecurityQualityOfService;
			ACCESS_MASK CreateDA = (ACCESS_MASK)PreCreateInfo->DesiredAccess;
			ACCESS_MASK CreateGA = (ACCESS_MASK)PreCreateInfo->GrantedAccess;
			PULONG CreateDisposition = (PULONG)PreCreateInfo->Disposition;
			PVOID  CreateREO = (PVOID)PreCreateInfo->ResultObject;
			PVOID  CreateCC = (PVOID)PreCreateInfo->CallContext;
			PVOID  CreateROC = (PVOID)PreCreateInfo->RootObjectContext;
			PVOID  CreateTransaction = (PVOID)PreCreateInfo->Transaction;
			PVOID  CreateReserved = (PVOID)PreCreateInfo->Reserved;

			//Get the process ID of the process making the registry operation
			ProcessID = (HANDLE)CallbackCtx->ProcessId;

			InfoPrint("Registry Operation Type: %s", RegOp);
			InfoPrint("Key created: %p", CreateCN);
			InfoPrint("Created key root object: %p", CreateRO);
			InfoPrint("Created key object type: %p", CreateOT);
			InfoPrint("Created key create option: %p", CreateCO);
			InfoPrint("Created key class: %p", CreateClass);
			InfoPrint("Created key security descriptor: %p", CreateSD);
			InfoPrint("Created key security quality of service: %p", CreateQS);
			InfoPrint("Created key desired access: %p", CreateDA);
			InfoPrint("Created key granted access: %p", CreateGA);
			InfoPrint("Created key disposition: %p", CreateDisposition);
			InfoPrint("Created key result object: %p", CreateREO);
			InfoPrint("Created key call context: %p", CreateCC);
			InfoPrint("Created key root object context: %p", CreateROC);
			InfoPrint("Created key transaction: %p", CreateTransaction);
			InfoPrint("Created key reserved: %p", CreateReserved);
			//processid
			InfoPrint("Key created by process ID: %p", ProcessID);
			InfoPrint("Root key: %p", Key);
			//userid
			InfoPrint("User SID: %wZ", userSid);
			//username
			InfoPrint("Username: %wZ", username);
			//path to key
			InfoPrint("Key path: %wZ", CapturedObjectName);
			//key name
			InfoPrint("Created key name: %wZ", PreCreateInfo->CompleteName);
			InfoPrint("==================================");

			InfoPrint("Write log: %s", sendLogs(t, RegOp, userSid, username, ProcessName, ProcessID, PreCreateInfo->CompleteName, hostname, activename, CapturedObjectName));


			DeleteCallbackContext(CallbackCtx);

			ExFreePoolWithTag(username.Buffer, 'REGF');
			ExFreePoolWithTag(userSid.Buffer, 'REGF');
			CmCallbackReleaseKeyObjectIDEx(ObjectName);
            
            break;
            
        case RegNtPreSetValueKey:
			//This case handles registry operations regarding key value setting
            PreSetValueInfo = (PREG_SET_VALUE_KEY_INFORMATION) Argument2;
			CallbackCtx = CreateCallbackContext(CALLBACK_MODE_PRE_NOTIFICATION_BYPASS,
				CALLBACK_ALTITUDE);

            //
            // REG_SET_VALUE_KEY_INFORMATION is a partially captured structure.
            // The value name is captured but the data is not. Since we are
            // passing the data to a zw* method, we need to capture it.
            //
            // *Note: in Windows 8 all fields are captured. See capture.c
            // for more details.
            //
            
            Mode = ExGetPreviousMode();

            if (!g_IsWin8OrGreater && Mode == UserMode) {
                Status = CaptureBuffer(&LocalData, 
                                       PreSetValueInfo->Data, 
                                       PreSetValueInfo->DataSize, 
                                       REGFLTR_CAPTURE_POOL_TAG);
                if (!NT_SUCCESS(Status)) {
                    break;
                }
                Data = LocalData;
            } else {
                Data = PreSetValueInfo->Data;
            }

			//Get time of registry event
			t = (unsigned long long)GetTimestamp();

			InfoPrint("Time: %llu", t);

			//Get the name of the process making the registry operation
			ProcessName = GetProcessNameFromPid(CallbackCtx->ProcessId);

			InfoPrint("Process Name: %s", ProcessName);

			//Get the SID of the user using the computer
			userSid.MaximumLength = 256;
			userSid.Buffer = ExAllocatePoolWithTag(PagedPool, userSid.MaximumLength, 'REGF');

			RtlZeroMemory(userSid.Buffer, userSid.MaximumLength);

			status = GetUserSID(&userSid);

			if (!NT_SUCCESS(status)) {
				ErrorPrint("GetUserSID failed. Status 0x%x", status);
				break;
			}

			//Get the username of the user using the computer
			username.MaximumLength = 1024;
			username.Buffer = ExAllocatePoolWithTag(PagedPool, username.MaximumLength, 'REGF');

			if (!username.Buffer) {
				return STATUS_INSUFFICIENT_RESOURCES;
			}

			RtlZeroMemory(username.Buffer, username.MaximumLength);

			status = GetUserID(&username);

			if (!NT_SUCCESS(status)) {

				ExFreePoolWithTag(username.Buffer, 'REGF');

				return STATUS_UNSUCCESSFUL;
			}

			//Get the full path of the registry key referenced in the operation
			Status = CmCallbackGetKeyObjectIDEx(&CallbackCtx->Cookie,
				PreSetValueInfo->Object,
				NULL,
				&ObjectName,
				0);           // Flag: reserved for future

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("CmCallbackGetKeyObjectIDEx failed. Status 0x%x", Status);
				break;
			}

			CapturedObjectName.Length = ObjectName->Length;
			CapturedObjectName.MaximumLength = ObjectName->MaximumLength;
			CapturedObjectName.Buffer = ObjectName->Buffer;

			//Get the computer name
			Status = LoadRegistryConfigKey(L"ComputerName", hostname);

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("LoadRegistryConfigKey failed. Status 0x%x", Status);
				break;
			}

			//Get computer's active hostname
			Status = LoadActiveName(L"ComputerName", activename);

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("LoadActiveName failed. Status 0x%x", Status);
				break;
			}

			//Setting the type of registry operation (Refer to the documentation for acronym meanings)
			RegOp = "KVSO";

			PVOID SetObj = (PVOID)PreSetValueInfo->Object;
			PUNICODE_STRING SetValueName = (PUNICODE_STRING)PreSetValueInfo->ValueName;
			ULONG SetTI = (ULONG)PreSetValueInfo->TitleIndex;
			ULONG SetType = (ULONG)PreSetValueInfo->Type;
			PVOID SetData = (PVOID)PreSetValueInfo->Data;
			ULONG SetDS = (ULONG)PreSetValueInfo->DataSize;
			PVOID SetCC = (PVOID)PreSetValueInfo->CallContext;
			PVOID SetOC = (PVOID)PreSetValueInfo->ObjectContext;
			PVOID SetReserved = (PVOID)PreSetValueInfo->Reserved;

			//Get the process ID
			ProcessID = (HANDLE)CallbackCtx->ProcessId;

			InfoPrint("Registry Operation Type: %s", RegOp);
			InfoPrint("Set value object: %p", SetObj);
			InfoPrint("Set value name: %p", SetValueName);
			InfoPrint("Set value title index: %p", SetTI);
			InfoPrint("Set value type: %p", SetType);
			InfoPrint("Set value data: %p", SetData);
			InfoPrint("Set value data size: %p", SetDS);
			InfoPrint("Set value call context: %p", SetCC);
			InfoPrint("Set value object context: %p", SetOC);
			InfoPrint("Set value reserved: %p", SetReserved);
			InfoPrint("Set value process ID: %p", ProcessID);
			InfoPrint("User SID: %wZ", userSid);
			InfoPrint("Username: %wZ", username);
			InfoPrint("Key path: %wZ", CapturedObjectName);
			InfoPrint("Set value name: %wZ", PreSetValueInfo->ValueName);
			InfoPrint("==================================");

			InfoPrint("Write log: %s", sendLogs(t, RegOp, userSid, username, ProcessName, ProcessID, PreSetValueInfo->ValueName, hostname, activename, CapturedObjectName));


			DeleteCallbackContext(CallbackCtx);

			ExFreePoolWithTag(username.Buffer, 'REGF');
			ExFreePoolWithTag(userSid.Buffer, 'REGF');
			CmCallbackReleaseKeyObjectIDEx(ObjectName);
            
            break;

		//Trying to add a new case for detecting deleting of registry keys
		case RegNtPreDeleteValueKey:
			//This case handles the registry opearations regarding key deletion
			PreDeleteValueInfo = (PREG_DELETE_VALUE_KEY_INFORMATION) Argument2;
			CallbackCtx = CreateCallbackContext(CALLBACK_MODE_PRE_NOTIFICATION_BYPASS,
				CALLBACK_ALTITUDE);

			//Get time of registry event
			t = (unsigned long long)GetTimestamp();

			InfoPrint("Time: %llu", t);

			//Get the name of the process making the registry operation
			ProcessName = GetProcessNameFromPid(CallbackCtx->ProcessId);

			InfoPrint("Process Name: %s", ProcessName);

			//Get the SID of the user using the computer
			userSid.MaximumLength = 256;
			userSid.Buffer = ExAllocatePoolWithTag(PagedPool, userSid.MaximumLength, 'REGF');

			RtlZeroMemory(userSid.Buffer, userSid.MaximumLength);

			status = GetUserSID(&userSid);

			if (!NT_SUCCESS(status)) {
				ErrorPrint("GetUserSID failed. Status 0x%x", status);
				break;
			}

			//Get the username of the user using the computer
			username.MaximumLength = 1024;
			username.Buffer = ExAllocatePoolWithTag(PagedPool, username.MaximumLength, 'REGF');

			if (!username.Buffer) {
				return STATUS_INSUFFICIENT_RESOURCES;
			}

			RtlZeroMemory(username.Buffer, username.MaximumLength);

			status = GetUserID(&username);

			if (!NT_SUCCESS(status)) {

				ExFreePoolWithTag(username.Buffer, 'REGF');

				return STATUS_UNSUCCESSFUL;
			}

			//Get the full path of the registry key referenced in the operation
			Status = CmCallbackGetKeyObjectIDEx(&CallbackCtx->Cookie,
				PreDeleteValueInfo->Object,
				NULL,
				&ObjectName,
				0);           // Flag: reserved for future

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("CmCallbackGetKeyObjectIDEx failed. Status 0x%x", Status);
				break;
			}

			CapturedObjectName.Length = ObjectName->Length;
			CapturedObjectName.MaximumLength = ObjectName->MaximumLength;
			CapturedObjectName.Buffer = ObjectName->Buffer;

			//Get the computer name
			Status = LoadRegistryConfigKey(L"ComputerName", hostname);

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("LoadRegistryConfigKey failed. Status 0x%x", Status);
				break;
			}

			//Get computer's active hostname
			Status = LoadActiveName(L"ComputerName", activename);

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("LoadActiveName failed. Status 0x%x", Status);
				break;
			}

			//Setting the type of registry operation (Refer to the documentation for acronym meanings)
			RegOp = "KVDO";

			PUNICODE_STRING DeletedValue = (PUNICODE_STRING)PreDeleteValueInfo->ValueName;
			PVOID DeletedObj = (PVOID)PreDeleteValueInfo->Object;
			PVOID DeletedCallContext = (PVOID)PreDeleteValueInfo->CallContext;
			PVOID DeletedOC = (PVOID)PreDeleteValueInfo->ObjectContext;
			PVOID DeletedReserved = (PVOID)PreDeleteValueInfo->Reserved;

			//Get the process ID of the process making the registry operation
			ProcessID = (HANDLE)CallbackCtx->ProcessId;

			InfoPrint("Registry Operation Type: %s", RegOp);
			InfoPrint("Deleted value: %p", DeletedValue);
			InfoPrint("Deleted object: %p", DeletedObj);
			InfoPrint("Deleted call context: %p", DeletedCallContext);
			InfoPrint("Deleted object context: %p", DeletedOC);
			InfoPrint("Deleted reserved: %p", DeletedReserved);
			InfoPrint("Process ID: %p", ProcessID);
			InfoPrint("User SID: %wZ", userSid);
			InfoPrint("Username: %wZ", username);
			InfoPrint("Key path: %wZ", CapturedObjectName);
			InfoPrint("Key value name: %wZ", PreDeleteValueInfo->ValueName);
			InfoPrint("==================================");

			InfoPrint("Write log: %s", sendLogs(t, RegOp, userSid, username, ProcessName, ProcessID, PreDeleteValueInfo->ValueName, hostname, activename, CapturedObjectName));


			DeleteCallbackContext(CallbackCtx);

			ExFreePoolWithTag(username.Buffer, 'REGF');
			ExFreePoolWithTag(userSid.Buffer, 'REGF');
			CmCallbackReleaseKeyObjectIDEx(ObjectName);

			Mode = ExGetPreviousMode();

			//do something

			break;

		case RegNtPreDeleteKey:
			//This case handles registry operations regarding key deletion
			PreDeleteKeyInfo = (PREG_DELETE_KEY_INFORMATION)Argument2;
			CallbackCtx = CreateCallbackContext(CALLBACK_MODE_PRE_NOTIFICATION_BYPASS,
				CALLBACK_ALTITUDE);

			//Get time of registry event
			t = (unsigned long long)GetTimestamp();

			InfoPrint("Time: %llu", t);

			//Get the process ID of process initiating registry event
			ProcessID = (HANDLE)CallbackCtx->ProcessId;

			//Get the name of process initiating registry event
			ProcessName = GetProcessNameFromPid(CallbackCtx->ProcessId);

			InfoPrint("Process Name: %s", ProcessName);


			//Get the SID of the user logged in when the registry event is initiated
			userSid.MaximumLength = 256;
			userSid.Buffer = ExAllocatePoolWithTag(PagedPool, userSid.MaximumLength, 'REGF');

			RtlZeroMemory(userSid.Buffer, userSid.MaximumLength);

			status = GetUserSID(&userSid);

			if (!NT_SUCCESS(status)) {
				ErrorPrint("GetUserSID failed. Status 0x%x", status);
				break;
			}

			//Get the username of the user logged in based on SID
			username.MaximumLength = 1024;
			username.Buffer = ExAllocatePoolWithTag(PagedPool, username.MaximumLength, 'REGF');

			if (!username.Buffer) {
				return STATUS_INSUFFICIENT_RESOURCES;
			}

			RtlZeroMemory(username.Buffer, username.MaximumLength);

			status = GetUserID(&username);

			if (!NT_SUCCESS(status)) {

				ExFreePoolWithTag(username.Buffer, 'REGF');

				return STATUS_UNSUCCESSFUL;
			}

			//Get the full path of the registry key referenced in the operation
			Status = CmCallbackGetKeyObjectIDEx(&CallbackCtx->Cookie,
				PreDeleteKeyInfo->Object,
				NULL,
				&ObjectName,
				0);           // Flag: reserved for future

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("CmCallbackGetKeyObjectIDEx failed. Status 0x%x", Status);
				break;
			}

			CapturedObjectName.Length = ObjectName->Length;
			CapturedObjectName.MaximumLength = ObjectName->MaximumLength;
			CapturedObjectName.Buffer = ObjectName->Buffer;

			//Get the computer name
			Status = LoadRegistryConfigKey(L"ComputerName", hostname);

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("LoadRegistryConfigKey failed. Status 0x%x", Status);
				break;
			}

			//Get computer's active hostname
			Status = LoadActiveName(L"ComputerName", activename);

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("LoadActiveName failed. Status 0x%x", Status);
				break;
			}

			//Setting the type of registry operation (Refer to the documentation for acronym meanings)
			RegOp = "KDO";

			//Print data captured for testing
			InfoPrint("Registry Operation Type: %s", RegOp);
			InfoPrint("Process ID: %p", ProcessID);
			InfoPrint("User SID: %wZ", userSid);
			InfoPrint("Username: %wZ", username);
			InfoPrint("Key path: %wZ", CapturedObjectName);
			InfoPrint("==================================");

			InfoPrint("Write log: %s", sendLogs(t, RegOp, userSid, username, ProcessName, ProcessID, NULL, hostname, activename, CapturedObjectName));


			DeleteCallbackContext(CallbackCtx);

			ExFreePoolWithTag(username.Buffer, 'REGF');
			ExFreePoolWithTag(userSid.Buffer, 'REGF');
			CmCallbackReleaseKeyObjectIDEx(ObjectName);

			break;

		case RegNtPreRenameKey:
			//This case handles registry operations regarding key renaming operations
			PreRenameInfo = (PREG_RENAME_KEY_INFORMATION) Argument2;
			CallbackCtx = CreateCallbackContext(CALLBACK_MODE_PRE_NOTIFICATION_BYPASS,
				CALLBACK_ALTITUDE);

			//Get time of registry event
			t = (unsigned long long)GetTimestamp();

			InfoPrint("Time: %llu", t);

			//Get the name of the process making the registry operation
			ProcessName = GetProcessNameFromPid(CallbackCtx->ProcessId);

			InfoPrint("Process Name: %s", ProcessName);

			//Get the SID of the user using the computer
			userSid.MaximumLength = 256;
			userSid.Buffer = ExAllocatePoolWithTag(PagedPool, userSid.MaximumLength, 'REGF');

			RtlZeroMemory(userSid.Buffer, userSid.MaximumLength);

			status = GetUserSID(&userSid);

			if (!NT_SUCCESS(status)) {
				ErrorPrint("GetUserSID failed. Status 0x%x", status);
				break;
			}

			//Get the username of the user using the computer
			username.MaximumLength = 1024;
			username.Buffer = ExAllocatePoolWithTag(PagedPool, username.MaximumLength, 'REGF');

			if (!username.Buffer) {
				return STATUS_INSUFFICIENT_RESOURCES;
			}

			RtlZeroMemory(username.Buffer, username.MaximumLength);

			status = GetUserID(&username);

			if (!NT_SUCCESS(status)) {

				ExFreePoolWithTag(username.Buffer, 'REGF');

				return STATUS_UNSUCCESSFUL;
			}

			//Get the full path of the registry key referenced in the operation
			Status = CmCallbackGetKeyObjectIDEx(&CallbackCtx->Cookie,
				PreRenameInfo->Object,
				NULL,
				&ObjectName,
				0);           // Flag: reserved for future

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("CmCallbackGetKeyObjectIDEx failed. Status 0x%x", Status);
				break;
			}

			CapturedObjectName.Length = ObjectName->Length;
			CapturedObjectName.MaximumLength = ObjectName->MaximumLength;
			CapturedObjectName.Buffer = ObjectName->Buffer;

			//Get the computer name
			Status = LoadRegistryConfigKey(L"ComputerName", hostname);

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("LoadRegistryConfigKey failed. Status 0x%x", Status);
				break;
			}

			//Get computer's active hostname
			Status = LoadActiveName(L"ComputerName", activename);

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("LoadActiveName failed. Status 0x%x", Status);
				break;
			}

			//Setting the type of registry operation (Refer to the documentation for acronym meanings)
			RegOp = "KRO";

			PUNICODE_STRING NewName = (PUNICODE_STRING)PreRenameInfo->NewName;
			PVOID RenamedObj = (PVOID)PreRenameInfo->Object;
			PVOID RenamedCallContext = (PVOID)PreRenameInfo->CallContext;
			PVOID RenamedOC = (PVOID)PreRenameInfo->ObjectContext;
			PVOID RenamedReserved = (PVOID)PreRenameInfo->Reserved;

			//Get the ID of process making the registry operation
			ProcessID = (HANDLE)CallbackCtx->ProcessId;

			InfoPrint("Registry Operation Type: %s", RegOp);
			InfoPrint("New name: %p", NewName);
			InfoPrint("Renamed key object: %p", RenamedObj);
			InfoPrint("Renamed key call context: %p", RenamedCallContext);
			InfoPrint("Renamed key object context: %p", RenamedOC);
			InfoPrint("Renamed key reserved: %p", RenamedReserved);
			InfoPrint("Process ID: %p", ProcessID);
			InfoPrint("User SID: %wZ", userSid);
			InfoPrint("Username: %wZ", username);
			InfoPrint("Key path: %wZ", CapturedObjectName);
			InfoPrint("New key name: %wZ", PreRenameInfo->NewName);
			InfoPrint("==================================");

			InfoPrint("Write log: %s", sendLogs(t, RegOp, userSid, username, ProcessName, ProcessID, PreRenameInfo->NewName, hostname, activename, CapturedObjectName));

			DeleteCallbackContext(CallbackCtx);

			ExFreePoolWithTag(username.Buffer, 'REGF');
			ExFreePoolWithTag(userSid.Buffer, 'REGF');
			CmCallbackReleaseKeyObjectIDEx(ObjectName);

			Mode = ExGetPreviousMode();

			break;

		case RegNtPreOpenKey:
			//This case handles registry operations regarding key opening
			PreOpenInfo = (PREG_OPEN_KEY_INFORMATION) Argument2;
			CallbackCtx = CreateCallbackContext(CALLBACK_MODE_PRE_NOTIFICATION_BYPASS,
				CALLBACK_ALTITUDE);

			//Get time of registry event
			t = (unsigned long long)GetTimestamp();

			InfoPrint("Time: %llu", t);

			//Get the name of the process making the registry operation
			ProcessName = GetProcessNameFromPid(CallbackCtx->ProcessId);

			InfoPrint("Process Name: %s", ProcessName);

			//Get the SID of the user using the computer
			userSid.MaximumLength = 256;
			userSid.Buffer = ExAllocatePoolWithTag(PagedPool, userSid.MaximumLength, 'REGF');

			RtlZeroMemory(userSid.Buffer, userSid.MaximumLength);

			status = GetUserSID(&userSid);

			if (!NT_SUCCESS(status)) {
				ErrorPrint("GetUserSID failed. Status 0x%x", status);
				break;
			}

			//Get the username of the user using the computer
			username.MaximumLength = 1024;
			username.Buffer = ExAllocatePoolWithTag(PagedPool, username.MaximumLength, 'REGF');

			if (!username.Buffer) {
				return STATUS_INSUFFICIENT_RESOURCES;
			}

			RtlZeroMemory(username.Buffer, username.MaximumLength);

			status = GetUserID(&username);

			if (!NT_SUCCESS(status)) {

				ExFreePoolWithTag(username.Buffer, 'REGF');

				return STATUS_UNSUCCESSFUL;
			}

			//Get the full path of the registry key referenced in the operation
			Status = CmCallbackGetKeyObjectIDEx(&CallbackCtx->Cookie,
				PreOpenInfo->RootObject,
				NULL,
				&ObjectName,
				0);           // Flag: reserved for future

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("CmCallbackGetKeyObjectIDEx failed. Status 0x%x", Status);
				break;
			}

			CapturedObjectName.Length = ObjectName->Length;
			CapturedObjectName.MaximumLength = ObjectName->MaximumLength;
			CapturedObjectName.Buffer = ObjectName->Buffer;

			//Get the computer name
			Status = LoadRegistryConfigKey(L"ComputerName", hostname);

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("LoadRegistryConfigKey failed. Status 0x%x", Status);
				break;
			}

			//Get computer's active hostname
			Status = LoadActiveName(L"ComputerName", activename);

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("LoadActiveName failed. Status 0x%x", Status);
				break;
			}

			//Setting the type of registry operation (Refer to the documentation for acronym meanings)
			RegOp = "KOO";

			PCUNICODE_STRING OpenedKey = (PCUNICODE_STRING)PreOpenInfo->CompleteName;
			PVOID OpenedRO = (PVOID)PreOpenInfo->RootObject;
			PVOID OpenedOT = (PVOID)PreOpenInfo->ObjectType;
			PVOID OpenedCO = (PVOID)PreOpenInfo->CreateOptions;
			PUNICODE_STRING OpenedClass = (PUNICODE_STRING)PreOpenInfo->Class;
			PVOID OpenedSD = (PVOID)PreOpenInfo->SecurityDescriptor;
			PVOID OpenedQS = (PVOID)PreOpenInfo->SecurityQualityOfService;
			ACCESS_MASK OpenedDA = (ACCESS_MASK)PreOpenInfo->DesiredAccess;
			ACCESS_MASK OpenedGA = (ACCESS_MASK)PreOpenInfo->GrantedAccess;
			PULONG OpenedDisposition = (PULONG)PreOpenInfo->Disposition;
			PVOID OpenedREO = (PVOID)PreOpenInfo->ResultObject;
			PVOID OpenedCC = (PVOID)PreOpenInfo->CallContext;
			PVOID OpenedROC = (PVOID)PreOpenInfo->RootObjectContext;
			PVOID OpenedTransaction = (PVOID)PreOpenInfo->Transaction;
			PVOID OpenedReserved = (PVOID)PreOpenInfo->Reserved;

			//Get the ID of process making the registry operation
			ProcessID = (HANDLE)CallbackCtx->ProcessId;

			InfoPrint("Registry Operation Type: %s", RegOp);
			InfoPrint("Key opened: %p", OpenedKey);
			InfoPrint("Opened key root object: %p", OpenedRO);
			InfoPrint("Opened key object type: %p", OpenedOT);
			InfoPrint("Opened key create option: %p", OpenedCO);
			InfoPrint("Opened key class: %p", OpenedClass);
			InfoPrint("Opened key security descriptor: %p", OpenedSD);
			InfoPrint("Opened key security quality of service: %p", OpenedQS);
			InfoPrint("Opened key desired access: %p", OpenedDA);
			InfoPrint("Opened key granted access: %p", OpenedGA);
			InfoPrint("Opened key disposition: %p", OpenedDisposition);
			InfoPrint("Opened key result object: %p", OpenedREO);
			InfoPrint("Opened key call context: %p", OpenedCC);
			InfoPrint("Opened key root object context: %p", OpenedROC);
			InfoPrint("Opened key transaction: %p", OpenedTransaction);
			InfoPrint("Opened key reserved: %p", OpenedReserved);
			InfoPrint("Process ID: %p", ProcessID);
			InfoPrint("User SID: %wZ", userSid);
			InfoPrint("Username: %wZ", username);
			InfoPrint("Key path: %wZ", CapturedObjectName);
			InfoPrint("Opened key name: %wZ", PreOpenInfo->CompleteName);
			InfoPrint("==================================");

			InfoPrint("Write log: %s", sendLogs(t, RegOp, userSid, username, ProcessName, ProcessID, PreOpenInfo->CompleteName, hostname, activename, CapturedObjectName));

			DeleteCallbackContext(CallbackCtx);

			ExFreePoolWithTag(username.Buffer, 'REGF');
			ExFreePoolWithTag(userSid.Buffer, 'REGF');
			CmCallbackReleaseKeyObjectIDEx(ObjectName);

			break;

		case RegNtPreQueryValueKey:
			//This case handles registry opeations regarding key value querying
			PreQueryValueInfo = (PREG_QUERY_VALUE_KEY_INFORMATION) Argument2;
			CallbackCtx = CreateCallbackContext(CALLBACK_MODE_PRE_NOTIFICATION_BYPASS,
				CALLBACK_ALTITUDE);

			//Get time of registry event
			t = (unsigned long long)GetTimestamp();
			InfoPrint("Time: %llu", t);
			InfoPrint("Time size: %d", sizeof(t));

			//Get name of process making the registry operation
			ProcessName = GetProcessNameFromPid(CallbackCtx->ProcessId);

			InfoPrint("Process Name: %s", ProcessName);
			
			//Setting the type of registry operation (Refer to the documentation for acronym meanings)
			RegOp = "KVQO";

			PUNICODE_STRING QueryValue = PreQueryValueInfo->ValueName;
			PVOID QueryObj = (PVOID)PreQueryValueInfo->Object;
			KEY_VALUE_INFORMATION_CLASS QueryKVIC = (KEY_VALUE_INFORMATION_CLASS)PreQueryValueInfo->KeyValueInformationClass;
			PVOID QueryKVI = (PVOID)PreQueryValueInfo->KeyValueInformation;
			ULONG QueryLength = (ULONG)PreQueryValueInfo->Length;
			PULONG QueryRL = (PULONG)PreQueryValueInfo->ResultLength;
			PVOID QueryCC = (PVOID)PreQueryValueInfo->CallContext;
			PVOID QueryOC = (PVOID)PreQueryValueInfo->ObjectContext;
			PVOID QueryReserved = (PVOID)PreQueryValueInfo->Reserved;

			//Get ID of process making the registry operation
			ProcessID = (HANDLE)CallbackCtx->ProcessId;

			//Get the SID of user using the computer
			userSid.MaximumLength = 256;
			userSid.Buffer = ExAllocatePoolWithTag(PagedPool, userSid.MaximumLength, 'REGF');

			RtlZeroMemory(userSid.Buffer, userSid.MaximumLength);

			status = GetUserSID(&userSid);

			//Get the username of user using the computer
			username.MaximumLength = 1024;
			username.Buffer = ExAllocatePoolWithTag(PagedPool, username.MaximumLength, 'REGF');

			if (!username.Buffer) {
				return STATUS_INSUFFICIENT_RESOURCES;
			}

			RtlZeroMemory(username.Buffer, username.MaximumLength);

			status = GetUserID(&username);

			if (!NT_SUCCESS(status)) {
				ErrorPrint("GetUserSID failed. Status 0x%x", status);
				break;
			}

			if (!NT_SUCCESS(status)) {

				ExFreePoolWithTag(username.Buffer, 'REGF');

				return STATUS_UNSUCCESSFUL;
			}

			//Get the full path of the registry key referenced in the operation
			Status = CmCallbackGetKeyObjectIDEx(&CallbackCtx->Cookie,
				PreQueryValueInfo->Object,
				NULL,
				&ObjectName,
				0);           // Flag: reserved for future

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("CmCallbackGetKeyObjectIDEx failed. Status 0x%x", Status);
				break;
			}

			CapturedObjectName.Length = ObjectName->Length;
			CapturedObjectName.MaximumLength = ObjectName->MaximumLength;
			CapturedObjectName.Buffer = ObjectName->Buffer;

			//Get the computer name
			Status = LoadRegistryConfigKey(L"ComputerName", hostname);

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("LoadRegistryConfigKey failed. Status 0x%x", Status);
				break;
			}

			//Get computer's active hostname
			Status = LoadActiveName(L"ComputerName", activename);

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("LoadActiveName failed. Status 0x%x", Status);
				break;
			}
			
			//InfoPrint("Hostname: %c", value);
			//InfoPrint("Status: 0x%x", Status);

			Status = CmCallbackGetKeyObjectIDEx(&CallbackCtx->Cookie,
				PreQueryValueInfo->Object,
				&ObjectValueName,
				NULL,
				0);           // Flag: reserved for future

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("CmCallbackGetKeyObjectIDEx failed. Status 0x%x", Status);
				break;
			}

			UNICODE_STRING vname = { 0 };
			vname.MaximumLength = 256;
			vname.Buffer = ExAllocatePoolWithTag(PagedPool, vname.MaximumLength, 'REGF');

			unsigned long test = PtrToUlong(&ObjectValueName);

			//char * testt = { 0 };
			//status = LoadRegistryValue(test, CapturedObjectName, testt);

			//InfoPrint("Status: 0x%x", status);
			//InfoPrint("Valuee: %s", testt);

			RtlIntegerToUnicodeString(test, 16, &vname); //Data is in the form of E.g. "BBD79308"

			//Data printed out are all in pointer format
			InfoPrint("Registry Operation Type: %s", RegOp);
			InfoPrint("Value queried: %p", QueryValue);
			InfoPrint("Query object: %p", QueryObj);
			InfoPrint("Query key value information class: %p", QueryKVIC);
			InfoPrint("Query key value information: %p", QueryKVI);
			InfoPrint("Query length: %p", QueryLength);
			InfoPrint("Query result length: %p", QueryRL);
			InfoPrint("Query call context: %p", QueryCC);
			InfoPrint("Query object context: %p", QueryOC);
			InfoPrint("Query reserved: %p", QueryReserved);
			InfoPrint("Process ID: %p", ProcessID);
			InfoPrint("User SID: %wZ", userSid);
			InfoPrint("Username: %wZ", username);
			InfoPrint("Key path: %wZ", CapturedObjectName);
			InfoPrint("Key value name: %wZ", PreQueryValueInfo->ValueName);
			InfoPrint("==================================");

			InfoPrint("Write log: %s", sendLogs(t, RegOp, userSid, username, ProcessName, ProcessID, PreQueryValueInfo->ValueName, hostname, activename, CapturedObjectName));

			DeleteCallbackContext(CallbackCtx);

			ExFreePoolWithTag(username.Buffer, 'REGF');
			ExFreePoolWithTag(userSid.Buffer, 'REGF');
			CmCallbackReleaseKeyObjectIDEx(ObjectName);
			ExFreePoolWithTag(vname.Buffer, 'REGF');

			break;

		case RegNtPreQueryKey:
			PreQueryKeyInfo = (PREG_QUERY_KEY_INFORMATION)Argument2;
			CallbackCtx = CreateCallbackContext(CALLBACK_MODE_PRE_NOTIFICATION_BYPASS,
				CALLBACK_ALTITUDE);

			//Get time of registry event
			t = (unsigned long long)GetTimestamp();

			InfoPrint("Time: %llu", t);

			//Get the process ID of process initiating registry event
			ProcessID = (HANDLE)CallbackCtx->ProcessId;

			//Get the name of process initiating registry event
			ProcessName = GetProcessNameFromPid(CallbackCtx->ProcessId);

			InfoPrint("Process Name: %s", ProcessName);


			//Get the SID of the user logged in when the registry event is initiated
			userSid.MaximumLength = 256;
			userSid.Buffer = ExAllocatePoolWithTag(PagedPool, userSid.MaximumLength, 'REGF');

			RtlZeroMemory(userSid.Buffer, userSid.MaximumLength);

			status = GetUserSID(&userSid);

			if (!NT_SUCCESS(status)) {
				ErrorPrint("GetUserSID failed. Status 0x%x", status);
				break;
			}

			//Get the username of the user logged in based on SID
			username.MaximumLength = 1024;
			username.Buffer = ExAllocatePoolWithTag(PagedPool, username.MaximumLength, 'REGF');

			if (!username.Buffer) {
				return STATUS_INSUFFICIENT_RESOURCES;
			}

			RtlZeroMemory(username.Buffer, username.MaximumLength);

			status = GetUserID(&username);

			if (!NT_SUCCESS(status)) {

				ExFreePoolWithTag(username.Buffer, 'REGF');

				return STATUS_UNSUCCESSFUL;
			}

			//Get the full path of the registry key referenced in the operation
			Status = CmCallbackGetKeyObjectIDEx(&CallbackCtx->Cookie,
				PreQueryKeyInfo->Object,
				NULL,
				&ObjectName,
				0);           // Flag: reserved for future

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("CmCallbackGetKeyObjectIDEx failed. Status 0x%x", Status);
				break;
			}

			CapturedObjectName.Length = ObjectName->Length;
			CapturedObjectName.MaximumLength = ObjectName->MaximumLength;
			CapturedObjectName.Buffer = ObjectName->Buffer;

			//Get the computer name
			Status = LoadRegistryConfigKey(L"ComputerName", hostname);

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("LoadRegistryConfigKey failed. Status 0x%x", Status);
				break;
			}

			//Get computer's active hostname
			Status = LoadActiveName(L"ComputerName", activename);

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("LoadActiveName failed. Status 0x%x", Status);
				break;
			}



			//Setting the type of registry operation (Refer to the documentation for acronym meanings)
			RegOp = "KQO";

			//Print data captured for testing
			InfoPrint("Registry Operation Type: %s", RegOp);
			InfoPrint("Process ID: %p", ProcessID);
			InfoPrint("User SID: %wZ", userSid);
			InfoPrint("Username: %wZ", username);
			InfoPrint("Key path: %wZ", CapturedObjectName);
			InfoPrint("==================================");

			InfoPrint("Write log: %s", sendLogs(t, RegOp, userSid, username, ProcessName, ProcessID, NULL, hostname, activename, CapturedObjectName));


			DeleteCallbackContext(CallbackCtx);

			ExFreePoolWithTag(username.Buffer, 'REGF');
			ExFreePoolWithTag(userSid.Buffer, 'REGF');
			CmCallbackReleaseKeyObjectIDEx(ObjectName);

			break;

		case RegNtPreSetKeySecurity:
			PreSetSecurityInfo = (PREG_SET_KEY_SECURITY_INFORMATION)Argument2;
			CallbackCtx = CreateCallbackContext(CALLBACK_MODE_PRE_NOTIFICATION_BYPASS,
				CALLBACK_ALTITUDE);

			//Get time of registry event
			t = (unsigned long long)GetTimestamp();

			InfoPrint("Time: %llu", t);

			//Get the process ID of process initiating registry event
			ProcessID = (HANDLE)CallbackCtx->ProcessId;

			//Get the name of process initiating registry event
			ProcessName = GetProcessNameFromPid(CallbackCtx->ProcessId);

			InfoPrint("Process Name: %s", ProcessName);


			//Get the SID of the user logged in when the registry event is initiated
			userSid.MaximumLength = 256;
			userSid.Buffer = ExAllocatePoolWithTag(PagedPool, userSid.MaximumLength, 'REGF');

			RtlZeroMemory(userSid.Buffer, userSid.MaximumLength);

			status = GetUserSID(&userSid);

			if (!NT_SUCCESS(status)) {
				ErrorPrint("GetUserSID failed. Status 0x%x", status);
				break;
			}

			//Get the username of the user logged in based on SID
			username.MaximumLength = 1024;
			username.Buffer = ExAllocatePoolWithTag(PagedPool, username.MaximumLength, 'REGF');

			if (!username.Buffer) {
				return STATUS_INSUFFICIENT_RESOURCES;
			}

			RtlZeroMemory(username.Buffer, username.MaximumLength);

			status = GetUserID(&username);

			if (!NT_SUCCESS(status)) {

				ExFreePoolWithTag(username.Buffer, 'REGF');

				return STATUS_UNSUCCESSFUL;
			}

			//Get the full path of the registry key referenced in the operation
			Status = CmCallbackGetKeyObjectIDEx(&CallbackCtx->Cookie,
				PreSetSecurityInfo->Object,
				NULL,
				&ObjectName,
				0);           // Flag: reserved for future

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("CmCallbackGetKeyObjectIDEx failed. Status 0x%x", Status);
				break;
			}

			CapturedObjectName.Length = ObjectName->Length;
			CapturedObjectName.MaximumLength = ObjectName->MaximumLength;
			CapturedObjectName.Buffer = ObjectName->Buffer;

			//Get the computer name
			Status = LoadRegistryConfigKey(L"ComputerName", hostname);

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("LoadRegistryConfigKey failed. Status 0x%x", Status);
				break;
			}

			//Get computer's active hostname
			Status = LoadActiveName(L"ComputerName", activename);

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("LoadActiveName failed. Status 0x%x", Status);
				break;
			}

			//Setting the type of registry operation (Refer to the documentation for acronym meanings)
			RegOp = "KSSO";

			//Print data captured for testing
			InfoPrint("Registry Operation Type: %s", RegOp);
			InfoPrint("Process ID: %p", ProcessID);
			InfoPrint("User SID: %wZ", userSid);
			InfoPrint("Username: %wZ", username);
			InfoPrint("Key path: %wZ", CapturedObjectName);
			InfoPrint("==================================");

			InfoPrint("Write log: %s", sendLogs(t, RegOp, userSid, username, ProcessName, ProcessID, NULL, hostname, activename, CapturedObjectName));

			DeleteCallbackContext(CallbackCtx);

			ExFreePoolWithTag(username.Buffer, 'REGF');
			ExFreePoolWithTag(userSid.Buffer, 'REGF');
			CmCallbackReleaseKeyObjectIDEx(ObjectName);

			break;

		case RegNtPreEnumerateKey:
			PreEnumerateInfo = (PREG_ENUMERATE_KEY_INFORMATION)Argument2;
			CallbackCtx = CreateCallbackContext(CALLBACK_MODE_PRE_NOTIFICATION_BYPASS,
				CALLBACK_ALTITUDE);

			//Get time of registry event
			t = (unsigned long long)GetTimestamp();

			InfoPrint("Time: %llu", t);

			//Get the process ID of process initiating registry event
			ProcessID = (HANDLE)CallbackCtx->ProcessId;

			//Get the name of process initiating registry event
			ProcessName = GetProcessNameFromPid(CallbackCtx->ProcessId);

			InfoPrint("Process Name: %s", ProcessName);


			//Get the SID of the user logged in when the registry event is initiated
			userSid.MaximumLength = 256;
			userSid.Buffer = ExAllocatePoolWithTag(PagedPool, userSid.MaximumLength, 'REGF');

			RtlZeroMemory(userSid.Buffer, userSid.MaximumLength);

			status = GetUserSID(&userSid);

			if (!NT_SUCCESS(status)) {
				ErrorPrint("GetUserSID failed. Status 0x%x", status);
				break;
			}

			//Get the username of the user logged in based on SID
			username.MaximumLength = 1024;
			username.Buffer = ExAllocatePoolWithTag(PagedPool, username.MaximumLength, 'REGF');

			if (!username.Buffer) {
				return STATUS_INSUFFICIENT_RESOURCES;
			}

			RtlZeroMemory(username.Buffer, username.MaximumLength);

			status = GetUserID(&username);

			if (!NT_SUCCESS(status)) {

				ExFreePoolWithTag(username.Buffer, 'REGF');

				return STATUS_UNSUCCESSFUL;
			}

			//Get the full path of the registry key referenced in the operation
			Status = CmCallbackGetKeyObjectIDEx(&CallbackCtx->Cookie,
				PreEnumerateInfo->Object,
				NULL,
				&ObjectName,
				0);           // Flag: reserved for future

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("CmCallbackGetKeyObjectIDEx failed. Status 0x%x", Status);
				break;
			}

			CapturedObjectName.Length = ObjectName->Length;
			CapturedObjectName.MaximumLength = ObjectName->MaximumLength;
			CapturedObjectName.Buffer = ObjectName->Buffer;

			//Get the computer name
			Status = LoadRegistryConfigKey(L"ComputerName", hostname);

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("LoadRegistryConfigKey failed. Status 0x%x", Status);
				break;
			}

			//Get computer's active hostname
			Status = LoadActiveName(L"ComputerName", activename);

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("LoadActiveName failed. Status 0x%x", Status);
				break;
			}

			//Setting the type of registry operation (Refer to the documentation for acronym meanings)
			RegOp = "KEO";

			//Print data captured for testing
			InfoPrint("Registry Operation Type: %s", RegOp);
			InfoPrint("Process ID: %p", ProcessID);
			InfoPrint("User SID: %wZ", userSid);
			InfoPrint("Username: %wZ", username);
			InfoPrint("Key path: %wZ", CapturedObjectName);
			InfoPrint("==================================");

			InfoPrint("Write log: %s", sendLogs(t, RegOp, userSid, username, ProcessName, ProcessID, NULL, hostname, activename, CapturedObjectName));

			DeleteCallbackContext(CallbackCtx);

			ExFreePoolWithTag(username.Buffer, 'REGF');
			ExFreePoolWithTag(userSid.Buffer, 'REGF');
			CmCallbackReleaseKeyObjectIDEx(ObjectName);

			break;

		case RegNtPreEnumerateValueKey:
			PreEnumerateValueInfo = (PREG_ENUMERATE_VALUE_KEY_INFORMATION)Argument2;
			CallbackCtx = CreateCallbackContext(CALLBACK_MODE_PRE_NOTIFICATION_BYPASS,
				CALLBACK_ALTITUDE);

			//Get time of registry event
			t = (unsigned long long)GetTimestamp();

			InfoPrint("Time: %llu", t);

			//Get the process ID of process initiating registry event
			ProcessID = (HANDLE)CallbackCtx->ProcessId;

			//Get the name of process initiating registry event
			ProcessName = GetProcessNameFromPid(CallbackCtx->ProcessId);

			InfoPrint("Process Name: %s", ProcessName);


			//Get the SID of the user logged in when the registry event is initiated
			userSid.MaximumLength = 256;
			userSid.Buffer = ExAllocatePoolWithTag(PagedPool, userSid.MaximumLength, 'REGF');

			RtlZeroMemory(userSid.Buffer, userSid.MaximumLength);

			status = GetUserSID(&userSid);

			if (!NT_SUCCESS(status)) {
				ErrorPrint("GetUserSID failed. Status 0x%x", status);
				break;
			}

			//Get the username of the user logged in based on SID
			username.MaximumLength = 1024;
			username.Buffer = ExAllocatePoolWithTag(PagedPool, username.MaximumLength, 'REGF');

			if (!username.Buffer) {
				return STATUS_INSUFFICIENT_RESOURCES;
			}

			RtlZeroMemory(username.Buffer, username.MaximumLength);

			status = GetUserID(&username);

			if (!NT_SUCCESS(status)) {

				ExFreePoolWithTag(username.Buffer, 'REGF');

				return STATUS_UNSUCCESSFUL;
			}

			//Get the full path of the registry key referenced in the operation
			Status = CmCallbackGetKeyObjectIDEx(&CallbackCtx->Cookie,
				PreEnumerateValueInfo->Object,
				NULL,
				&ObjectName,
				0);           // Flag: reserved for future

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("CmCallbackGetKeyObjectIDEx failed. Status 0x%x", Status);
				break;
			}

			CapturedObjectName.Length = ObjectName->Length;
			CapturedObjectName.MaximumLength = ObjectName->MaximumLength;
			CapturedObjectName.Buffer = ObjectName->Buffer;

			//Get the computer name
			Status = LoadRegistryConfigKey(L"ComputerName", hostname);

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("LoadRegistryConfigKey failed. Status 0x%x", Status);
				break;
			}

			//Get computer's active hostname
			Status = LoadActiveName(L"ComputerName", activename);

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("LoadActiveName failed. Status 0x%x", Status);
				break;
			}

			//Setting the type of registry operation (Refer to the documentation for acronym meanings)
			RegOp = "KEVO";

			//Print data captured for testing
			InfoPrint("Registry Operation Type: %s", RegOp);
			InfoPrint("Process ID: %p", ProcessID);
			InfoPrint("User SID: %wZ", userSid);
			InfoPrint("Username: %wZ", username);
			InfoPrint("Key path: %wZ", CapturedObjectName);
			InfoPrint("==================================");

			InfoPrint("Write log: %s", sendLogs(t, RegOp, userSid, username, ProcessName, ProcessID, NULL, hostname, activename, CapturedObjectName));

			DeleteCallbackContext(CallbackCtx);

			ExFreePoolWithTag(username.Buffer, 'REGF');
			ExFreePoolWithTag(userSid.Buffer, 'REGF');
			CmCallbackReleaseKeyObjectIDEx(ObjectName);

			break;

		case RegNtPreQueryMultipleValueKey:
			PreQueryMultipleValueInfo = (PREG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION)Argument2;
			CallbackCtx = CreateCallbackContext(CALLBACK_MODE_PRE_NOTIFICATION_BYPASS,
				CALLBACK_ALTITUDE);

			//Get time of registry event
			t = (unsigned long long)GetTimestamp();

			InfoPrint("Time: %llu", t);

			//Get the process ID of process initiating registry event
			ProcessID = (HANDLE)CallbackCtx->ProcessId;

			//Get the name of process initiating registry event
			ProcessName = GetProcessNameFromPid(CallbackCtx->ProcessId);

			InfoPrint("Process Name: %s", ProcessName);


			//Get the SID of the user logged in when the registry event is initiated
			userSid.MaximumLength = 256;
			userSid.Buffer = ExAllocatePoolWithTag(PagedPool, userSid.MaximumLength, 'REGF');

			RtlZeroMemory(userSid.Buffer, userSid.MaximumLength);

			status = GetUserSID(&userSid);

			if (!NT_SUCCESS(status)) {
				ErrorPrint("GetUserSID failed. Status 0x%x", status);
				break;
			}

			//Get the username of the user logged in based on SID
			username.MaximumLength = 1024;
			username.Buffer = ExAllocatePoolWithTag(PagedPool, username.MaximumLength, 'REGF');

			if (!username.Buffer) {
				return STATUS_INSUFFICIENT_RESOURCES;
			}

			RtlZeroMemory(username.Buffer, username.MaximumLength);

			status = GetUserID(&username);

			if (!NT_SUCCESS(status)) {

				ExFreePoolWithTag(username.Buffer, 'REGF');

				return STATUS_UNSUCCESSFUL;
			}

			//Get the full path of the registry key referenced in the operation
			Status = CmCallbackGetKeyObjectIDEx(&CallbackCtx->Cookie,
				PreQueryMultipleValueInfo->Object,
				NULL,
				&ObjectName,
				0);           // Flag: reserved for future

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("CmCallbackGetKeyObjectIDEx failed. Status 0x%x", Status);
				break;
			}

			CapturedObjectName.Length = ObjectName->Length;
			CapturedObjectName.MaximumLength = ObjectName->MaximumLength;
			CapturedObjectName.Buffer = ObjectName->Buffer;

			//Get the computer name
			Status = LoadRegistryConfigKey(L"ComputerName", hostname);

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("LoadRegistryConfigKey failed. Status 0x%x", Status);
				break;
			}

			//Get computer's active hostname
			Status = LoadActiveName(L"ComputerName", activename);

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("LoadActiveName failed. Status 0x%x", Status);
				break;
			}

			//Setting the type of registry operation (Refer to the documentation for acronym meanings)
			RegOp = "MKQO";

			//Print data captured for testing
			InfoPrint("Registry Operation Type: %s", RegOp);
			InfoPrint("Process ID: %p", ProcessID);
			InfoPrint("User SID: %wZ", userSid);
			InfoPrint("Username: %wZ", username);
			InfoPrint("Key path: %wZ", CapturedObjectName);
			InfoPrint("==================================");

			InfoPrint("Write log: %s", sendLogs(t, RegOp, userSid, username, ProcessName, ProcessID, NULL, hostname, activename, CapturedObjectName));

			DeleteCallbackContext(CallbackCtx);

			ExFreePoolWithTag(username.Buffer, 'REGF');
			ExFreePoolWithTag(userSid.Buffer, 'REGF');
			CmCallbackReleaseKeyObjectIDEx(ObjectName);

			break;

		case RegNtPreSetInformationKey:
			PreSetInformationInfo = (PREG_SET_INFORMATION_KEY_INFORMATION)Argument2;
			CallbackCtx = CreateCallbackContext(CALLBACK_MODE_PRE_NOTIFICATION_BYPASS,
				CALLBACK_ALTITUDE);

			//Get time of registry event
			t = (unsigned long long)GetTimestamp();

			InfoPrint("Time: %llu", t);

			//Get the process ID of process initiating registry event
			ProcessID = (HANDLE)CallbackCtx->ProcessId;

			//Get the name of process initiating registry event
			ProcessName = GetProcessNameFromPid(CallbackCtx->ProcessId);

			InfoPrint("Process Name: %s", ProcessName);


			//Get the SID of the user logged in when the registry event is initiated
			userSid.MaximumLength = 256;
			userSid.Buffer = ExAllocatePoolWithTag(PagedPool, userSid.MaximumLength, 'REGF');

			RtlZeroMemory(userSid.Buffer, userSid.MaximumLength);

			status = GetUserSID(&userSid);

			if (!NT_SUCCESS(status)) {
				ErrorPrint("GetUserSID failed. Status 0x%x", status);
				break;
			}

			//Get the username of the user logged in based on SID
			username.MaximumLength = 1024;
			username.Buffer = ExAllocatePoolWithTag(PagedPool, username.MaximumLength, 'REGF');

			if (!username.Buffer) {
				return STATUS_INSUFFICIENT_RESOURCES;
			}

			RtlZeroMemory(username.Buffer, username.MaximumLength);

			status = GetUserID(&username);

			if (!NT_SUCCESS(status)) {

				ExFreePoolWithTag(username.Buffer, 'REGF');

				return STATUS_UNSUCCESSFUL;
			}

			//Get the full path of the registry key referenced in the operation
			Status = CmCallbackGetKeyObjectIDEx(&CallbackCtx->Cookie,
				PreSetInformationInfo->Object,
				NULL,
				&ObjectName,
				0);           // Flag: reserved for future

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("CmCallbackGetKeyObjectIDEx failed. Status 0x%x", Status);
				break;
			}

			CapturedObjectName.Length = ObjectName->Length;
			CapturedObjectName.MaximumLength = ObjectName->MaximumLength;
			CapturedObjectName.Buffer = ObjectName->Buffer;

			//Get the computer name
			Status = LoadRegistryConfigKey(L"ComputerName", hostname);

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("LoadRegistryConfigKey failed. Status 0x%x", Status);
				break;
			}

			//Get computer's active hostname
			Status = LoadActiveName(L"ComputerName", activename);

			if (!NT_SUCCESS(Status)) {
				ErrorPrint("LoadActiveName failed. Status 0x%x", Status);
				break;
			}

			//Setting the type of registry operation (Refer to the documentation for acronym meanings)
			RegOp = "SKIO";

			//Print data captured for testing
			InfoPrint("Registry Operation Type: %s", RegOp);
			InfoPrint("Process ID: %p", ProcessID);
			InfoPrint("User SID: %wZ", userSid);
			InfoPrint("Username: %wZ", username);
			InfoPrint("Key path: %wZ", CapturedObjectName);
			InfoPrint("==================================");

			InfoPrint("Write log: %s", sendLogs(t, RegOp, userSid, username, ProcessName, ProcessID, NULL, hostname, activename, CapturedObjectName));

			DeleteCallbackContext(CallbackCtx);

			ExFreePoolWithTag(username.Buffer, 'REGF');
			ExFreePoolWithTag(userSid.Buffer, 'REGF');
			CmCallbackReleaseKeyObjectIDEx(ObjectName);

			break;
		    
	/*
	New cases are created here:
	case RegNtPreKeyHandleClose:
	
	break;
	*/
           
        default:
            //
            // Do nothing for other notifications
            //
            break;
    }

    //
    // Free buffers used for capturing user mode values.
    //

    if (LocalClass.Buffer != NULL) {
        FreeCapturedUnicodeString(&LocalClass, REGFLTR_CAPTURE_POOL_TAG);
    }
    
    if (LocalData != NULL) {
        FreeCapturedBuffer(LocalData, REGFLTR_CAPTURE_POOL_TAG);
    }

    return Status;

}

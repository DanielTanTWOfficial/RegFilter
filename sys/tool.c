#include "regfltr.h"
#include <ntifs.h>
#include <fltKernel.h>
#include <Ntstrsafe.h>
#include <stdio.h>

/*
	Daniel 5/22/2018

	This file contains the functions to get a few pieces of information from the registry operations intercepted:
		1. GetUserID() -> Gets the ID of the user responsible for registry operation
		2. LoadRegistryConfigKey() -> Reads the current hostname value from the registry
		3. LoadActiveName() -> Reads the active hostname value from the registry
*/

//This function gets the username of the user who initiated the registry operation intercepted
NTSTATUS GetUserID(_Inout_ PUNICODE_STRING userId)
{
	/*
		Daniel May 2018
		
		In this function, 5 main things are done
		
		1. Opening of token from registry operation thread
		2. Querying information from token -> ZwQueryInformationToken()
		3. Querying information from token again to get user data -> ZwQueryInformationToken()
		4. Performing a lookup of account SID -> SecLookupAccountSid()
		5. Performing lookup again to get user SID -> SecLookupAccountSid()
	*/
	PTOKEN_USER User;
	HANDLE token;
	ULONG len;
	NTSTATUS status;

	userId->Length = 0;

	status = ZwOpenThreadTokenEx(NtCurrentThread(), GENERIC_READ, TRUE, OBJ_KERNEL_HANDLE, &token);

	if (!NT_SUCCESS(status)) {
		status = ZwOpenProcessTokenEx(NtCurrentProcess(), GENERIC_READ, OBJ_KERNEL_HANDLE, &token);
	}

	if (!NT_SUCCESS(status)) {
		userId->Length = (USHORT)swprintf_s(userId->Buffer, userId->MaximumLength, L"{GetUserID error:1:%x}", status);
		return status;
	}

	status = ZwQueryInformationToken(token, TokenUser, NULL, 0, &len);

	if (!NT_SUCCESS(status) && status != STATUS_BUFFER_TOO_SMALL) {
		userId->Length = (USHORT)swprintf_s(userId->Buffer, userId->MaximumLength, L"{GetUserID error:2:%x}", status);
		ZwClose(token);
		return status;
	}

	User = ExAllocatePoolWithTag(PagedPool, len, 'REGF');

	if (!User) {
		userId->Length = (USHORT)swprintf_s(userId->Buffer, userId->MaximumLength, L"{GetUserID error:no memory}");
		ZwClose(token);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	status = ZwQueryInformationToken(token, TokenUser, User, len, &len);

	ULONG NameSize = 0;
	SID_NAME_USE NameUse;
	UNICODE_STRING NameBuffer = { 0 };
	ULONG DomainSize = 0;
	UNICODE_STRING DomainBuffer = { 0 };
	status = SecLookupAccountSid((PSID)User->User.Sid, &NameSize, &NameBuffer, &DomainSize, NULL, &NameUse);

	if (!NT_SUCCESS(status) && status != STATUS_BUFFER_TOO_SMALL) {
		userId->Length = (USHORT)swprintf_s(userId->Buffer, userId->MaximumLength, L"{GetUserID error:3:%x}", status);
		ExFreePoolWithTag(User, 'REGF');
		ZwClose(token);
		return status;
	}

	NameBuffer.Buffer = ExAllocatePoolWithTag(PagedPool, NameSize, 'REGF');
	NameBuffer.MaximumLength = (USHORT)NameSize;
	DomainBuffer.Buffer = ExAllocatePoolWithTag(PagedPool, DomainSize, 'REGF');
	DomainBuffer.MaximumLength = (USHORT)DomainSize;

	status = SecLookupAccountSid((PSID)User->User.Sid, &NameSize, &NameBuffer, &DomainSize, &DomainBuffer, &NameUse);

	if (!NT_SUCCESS(status)) {
		userId->Length = (USHORT)swprintf_s(userId->Buffer, userId->MaximumLength, L"{GetUserID error:4:%x}", status);
		ExFreePoolWithTag(User, 'REGF');
		ZwClose(token);
		return status;
	}

	// So this is a very hack way to just change the result of this method without affecting
	// other methods which call it. Ideally, rather than storing this to a char*, this should
	// be stored to a UNICODE_STRING that is passed by the caller.
	// To be clear, NameBuffer above should actually be a passed parameter.
	// sprintf_s(UserId, UserBufferSize, "%wZ\\%wZ", DomainBuffer, NameBuffer);

	RtlCopyUnicodeString(userId, &DomainBuffer);
	RtlUnicodeStringCat(userId, &NameBuffer);

	ExFreePoolWithTag(User, 'REGF');
	ZwClose(token);

	return status;
}

//This function gets the current computer name from the registry
NTSTATUS LoadRegistryConfigKey(
	_In_ const PWCHAR Value,
	_Inout_ CHAR Variable[256]) {

	//This method gets the computer name from the registry
	
	/*
		Daniel May 2018
		
		In this function, we are reading the registry of the target machine to get the current hostname
		
		Path to the registry key is: \\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName
		
		In the case of current hostname, the value name is ComputerName, which is set when we call this function, as a PWCHAR
		
		Useful links to help you understand what is going on here:
			1. https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/ntstrsafe/nf-ntstrsafe-rtlunicodestringinit
			2. https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wudfwdm/nf-wudfwdm-initializeobjectattributes
			3. https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/nf-wdm-zwopenkey
			4. https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/nf-wdm-zwqueryvaluekey
			
		After we get the value from the registry, we have to convert it into unicode hex values, to prevent the raw data from getting
		screwed up;For this we use sprintf
			1. https://stackoverflow.com/questions/5661101/how-to-convert-an-unsigned-character-array-into-a-hexadecimal-string-in-c/5662551
	*/

	NTSTATUS status;

	UNICODE_STRING KeyName = { 0 };
	UNICODE_STRING ValueName = { 0 };

	//Setting the path to the key
	status = RtlUnicodeStringInit(&KeyName, L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName");
	status = RtlUnicodeStringInit(&ValueName, Value);

	OBJECT_ATTRIBUTES object;
	HANDLE key = NULL;

	InitializeObjectAttributes(&object, &KeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwOpenKey(&key, KEY_READ | KEY_SET_VALUE, &object);

	// If the key cannot be opened (perhaps it wasn't able to be found?) clean up and return the
	// reason that said key can't be opened.
	if (!NT_SUCCESS(status)) {
		//PROGGER_ASSERT_STATUS(status);
		ZwClose(&key);
		return status;
	}

	PKEY_VALUE_PARTIAL_INFORMATION valueInfomation = ExAllocatePoolWithTag(NonPagedPool, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 256, 'CROW');

	if (!valueInfomation) {
		ZwClose(key);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	ULONG realSize = 0;

	status = ZwQueryValueKey(key, &ValueName, KeyValuePartialInformation, valueInfomation, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 256, &realSize);

	///*if (status == STATUS_OBJECT_NAME_NOT_FOUND) {
	//	status = ZwSetValueKey(key, &ValueName, 0, REG_SZ, Variable, sizeof(PUNICODE_STRING));
	//	ZwClose(key);
	//	ExFreePoolWithTag(valueInfomation, 'CROW');
	//	return status;
	//}*/
	//else if (!NT_SUCCESS(status)) {
	//	ZwClose(key);
	//	ExFreePoolWithTag(valueInfomation, 'CROW');
	//	//PROGGER_ASSERT_STATUS(status);
	//	return status;
	//}
	//else if (valueInfomation->Type != REG_SZ) {
	//	status = STATUS_INVALID_PARAMETER;
	//	ZwClose(key);
	//	ExFreePoolWithTag(valueInfomation, 'CROW');
	//	return status;
	//}

	// The driver will fail to load if the data length is too long
	//ASSERT(valueInfomation->DataLength == 4);

	int buffer = valueInfomation->DataLength;
	
	//Try to convert numbers to hex
	//This result will be the unicode version of the computer hostname
	char converted[256];
	int i;

	for (i = 0; i<buffer; i++) {
		sprintf(&converted[i * 2], "%02X", valueInfomation->Data[i]);

		/* equivalent using snprintf, notice len field keeps reducing
		with each pass, to prevent overruns

		snprintf(&converted[i*2], sizeof(converted)-(i*2),"%02X", buffer[i]);
		*/

	}

	InfoPrint("Hostname: %s", converted);
	
	strncpy(Variable, converted, sizeof(converted));

	status = ZwClose(key);

	ExFreePoolWithTag(valueInfomation, 'CROW');

	return status;
}

//This function gets the active computer name from the registry
NTSTATUS LoadActiveName(
	_In_ const PWCHAR Value,
	_Inout_ CHAR Variable[256]) {

	//This method gets the computer's active hostname from the registry
	/*
		Daniel May 2018
		
		In this function, we are reading the registry of the target machine to get the active hostname
		
		Path to the registry key is: \\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName
		
		In the case of active hostname, the value name is also ComputerName, which is set when we call this function, as a PWCHAR
		
		Useful links to help you understand what is going on here:
			1. https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/ntstrsafe/nf-ntstrsafe-rtlunicodestringinit
			2. https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wudfwdm/nf-wudfwdm-initializeobjectattributes
			3. https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/nf-wdm-zwopenkey
			4. https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/nf-wdm-zwqueryvaluekey
			
		After we get the value from the registry, we have to convert it into unicode hex values, to prevent the raw data from getting
		screwed up;For this we use sprintf
			1. https://stackoverflow.com/questions/5661101/how-to-convert-an-unsigned-character-array-into-a-hexadecimal-string-in-c/5662551
	*/

	NTSTATUS status;

	UNICODE_STRING KeyName = { 0 };
	UNICODE_STRING ValueName = { 0 };

	//Setting the path to the key
	status = RtlUnicodeStringInit(&KeyName, L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName");
	status = RtlUnicodeStringInit(&ValueName, Value);

	OBJECT_ATTRIBUTES object;
	HANDLE key = NULL;

	InitializeObjectAttributes(&object, &KeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwOpenKey(&key, KEY_READ | KEY_SET_VALUE, &object);

	// If the key cannot be opened (perhaps it wasn't able to be found?) clean up and return the
	// reason that said key can't be opened.
	if (!NT_SUCCESS(status)) {
		//PROGGER_ASSERT_STATUS(status);
		ZwClose(&key);
		return status;
	}

	PKEY_VALUE_PARTIAL_INFORMATION valueInfomation = ExAllocatePoolWithTag(NonPagedPool, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 256, 'CROW');

	if (!valueInfomation) {
		ZwClose(key);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	ULONG realSize = 0;

	status = ZwQueryValueKey(key, &ValueName, KeyValuePartialInformation, valueInfomation, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 256, &realSize);

	///*if (status == STATUS_OBJECT_NAME_NOT_FOUND) {
	//	status = ZwSetValueKey(key, &ValueName, 0, REG_SZ, Variable, sizeof(PUNICODE_STRING));
	//	ZwClose(key);
	//	ExFreePoolWithTag(valueInfomation, 'CROW');
	//	return status;
	//}*/
	//else if (!NT_SUCCESS(status)) {
	//	ZwClose(key);
	//	ExFreePoolWithTag(valueInfomation, 'CROW');
	//	//PROGGER_ASSERT_STATUS(status);
	//	return status;
	//}
	//else if (valueInfomation->Type != REG_SZ) {
	//	status = STATUS_INVALID_PARAMETER;
	//	ZwClose(key);
	//	ExFreePoolWithTag(valueInfomation, 'CROW');
	//	return status;
	//}

	// The driver will fail to load if the data length is too long
	//ASSERT(valueInfomation->DataLength == 4);

	int buffer = valueInfomation->DataLength;

	//Try to convert numbers to hex
	//This result will be the unicode version of the computer hostname
	char converted[256];
	int i;

	for (i = 0; i<buffer; i++) {
		sprintf(&converted[i * 2], "%02X", valueInfomation->Data[i]);

		/* equivalent using snprintf, notice len field keeps reducing
		with each pass, to prevent overruns

		snprintf(&converted[i*2], sizeof(converted)-(i*2),"%02X", buffer[i]);
		*/

	}

	InfoPrint("Active hostname: %s", converted);

	strncpy(Variable, converted, sizeof(converted));

	status = ZwClose(key);

	ExFreePoolWithTag(valueInfomation, 'CROW');

	return status;
}

//This function is not used 
NTSTATUS LoadRegistryValue(
	_In_ ULONG Value,
	_In_ UNICODE_STRING KeyPath,
	_Inout_ CHAR *Variable) {

	NTSTATUS status;

	UNICODE_STRING KeyName = { 0 };
	UNICODE_STRING ValueName = { 0 };

	status = RtlUnicodeStringInit(&KeyName, L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName");
	//status = RtlUnicodeStringInit(&ValueName, Value);
	status = RtlIntegerToUnicodeString(Value, 16, &ValueName);

	OBJECT_ATTRIBUTES object;
	HANDLE key = NULL;

	//We are trying to use the provided key path to initialize and open the key
	//InitializeObjectAttributes(&object, &KeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	InitializeObjectAttributes(&object, &KeyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwOpenKey(&key, KEY_READ | KEY_SET_VALUE, &object);

	// If the key cannot be opened (perhaps it wasn't able to be found?) clean up and return the
	// reason that said key can't be opened.
	if (!NT_SUCCESS(status)) {
		//PROGGER_ASSERT_STATUS(status);
		ZwClose(&key);
		return status;
	}

	PKEY_VALUE_PARTIAL_INFORMATION valueInfomation = ExAllocatePoolWithTag(NonPagedPool, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 256, 'CROW');

	if (!valueInfomation) {
		ZwClose(key);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	ULONG realSize = 0;

	status = ZwQueryValueKey(key, &ValueName, KeyValuePartialInformation, valueInfomation, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 256, &realSize);

	///*if (status == STATUS_OBJECT_NAME_NOT_FOUND) {
	//	status = ZwSetValueKey(key, &ValueName, 0, REG_SZ, Variable, sizeof(PUNICODE_STRING));
	//	ZwClose(key);
	//	ExFreePoolWithTag(valueInfomation, 'CROW');
	//	return status;
	//}*/
	//else if (!NT_SUCCESS(status)) {
	//	ZwClose(key);
	//	ExFreePoolWithTag(valueInfomation, 'CROW');
	//	//PROGGER_ASSERT_STATUS(status);
	//	return status;
	//}
	//else if (valueInfomation->Type != REG_SZ) {
	//	status = STATUS_INVALID_PARAMETER;
	//	ZwClose(key);
	//	ExFreePoolWithTag(valueInfomation, 'CROW');
	//	return status;
	//}

	// The driver will fail to load if the data length is too long
	//ASSERT(valueInfomation->DataLength == 4);

	int buffer = valueInfomation->DataLength;

	//Try to convert numbers to hex
	//This result will be the unicode version of the computer hostname
	char converted[256];
	int i;

	for (i = 0; i<buffer; i++) {
		sprintf(&converted[i * 2], "%02X", valueInfomation->Data[i]);

		/* equivalent using snprintf, notice len field keeps reducing
		with each pass, to prevent overruns

		snprintf(&converted[i*2], sizeof(converted)-(i*2),"%02X", buffer[i]);
		*/

	}

	InfoPrint("Value: %s", converted);

	Variable = converted;

	status = ZwClose(key);

	ExFreePoolWithTag(valueInfomation, 'CROW');

	return status;
}

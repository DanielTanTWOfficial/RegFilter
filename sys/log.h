/*
	Jun Kang 5/22/2018
	This file contains the declaration of the main methods that is used for the communication between the Windows Registry Filter Driver and the Redis
	This form of communication make use of the Winsock Kernel (WSK).
	More information about how to use the Winsock Kernel can be found in the report or under the Microsoft Documentation.
	https://docs.microsoft.com/en-us/windows-hardware/drivers/network/winsock-kernel-operations
*/

#include <ntstrsafe.h>


// Declaration of all the functions that are used for logging
// Used for opening the log file, called during DriverEntry in driver.c 
NTSTATUS OpenLogFile();
// Used for writing the log file and sending it over to Redis
NTSTATUS WriteLog(PCHAR contents, INT size);
// Used for closing the log file
NTSTATUS CloseLogFile();

//Method that is used to take in all the information captured by the Windows Registry Filter Driver, then formats and concat them together
//before sending it over to the Redis
PCHAR sendLogs(unsigned long long timeStamp, PCHAR operationType, UNICODE_STRING userId, UNICODE_STRING userName, PCHAR processName, 
HANDLE processId, _In_opt_ PUNICODE_STRING newValue, char hostname[256], char activename[256], UNICODE_STRING registryPath);

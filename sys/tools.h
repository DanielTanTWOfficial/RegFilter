#pragma once
#include <ntddk.h>

/*
	Daniel 5/22/2018

	This header file contains the function to get the process name based on the process ID
		- GetProcessNameFromPid()

	This code was derived from:
	http://www.rohitab.com/discuss/topic/40560-get-process-name-form-pid-in-kernel-mode-driver/

	Take note that the reason why this function is in a header file of its own is because the <ntddk.h>
	header file is not compatible with the <ntifs.h> header file for some reason.
	
	2 things are done in the function GetProcessNameFromPid()
	
		1. Look up the process information structure from process ID -> PsLookupProcessByProcessId()
		2. Get the process name from the PEPROCESS structure -> PsGetProcessImageFileName()
*/

extern UCHAR *PsGetProcessImageFileName(IN PEPROCESS Process);

typedef PCHAR(*GET_PROCESS_IMAGE_NAME) (PEPROCESS Process);
GET_PROCESS_IMAGE_NAME gGetProcessImageFileName;

//This function gets the process name of the process initiating the registry operation intercepted
/*+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+--+--+-+-+-+-+-+-+-+-+-+-+-+-+*/
char * GetProcessNameFromPid(HANDLE pid)
{
	PEPROCESS Process;
	if (PsLookupProcessByProcessId(pid, &Process) == STATUS_INVALID_PARAMETER)
	{
		return "pid???";
	}
	return (CHAR*)PsGetProcessImageFileName(Process);
}

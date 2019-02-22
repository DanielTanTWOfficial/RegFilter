/*
	Jun Kang 5/22/2018
	This file contains the main methods that is used for the communication between the Windows Registry Filter Driver and the Redis
	This form of communication make use of the Winsock Kernel (WSK).
	More information about how to use the Winsock Kernel can be found in the report or under the Microsoft Documentation.
	https://docs.microsoft.com/en-us/windows-hardware/drivers/network/winsock-kernel-operations
	
	Possible areas for improvement:
	1. Receive acknowledgement from Redis itself after sending and push data into the list (Error-checking and reliabilty)
	At the current state of this part of the project, we are only focusing on the sending of data over to the Redis. However, we do
	not have any form of acknowledgement from Redis itself. Allowing the receiving of data from Redis to the Windows Registry Filter 
	Driver can be useful as a form of acknowledge to ensure that the data is successfully sent and logged into the list in Redis.
	
	Possible solution that may work:
	1. From the research I done with the connection between Redis and Winsock Kernel. It is definitely possible using the Winsock 
	Kernel functions (most likely WskReceive) and the Redis Serialization Protocol (RESP). Currently, how we send our data to 
	Redis is through Winsock Kernel Socket using the Redis Serialization Protocol (RESP)(at Line 454). As the Redis Serialization 
	Protocol (RESP) is a request-response protocol, it generally does two main things which is first, clients send commands to a 
	Redis server as a RESP Array of Bulk Strings and second, the server replies with one of the RESP types according to the command 
	implementation.
	You can find out more information about the protocol itself and how to use it here
	https://redis.io/topics/protocol

	The other possible area of improvement and its possible solution can be found in the Python script (redis_regfltr.py)
*/


#include <fltKernel.h>
#include <ntstrsafe.h>
#include <wsk.h>
#include <stdio.h>
#include "log.h"
#include "logFormat.h"
#include <assert.h>

//initialize message id for method use
int messageId=0;
//initialize the char array that takes in all the information
CHAR totalChar[10000];


#ifdef ALLOC_PRAGMA

#pragma alloc_text(PAGE, OpenLogFile)
#pragma alloc_text(PAGE, CloseLogFile)
#pragma alloc_text(PAGE, WriteLog)


#endif

// Source: https://code.google.com/p/wskudp/source/browse/trunk/wskudp/wskudp.c
#define HTON_SHORT(n) (((((unsigned short)(n) & 0xFFu  )) << 8) | \
                                        (((unsigned short)(n) & 0xFF00u) >> 8))

#define HTON_LONG(x)    (((((x)& 0xff)<<24) | ((x)>>24) & 0xff) | \
                                        (((x) & 0xff0000)>>8) | (((x) & 0xff00)<<8))


LONG bWSKInit = FALSE;
LONG bSocketAvailable = FALSE;
static PWSK_SOCKET wSocket = NULL;
static WSK_REGISTRATION wRegistration;
static WSK_PROVIDER_NPI wProvider;
static WSK_CLIENT_DISPATCH wDispatch = {
	MAKE_WSK_VERSION(1,0),
	0,
	NULL
};

PFLT_INSTANCE gFltInstance = NULL;
HANDLE gFileHandle;
PFILE_OBJECT gFileObject = NULL;
BOOLEAN gFileOpen = FALSE;
BOOLEAN gFileWritable = FALSE;

static
NTSTATUS
NTAPI
IrpCallback(
	__in PDEVICE_OBJECT DeviceObject,
	__in PIRP Irp,
	__in PKEVENT CompletionEvent
) {
	ASSERT(CompletionEvent);

	UNREFERENCED_PARAMETER(Irp);
	UNREFERENCED_PARAMETER(DeviceObject);

	KeSetEvent(CompletionEvent, IO_NO_INCREMENT, FALSE);

	return STATUS_MORE_PROCESSING_REQUIRED;
}

// A connection-oriented socket's WskReceiveEvent
// event callback function
NTSTATUS WSKAPI
WskReceiveEvent(
	PVOID SocketContext,
	ULONG Flags,
	PWSK_DATA_INDICATION DataIndication,
	SIZE_T BytesIndicated,
	SIZE_T *BytesAccepted
)
{
	UNREFERENCED_PARAMETER(SocketContext);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(BytesIndicated);
	UNREFERENCED_PARAMETER(BytesAccepted);


	// Check for a valid data indication
	if (DataIndication != NULL)
	{
		// Loop through the list of data indication structures
		while (DataIndication != NULL)
		{
			// Process the data in the data indication structure
			PCHAR data = (PCHAR)MmGetMdlVirtualAddress(DataIndication->Buffer.Mdl);

			if (data[0] == '-') {
				DbgPrintEx(DPFLTR_FLTMGR_ID, 1, "Error: %s\n", data);
			}

			// TODO: handle buffer data and check for errors
			DataIndication = DataIndication->Next;
		}

		// Return status indicating the data was received
		return STATUS_SUCCESS;
	}
	else {
		// TODO: Fix this
		KeBugCheck(0xDEADBEEF);
	}
}

NTSTATUS WSKAPI
WskDisconnectEvent(
	_In_opt_ PVOID SocketContext,
	_In_     ULONG Flags
) {
	UNREFERENCED_PARAMETER(SocketContext);
	UNREFERENCED_PARAMETER(Flags);

	InterlockedExchange(&bSocketAvailable, FALSE);

	return STATUS_SUCCESS;
}

// This needs to be at a fixed address in memory since the system kernel uses this as a callback.
// This is not well documented on the site.
const static WSK_CLIENT_CONNECTION_DISPATCH dispatch = { WskReceiveEvent, WskDisconnectEvent, NULL, };

NTSTATUS OpenLogFile() {
	PAGED_CODE();

	NTSTATUS status;

	// Open the WSK Client
	if (bWSKInit == FALSE) {

		WSK_CLIENT_NPI clientNpi = { 0 };

		clientNpi.ClientContext = NULL;
		clientNpi.Dispatch = &wDispatch;

		/*
		ERROR CASES

		*/
		status = WskRegister(&clientNpi, &wRegistration);
		if (!NT_SUCCESS(status)) {
			InterlockedExchange(&bWSKInit, FALSE);
			return status;
		}

		/*
		ERROR CASES

		*/
		status = WskCaptureProviderNPI(&wRegistration, WSK_INFINITE_WAIT, &wProvider);
		if (!NT_SUCCESS(status)) {
			InterlockedExchange(&bWSKInit, FALSE);
			WskDeregister(&wRegistration);
			return status;
		}

		InterlockedExchange(&bWSKInit, TRUE);
	}

	if (bSocketAvailable == FALSE) {
		/*
		ERROR CASES

		*/
		PIRP irp = IoAllocateIrp(1, FALSE);

		if (!irp) {
			InterlockedExchange(&bSocketAvailable, FALSE);
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		KEVENT eCallback = { 0 };

		// Init the event and set the callback for the wait object

		/*
		ERROR CASES

		*/
		KeInitializeEvent(&eCallback, SynchronizationEvent, FALSE);

		/*
		ERROR CASES

		*/
		IoSetCompletionRoutine(irp, IrpCallback, &eCallback, TRUE, TRUE, TRUE);

		// Create the socket

		SOCKADDR_IN localAddress = { 0, };
		localAddress.sin_family = AF_INET;
		localAddress.sin_addr.s_addr = INADDR_ANY;
		localAddress.sin_port = 0;

		SOCKADDR_IN remoteAddress = { 0, };
		remoteAddress.sin_family = AF_INET;
		//use ip address converter 32bit (https://www.psyon.org/tools/ip_address_converter.php?ip=127.0.0.1)
		remoteAddress.sin_addr.S_un.S_addr = HTON_LONG(0x7F000001);
		remoteAddress.sin_port = HTON_SHORT(6379);

												   /*
												   ERROR CASES

												   */
		status = wProvider.Dispatch->WskSocketConnect(
			wProvider.Client,
			SOCK_STREAM,
			IPPROTO_TCP,
			(PSOCKADDR)&localAddress,
			(PSOCKADDR)&remoteAddress,
			0,
			NULL,
			&dispatch,
			NULL,
			NULL,
			NULL,
			irp);

		if (status == STATUS_PENDING) {
			/*
			ERROR CASES

			*/
			KeWaitForSingleObject(&eCallback, Executive, KernelMode, FALSE, NULL);
			status = irp->IoStatus.Status;
		}

		wSocket = NT_SUCCESS(status) ? (PWSK_SOCKET)irp->IoStatus.Information : NULL;

		if (status == STATUS_IO_TIMEOUT) {
			DbgPrintEx(DPFLTR_FLTMGR_ID, 1, "Connect Timeout\n");

			IoFreeIrp(irp);

			CloseLogFile();

			return status;
		}

		/*
		ERROR CASES

		*/
		IoFreeIrp(irp);

		if (wSocket == NULL) {
			DbgPrintEx(DPFLTR_FLTMGR_ID, 1, "Could not create socket\n");
			return STATUS_UNSUCCESSFUL;
		}

		// Set Receive Callback

		WSK_EVENT_CALLBACK_CONTROL EventCallbackControl;

		EventCallbackControl.NpiId = &NPI_WSK_INTERFACE_ID;

		EventCallbackControl.EventMask = WSK_EVENT_RECEIVE;

		/*
		ERROR CASES

		*/
		status = ((PWSK_PROVIDER_BASIC_DISPATCH)wSocket->Dispatch)->WskControlSocket(wSocket,
			WskSetOption,
			SO_WSK_EVENT_CALLBACK,
			SOL_SOCKET,
			sizeof(WSK_EVENT_CALLBACK_CONTROL),
			&EventCallbackControl,
			0,
			NULL,
			NULL,
			NULL);

		if (!NT_SUCCESS(status)) {
			DbgPrintEx(DPFLTR_FLTMGR_ID, 1, "Could not enable receive callback on socket\n");
			return status;
		}

		InterlockedExchange(&bSocketAvailable, TRUE);
	}

	return STATUS_SUCCESS;
}


NTSTATUS CloseLogFile(
) {
	/*
	ERROR CASES
	- Success
	The kernel is at a IRQL of <= APC_LEVEL and paged code is safe to run
	- Failure
	An assertion will be triggered
	*/
	PAGED_CODE();

	NTSTATUS status = STATUS_UNSUCCESSFUL;

	// Close the network socket

	if (bWSKInit == FALSE && bSocketAvailable == TRUE) {
		// Assume that if somehow WSKInit is false then the socket is dead
		InterlockedExchange(&bSocketAvailable, FALSE);
		return STATUS_SUCCESS;
	}

	if (bSocketAvailable == TRUE) {
		/*
		ERROR CASES

		*/
		PIRP irp = IoAllocateIrp(1, FALSE);

		if (!irp) {
			// The state didn't change but theres not enough resources to free the socket
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		KEVENT eCallback = { 0 };

		// Init the event and set the callback for the wait object

		/*
		ERROR CASES

		*/
		KeInitializeEvent(&eCallback, SynchronizationEvent, FALSE);

		/*
		ERROR CASES

		*/
		IoSetCompletionRoutine(irp, IrpCallback, &eCallback, TRUE, TRUE, TRUE);

		/*
		ERROR CASES

		*/
		status = ((PWSK_PROVIDER_BASIC_DISPATCH)wSocket->Dispatch)->WskCloseSocket(wSocket, irp);

		if (status == STATUS_PENDING) {
			/*
			ERROR CASES

			*/
			KeWaitForSingleObject(&eCallback, Executive, KernelMode, FALSE, NULL);
			status = irp->IoStatus.Status;
		}

		if (!NT_SUCCESS(status)) {
			DbgPrintEx(DPFLTR_FLTMGR_ID, 1, "Could not close socket\n");
		}

		/*
		ERROR CASES

		*/
		IoFreeIrp(irp);

		InterlockedExchange(&bSocketAvailable, FALSE);
	}

	if (bWSKInit == TRUE) {
		/*
		ERROR CASES

		*/
		WskReleaseProviderNPI(&wRegistration);

		/*
		ERROR CASES

		*/
		WskDeregister(&wRegistration);

		InterlockedExchange(&bWSKInit, FALSE);
	}

	return STATUS_SUCCESS;
}


NTSTATUS WriteLog(
	PCHAR plaintextContents,
	INT plaintextSize
) {

	/*
	ERROR CASES
	- Success
	The kernel is at a IRQL of <= APC_LEVEL and paged code is safe to run
	- Failure
	An assertion will be triggered
	*/
	PAGED_CODE();

	NTSTATUS status = STATUS_UNSUCCESSFUL;

	ASSERT(plaintextContents);
	DbgPrint("[bSocketAvailable1] %x", bSocketAvailable);
	if (!bSocketAvailable) {
		DbgPrint("[bSocketAvailable2] %x", bSocketAvailable);
		if (!bSocketAvailable) {
			DbgPrint("Could not reconnect\n");
			return STATUS_SUCCESS;
		}
	}

	// Wrap the buffer in the content required by redis

	/*
	ERROR CASES

	*/
	PCHAR string = ExAllocatePoolWithTag(PagedPool, plaintextSize + 64, 'CROW'); // A little over allocation just in case

	if (!string) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroBytes(string, plaintextSize + 64);

	// wrap plaintextContents in a redis RPUSH
	int newLength = _snprintf_s(string, plaintextSize + 64, _TRUNCATE, "*3\r\n$5\r\nRPUSH\r\n$11\r\nregfltrList\r\n$%d\r\n", plaintextSize);

	ASSERT(newLength + 12 < 64);

	memcpy(&string[newLength], plaintextContents, plaintextSize);

	string[newLength + plaintextSize] = 13; // CR (\r)
	string[newLength + plaintextSize + 1] = 10; // LF (\n)

	newLength += plaintextSize + 2;

	// Alloc the buffer
	WSK_BUF wBuffer = { 0 };
	wBuffer.Offset = 0;
	wBuffer.Length = newLength;

	wBuffer.Mdl = IoAllocateMdl(string, newLength, FALSE, FALSE, NULL);
	if (wBuffer.Mdl == NULL) {
		// TODO: Maybe record the type of event sending problem that occurred and record that to
		// an event log for debugging reasons.
		ExFreePoolWithTag(string, 'CROW');
		return status;
	}

	__try {
		MmProbeAndLockPages(wBuffer.Mdl, KernelMode, IoWriteAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		// The OS will bug-check if the exception is not handled successfully
		IoFreeMdl(wBuffer.Mdl);
		ExFreePoolWithTag(string, 'CROW');
		return STATUS_ACCESS_VIOLATION;
	}

	// Allocate the IRP
	PIRP irp = IoAllocateIrp(1, FALSE);

	if (!irp) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	KEVENT eCallback = { 0 };

	// Initialize the event and set the callback for the wait object
	KeInitializeEvent(&eCallback, SynchronizationEvent, FALSE);

	IoSetCompletionRoutine(irp, IrpCallback, &eCallback, TRUE, TRUE, TRUE);

	// Send the data
	status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)wSocket->Dispatch)->WskSend(wSocket, &wBuffer, 0, irp);
	DbgPrint("[Socket] %x", status);

	if (status == STATUS_PENDING) {
		KeWaitForSingleObject(&eCallback, Executive, KernelMode, FALSE, NULL);
	}
	else if (status == STATUS_FILE_FORCED_CLOSED) {
		KeBugCheck(0xDEADBEEF); // This is going to be interesting
	}
	else if (!NT_SUCCESS(status)) {
		MmUnlockPages(wBuffer.Mdl);

		IoFreeMdl(wBuffer.Mdl);
		IoFreeIrp(irp);

		ExFreePoolWithTag(string, 'CROW');

		return status;
	}
	DbgPrint("[IoStatus.Status2] %x", irp->IoStatus.Status);
	if (!NT_SUCCESS(irp->IoStatus.Status)) {

		MmUnlockPages(wBuffer.Mdl);

		IoFreeMdl(wBuffer.Mdl);
		IoFreeIrp(irp);

		ExFreePoolWithTag(string, 'CROW');

		return status;
	}

	MmUnlockPages(wBuffer.Mdl);

	IoFreeMdl(wBuffer.Mdl);

	IoFreeIrp(irp);

	ExFreePoolWithTag(string, 'CROW');

	return STATUS_SUCCESS;
}


// A method to calculate size of char array in a char array pointer
int numberOfCharsInArray(char* array) {
	int numberOfChars = 0;
	while (*array != '\0') {
		numberOfChars++; array++;
	}
	return numberOfChars;
}

// A method to concat all the informations in a char array and send it over to Redis
PCHAR sendLogs(unsigned long long timeStamp, PCHAR operationType, UNICODE_STRING userId, UNICODE_STRING userName, PCHAR processName, HANDLE processId, _In_opt_ PUNICODE_STRING newValue, char hostname[256], char activename[256], UNICODE_STRING registryPath) {
	int convertCheck = 0;
	//id for message (0-9)
	
	if (messageId >= 10) {
		messageId = 0;
	}

	// CHAR array to store the different types of information
	CHAR messageIdChar[100];
	CHAR timeStampChar[100];
	CHAR operationTypeChar[100];
	CHAR userIdChar[100];
	CHAR userNameChar[100];
	CHAR processNameChar[100];
	CHAR processIdChar[100];
	CHAR newValueChar[100];
	CHAR hostnameChar[256];
	CHAR activenameChar[256];
	CHAR registryPathChar[600];

	// Changing the different data types and putting them into a char array
	convertCheck = sprintf(messageIdChar, "%d", messageId);
	if (convertCheck < 0){
		return "FAILED";
	}
	convertCheck = sprintf(timeStampChar, "%llu", timeStamp);
	if (convertCheck < 0) {
		return "FAILED";
	}
	convertCheck = sprintf(operationTypeChar, "%s", operationType);
	if (convertCheck < 0) {
		return "FAILED";
	}
	convertCheck = sprintf(userIdChar, "%wZ", userId);
	if (convertCheck < 0) {
		return "FAILED";
	}
	convertCheck = sprintf(userNameChar, "%wZ", userName);
	if (convertCheck < 0) {
		return "FAILED";
	}
	convertCheck = sprintf(processNameChar, "%s", processName);
	if (convertCheck < 0) {
		return "FAILED";
	}
	convertCheck = sprintf(processIdChar, "%p", processId);
	if (convertCheck < 0) {
		return "FAILED";
	}
	convertCheck = sprintf(newValueChar, "%wZ", newValue);
	if (convertCheck < 0) {
		return "FAILED";
	}
	convertCheck = sprintf(hostnameChar, "%s", hostname);
	if (convertCheck < 0) {
		return "FAILED";
	}
	convertCheck = sprintf(activenameChar, "%s", activename);
	if (convertCheck < 0) {
		return "FAILED";
	}
	convertCheck = sprintf(registryPathChar, "%wZ", registryPath);
	if (convertCheck < 0) {
		return "FAILED";
	}


	strncpy(totalChar, messageIdChar, sizeof(messageIdChar));

	//separator
	strncat(totalChar, ", ", sizeof(","));
	//add timestamp
	strncat(totalChar, timeStampChar, sizeof(timeStampChar));

	//separator
	strncat(totalChar, ", ", sizeof(","));
	//add operation type
	strncat(totalChar, operationTypeChar, sizeof(operationTypeChar));

	//separator
	strncat(totalChar, ", ", sizeof(","));
	//add userId
	strncat(totalChar, userIdChar, sizeof(userIdChar));

	//separator
	strncat(totalChar, ", ", sizeof(","));
	//add userName
	strncat(totalChar, userNameChar, sizeof(userNameChar));

	//separator
	strncat(totalChar, ", ", sizeof(","));
	//add processName
	strncat(totalChar, processNameChar, sizeof(processNameChar));

	//separator
	strncat(totalChar, ", ", sizeof(","));
	//add registry path
	strncat(totalChar, processIdChar,sizeof(processIdChar));

	//separator
	strncat(totalChar, ", ", sizeof(","));
	//add registry path
	strncat(totalChar, newValueChar, sizeof(newValueChar));

	//separator
	strncat(totalChar, ", ", sizeof(","));
	//add registry path
	strncat(totalChar, hostnameChar, sizeof(hostnameChar));

	//separator
	strncat(totalChar, ", ", sizeof(","));
	//add registry path
	strncat(totalChar, activenameChar, sizeof(activenameChar));

	//separator
	strncat(totalChar, ", ", sizeof(","));
	//add registry path
	strncat(totalChar, registryPathChar, sizeof(registryPathChar));


	// Call the method which sends the char array over into Redis
	WriteLog(totalChar, numberOfCharsInArray(totalChar));
	
	messageId++;
	
	return "SUCCESS";
}

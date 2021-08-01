#pragma once
#include <windows.h>
#include "pipe_constants.h"

class PipeClient {
public:
	PipeClient(bool& success);
	~PipeClient();
	bool sendData(char* buf, ULONG len);
	int readData(char* buf);
	bool waitingData();
private:
	HANDLE hPipe = NULL;
	bool initPipe();
};
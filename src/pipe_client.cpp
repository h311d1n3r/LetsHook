#include <pch.h>
#include <pipe_client.h>

#ifdef DBG
#include <iostream>
#endif

PipeClient::PipeClient(bool& success) {
    success = this->initPipe();
}

PipeClient::~PipeClient() {
    if (this->hPipe) CloseHandle(this->hPipe);
}

bool PipeClient::initPipe() {
    while (true) {
        this->hPipe = CreateFile(
            PIPE_NAME,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL);
        if (this->hPipe != INVALID_HANDLE_VALUE) break;
        if (GetLastError() != ERROR_PIPE_BUSY) {
            #ifdef DBG
            HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
            SetConsoleTextAttribute(hConsole, 12);
            std::cout << "An error occured while trying to open the pipe : " << GetLastError() << std::endl;
            SetConsoleTextAttribute(hConsole, 8);
            #endif
            return false;
        }
        if (!WaitNamedPipe(PIPE_NAME, 20000)) {
            #ifdef DBG
            HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
            SetConsoleTextAttribute(hConsole, 12);
            std::cout << "All pipe instances are busy, new attempt in 20 seconds..." << std::endl;
            SetConsoleTextAttribute(hConsole, 8);
            #endif
            return false;
        }
    }
    DWORD dwMode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(this->hPipe, &dwMode, NULL, NULL)) {
        #ifdef DBG
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hConsole, 12);
        std::cout << "SetNamedPipeHandleState failed due to error : " << GetLastError() << std::endl;
        SetConsoleTextAttribute(hConsole, 8);
        #endif
        return false;
    }
    return true;
}

bool PipeClient::sendData(char* buf, ULONG len) {
    ULONG writtenLen;
    if (WriteFile(this->hPipe, buf, len, &writtenLen, NULL)) {
        if(writtenLen == len) return true;
        return false;
    }
    #ifdef DBG
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, 12);
    std::cout << "Couldn't write to pipe due to error : " << GetLastError() << std::endl;
    SetConsoleTextAttribute(hConsole, 8);
    #endif
    return false;
}

int PipeClient::readData(char* buf) {
    ULONG readLen;
    if (ReadFile(this->hPipe, buf, BUFF_LEN, &readLen, NULL)) {
        return readLen;
    }
    #ifdef DBG
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, 12);
    std::cout << "Couldn't read from pipe due to error : " << GetLastError() << std::endl;
    SetConsoleTextAttribute(hConsole, 8);
    #endif
    return -1;
}

bool PipeClient::waitingData() {
    DWORD total_available_bytes;
    if (PeekNamedPipe(hPipe, 0, 0, 0, &total_available_bytes, 0)) {
        if (total_available_bytes > 0) {
            return true;
        }
    }
    return false;
}
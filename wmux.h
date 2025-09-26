#ifndef WMUX_H
#define WMUX_H

#include <ConsoleApi.h>
#include <windows.h>

#define PIPE_BUFFER_SIZE 256

static const char * const SERVER_STDIN_PIPE_NAME = "\\\\.\\pipe\\server_stdin";
static const char * const SERVER_STDOUT_PIPE_NAME = "\\\\.\\pipe\\server_stdout";

bool start_read(char *buffer, size_t buffer_size, HANDLE handle, OVERLAPPED *overlapped, HANDLE out_handle);
int server_main(COORD console_init_size);

#endif // WMUX_H

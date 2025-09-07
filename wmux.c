#define NOB_STRIP_PREFIX
#define NOB_IMPLEMENTATION
#include "nob.h"
#undef INFO
#undef ERROR

#include <stdio.h>
#include <windows.h>
#include <ConsoleApi2.h>
#include <ConsoleApi.h>
#include <fcntl.h>

#define PIPE_BUFFER_SIZE 4096
static const char *POWERSHELL_STDOUT_PIPE_NAME = "\\\\.\\pipe\\powershell_stdout";
static const char *SERVER_STDIN_PIPE_NAME = "\\\\.\\pipe\\server_stdin";
static const char *SERVER_STDOUT_PIPE_NAME = "\\\\.\\pipe\\server_stdout";
static const char *THREAD_OUTPUT_PIPE_NAME = "\\\\.\\pipe\\thread_stdout";

typedef struct {
    HANDLE thread_out;
    HANDLE thread_in;
} ProcessEventHandlerArg;

#define STDOUT_INDEX 0
#define PROCESS_INDEX 1
#define PROCESS_THREAD_INDEX 2

#define SERVER_INPUT_INDEX 0
#define PROCESS_HANDLER_THREAD_INDEX 1
#define THREAD_OUTPUT_INDEX 2
#define SERVER_OUTPUT_INDEX 3

bool start_read(char *buffer, size_t buffer_size, HANDLE handle, OVERLAPPED *overlapped, HANDLE out_handle) {
    DWORD bytes = 0;
    while (true) {
        BOOL finished = ReadFile(handle, buffer, (DWORD)buffer_size, &bytes, overlapped);
        if (finished) {
            if (bytes == 0) {
                return false;
            }
            if (!WriteFile(out_handle, buffer, bytes, NULL, NULL)) {
                nob_log(NOB_ERROR, "Failed to write to console, %s", win32_error_message(GetLastError()));
                return false;
            }
        } else if (GetLastError() != ERROR_IO_PENDING) {
            nob_log(NOB_ERROR, "Failed to start async read, %s", win32_error_message(GetLastError()));
            return false;
        } else {
            break;
        }
    }
    return true;
}

bool create_async_name_pipe(const char *name, HANDLE *out_handle, OVERLAPPED *out_overlapped) {
    HANDLE read_end = INVALID_HANDLE_VALUE;
    read_end = CreateNamedPipeA(
        name,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1,
        PIPE_BUFFER_SIZE,
        PIPE_BUFFER_SIZE,
        0,
        NULL
    );
    if (read_end == INVALID_HANDLE_VALUE) {
        nob_log(NOB_ERROR, "Failed to create named pipe, %s", win32_error_message(GetLastError()));
        return false;
    }

    OVERLAPPED read_end_overlapped = {0};
    read_end_overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (read_end_overlapped.hEvent == INVALID_HANDLE_VALUE) {
        nob_log(NOB_ERROR, "Failed to create async event for pipe, %s", win32_error_message(GetLastError()));
        CloseHandle(read_end);
        return false;
    }
    read_end_overlapped.Offset = 0;
    read_end_overlapped.OffsetHigh = 0;

    *out_overlapped = read_end_overlapped;
    *out_handle = read_end;
    return true;
}

bool create_async_connected_named_pipe(const char *name, HANDLE *out_read_end, OVERLAPPED *out_read_end_overlapped, HANDLE *out_write_end) {
    OVERLAPPED read_end_overlapped = {0};
    read_end_overlapped.hEvent = INVALID_HANDLE_VALUE;
    HANDLE read_end = INVALID_HANDLE_VALUE, write_end = INVALID_HANDLE_VALUE;


    do {
        read_end = CreateNamedPipeA(
            name,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            PIPE_BUFFER_SIZE,
            PIPE_BUFFER_SIZE,
            0,
            NULL
        );
        if (read_end == INVALID_HANDLE_VALUE) {
            nob_log(NOB_ERROR, "Failed to create named pipe, %s", win32_error_message(GetLastError()));
            break;
        }


        read_end_overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (read_end_overlapped.hEvent == INVALID_HANDLE_VALUE) {
            nob_log(NOB_ERROR, "Failed to create async event for pipe, %s", win32_error_message(GetLastError()));
            break;
        }
        read_end_overlapped.Offset = 0;
        read_end_overlapped.OffsetHigh = 0;

        if (ConnectNamedPipe(read_end, &read_end_overlapped)) {
            nob_log(NOB_ERROR, "ConnectNamedPipe failed, %s", win32_error_message(GetLastError()));
            break;
        }
        int code = GetLastError();
        if (code != ERROR_IO_PENDING) {
            nob_log(NOB_ERROR, "Failed to connect named pipe, %s", win32_error_message(GetLastError()));
            break;
        }

        write_end = CreateFileA(
            name,
            GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        if (write_end == INVALID_HANDLE_VALUE) {
            nob_log(NOB_ERROR, "Failed to connect write end to read end, %s", win32_error_message(GetLastError()));
            break;
        }

        DWORD result = WaitForSingleObject(read_end_overlapped.hEvent, INFINITE);
        ResetEvent(read_end_overlapped.hEvent);
        if (result != WAIT_OBJECT_0) {
            nob_log(NOB_ERROR, "Failed to wait for connect event, %s", win32_error_message(GetLastError()));
            break;
        }
        if (!GetOverlappedResult(read_end, &read_end_overlapped, &result, FALSE)) {
            nob_log(NOB_ERROR, "Failed to connect to named pipe, %s", win32_error_message(GetLastError()));
            break;
        }

        *out_read_end = read_end;
        *out_write_end = write_end;
        out_read_end_overlapped->hEvent = read_end_overlapped.hEvent;

        return true;
    } while (false);

    if (read_end_overlapped.hEvent != INVALID_HANDLE_VALUE) CloseHandle(read_end_overlapped.hEvent);
    if (read_end != INVALID_HANDLE_VALUE) CloseHandle(read_end);
    if (write_end != INVALID_HANDLE_VALUE) CloseHandle(write_end);

    return false;
}

bool create_virtual_console(HPCON *virtual_console, LPPROC_THREAD_ATTRIBUTE_LIST *proc_thread_attribute_list, HANDLE output_handle, HANDLE input_handle) {
    CONSOLE_SCREEN_BUFFER_INFO console_screen_info = {0};
    if (!GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &console_screen_info)) {
        nob_log(NOB_ERROR, "Failed to get current console size, %s", win32_error_message(GetLastError()));
        return false;
    }

    HPCON console = {0};
    HRESULT result = S_OK;
    LPPROC_THREAD_ATTRIBUTE_LIST attribute_list = NULL;

    if ((result = CreatePseudoConsole(console_screen_info.dwSize, input_handle, output_handle, 0, &console)) != S_OK) {
        nob_log(NOB_ERROR, "Failed to create virtual console for powershell, (%d)", result);
        return false;
    }

    do {
        size_t bytes_required = 0;
        InitializeProcThreadAttributeList(NULL, 1, 0, &bytes_required);

        attribute_list = malloc(bytes_required);
        if (!attribute_list) {
            nob_log(NOB_ERROR, "Buy more RAM bro");
            break;
        }

        if (!InitializeProcThreadAttributeList(attribute_list, 1, 0, &bytes_required)) {
            nob_log(NOB_ERROR, "Failed to initialize proc thread attribute list, %s", win32_error_message(GetLastError()));
            break;
        }

        if (!UpdateProcThreadAttribute(attribute_list, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, console, sizeof(virtual_console), NULL, NULL)) {
            nob_log(NOB_ERROR, "Failed to update proc thread attribute list, %s", win32_error_message(GetLastError()));
            break;
        }

        *virtual_console = console;
        *proc_thread_attribute_list = attribute_list;

        return true;
    } while (false);

    if (attribute_list) free(attribute_list);
    if (console) ClosePseudoConsole(console);
    return false;
}

static ProcessEventHandlerArg process_event_handler_arg = {0};
DWORD WINAPI process_event_handler(void *_arg) {
    ProcessEventHandlerArg* arg = _arg;

    HANDLE process_out = INVALID_HANDLE_VALUE, process_write_out = INVALID_HANDLE_VALUE;
    OVERLAPPED process_out_overlapped = {0};
    if (!create_async_connected_named_pipe(POWERSHELL_STDOUT_PIPE_NAME, &process_out, &process_out_overlapped, &process_write_out)) {
        return 1;
    }

    HPCON virtual_console = {0};
    LPPROC_THREAD_ATTRIBUTE_LIST virtual_console_proc_thread_attribute_list = NULL;
    if (!create_virtual_console(&virtual_console, &virtual_console_proc_thread_attribute_list, process_write_out, arg->thread_in)) {
        return 1;
    }

    STARTUPINFOEXA startup_info = {
        .StartupInfo.cb = sizeof(STARTUPINFOEXA),
        .lpAttributeList = virtual_console_proc_thread_attribute_list,
    };

    PROCESS_INFORMATION process_info = {0};
    BOOL success = CreateProcessA(
        NULL,
        "powershell -NoLogo -InputFormat Text -OutputFormat Text",
        NULL,
        NULL,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT,
        NULL,
        NULL,
        &startup_info.StartupInfo,
        &process_info
    );
    if (!success) {
        nob_log(NOB_ERROR, "Failed to create shell process, %s", win32_error_message(GetLastError()));
        return 1;
    }

    const HANDLE handles[] = {
        [STDOUT_INDEX] = process_out,
        [PROCESS_INDEX] = process_info.hProcess
        // [PROCESS_THREAD_INDEX] = arg->process.hThread,
    };
    char stdout_buffer[PIPE_BUFFER_SIZE] = {0};

    if (!start_read(stdout_buffer, ARRAY_LEN(stdout_buffer), process_out, &process_out_overlapped, arg->thread_out)) {
        return 1;
    }

    while (true) {
        DWORD result = WaitForMultipleObjects(ARRAY_LEN(handles), handles, FALSE, INFINITE);
        if (result == WAIT_FAILED) {
            nob_log(NOB_ERROR, "Failed to wait for handle state, %s", win32_error_message(GetLastError()));
            break;
        }
        if (result >= WAIT_ABANDONED_0) {
            TODO("Handle abandoned");
            break;
        }

        int index = result - WAIT_OBJECT_0;
        if (index < 0 || index >= (int)ARRAY_LEN(handles)) {
            nob_log(NOB_ERROR, "Index out of range");
            break;
        }

        ResetEvent(handles[index]);

        DWORD bytes = 0;
        if (index == STDOUT_INDEX) {
            if (!GetOverlappedResult(process_out, &process_out_overlapped, &bytes, FALSE)) {
                nob_log(NOB_ERROR, "Failed to get result from stdout, %s", win32_error_message(GetLastError()));
                break;
            }
            if (bytes == 0) {
                break;
            }
            if (!WriteConsoleA(arg->thread_out, stdout_buffer, bytes, NULL, NULL)) {
                nob_log(NOB_ERROR, "Failed to write to stdout, %s", win32_error_message(GetLastError()));
                return false;
            }
            if (!start_read(stdout_buffer, ARRAY_LEN(stdout_buffer), process_out, &process_out_overlapped, arg->thread_out)) {
                break;
            }
            continue;
        }

        if (index == PROCESS_INDEX) {
            DWORD exit_code = (DWORD)-1;
            GetExitCodeProcess(process_info.hProcess, &exit_code);
            nob_log(NOB_INFO, "Powershell process exited, code: (%d)", exit_code);
            break;
        }

        UNREACHABLE("Unknown index");
    }

    CloseHandle(arg->thread_in);
    CloseHandle(arg->thread_out);
    CloseHandle(process_out_overlapped.hEvent);
    CloseHandle(process_out);
    CloseHandle(process_info.hProcess);
    CloseHandle(process_info.hThread);
    free(virtual_console_proc_thread_attribute_list);
    ClosePseudoConsole(virtual_console);
    nob_log(NOB_INFO, "Process event handler thread exited");

    // NOTE: do this to exit on `exit` command ^^, a little hacky but fine for now
    FreeConsole();

    return 0;
}

typedef enum {
    CONNECTED,
    CONNECTING,
    UNCONNECTED
} PipeState;

int server_main(void) {
    PipeState input_state = UNCONNECTED;
    OVERLAPPED input_read_end_overlapped = {0};
    HANDLE input_read_end = INVALID_HANDLE_VALUE;
    if (!create_async_name_pipe(SERVER_STDIN_PIPE_NAME, &input_read_end, &input_read_end_overlapped)) {
        return 1;
    }

    PipeState output_state = UNCONNECTED;
    OVERLAPPED output_write_end_overlapped = {0};
    HANDLE output_write_end = INVALID_HANDLE_VALUE;
    if (!create_async_name_pipe(SERVER_STDOUT_PIPE_NAME, &output_write_end, &output_write_end_overlapped)) {
        return 1;
    }

    HANDLE thread_input_read_end, thread_input_write_end;
    if (!CreatePipe(&thread_input_read_end, &thread_input_write_end, NULL, 0)) {
        nob_log(NOB_ERROR, "Failed to create stderr pipe %s", win32_error_message(GetLastError()));
        return 1;
    }

    HANDLE thread_output_read_end = INVALID_HANDLE_VALUE, thread_output_write_end = INVALID_HANDLE_VALUE;
    OVERLAPPED thread_output_overlapped = {0};
    if (!create_async_connected_named_pipe(THREAD_OUTPUT_PIPE_NAME, &thread_output_read_end, &thread_output_overlapped, &thread_output_write_end)) {
        return 1;
    }

    process_event_handler_arg.thread_in = thread_input_read_end;
    process_event_handler_arg.thread_out = thread_output_write_end;

    DWORD reader_thread_id = 0;
    HANDLE thread_handle = CreateThread(
            NULL,                       // default security attributes
            0,                          // use default stack size  
            process_event_handler,      // thread function name
            &process_event_handler_arg, // argument to thread function 
            0,                          // use default creation flags 
            &reader_thread_id);
    if (thread_handle == INVALID_HANDLE_VALUE) {
        nob_log(NOB_ERROR, "Failed to create powershell handler thread, %s", win32_error_message(GetLastError()));
        return 1;
    }

    nob_log(NOB_INFO, "Powershell handler thread created");

    HANDLE handles[] = {
        [SERVER_INPUT_INDEX] = input_read_end_overlapped.hEvent,
        [SERVER_OUTPUT_INDEX] = output_write_end_overlapped.hEvent,
        [PROCESS_HANDLER_THREAD_INDEX] = thread_handle,
        [THREAD_OUTPUT_INDEX] = thread_output_overlapped.hEvent,
    };
    char input_buffer[PIPE_BUFFER_SIZE] = {0};
    char output_buffer[PIPE_BUFFER_SIZE] = {0};

    bool running = true;
    while (running) {
        while (output_state == UNCONNECTED && WaitForSingleObject(thread_handle, 10) == WAIT_TIMEOUT) {
            ConnectNamedPipe(output_write_end, &output_write_end_overlapped);
            DWORD connect_error_code = GetLastError();
            if (connect_error_code == ERROR_PIPE_CONNECTED) {
                output_state = CONNECTED;
                nob_log(NOB_INFO, "Output pipe connected synchonously");
                break;
            }

            if (connect_error_code != ERROR_IO_PENDING) {
                nob_log(NOB_WARNING, 0, "Failed to connect server input named pipe, %s", win32_error_message(connect_error_code));
                Sleep(1000);
                continue;
            }

            output_state = CONNECTING;
        }

        while (input_state == UNCONNECTED && WaitForSingleObject(thread_handle, 10) == WAIT_TIMEOUT) {
            ConnectNamedPipe(input_read_end, &input_read_end_overlapped);
            DWORD connect_error_code = GetLastError();
            if (connect_error_code == ERROR_PIPE_CONNECTED) {
                input_state = CONNECTED;
                nob_log(NOB_INFO, "Input pipe connected synchonously");
                break;
            }

            if (connect_error_code != ERROR_IO_PENDING) {
                nob_log(NOB_WARNING, 0, "Failed to connect server input named pipe, %s", win32_error_message(connect_error_code));
                Sleep(1000);
                continue;
            }

            input_state = CONNECTING;
        }

        nob_log(NOB_INFO, "Server waiting");
        DWORD result = WaitForMultipleObjects(ARRAY_LEN(handles), handles, FALSE, INFINITE);
        if (result == WAIT_FAILED) {
            nob_log(NOB_ERROR, "Failed to wait for handle state, %s", win32_error_message(GetLastError()));
            break;
        }
        if (result >= WAIT_ABANDONED_0) {
            TODO("Handle abandoned");
            break;
        }

        int index = result - WAIT_OBJECT_0;
        if (index < 0 || index >= (int)ARRAY_LEN(handles)) {
            nob_log(NOB_ERROR, "Index out of range");
            break;
        }

        ResetEvent(handles[index]);
        DWORD bytes = 0;

        static_assert(ARRAY_LEN(handles) == 4);
        switch (index) {
            case SERVER_INPUT_INDEX: {
                nob_log(NOB_INFO, "Server input event signaled");
                if (!GetOverlappedResult(input_read_end, &input_read_end_overlapped, &bytes, FALSE)) {
                    TODO("Handle input async result failed");
                }
                if (input_state == CONNECTING) {
                    input_state = CONNECTED;
                    nob_log(NOB_INFO, "Input pipe connected");
                } else if (bytes == 0) {
                    TODO("Handle read 0 bytes");
                } else if (!WriteFile(thread_input_write_end, input_buffer, bytes*sizeof(*input_buffer), NULL, NULL)) {
                    nob_log(NOB_ERROR, "Failed to write input to process handler, %s", win32_error_message(GetLastError()));
                    break;
                }

                if (!start_read(input_buffer, ARRAY_LEN(input_buffer), input_read_end, &input_read_end_overlapped, thread_input_write_end)) {
                    TODO("Handle start read failed");
                }
            } break;

            case SERVER_OUTPUT_INDEX: {
                nob_log(NOB_INFO, "Server output event signaled");
                if (!GetOverlappedResult(output_write_end, &output_write_end_overlapped, &bytes, FALSE)) {
                    TODO("Handle input async result failed");
                }
                if (input_state == CONNECTING) {
                    input_state = CONNECTED;
                    nob_log(NOB_INFO, "Output pipe connected");
                }
            } break;

            case THREAD_OUTPUT_INDEX: {
                nob_log(NOB_INFO, "Thread output event signaled");
                if (!GetOverlappedResult(thread_output_read_end, &thread_output_overlapped, &bytes, FALSE)) {
                    TODO("Handle input async result failed");
                }
                if (output_state == CONNECTED) {
                    if (!WriteFile(output_write_end, output_buffer, bytes, NULL, NULL)) {
                        TODO("Handle write output failed");
                    }
                } else {
                    nob_log(NOB_WARNING, "Output not connected");
                }

                if (!start_read(output_buffer, ARRAY_LEN(output_buffer), thread_output_read_end, &thread_output_overlapped, output_write_end)) {
                    break;
                }
            } break;

            case PROCESS_HANDLER_THREAD_INDEX: {
                nob_log(NOB_INFO, "Process thread handler exited");
                running = false;
            } break;
        }
    }

    CloseHandle(thread_output_overlapped.hEvent);
    CloseHandle(thread_output_read_end);
    CloseHandle(thread_input_write_end);
    CloseHandle(thread_handle);
    CloseHandle(input_read_end_overlapped.hEvent);
    CloseHandle(input_read_end);
    CloseHandle(output_write_end_overlapped.hEvent);
    CloseHandle(output_write_end);
    nob_log(NOB_INFO, "Server exited");

    return 0;
}

DWORD WINAPI client_output_reader(void *arg) {
    UNUSED(arg);

    HANDLE server_output = CreateFileA(
        SERVER_STDOUT_PIPE_NAME,
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    do {
        if (server_output == INVALID_HANDLE_VALUE) {
            nob_log(NOB_ERROR, "Failed to connect write end to read end, %s", win32_error_message(GetLastError()));
            break;
        }

        nob_log(NOB_INFO, "Server output connected");

        char buffer[PIPE_BUFFER_SIZE] = {0};
        DWORD bytes_read = 0;
        while (true) {
            if (!ReadFile(server_output, buffer, ARRAY_LEN(buffer), &bytes_read, NULL)) {
                nob_log(NOB_ERROR, "Failed to read output from server, %s", win32_error_message(GetLastError()));
                break;
            }
            if (bytes_read == 0) {
                break;
            }
            nob_log(NOB_INFO, "Read %d", bytes_read);
            if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), buffer, bytes_read, NULL, NULL)) {
                break;
            }
        }
    } while (false);

    CloseHandle(server_output);

    FreeConsole();
    nob_log(NOB_INFO, "Client reader exited");
    return 0;
}

int client_main(void) {
    DWORD console_mode = 0;
    HANDLE console_input = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE console_output = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!GetConsoleMode(console_input, &console_mode) ||
        !SetConsoleMode(console_input, (console_mode & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT)) | ENABLE_VIRTUAL_TERMINAL_INPUT)) {
        nob_log(NOB_ERROR, "Failed to set input console mode, %s", win32_error_message(GetLastError()));
        return 1;
    }
    if (!GetConsoleMode(console_output, &console_mode) ||
        !SetConsoleMode(console_output, console_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING | ENABLE_PROCESSED_OUTPUT)) {
        nob_log(NOB_ERROR, "Failed to set output console mode, %s", win32_error_message(GetLastError()));
        return 1;
    }

    DWORD reader_thread_id = 0;
    HANDLE thread_handle = CreateThread(
            NULL,                       // default security attributes
            0,                          // use default stack size  
            client_output_reader,       // thread function name
            NULL,                       // argument to thread function 
            0,                          // use default creation flags 
            &reader_thread_id);
    if (thread_handle == INVALID_HANDLE_VALUE) {
        nob_log(NOB_ERROR, "Failed to create client reader thread, %s", win32_error_message(GetLastError()));
        return 1;
    }
    nob_log(NOB_INFO, "Client reader thread created");

    HANDLE server_input = CreateFileA(
        SERVER_STDIN_PIPE_NAME,
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (server_input == INVALID_HANDLE_VALUE) {
        nob_log(NOB_ERROR, "Failed to connect write end to read end, %s", win32_error_message(GetLastError()));
        return 1;
    }
    nob_log(NOB_INFO, "Server input connected");

    char buffer[PIPE_BUFFER_SIZE] = {0};
    DWORD bytes_read = 0;
    while (true) {
        if (!ReadFile(console_input, buffer, ARRAY_LEN(buffer), &bytes_read, NULL)) {
            nob_log(NOB_ERROR, "Failed to read input from console, %s", win32_error_message(GetLastError()));
            break;
        }
        if (bytes_read == 0) {
            break;
        }
        nob_log(NOB_INFO, "Read %d", bytes_read);
        if (!WriteFile(server_input, buffer, bytes_read, NULL, NULL)) {
            break;
        }
    }

    WaitForSingleObject(thread_handle, INFINITE);
    CloseHandle(thread_handle);
    CloseHandle(server_input);
    nob_log(NOB_INFO, "Client exited");
    return 0;
}

int main(int argc, char **argv) {
    nob_log(NOB_INFO, "%s started with pid: %d", GetCommandLineA(), GetCurrentProcessId());
    char *program_name = shift(argv, argc);
    UNUSED(program_name);
    if (argc == 0) {
        TODO("Usage instruction");
    }

    char *mode = shift(argv, argc);
    if (strcmp(mode, "server") == 0) {
        return server_main();
    }

    if (strcmp(mode, "client") == 0) {
        return client_main();
    }

    TODO("Usage instruction");
}

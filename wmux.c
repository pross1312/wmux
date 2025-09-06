#define NOB_STRIP_PREFIX
#define NOB_IMPLEMENTATION
#include "nob.h"
#undef INFO
#undef ERROR

#include <stdio.h>
#include <windows.h>
#include <fcntl.h>

#define PIPE_BUFFER_SIZE 4096
static LPCTSTR POWERSHELL_STDOUT_PIPE_NAME = TEXT("\\\\.\\pipe\\powershell_stdout");
static LPCTSTR POWERSHELL_STDERR_PIPE_NAME = TEXT("\\\\.\\pipe\\powershell_stderr");

typedef struct {
    HANDLE out;
    HANDLE err;
    OVERLAPPED out_overlapped;
    OVERLAPPED err_overlapped;
} ReaderArgs;

#define STDOUT_INDEX 0
#define STDERR_INDEX 1

bool start_read(char *buffer, size_t buffer_size, HANDLE handle, OVERLAPPED *overlapped, FILE *out_file) {
    DWORD bytes = 0;
    while (true) {
        BOOL finished = ReadFile(handle, buffer, (DWORD)buffer_size, &bytes, overlapped);
        if (finished) {
            if (bytes == 0) {
                return false;
            }
            fprintf(out_file, "%.*s", (int)bytes, buffer);
        } else if (GetLastError() != ERROR_IO_PENDING) {
            nob_log(NOB_ERROR, "Failed to start async read, %s", win32_error_message(GetLastError()));
            return false;
        } else {
            break;
        }
    }
    return true;
}

static ReaderArgs reader_args = {0};
DWORD WINAPI reader_thread(void *_arg) {
    ReaderArgs* arg = _arg;
    const HANDLE handles[] = {
        [STDOUT_INDEX] = arg->out_overlapped.hEvent,
        [STDERR_INDEX] = arg->err_overlapped.hEvent,
    };
    char stdout_buffer[PIPE_BUFFER_SIZE] = {0};
    char stderr_buffer[PIPE_BUFFER_SIZE] = {0};

    if (!start_read(stdout_buffer, ARRAY_LEN(stdout_buffer), arg->out, &arg->out_overlapped, stdout)) {
        return 1;
    }
    if (!start_read(stderr_buffer, ARRAY_LEN(stderr_buffer), arg->err, &arg->err_overlapped, stderr)) {
        return 1;
    }

    while (true) {
        DWORD result = WaitForMultipleObjects(ARRAY_LEN(handles), handles, FALSE, INFINITE);
        if (result == WAIT_FAILED) {
            nob_log(NOB_ERROR, "Failed to wait for output from named pipes, %s", win32_error_message(GetLastError()));
            break;
        }
        if (result >= WAIT_ABANDONED_0) {
            nob_log(NOB_ERROR, "WHAT TO DO!!");
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
            if (!GetOverlappedResult(arg->out, &arg->out_overlapped, &bytes, FALSE)) {
                nob_log(NOB_ERROR, "Failed to get result from stdout, %s", win32_error_message(GetLastError()));
                break;
            }
            if (bytes == 0) {
                break;
            }
            fprintf(stdout, "%.*s", (int)bytes, stdout_buffer);
            if (!start_read(stdout_buffer, ARRAY_LEN(stdout_buffer), arg->out, &arg->out_overlapped, stdout)) {
                break;
            }
            continue;
        }

        if (index == STDERR_INDEX) {
            if (!GetOverlappedResult(arg->err, &arg->err_overlapped, &bytes, FALSE)) {
                nob_log(NOB_ERROR, "Failed to get result from stderr, %s", win32_error_message(GetLastError()));
                break;
            }
            if (bytes == 0) {
                break;
            }
            fprintf(stderr, "%.*s", (int)bytes, stderr_buffer);
            if (!start_read(stderr_buffer, ARRAY_LEN(stderr_buffer), arg->err, &arg->err_overlapped, stderr)) {
                break;
            }
            continue;
        }

        UNREACHABLE("Unknown index");
    }

    CloseHandle(arg->out_overlapped.hEvent);
    CloseHandle(arg->err_overlapped.hEvent);
    CloseHandle(arg->out);
    CloseHandle(arg->err);
    return 0;
}

bool create_named_pipe(LPCTSTR name, HANDLE *out_read_end, OVERLAPPED *out_read_end_overlapped, HANDLE *out_write_end) {
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

        read_end_overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
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

        SECURITY_ATTRIBUTES attr = {0};
        attr.bInheritHandle = TRUE;
        write_end = CreateFileA(
            name,
            GENERIC_WRITE,
            0,
            &attr,
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

int main(int argc, char **argv) {
    UNUSED(argc);
    UNUSED(argv);
    HANDLE read_stdout = INVALID_HANDLE_VALUE, write_stdout = INVALID_HANDLE_VALUE;
    OVERLAPPED stdout_overlapped = {0};
    if (!create_named_pipe(POWERSHELL_STDOUT_PIPE_NAME, &read_stdout, &stdout_overlapped, &write_stdout)) {
        return 1;
    }

    HANDLE read_stderr = INVALID_HANDLE_VALUE, write_stderr = INVALID_HANDLE_VALUE;
    OVERLAPPED stderr_overlapped = {0};
    if (!create_named_pipe(POWERSHELL_STDERR_PIPE_NAME, &read_stderr, &stderr_overlapped, &write_stderr)) {
        return 1;
    }

    HANDLE read_stdin, write_stdin;
    SECURITY_ATTRIBUTES security_attributes = {
        .nLength = sizeof(security_attributes),
        .bInheritHandle = TRUE,
    };
    if (!CreatePipe(&read_stdin, &write_stdin, &security_attributes, 0)) {
        nob_log(NOB_ERROR, "Failed to create stderr pipe %s", win32_error_message(GetLastError()));
        return 1;
    }

    SetHandleInformation(write_stdin, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(read_stdout, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(read_stderr, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFO startup_info = {
        .cb = sizeof(STARTUPINFO),
        .dwFlags = STARTF_USESTDHANDLES,
        .hStdOutput = write_stdout,
        .hStdError = write_stderr,
        .hStdInput = read_stdin,
    };
    PROCESS_INFORMATION process_info = {0};
    BOOL success = CreateProcessA(
        NULL,
        "powershell",
        NULL,
        NULL,
        TRUE,
        CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &startup_info,
        &process_info
    );
    if (!success) {
        nob_log(NOB_ERROR, "Failed to create shell process, %s", win32_error_message(GetLastError()));
        return 1;
    }
    CloseHandle(write_stdout);
    CloseHandle(write_stderr);
    CloseHandle(read_stdin);

    reader_args.out = read_stdout;
    reader_args.out_overlapped = stdout_overlapped;
    reader_args.err = read_stderr;
    reader_args.err_overlapped = stderr_overlapped;

    DWORD reader_thread_id = 0;
    HANDLE thread_handle = CreateThread( 
            NULL,                // default security attributes
            0,                   // use default stack size  
            reader_thread,       // thread function name
            &reader_args,        // argument to thread function 
            0,                   // use default creation flags 
            &reader_thread_id);

    char buffer[PIPE_BUFFER_SIZE] = {0};
    DWORD bytes = 0;
    while (ReadFile(GetStdHandle(STD_INPUT_HANDLE), buffer, ARRAY_LEN(buffer), &bytes, NULL) && bytes != 0) {
        if (!WriteFile(write_stdin, buffer, bytes, &bytes, NULL) || bytes == 0) {
            break;
        }
    }

    WaitForSingleObject(process_info.hProcess, INFINITE);
    WaitForSingleObject(thread_handle, INFINITE);

    CloseHandle(thread_handle);
    CloseHandle(process_info.hProcess);
    CloseHandle(process_info.hThread);

    return 0;
}

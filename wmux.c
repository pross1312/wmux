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
static const char *POWERSHELL_STDERR_PIPE_NAME = "\\\\.\\pipe\\powershell_stderr";

typedef struct {
    HANDLE out;
    HANDLE in;
    PROCESS_INFORMATION process;
    OVERLAPPED out_overlapped;
} ProcessEventHandlerArg;

#define STDOUT_INDEX 0
#define PROCESS_INDEX 1
#define PROCESS_THREAD_INDEX 2

bool start_read(char *buffer, size_t buffer_size, HANDLE handle, OVERLAPPED *overlapped, HANDLE out_handle) {
    DWORD bytes = 0;
    while (true) {
        BOOL finished = ReadFile(handle, buffer, (DWORD)buffer_size, &bytes, overlapped);
        if (finished) {
            if (bytes == 0) {
                return false;
            }
            if (!WriteConsoleA(out_handle, buffer, bytes, NULL, NULL)) {
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

static ProcessEventHandlerArg process_event_handler_arg = {0};
DWORD WINAPI process_event_handler(void *_arg) {
    ProcessEventHandlerArg* arg = _arg;
    const HANDLE handles[] = {
        [STDOUT_INDEX] = arg->out_overlapped.hEvent,
        [PROCESS_INDEX] = arg->process.hProcess
        // [PROCESS_THREAD_INDEX] = arg->process.hThread,
    };
    char stdout_buffer[PIPE_BUFFER_SIZE] = {0};

    HANDLE console_output = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!start_read(stdout_buffer, ARRAY_LEN(stdout_buffer), arg->out, &arg->out_overlapped, console_output)) {
        return 1;
    }

    while (true) {
        DWORD result = WaitForMultipleObjects(ARRAY_LEN(handles), handles, FALSE, INFINITE);
        if (result == WAIT_FAILED) {
            nob_log(NOB_ERROR, "Failed to wait for handle state, %s", win32_error_message(GetLastError()));
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
            if (!WriteConsoleA(console_output, stdout_buffer, bytes, NULL, NULL)) {
                nob_log(NOB_ERROR, "Failed to write to stdout, %s", win32_error_message(GetLastError()));
                return false;
            }
            if (!start_read(stdout_buffer, ARRAY_LEN(stdout_buffer), arg->out, &arg->out_overlapped, console_output)) {
                break;
            }
            continue;
        }

        if (index == PROCESS_INDEX) {
            DWORD exit_code = (DWORD)-1;
            GetExitCodeProcess(arg->process.hProcess, &exit_code);
            nob_log(NOB_INFO, "Powershell process exited, code: (%d)", exit_code);
            break;
        }

        UNREACHABLE("Unknown index");
    }

    CloseHandle(arg->in);
    CloseHandle(arg->out_overlapped.hEvent);
    CloseHandle(arg->out);
    CloseHandle(arg->process.hThread);
    CloseHandle(arg->process.hProcess);
    nob_log(NOB_INFO, "Process event handler thread exited");

    // NOTE: do this to exit on `exit` command ^^, a little hacky but fine for now
    FreeConsole();
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

int main(int argc, char **argv) {
    UNUSED(argc), UNUSED(argv);
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

    HANDLE read_stdout = INVALID_HANDLE_VALUE, write_stdout = INVALID_HANDLE_VALUE;
    OVERLAPPED stdout_overlapped = {0};
    if (!create_named_pipe(POWERSHELL_STDOUT_PIPE_NAME, &read_stdout, &stdout_overlapped, &write_stdout)) {
        return 1;
    }

    HANDLE read_stdin, write_stdin;
    SECURITY_ATTRIBUTES security_attributes = {
        .nLength = sizeof(security_attributes)
    };
    if (!CreatePipe(&read_stdin, &write_stdin, &security_attributes, 0)) {
        nob_log(NOB_ERROR, "Failed to create stderr pipe %s", win32_error_message(GetLastError()));
        return 1;
    }

    SetHandleInformation(write_stdin, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(read_stdout, HANDLE_FLAG_INHERIT, 0);

    HPCON virtual_console = {0};
    LPPROC_THREAD_ATTRIBUTE_LIST virtual_console_proc_thread_attribute_list = NULL;
    if (!create_virtual_console(&virtual_console, &virtual_console_proc_thread_attribute_list, write_stdout, read_stdin)) {
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
    // CloseHandle(write_stdout);
    // CloseHandle(write_stderr);
    // CloseHandle(read_stdin);

    process_event_handler_arg.in = write_stdin;
    process_event_handler_arg.out = read_stdout;
    process_event_handler_arg.process = process_info;
    process_event_handler_arg.out_overlapped = stdout_overlapped;

    DWORD reader_thread_id = 0;
    HANDLE thread_handle = CreateThread(
            NULL,                       // default security attributes
            0,                          // use default stack size  
            process_event_handler,      // thread function name
            &process_event_handler_arg, // argument to thread function 
            0,                          // use default creation flags 
            &reader_thread_id);

    char buffer[PIPE_BUFFER_SIZE] = {0};
    DWORD read_count = 0;
    while (true) {
        if (!ReadConsoleA(console_input, buffer, ARRAY_LEN(buffer), &read_count, NULL)) {
            nob_log(NOB_ERROR, "Failed to read from console, %s", win32_error_message(GetLastError()));
            break;
        }
        if (read_count == 0) {
            break;
        }
        // nob_log(NOB_INFO, "Read %d input", read_count);
        if (!WriteFile(write_stdin, buffer, read_count*sizeof(*buffer), NULL, NULL)) {
            // nob_log(NOB_ERROR, "Failed to write to powershell, (%d) %s", GetLastError(), win32_error_message(GetLastError()));
            break;
        }
    }

    WaitForSingleObject(thread_handle, INFINITE);
    CloseHandle(thread_handle);

    free(virtual_console_proc_thread_attribute_list);
    ClosePseudoConsole(virtual_console);

    return 0;
}

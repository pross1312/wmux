#define NOB_STRIP_PREFIX
#include "nob.h"
#undef INFO
#undef ERROR

#include "wmux.h"

static const char * const POWERSHELL_STDOUT_PIPE_NAME = "\\\\.\\pipe\\powershell_stdout";

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

bool create_virtual_console(HPCON *virtual_console, LPPROC_THREAD_ATTRIBUTE_LIST *proc_thread_attribute_list, HANDLE output_handle, HANDLE input_handle, COORD console_size) {
    HPCON console = {0};
    HRESULT result = S_OK;
    LPPROC_THREAD_ATTRIBUTE_LIST attribute_list = NULL;

    if ((result = CreatePseudoConsole(console_size, input_handle, output_handle, 0, &console)) != S_OK) {
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

typedef enum {
    CONNECTED,
    CONNECTING,
    UNCONNECTED
} PipeState;

int server_main(COORD console_init_size) {
    HANDLE console_input_read_end = INVALID_HANDLE_VALUE, console_input_write_end = INVALID_HANDLE_VALUE;
    if (!CreatePipe(&console_input_read_end, &console_input_write_end, NULL, 0)) {
        nob_log(NOB_ERROR, "Failed to setup console input pipe, %s", win32_error_message(GetLastError()));
        return 1;
    }

    HANDLE console_output_read_end = INVALID_HANDLE_VALUE, console_output_write_end = INVALID_HANDLE_VALUE;
    OVERLAPPED console_output_read_end_overlapped = {0};
    if (!create_async_connected_named_pipe(POWERSHELL_STDOUT_PIPE_NAME, &console_output_read_end, &console_output_read_end_overlapped, &console_output_write_end)) {
        return 1;
    }

    HPCON virtual_console = {0};
    LPPROC_THREAD_ATTRIBUTE_LIST virtual_console_proc_thread_attribute_list = NULL;
    if (!create_virtual_console(&virtual_console, &virtual_console_proc_thread_attribute_list, console_output_write_end, console_input_read_end, console_init_size)) {
        return 1;
    }

    STARTUPINFOEXA startup_info = {
        .StartupInfo.cb = sizeof(STARTUPINFOEXA),
        .lpAttributeList = virtual_console_proc_thread_attribute_list,
    };

    PROCESS_INFORMATION process_info = {0};
    BOOL success = CreateProcessA(
        NULL,
        "powershell -NoLogo",
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

    nob_log(NOB_INFO, "Powershell process created");

    PipeState output_state = UNCONNECTED;
    OVERLAPPED output_write_end_overlapped = {0};
    HANDLE output_write_end = INVALID_HANDLE_VALUE;
    if (!create_async_name_pipe(SERVER_STDOUT_PIPE_NAME, &output_write_end, &output_write_end_overlapped)) {
        return 1;
    }

    PipeState input_state = UNCONNECTED;
    OVERLAPPED input_read_end_overlapped = {0};
    HANDLE input_read_end = INVALID_HANDLE_VALUE;
    if (!create_async_name_pipe(SERVER_STDIN_PIPE_NAME, &input_read_end, &input_read_end_overlapped)) {
        return 1;
    }

    #define SERVER_INPUT_INDEX 0
    #define SERVER_OUTPUT_INDEX 1
    #define PROCESS_HANDLE_INDEX 2
    #define CONSOLE_OUTPUT_INDEX 3
    HANDLE handles[] = {
        [SERVER_INPUT_INDEX] = input_read_end_overlapped.hEvent,
        [SERVER_OUTPUT_INDEX] = output_write_end_overlapped.hEvent,
        [PROCESS_HANDLE_INDEX] = process_info.hProcess,
        [CONSOLE_OUTPUT_INDEX] = console_output_read_end_overlapped.hEvent,
    };


    char preserve_buffer[PIPE_BUFFER_SIZE * 32] = {0};
    size_t preserve_buffer_count = 0;

    char input_buffer[PIPE_BUFFER_SIZE] = {0};
    char output_buffer[PIPE_BUFFER_SIZE] = {0};
    bool no_client_before = true;

    bool running = true;
    bool reset_connection = false;

    while (running) {
        while (output_state == UNCONNECTED && WaitForSingleObject(process_info.hProcess, 10) == WAIT_TIMEOUT) {
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

        while (input_state == UNCONNECTED && WaitForSingleObject(process_info.hProcess, 10) == WAIT_TIMEOUT) {
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

        static_assert(ARRAY_LEN(handles) == 4, "Change here too!!!");
        switch (index) {
            case SERVER_INPUT_INDEX: {
                if (!GetOverlappedResult(input_read_end, &input_read_end_overlapped, &bytes, FALSE)) {
                    nob_log(NOB_WARNING, "Failed to get server input overlapped result, %s (%d)", win32_error_message(GetLastError()), GetLastError());
                    reset_connection = true;
                    break;
                }
                if (input_state == CONNECTING) {
                    input_state = CONNECTED;
                    nob_log(NOB_INFO, "Input pipe connected");
                } else if (bytes == 0) {
                    reset_connection = true;
                    break;
                } else if (bytes == sizeof(COORD) + 2 && input_buffer[0] == 0 && input_buffer[sizeof(COORD)+1] == 0) {
                    COORD new_size = *(COORD*)&input_buffer[1];
                    HRESULT resize_result = ResizePseudoConsole(virtual_console, new_size);
                    if (resize_result != S_OK) {
                        nob_log(NOB_WARNING, "Failed to resize virtual console (%d)", resize_result);
                    } else {
                        nob_log(NOB_INFO, "Resize virtual console -> %dx%d", new_size.X, new_size.Y);
                    }
                } else if (!WriteFile(console_input_write_end, input_buffer, bytes*sizeof(*input_buffer), NULL, NULL)) {
                    nob_log(NOB_ERROR, "Failed to write input to process, %s", win32_error_message(GetLastError()));
                    break;
                }

                if (!start_read(input_buffer, ARRAY_LEN(input_buffer), input_read_end, &input_read_end_overlapped, console_input_write_end)) {
                    reset_connection = true;
                    break;
                }
            } break;

            case SERVER_OUTPUT_INDEX: {
                if (!GetOverlappedResult(output_write_end, &output_write_end_overlapped, &bytes, FALSE)) {
                    nob_log(NOB_WARNING, "Failed to connect to client output, %s (%d)", win32_error_message(GetLastError()), GetLastError());
                    reset_connection = true;
                    break;
                }
                if (output_state == CONNECTING) {
                    output_state = CONNECTED;
                    nob_log(NOB_INFO, "Output pipe connected");

                    if (preserve_buffer_count > 0 && !WriteFile(output_write_end, preserve_buffer, (DWORD)preserve_buffer_count, NULL, NULL)) {
                        nob_log(NOB_WARNING, "Failed to write to client, %s (%d)", win32_error_message(GetLastError()), GetLastError());
                        reset_connection = true;
                    }

                    if (no_client_before && !start_read(output_buffer, ARRAY_LEN(output_buffer), console_output_read_end, &console_output_read_end_overlapped, output_write_end)) {
                        break;
                    }

                    no_client_before = false;
                }
            } break;

            case CONSOLE_OUTPUT_INDEX: {
                if (!GetOverlappedResult(console_output_read_end, &console_output_read_end_overlapped, &bytes, FALSE)) {
                    nob_log(NOB_WARNING, "Failed to get console output overlapped result, %s", win32_error_message(GetLastError()));
                    break;
                }

                if (output_state == CONNECTED && !WriteFile(output_write_end, output_buffer, bytes, NULL, NULL)) {
                    nob_log(NOB_WARNING, "Failed to write to client, %s (%d)", win32_error_message(GetLastError()), GetLastError());
                    reset_connection = true;
                }

                if (preserve_buffer_count + bytes > ARRAY_LEN(preserve_buffer)) {
                    size_t move_count = preserve_buffer_count + bytes - ARRAY_LEN(preserve_buffer);
                    if (move_count > preserve_buffer_count) {
                        move_count = preserve_buffer_count;
                    }
                    memmove(preserve_buffer, preserve_buffer + move_count, ARRAY_LEN(preserve_buffer) - move_count);
                    preserve_buffer_count -= move_count;
                }

                memcpy(preserve_buffer + preserve_buffer_count, output_buffer, bytes);
                preserve_buffer_count += bytes;

                if (!start_read(output_buffer,
                                ARRAY_LEN(output_buffer),
                                console_output_read_end,
                                &console_output_read_end_overlapped,
                                output_write_end)) {
                    break;
                }
            } break;

            case PROCESS_HANDLE_INDEX: {
                nob_log(NOB_INFO, "Process exited");
                running = false;
            } break;
        }

        if (reset_connection) {
            reset_connection = false;
            DisconnectNamedPipe(input_read_end);
            DisconnectNamedPipe(output_write_end);
            input_state = UNCONNECTED;
            output_state = UNCONNECTED;
            nob_log(NOB_INFO, "Client connection reset");
        }
    }

    CloseHandle(output_write_end_overlapped.hEvent);
    CloseHandle(output_write_end);

    CloseHandle(input_read_end_overlapped.hEvent);
    CloseHandle(input_read_end);

    CloseHandle(process_info.hThread);
    CloseHandle(process_info.hProcess);

    CloseHandle(console_input_write_end);
    CloseHandle(console_input_read_end);
    CloseHandle(console_output_write_end);
    CloseHandle(console_output_read_end_overlapped.hEvent);
    CloseHandle(console_output_read_end);
    free(virtual_console_proc_thread_attribute_list);
    ClosePseudoConsole(virtual_console);

    nob_log(NOB_INFO, "Server exited");

    return 0;
}



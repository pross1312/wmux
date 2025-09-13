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

#define PIPE_BUFFER_SIZE 256
static const char *POWERSHELL_STDOUT_PIPE_NAME = "\\\\.\\pipe\\powershell_stdout";
static const char *SERVER_STDIN_PIPE_NAME = "\\\\.\\pipe\\server_stdin";
static const char *SERVER_STDOUT_PIPE_NAME = "\\\\.\\pipe\\server_stdout";

#define SERVER_INPUT_INDEX 0
#define PROCESS_HANDLE_INDEX 1
#define CONSOLE_OUTPUT_INDEX 2
#define SERVER_OUTPUT_INDEX 3

#define DETACHED_CODE 24 // CTRL-X

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

// NOTE: setup on main thread then reset on reader thread ^^
static DWORD console_input_mode = 0;
static DWORD console_output_mode = 0;
bool setup_client_console_mode(void) {
    HANDLE console_input = GetStdHandle(STD_INPUT_HANDLE);
    if (!GetConsoleMode(console_input, &console_input_mode) ||
        !SetConsoleMode(console_input, (console_input_mode & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT)) | ENABLE_VIRTUAL_TERMINAL_INPUT)) {
        nob_log(NOB_ERROR, "Failed to set input console mode, %s", win32_error_message(GetLastError()));
        return false;
    }

    HANDLE console_output = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!GetConsoleMode(console_output, &console_output_mode) ||
        !SetConsoleMode(console_output, console_output_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING | ENABLE_PROCESSED_OUTPUT | DISABLE_NEWLINE_AUTO_RETURN)) {
        nob_log(NOB_ERROR, "Failed to set output console mode, %s", win32_error_message(GetLastError()));
        return false;
    }
    return true;
}

void reset_client_console_mode(void) {
    if (!SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), console_output_mode)) {
        nob_log(NOB_ERROR, "Failed to reset output console mode, %s", win32_error_message(GetLastError()));
    }
    if (!SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), console_input_mode)) {
        nob_log(NOB_ERROR, "Failed to reset input console mode, %s", win32_error_message(GetLastError()));
    }
}

DWORD WINAPI client_output_reader(void *arg) {
    HANDLE detached_event = (HANDLE)arg;

    HANDLE console_output = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE server_output = CreateFileA(
        SERVER_STDOUT_PIPE_NAME,
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        NULL
    );

    OVERLAPPED server_output_overlapped = {0};
    server_output_overlapped.hEvent = INVALID_HANDLE_VALUE;
    do {
        if (server_output == INVALID_HANDLE_VALUE) {
            nob_log(NOB_ERROR, "Failed to connect to server output, (%d) %s", GetLastError(), win32_error_message(GetLastError()));
            break;
        }

        server_output_overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (server_output_overlapped.hEvent == INVALID_HANDLE_VALUE) {
            nob_log(NOB_ERROR, "Failed to create async event for server output, %s", win32_error_message(GetLastError()));
            break;
        }
        server_output_overlapped.Offset = 0;
        server_output_overlapped.OffsetHigh = 0;


        nob_log(NOB_INFO, "Server output connected");

        char buffer[PIPE_BUFFER_SIZE] = {0};
        DWORD bytes_read = 0;

        const char* clear_seq = "\x1b[2J\x1b[H";
        if (!WriteFile(console_output, clear_seq, (DWORD)strlen(clear_seq), NULL, NULL)) {
            nob_log(NOB_ERROR, "Failed to clear sreen, %s", win32_error_message(GetLastError()));
            break;
        }

        if (!start_read(buffer, ARRAY_LEN(buffer), server_output, &server_output_overlapped, console_output)) {
            break;
        }

        #define CLIENT_READER_DETACHED_EVENT_INDEX 0
        #define CLIENT_READER_SERVER_OUTPUT_INDEX 1
        HANDLE handles[] = {
            [CLIENT_READER_DETACHED_EVENT_INDEX] = detached_event,
            [CLIENT_READER_SERVER_OUTPUT_INDEX] = server_output_overlapped.hEvent,
        };

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

            if (index == CLIENT_READER_SERVER_OUTPUT_INDEX) {
                if (!GetOverlappedResult(server_output, &server_output_overlapped, &bytes_read, FALSE)) {
                    nob_log(NOB_ERROR, "Failed to get server output overlapped result, %s", win32_error_message(GetLastError()));
                    break;
                }

                if (!WriteFile(console_output, buffer, bytes_read, NULL, NULL)) {
                    break;
                }

                if (!start_read(buffer, ARRAY_LEN(buffer), server_output, &server_output_overlapped, console_output)) {
                    break;
                }
                continue;
            }

            if (index == CLIENT_READER_DETACHED_EVENT_INDEX) {
                nob_log(NOB_INFO, "Client reader received detached event");
                break;
            }
        }
    } while (false);

    if (server_output_overlapped.hEvent != INVALID_HANDLE_VALUE) CloseHandle(server_output_overlapped.hEvent);
    if (server_output != INVALID_HANDLE_VALUE) CloseHandle(server_output);
    CloseHandle(detached_event);

    reset_client_console_mode();
    FreeConsole();
    nob_log(NOB_INFO, "Client reader exited");
    return 0;
}

static PROCESS_INFORMATION server_info = {0};
void terminate_server(void) {
    if (!server_info.hProcess) return;
    TerminateProcess(server_info.hProcess, 254);
    CloseHandle(server_info.hProcess);
    CloseHandle(server_info.hThread);
    ZeroMemory(&server_info, sizeof(server_info));
}
bool start_server(char *command_line) {
    if (server_info.hProcess) {
        DWORD result = WaitForSingleObject(server_info.hProcess, 10);
        if (result == WAIT_TIMEOUT) {
            return true;
        }

        if (result != WAIT_OBJECT_0) {
            nob_log(NOB_ERROR, "Failed to wait for server process, %s (%d)", win32_error_message(GetLastError()), GetLastError());
            return false;
        }

        DWORD exit_code = 255;
        GetExitCodeProcess(server_info.hProcess, &exit_code);
        nob_log(NOB_INFO, "Server exited with code (%d)", exit_code);
        CloseHandle(server_info.hProcess);
        CloseHandle(server_info.hThread);
        ZeroMemory(&server_info, sizeof(server_info));
    }

    STARTUPINFO startup_info = {
        .cb = sizeof(STARTUPINFO)
    };

    BOOL success = CreateProcessA(
        NULL,
        command_line,
        NULL,
        NULL,
        FALSE,
        DETACHED_PROCESS | CREATE_BREAKAWAY_FROM_JOB,
        NULL,
        NULL,
        &startup_info,
        &server_info
    );
    if (!success) {
        nob_log(NOB_ERROR, "Failed to create server process, %s (%d)", win32_error_message(GetLastError()), GetLastError());
        return false;
    }
    nob_log(NOB_INFO, "Started detached server, command line: %s (%d)", command_line, server_info.dwProcessId);

    return true;
}

COORD get_console_size(void) {
    CONSOLE_SCREEN_BUFFER_INFO console_screen_info = {0};
    if (!GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &console_screen_info)) {
        UNREACHABLE("Must be able to read console size");
    }
    return console_screen_info.dwSize;
}

int client_main(char *server_command_line) {
    if (!setup_client_console_mode()) {
        return 1;
    }
    HANDLE console_input = GetStdHandle(STD_INPUT_HANDLE);

    HANDLE server_input = INVALID_HANDLE_VALUE;
    bool should_start_server = false;
    do {
        if (should_start_server && !start_server(server_command_line)) {
            return 1;
        }

        server_input = CreateFileA(
            SERVER_STDIN_PIPE_NAME,
            GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (server_input == INVALID_HANDLE_VALUE) {
            if (GetLastError() == ERROR_FILE_NOT_FOUND) {
                if (should_start_server) {
                    nob_log(NOB_INFO, "Waiting for server to initialize pipes");
                    Sleep(100);
                } else {
                    nob_log(NOB_INFO, "Server has not started yet, starting server...");
                    should_start_server = true;
                }
                continue;
            }

            terminate_server();
            nob_log(NOB_ERROR, "Failed to connect to server input, (%d) %s", GetLastError(), win32_error_message(GetLastError()));
            return 1;
        }

        break;
    } while (true);
    nob_log(NOB_INFO, "Server input connected");

    HANDLE detached_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (detached_event == INVALID_HANDLE_VALUE) {
        nob_log(NOB_ERROR, "Failed to create shutdown event, %s (%d)", win32_error_message(GetLastError()), GetLastError());
        return 1;
    }

    DWORD reader_thread_id = 0;
    HANDLE thread_handle = CreateThread(
            NULL,                       // default security attributes
            0,                          // use default stack size
            client_output_reader,       // thread function name
            detached_event,             // argument to thread function
            0,                          // use default creation flags
            &reader_thread_id);
    if (thread_handle == INVALID_HANDLE_VALUE) {
        nob_log(NOB_ERROR, "Failed to create client reader thread, %s", win32_error_message(GetLastError()));
        return 1;
    }

    char buffer[PIPE_BUFFER_SIZE] = {0};
    DWORD bytes_read = 0;
    COORD console_size = get_console_size();
    size_t mark = temp_save();
    while (true) {
        temp_rewind(mark);
        if (!ReadFile(console_input, buffer, ARRAY_LEN(buffer), &bytes_read, NULL)) {
            nob_log(NOB_ERROR, "Failed to read input from console, %s", win32_error_message(GetLastError()));
            break;
        }
        if (bytes_read == 0) {
            break;
        }
        if (bytes_read == 1 && buffer[0] == DETACHED_CODE) {
            SetEvent(detached_event);
            break;
        }

        if (!WriteFile(server_input, buffer, bytes_read, NULL, NULL)) {
            break;
        }

        COORD new_size = get_console_size();
        if (console_size.X != new_size.X && console_size.Y != new_size.Y) {
            nob_log(NOB_INFO, "Client size changed %dx%d -> %dx%d", console_size.X, console_size.Y, new_size.X, new_size.Y);
            console_size = new_size;

            assert(ARRAY_LEN(buffer) > sizeof(console_size) + 2);
            buffer[0] = 0;
            memcpy(&buffer[1], &console_size, sizeof(console_size));
            buffer[sizeof(console_size)+1] = 0;
            if (!WriteFile(server_input, buffer, sizeof(console_size)+2, NULL, NULL)) {
                break;
            }
        }
    }

    WaitForSingleObject(thread_handle, INFINITE);
    CloseHandle(thread_handle);
    CloseHandle(server_input);
    nob_log(NOB_INFO, "Client exited");
    return 0;
}

bool setup_logger(const char *in_mode) {
    char path[MAX_PATH] = {0};
    DWORD length = GetModuleFileNameA(NULL, path, MAX_PATH);
    if (length == 0) {
        nob_log(NOB_ERROR, "Failed to get executable path, %s", win32_error_message(GetLastError()));
        return false;
    }
    Nob_String_View path_sv = nob_sv_from_parts(path, length);
    assert(nob_sv_end_with(path_sv, ".exe"));
    size_t i = path_sv.count-1;
    for (; i != 0; i -= 1) {
        if (path_sv.data[i] == '\\') {
            i += 1;
            break;
        }
    }
    if (freopen(temp_sprintf("%.*swmux_%s.log", i, path_sv.data, in_mode), "a", stderr) == NULL) {
        nob_log(NOB_ERROR, "Failed to reopen stderr for loggin", win32_error_message(GetLastError()));
        return false;
    }
    return true;
}

int main(int argc, char **argv) {
    char *program_name = shift(argv, argc);

    const char *mode;
    if (argc == 0) {
        mode = "client";
    } else {
        mode = shift(argv, argc);
    }
    if (!setup_logger(mode)) {
        return 1;
    }

    nob_log(NOB_INFO, "%s started with pid: %d", GetCommandLineA(), GetCurrentProcessId());

    if (strcmp(mode, "client") == 0) {
        COORD console_size = get_console_size();
        nob_log(NOB_INFO, "Client start with console size %dx%d", console_size.X, console_size.Y);
        char *server_command_line = temp_sprintf("\"%s\" \"server\" %d %d", program_name, console_size.X, console_size.Y);

        temp_reset();
        return client_main(server_command_line);
    }

    if (argc <= 1) {
        TODO("Usage");
    }

    for (int i = 0; i < argc; i++) {
        nob_log(NOB_INFO, "Arg %d: %s", i, argv[i]);
    }
    short console_width = (short)atoi(shift(argv, argc));
    short console_height = (short)atoi(shift(argv, argc));
    nob_log(NOB_INFO, "Server started with console size %dx%d", console_width, console_height);
    if (strcmp(mode, "server") == 0) {
        temp_reset();
        return server_main((COORD){.X = console_width, .Y = console_height});
    }

    TODO("Usage");
}

// [_] TODO: allow customize shell
// [_] TODO: usage
// [_] TODO: switch to unicode (wstr)
// [X] TODO: client check and start server if needed
// [x] TODO: log to file for both client and server
// [x] TODO: remove unnecessary process handler thread in server
// [X] TODO: handle resize
//      [X] TODO: set server virtual console initial size to be client console initial size
// [X] TODO: allow disconnect client with command/keybinding
// [X] TODO: buffer output from powershell and send them to client on connected

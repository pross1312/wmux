#define NOB_STRIP_PREFIX
#define NOB_IMPLEMENTATION
#include "nob.h"
#undef INFO
#undef ERROR

#include "wmux.h"
#include <ConsoleApi2.h>
#include <stdio.h>
#include <fcntl.h>

#define DETACHED_CODE 24 // CTRL-X

static const char * const DISABLE_WIN32_INPUT_MODE = "\x1b[?9001l";
static const char * const ENABLE_WIN32_INPUT_MODE = "\x1b[?9001h";

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


// NOTE: setup on main thread then reset on reader thread ^^
static DWORD console_input_mode = 0;
static DWORD console_output_mode = 0;
static UINT console_output_cp = 0;
static UINT console_input_cp = 0;
const static UINT UTF8_CODEPOINT = 65001;
bool setup_client_console_mode(void) {
    HANDLE console_input = GetStdHandle(STD_INPUT_HANDLE);
    if (!GetConsoleMode(console_input, &console_input_mode) ||
        !SetConsoleMode(console_input, ENABLE_VIRTUAL_TERMINAL_INPUT)) {
        nob_log(NOB_ERROR, "Failed to set input console mode, %s", win32_error_message(GetLastError()));
        return false;
    }

    HANDLE console_output = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!GetConsoleMode(console_output, &console_output_mode) ||
        !SetConsoleMode(console_output, ENABLE_VIRTUAL_TERMINAL_PROCESSING | ENABLE_PROCESSED_OUTPUT | DISABLE_NEWLINE_AUTO_RETURN)) {
        nob_log(NOB_ERROR, "Failed to set output console mode, %s", win32_error_message(GetLastError()));
        return false;
    }
    console_output_cp = GetConsoleOutputCP();
    if (console_output_cp == 0) {
        nob_log(NOB_ERROR, "Failed to get console output codepoint, %s", win32_error_message(GetLastError()));
        return false;
    }
    if (!SetConsoleOutputCP(UTF8_CODEPOINT)) {
        nob_log(NOB_ERROR, "Failed to set console output codepoint to (%d), %s", UTF8_CODEPOINT, win32_error_message(GetLastError()));
        return false;
    }
    console_input_cp = GetConsoleCP();
    if (console_input_cp == 0) {
        nob_log(NOB_ERROR, "Failed to get console input codepoint, %s", win32_error_message(GetLastError()));
        return false;
    }
    if (!SetConsoleCP(UTF8_CODEPOINT)) {
        nob_log(NOB_ERROR, "Failed to set console input codepoint to (%d), %s", UTF8_CODEPOINT, win32_error_message(GetLastError()));
        return false;
    }
    return true;
}

void reset_client_console_mode(void) {
    if (console_input_cp != 0 && !SetConsoleCP(console_input_cp)) {
        nob_log(NOB_ERROR, "Failed to reset console input codepoint to (%d), %s", console_input_cp, win32_error_message(GetLastError()));
    }
    if (console_output_cp != 0 && !SetConsoleOutputCP(console_output_cp)) {
        nob_log(NOB_ERROR, "Failed to reset console output codepoint to (%d), %s", console_output_cp, win32_error_message(GetLastError()));
    }
    if (console_output_mode != 0 && !SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), console_output_mode)) {
        nob_log(NOB_ERROR, "Failed to reset output console mode, %s", win32_error_message(GetLastError()));
    }
    if (console_input_mode != 0 && !SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), console_input_mode)) {
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

        const char* clear_seq = "\x1b[2J";
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

        bool first = true;

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

                if (first && !WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), DISABLE_WIN32_INPUT_MODE, (DWORD)strlen(DISABLE_WIN32_INPUT_MODE), NULL, NULL)) {
                    nob_log(NOB_WARNING, "Failed to disable win32 input mode");
                } else {
                    first = false;
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
        reset_client_console_mode();
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
// [X] TODO: fix codepoint, vim, resize issue

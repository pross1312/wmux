#define NOB_STRIP_PREFIX
#define NOB_IMPLEMENTATION
#include "nob.h"

#define OUTPUT_FOLDER ".build/"
#define OBJ_FOLDER OUTPUT_FOLDER"obj/"

int main(int argc, char **argv) {
    NOB_GO_REBUILD_URSELF(argc, argv);

    if (!mkdir_if_not_exists(OUTPUT_FOLDER)) return 1;
    if (!mkdir_if_not_exists(OBJ_FOLDER)) return 1;

    Cmd cmd = {0};
    cmd_append(&cmd, "cl");
    cmd_append(&cmd, "/std:c17");
    cmd_append(&cmd, "/Wall");
    cmd_append(&cmd, "/wd5045", "/wd4820", "/wd5105");
    cmd_append(&cmd, "/Fo:"OBJ_FOLDER);
    cmd_append(&cmd, "/Fe:"OUTPUT_FOLDER"wmux.exe");
    cmd_append(&cmd, "wmux.c");
    if (!cmd_run(&cmd)) return 1;

    //  cmd_append(&cmd, OUTPUT_FOLDER"wmux.exe");
    //  if (!cmd_run(&cmd)) return 1;

    return 0;
}

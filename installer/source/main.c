#include "../include/syscall.h"
#include "../include/installer.h"

int _main(void) {
    return syscall(11, runinstaller);
}

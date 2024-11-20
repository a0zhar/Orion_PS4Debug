#include <ps4.h>
#include "../include/ptrace.h"
#include "../include/server.h"
#include "../include/debug.h"

int _main(void) {
    initKernel();
    initLibc();
    initPthread();
    initNetwork();
    initSysUtil();

    // sleep a few seconds
    // maybe lower our thread priority?
    sceKernelSleep(2);

    // just a little notify
    sceSysUtilSendSystemNotificationWithText(222, "ps4debug by golden\n 6.72 port by GiantPluto");
    
    // jailbreak current thread
    sys_console_cmd(SYS_CONSOLE_CMD_JAILBREAK, NULL);

    // start the server, this will block
    start_server();

    return 0;
}
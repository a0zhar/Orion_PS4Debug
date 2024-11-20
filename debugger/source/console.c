#include <ps4.h>
#include "../include/console.h"
#include "../include/net.h"
#include "../include/debug.h"

int console_reboot_handle(int fd, struct cmd_packet* packet) {
    if (g_debugging) {
        debugger_cleanup(current_dbgr_ctx);

        // close the socket, we are not about to call free_client
        // this is a little hacky but meh
        sceNetSocketClose(fd);
    }

    sys_console_cmd(SYS_CONSOLE_CMD_REBOOT, NULL);
    return 1;
}

int console_print_handle(int fd, struct cmd_packet* packet) {
    struct cmd_console_print_packet* pp;
    void* data;

    pp = (struct cmd_console_print_packet*)packet->data;

    if (pp) {
        data = pfmalloc(pp->length);
        if (!data) {
            net_send_status(fd, CMD_DATA_NULL);
            return 1;
        }

        memset(data, NULL, pp->length);
        
        networkReceiveData(fd, data, pp->length, 1);
        sys_console_cmd(SYS_CONSOLE_CMD_PRINT, data);
        net_send_status(fd, CMD_SUCCESS);

        free(data);
        return 0;
    }

    net_send_status(fd, CMD_DATA_NULL);

    return 1;
}

int console_notify_handle(int fd, struct cmd_packet* packet) {
    struct cmd_console_notify_packet* np;
    void* data;

    np = (struct cmd_console_notify_packet*)packet->data;

    if (np) {
        data = pfmalloc(np->length);
        if (!data) {
            net_send_status(fd, CMD_DATA_NULL);
            return 1;
        }

        memset(data, NULL, np->length);

        networkReceiveData(fd, data, np->length, 1);

        sceSysUtilSendSystemNotificationWithText(np->messageType, data);
        net_send_status(fd, CMD_SUCCESS);

        free(data);

        return 0;
    }

    net_send_status(fd, CMD_DATA_NULL);

    return 1;
}

int hLoadedLibkernelModule = 0;
int console_info_handle(int fd, struct cmd_packet* packet) {
   /* if (hLoadedLibkernelModule == 0) {
        if (loadModule("libkernel.sprx", &hLoadedLibkernelModule))
            if (loadModule("libkernel_web.sprx", &hLoadedLibkernelModule))
                loadModule("libkernel_sys.sprx", &hLoadedLibkernelModule);

        if (!hLoadedLibkernelModule)
            return -1;
    }

    struct cmd_console_info_response resp;
    size_t len;
    
    int (*sysctl)(int* name, unsigned int namelen, char* oldval, size_t * oldlen, char* newval, size_t newlen);
    int (*sysctlbyname)(char* name, char* oldval, size_t * oldlen, char* newval, size_t newlen);
    RESOLVE(hLoadedLibkernelModule, sysctl);
    RESOLVE(hLoadedLibkernelModule, sysctlbyname);

    net_send_status(fd, CMD_SUCCESS);
    networkSendData(fd, &resp, CMD_CONSOLE_INFO_RESPONSE_SIZE);
*/
    return 0;
}

int console_handle(int fd, struct cmd_packet* packet) {
    switch (packet->cmd) {
        case CMD_CONSOLE_REBOOT:
            return console_reboot_handle(fd, packet);
        case CMD_CONSOLE_END:
            return 1;
        case CMD_CONSOLE_PRINT:
            return console_print_handle(fd, packet);
        case CMD_CONSOLE_NOTIFY:
            return console_notify_handle(fd, packet);
        case CMD_CONSOLE_INFO:
            return console_info_handle(fd, packet);
    }

    return 0;
}

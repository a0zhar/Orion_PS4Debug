#include "../include/net.h"
#include "../include/proc.h"
#include "../include/debug.h"
#include "../include/kern.h"
#include "../include/console.h"
#include "../include/server.h"

struct server_client servclients[SERVER_MAXCLIENTS];

struct server_client* alloc_client() {
    for (int i = 0; i < SERVER_MAXCLIENTS; i++) {
        if (servclients[i].id == 0) {
            servclients[i].id = i + 1;
            return &servclients[i];
        }
    }

    return NULL;
}

void free_client(struct server_client* svc) {
    svc->id = 0;
    sceNetSocketClose(svc->fd);

    if (svc->debugging)
        debugger_cleanup(&svc->dbgctx);

    memset(svc, NULL, sizeof(struct server_client));
}

int handle_version(int fd, struct cmd_packet* packet) {
    uint32_t len = strlen(PACKET_VERSION);
    networkSendData(fd, &len, sizeof(uint32_t));
    networkSendData(fd, PACKET_VERSION, len);
    return 0;
}

int cmd_handler(int fd, struct cmd_packet* packet) {
    if (!VALID_CMD(packet->cmd))
        return 1;

    uprintf("cmd_handler %X", packet->cmd);

    if (packet->cmd == CMD_VERSION)      return handle_version(fd, packet);
    if (VALID_PROC_CMD(packet->cmd))     return proc_handle(fd, packet);
    if (VALID_DEBUG_CMD(packet->cmd))    return debug_handle(fd, packet);
    if (VALID_KERN_CMD(packet->cmd))     return kern_handle(fd, packet);
    if (VALID_CONSOLE_CMD(packet->cmd))  return console_handle(fd, packet);

    return 0;
}
int check_debug_interrupt() {
    struct debug_interrupt_packet resp; // Variable for response packet to send back interrupt data
    struct ptrace_lwpinfo* lwpinfo;     // For the thread information structure
    int status;                         // Storing the status of the process
    int signal;                         // For the signal received from the process
    uint8_t int3 = 0xCC;                // Breakpoint instruction

    // Perform a non-blocking wait for the process to change state.
    // If No state change, we return immediately
    if (!wait4(current_dbgr_ctx->pid, &status, WNOHANG, NULL))
        return 0;

    // Extract the signal that caused the state change,
    // and then log the received signal
    signal = WSTOPSIG(status);
    uprintf("check_debug_interrupt signal %i", signal);

    // Check if the received signal is SIGSTOP which indicates process
    // suspension, and handle it if true.
    if (signal == SIGSTOP) {
        uprintf("Received signal (SIGSTOP), indicates process suspension");
        return 0;
    }

    // Check if the received signal is SIGKILL which indicates the 
    // process is being terminated, and handle it if true.
    if (signal == SIGKILL) {
        debugger_cleanup(current_dbgr_ctx); // Clean up the debug context
        // Send a continue signal to the process, allowing it to exit
        ptrace(PT_CONTINUE, current_dbgr_ctx->pid, (void*)1, SIGKILL);
        uprintf("sent final SIGKILL");
        return 0;
    }

    // Allocate memory for thread information, and if it fails we log
    // it, before returning with 1
    lwpinfo = (struct ptrace_lwpinfo*)pfmalloc(sizeof(struct ptrace_lwpinfo));
    if (!lwpinfo) {
        uprintf("could not allocate memory for thread information");
        return 1;
    }

    // Retrieve the thread information for the current process
    if (ptrace(PT_LWPINFO, current_dbgr_ctx->pid, lwpinfo, sizeof(struct ptrace_lwpinfo))) {
        uprintf("could not get lwpinfo errno %i", errno);
    }

    // Clear the response packet
    memset(&resp, 0, DEBUG_INTERRUPT_PACKET_SIZE);

    // TODO: fix size mismatch with these fields
    memcpy(resp.tdname, lwpinfo->pl_tdname, sizeof(lwpinfo->pl_tdname));


    // Retrieve and set register states from the process using ptrace
    if (ptrace(PT_GETREGS, resp.lwpid, &resp.reg64, NULL)) {
        uprintf("could not get registers errno %i", errno);
    }

    // Retrieve FPS register state
    if (ptrace(PT_GETFPREGS, resp.lwpid, &resp.savefpu, NULL)) {
        uprintf("could not get float registers errno %i", errno);
    }

    // Retrieve debug register state
    if (ptrace(PT_GETDBREGS, resp.lwpid, &resp.dbreg64, NULL)) {
        uprintf("could not get debug registers errno %i", errno);
    }

    // Prepare to handle software breakpoints
    struct debug_breakpoint* breakpoint = NULL;
    for (int i = 0; i < MAX_BREAKPOINTS; i++) {
        // Check if there's a breakpoint at the current instruction
        // pointer minus one. If true, the corresponding breakpoint
        // has then been found and we exit for-loop
        if (current_dbgr_ctx->breakpoints[i].address == resp.reg64.r_rip - 1) {
            // Found the corresponding breakpoint
            breakpoint = &current_dbgr_ctx->breakpoints[i];
            break;
        }
    }

    // If a software breakpoint was hit, we handle it
    if (breakpoint) {
        uprintf("dealing with software breakpoint");
        uprintf("breakpoint: %llX %X", breakpoint->address, breakpoint->original);

        // Write back the old instruction to the breakpoint location
        sys_proc_rw(current_dbgr_ctx->pid, breakpoint->address, &breakpoint->original, 1, 1);

        // Step back one instruction to allow proper handling of the breakpoint
        resp.reg64.r_rip -= 1; // Adjust instruction pointer
        ptrace(PT_SETREGS, resp.lwpid, &resp.reg64, NULL);  // Update registers

        // Step over the instruction at the breakpoint
        ptrace(PT_STEP, resp.lwpid, (void*)1, NULL);

        int wait_status;
        while (!wait4(current_dbgr_ctx->pid, &wait_status, WNOHANG, NULL))
            sceKernelUsleep(4000);  // Sleep briefly to avoid busy-wait

        // Re-set breakpoint:
        // Restore the breakpoint after single-stepping through it.
        sys_proc_rw(current_dbgr_ctx->pid, breakpoint->address, &int3, 1, 1);
    }
    else uprintf("dealing with hardware breakpoint");


    // Send the response packet of debug interrupt data over the network
    int r = networkSendData(current_dbgr_ctx->dbgfd, &resp, DEBUG_INTERRUPT_PACKET_SIZE);
    if (r != DEBUG_INTERRUPT_PACKET_SIZE) {
        // Log if sending fails
        uprintf("networkSendData failed %i %i", r, errno);
    }

    // For tracking successful communication
    uprintf("check_debug_interrupt interrupt data sent");

    // Free the allocated memory for thread info
    free(lwpinfo);

    // Indicate successful processing of the interrupt
    return 0;
}


/**
 * Handles communication with a connected client.
 * @param svc - Pointer to the server client structure.
 * @return Always returns 0.
 */
int handle_client(struct server_client* svc) {
    struct cmd_packet packet; // Packet structure for client communication
    uint32_t rsize;           // Size of data received
    uint32_t length;          // Length of packet data
    void* data = NULL;        // Pointer to allocated packet data
    int fd = svc->fd;         // File descriptor for client socket
    int r;                    // General-purpose return value

    struct timeval tv = { 0 };
    tv.tv_usec = 1000;      

    while (1) {
        // Set up the file descriptor set
        fd_set sfd;
        FD_ZERO(&sfd);          // Clear the set
        FD_SET(fd, &sfd);       // Add the client file descriptor to the set
        errno = 0;              // Clear errno before select

        // Wait for activity
        net_select(FD_SETSIZE, &sfd, NULL, NULL, &tv);

        // check if we can recieve
        if (FD_ISSET(fd, &sfd)) {
            // zero out
            memset(&packet, NULL, CMD_PACKET_SIZE);

            // recieve our data
            rsize = networkReceiveData(fd, &packet, CMD_PACKET_SIZE, 0);

            // if we didnt recieve hmm
            if (rsize <= 0) goto error;           

            // check if disconnected
            if (errno == ECONNRESET) 
            goto error;
        }
        else {
            // if we have a valid debugger context then check for interrupt
            // this does not block, as wait is called with option WNOHANG
            if (svc->debugging) 
                if (check_debug_interrupt()) 
                    goto error;
                
            // check if disconnected
            if (errno == ECONNRESET) 
            goto error;
            
            sceKernelUsleep(25000);
            continue;
        }

        uprintf("client packet recieved");

        // invalid packet
        if (packet.magic != PACKET_MAGIC) {
            uprintf("invalid packet magic %X!", packet.magic);
            continue;
        }

        // mismatch received size
        if (rsize != CMD_PACKET_SIZE) {
            uprintf("invalid recieve size %i!", rsize);
            continue;
        }

        length = packet.datalen;
        if (length) {
            // allocate data
            data = pfmalloc(length);
            if (!data) goto error;
            
            // recv data
            uprintf("recieving data length %i", length);
            if (!networkReceiveData(fd, data, length, 1)) 
                goto error;

            // set data
            packet.data = data;
        }
        else {
            packet.data = NULL;
        }

        // special case when attaching
        // if we are debugging then the handler for CMD_DEBUG_ATTACH will send back the right error
        if (!g_debugging && packet.cmd == CMD_DEBUG_ATTACH) {
            curdbgcli = svc;
            current_dbgr_ctx = &svc->dbgctx;
        }


        if (data) {
            free(data);
            data = NULL;
        }

        // handle the packet
        int r = cmd_handler(fd, &packet);
        // check cmd handler error
        if (r) goto error;
    }

error:
    uprintf("client disconnected");
    free_client(svc);

    return 0;
}

void configure_socket(int fd) {
    int flag;

    flag = 1;
    // Enable non-blocking mode
    sceNetSetsockopt(fd, SOL_SOCKET, SO_NBIO, (char*)&flag, sizeof(flag));

    flag = 1;
    // Disable Nagle's algorithm to minimize latency
    sceNetSetsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag));

    flag = 1;
    // Disable SIGPIPE signals for this socket
    sceNetSetsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, (char*)&flag, sizeof(flag));
}

void* broadcast_thread(void* arg) {
    struct sockaddr_in server;
    struct sockaddr_in client;
    unsigned int clisize;
    int serv;
    int flag;
    int r;
    uint32_t magic;

    uprintf("broadcast server started");

    // setup server
    server.sin_len = sizeof(server);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = IN_ADDR_ANY;
    server.sin_port = sceNetHtons(BROADCAST_PORT);
    memset(server.sin_zero, NULL, sizeof(server.sin_zero));

    serv = sceNetSocket("broadsock", AF_INET, SOCK_DGRAM, 0);
    if (serv < 0) {
        uprintf("failed to create broadcast server");
        return NULL;
    }

    flag = 1;
    sceNetSetsockopt(serv, SOL_SOCKET, SO_BROADCAST, (char*)&flag, sizeof(flag));

    r = sceNetBind(serv, (struct sockaddr*)&server, sizeof(server));
    if (r) {
        uprintf("failed to bind broadcast server");
        return NULL;
    }

    // TODO: XXX: clean this up, but meh not too dirty? is it? hmmm
    int libNet = sceKernelLoadStartModule("libSceNet.sprx", 0, NULL, 0, 0, 0);
    int (*sceNetRecvfrom)(int s, void* buf, unsigned int len, int flags, struct sockaddr* from, unsigned int* fromlen);
    int (*sceNetSendto)(int s, void* msg, unsigned int len, int flags, struct sockaddr* to, unsigned int tolen);
    RESOLVE(libNet, sceNetRecvfrom);
    RESOLVE(libNet, sceNetSendto);

    while (1) {
        scePthreadYield();

        magic = 0;
        clisize = sizeof(client);
        r = sceNetRecvfrom(serv, &magic, sizeof(uint32_t), 0, (struct sockaddr*)&client, &clisize);

        if (r >= 0) {
            uprintf("broadcast server received a message");
            if (magic == BROADCAST_MAGIC) {
                sceNetSendto(serv, &magic, sizeof(uint32_t), 0, (struct sockaddr*)&client, clisize);
            }
        }
        else {
            uprintf("sceNetRecvfrom failed");
        }

        sceKernelSleep(1);
    }

    return NULL;
}

int start_server() {
    struct sockaddr_in server;
    struct sockaddr_in client;
    struct server_client* svc;
    unsigned int len = sizeof(client);
    int serv, fd;
    int r;

    uprintf("ps4debug " PACKET_VERSION " server started");

    ScePthread broadcast;
    scePthreadCreate(&broadcast, NULL, broadcast_thread, NULL, "broadcast");

    // server structure
    server.sin_len = sizeof(server);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = IN_ADDR_ANY;
    server.sin_port = sceNetHtons(SERVER_PORT);
    memset(server.sin_zero, NULL, sizeof(server.sin_zero));

    // start up server
    serv = sceNetSocket("debugserver", AF_INET, SOCK_STREAM, 0);
    if (serv < 0) {
        uprintf("could not create socket!");
        return 1;
    }

    configure_socket(serv);

    r = sceNetBind(serv, (struct sockaddr*)&server, sizeof(server));
    if (r) {
        uprintf("bind failed!");
        return 1;
    }

    r = sceNetListen(serv, SERVER_MAXCLIENTS * 2);
    if (r) {
        uprintf("bind failed!");
        return 1;
    }

    // reset clients
    memset(servclients, NULL, sizeof(struct server_client) * SERVER_MAXCLIENTS);

    // reset debugging stuff
    g_debugging = 0;
    curdbgcli = NULL;
    current_dbgr_ctx = NULL;

    while (1) {
        scePthreadYield();

        errno = NULL;
        fd = sceNetAccept(serv, (struct sockaddr*)&client, &len);
        if (fd > -1 && !errno) {
            uprintf("accepted a new client");

            svc = alloc_client();
            if (!svc) {
                uprintf("server can not accept anymore clients");
                continue;
            }

            configure_socket(fd);

            svc->fd = fd;
            svc->debugging = 0;
            memcpy(&svc->client, &client, sizeof(svc->client));
            memset(&svc->dbgctx, NULL, sizeof(svc->dbgctx));

            ScePthread thread;
            scePthreadCreate(&thread, NULL, (void* (*)(void*))handle_client, (void*)svc, "clienthandler");
        }

        sceKernelSleep(2);
    }

    return 0;
}

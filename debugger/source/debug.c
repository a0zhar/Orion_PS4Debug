#include "../include/debug.h"

int g_debugging;
struct server_client* curdbgcli;
struct debug_context* current_dbgr_ctx;

// Function to attach the debugger to a specified process
int debugger_attach(int fd, struct cmd_packet* packet) {
    // Check if already in debugging mode
    if (g_debugging) {
        net_send_status(fd, CMD_ALREADY_DEBUG);
        return 1; // Early exit if already debugging
    }

    struct cmd_debug_attach_packet* ap;
    ap = (struct cmd_debug_attach_packet*)packet->data;
    if (!ap) {
        net_send_status(fd, CMD_DATA_NULL);
        return 1;
    }

    // Attempt to attach to the process using ptrace
    if (ptrace(PT_ATTACH, ap->pid, NULL, NULL)) {
        net_send_status(fd, CMD_ERROR);
        return 1; // Error handling if attach fails
    }

    // Continue the process after attaching
    if (ptrace(PT_CONTINUE, ap->pid, (void*)1, NULL)) {
        net_send_status(fd, CMD_ERROR);
        return 1; // Error handling if continue fails
    }

    // Connect to the debugger server
    if (debugger_connect(current_dbgr_ctx, &curdbgcli->client)) {
        uprintf("could not connect to server");
        net_send_status(fd, CMD_ERROR);
        return 1; // Handle server connection error
    }

    // Update debugger client and context with current process's PID
    curdbgcli->debugging = 1;
    current_dbgr_ctx->pid = ap->pid;
    uprintf("debugger is attached");  // Inform the client of successful attachment
    net_send_status(fd, CMD_SUCCESS); // Inform the client of success
    return 0; // Successful operation

}

// Function to detach the debugger from the current process
int debugger_detach(int fd, struct cmd_packet* packet) {
    // Cleanup the current debug context
    debugger_cleanup(current_dbgr_ctx);

    // Inform the client of success
    net_send_status(fd, CMD_SUCCESS);
    return 0;
}


int debugger_handle_breakpoint(int fd, struct cmd_packet* packet) {
    // Check if a current process is set for debugging
    if (current_dbgr_ctx->pid == 0) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    uint8_t int3 = 0xCC; // Interrupt instruction for breakpoint

    // Retrieve breakpoint data from the command packet, and check
    // if it is invalid, which in case, we handle it
    struct cmd_debug_breakpt_packet* bp;
    bp = (struct cmd_debug_breakpt_packet*)packet->data;
    if (!bp) {
        net_send_status(fd, CMD_DATA_NULL);
        return 1;
    }

    // Check if the index of the breakpoint is invalid, by checking
    // if the current breakpoint index is greater than or equal
    // to the maximum number of breakpoints allowed
    if (bp->index >= MAX_BREAKPOINTS) {
        net_send_status(fd, CMD_INVALID_INDEX);
        return 1;
    }

    struct debug_breakpoint* breakpoint = &current_dbgr_ctx->breakpoints[bp->index];

    // Check if the breakpoint specified is enabled or not. If it is enabled
    // we can then handle it, but if it's not enabled, we disable/clear it
    if (bp->enabled) {
        breakpoint->enabled = 1;           // Mark the breakpoint as enabled
        breakpoint->address = bp->address; // Set the address for the breakpoint

        // Save the original byte at the breakpoint address before modification
        sys_proc_rw(current_dbgr_ctx->pid, breakpoint->address, &breakpoint->original, 1, 0);

        // Inject the breakpoint
        sys_proc_rw(current_dbgr_ctx->pid, breakpoint->address, &int3, 1, 1);
    }
    else {
        // Restore original byte at the breakpoint address
        sys_proc_rw(current_dbgr_ctx->pid, breakpoint->address, &breakpoint->original, 1, 1);

        breakpoint->enabled = 0;    // Mark the breakpoint as disabled
        breakpoint->address = NULL; // Reset the address
    }

    // Inform the client (PS4Cheater/Ps4Reaper) of success
    net_send_status(fd, CMD_SUCCESS);
    return 0;
}

int debugger_handle_watchpoint(int fd, struct cmd_packet* packet) {
    struct cmd_debug_watchpt_packet* wp; // The watchpoint RPC command structure
    struct __dbreg64* dbreg64;           // The debug registers state for the current ctx
    uint32_t* lwpids;                    // For storing thread IDs (LWP IDs)
    int nlwps;
    int size;

    if (current_dbgr_ctx->pid == 0) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    // Cast the packet data to the appropriate watchpoint command type
    // Validate that the watchpoint command structure is not null
    wp = (struct cmd_debug_watchpt_packet*)packet->data;
    if (!wp) {
        net_send_status(fd, CMD_DATA_NULL);
        return 1;
    }

    // Check if the requested watchpoint index exceeds the maximum
    // number of allowed watchpoints, or if it is at maximum
    if (wp->index >= MAX_WATCHPOINTS) {
        net_send_status(fd, CMD_INVALID_INDEX);
        return 1;
    }

    // Get the threads
    nlwps = ptrace(PT_GETNUMLWPS, current_dbgr_ctx->pid, NULL, 0);
    size = nlwps * sizeof(uint32_t);
    lwpids = (uint32_t*)pfmalloc(size);
    if (!lwpids) {
        net_send_status(fd, CMD_DATA_NULL);
        return 1;
    }

    if (ptrace(PT_GETLWPLIST, current_dbgr_ctx->pid, (void*)lwpids, nlwps) == -1 && errno) {
        net_send_status(fd, CMD_ERROR);
        free(lwpids);
        return -1;
    }

    // Setup the watchpoint in the debug registers:
    // Get the debug register state
    dbreg64 = (struct __dbreg64*)&current_dbgr_ctx->watchdata;

    // Disable the current watchpoint in the debug control register
    dbreg64->dr[7] &= ~DBREG_DR7_MASK(wp->index);

    // Check if the watchpoint should be enabled or disabled
    if (wp->enabled) {
        // Set the watchpoint address in the debug register
        dbreg64->dr[wp->index] = wp->address;

        // Enable the watchpoint for local and global access
        dbreg64->dr[7] |= DBREG_DR7_SET(
            wp->index, wp->length,
            wp->breaktype,
            DBREG_DR7_LOCAL_ENABLE | DBREG_DR7_GLOBAL_ENABLE
        );
    }
    else {
        // WatchPoint is disabled: Clear it's address
        dbreg64->dr[wp->index] = NULL;

        // Then Disable the watchpoint
        dbreg64->dr[7] |= DBREG_DR7_SET(wp->index, 0, 0, DBREG_DR7_DISABLE);
    }

    // uprintf("dr%i: %llX dr7: %llX", wp->index, wp->address, dbreg64->dr[7]);

    // For each current lwpid edit the watchpoint
    for (int i = 0; i < nlwps; i++) {
        if (ptrace(PT_SETDBREGS, lwpids[i], dbreg64, NULL) == -1 && errno) {
            net_send_status(fd, CMD_ERROR);
            free(lwpids);
            return -1;
        }
    }

    net_send_status(fd, CMD_SUCCESS);
    free(lwpids);
    return 0;
}

int debugger_handle_threads(int fd, struct cmd_packet* packet) {
    if (current_dbgr_ctx->pid == 0) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    int nlwps = ptrace(PT_GETNUMLWPS, current_dbgr_ctx->pid, NULL, 0);
    if (nlwps == -1) {
        net_send_status(fd, CMD_ERROR);
        return 0;
    }

    // i assume the lwpid_t is 32 bits wide
    int size = nlwps * sizeof(uint32_t);
    void* lwpids = pfmalloc(size);
    if (!lwpids) {
        net_send_status(fd, CMD_DATA_NULL);
        return 1;
    }

    if (ptrace(PT_GETLWPLIST, current_dbgr_ctx->pid, lwpids, nlwps) == -1) {
        net_send_status(fd, CMD_ERROR);
        free(lwpids);
        return 0;
    }

    net_send_status(fd, CMD_SUCCESS);
    networkSendData(fd, &nlwps, sizeof(nlwps));
    networkSendData(fd, lwpids, size);

    free(lwpids);
    return 0;
}

int debugger_suspend_thread(int fd, struct cmd_packet* packet) {
    if (current_dbgr_ctx->pid == 0) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    struct cmd_debug_stopthr_packet* sp;
    sp = (struct cmd_debug_stopthr_packet*)packet->data;
    if (!sp) {
        net_send_status(fd, CMD_DATA_NULL);
        return 1;
    }

    if (ptrace(PT_SUSPEND, sp->lwpid, NULL, 0) == -1) {
        net_send_status(fd, CMD_ERROR);
        return 0;
    }

    net_send_status(fd, CMD_SUCCESS);
    return 0;
}

int debugger_resume_thread(int fd, struct cmd_packet* packet) {
    if (current_dbgr_ctx->pid == 0) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    struct cmd_debug_resumethr_packet* rp;
    rp = (struct cmd_debug_resumethr_packet*)packet->data;
    if (!rp) {
        net_send_status(fd, CMD_DATA_NULL);
        return 1;
    }

    if (ptrace(PT_RESUME, rp->lwpid, NULL, 0) == -1) {
        net_send_status(fd, CMD_ERROR);
        return 0;
    }

    net_send_status(fd, CMD_SUCCESS);

    return 0;
}

int debugger_get_regs(int fd, struct cmd_packet* packet) {
    if (current_dbgr_ctx->pid == 0) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    struct cmd_debug_getregs_packet* rp;
    struct __reg64 reg64;

    rp = (struct cmd_debug_getregs_packet*)packet->data;
    if (!rp) {
        net_send_status(fd, CMD_DATA_NULL);
        return 1;
    }

    if (ptrace(PT_GETREGS, rp->lwpid, &reg64, NULL) == -1 && errno) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    net_send_status(fd, CMD_SUCCESS);
    networkSendData(fd, &reg64, sizeof(struct __reg64));

    return 0;
}

int debugger_get_fpregs(int fd, struct cmd_packet* packet) {
    if (current_dbgr_ctx->pid == 0) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    struct cmd_debug_getregs_packet* rp;
    struct savefpu_ymm savefpu;
    rp = (struct cmd_debug_getregs_packet*)packet->data;
    if (!rp) {
        net_send_status(fd, CMD_DATA_NULL);
        return 1;
    }

    if (ptrace(PT_GETFPREGS, rp->lwpid, &savefpu, NULL) == -1 && errno) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    net_send_status(fd, CMD_SUCCESS);
    networkSendData(fd, &savefpu, sizeof(struct savefpu_ymm));

    return 0;
}

int debugger_get_dbregs(int fd, struct cmd_packet* packet) {
    if (current_dbgr_ctx->pid == 0) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    struct cmd_debug_getregs_packet* rp;
    struct __dbreg64 dbreg64;
    rp = (struct cmd_debug_getregs_packet*)packet->data;
    if (!rp) {
        net_send_status(fd, CMD_DATA_NULL);
        return 1;
    }

    if (ptrace(PT_GETDBREGS, rp->lwpid, &dbreg64, NULL) && errno) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    net_send_status(fd, CMD_SUCCESS);
    networkSendData(fd, &dbreg64, sizeof(struct __dbreg64));

    return 0;
}

int debugger_set_regs(int fd, struct cmd_packet* packet) {
    if (current_dbgr_ctx->pid == 0) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    struct __reg64 reg64;
    struct cmd_debug_setregs_packet* sp;
    sp = (struct cmd_debug_setregs_packet*)packet->data;
    if (!sp) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    net_send_status(fd, CMD_SUCCESS);

    networkReceiveData(fd, &reg64, sp->length, 1);

    if (ptrace(PT_SETREGS, current_dbgr_ctx->pid, &reg64, NULL) == -1 && errno) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    net_send_status(fd, CMD_SUCCESS);

    return 0;
}

int debugger_set_fpregs(int fd, struct cmd_packet* packet) {
    if (current_dbgr_ctx->pid == 0) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    struct cmd_debug_setregs_packet* sp;
    struct savefpu_ymm* fpregs;
    sp = (struct cmd_debug_setregs_packet*)packet->data;
    if (!sp) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    net_send_status(fd, CMD_SUCCESS);
    networkReceiveData(fd, &fpregs, sp->length, 1);

    if (ptrace(PT_SETFPREGS, current_dbgr_ctx->pid, fpregs, NULL) == -1 && errno) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    net_send_status(fd, CMD_SUCCESS);

    return 0;
}

int debugger_set_dbregs(int fd, struct cmd_packet* packet) {
    if (current_dbgr_ctx->pid == 0) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    struct cmd_debug_setregs_packet* sp;
    struct __dbreg64 dbreg64;
    sp = (struct cmd_debug_setregs_packet*)packet->data;

    if (!sp) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    net_send_status(fd, CMD_SUCCESS);
    networkReceiveData(fd, &dbreg64, sp->length, 1);


    if (ptrace(PT_SETDBREGS, current_dbgr_ctx->pid, &dbreg64, NULL) == -1 && errno) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    net_send_status(fd, CMD_SUCCESS);

    return 0;
}

int debugger_stopgo_handle(int fd, struct cmd_packet* packet) {
    if (current_dbgr_ctx->pid == 0) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    struct cmd_debug_stopgo_packet* sp;
    int signal;

    sp = (struct cmd_debug_stopgo_packet*)packet->data;
    if (!sp) {
        net_send_status(fd, CMD_DATA_NULL);
        return 1;
    }

    signal = NULL;

    if (sp->stop == 1) {
        signal = SIGSTOP;
    }
    else if (sp->stop == 2) {
        signal = SIGKILL;
    }

    if (ptrace(PT_CONTINUE, current_dbgr_ctx->pid, (void*)1, signal) == -1 && errno) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    net_send_status(fd, CMD_SUCCESS);

    return 0;
}

// Retrieves thread information for the specified process
int debugger_get_thread_info(int fd, struct cmd_packet* packet) {
    if (current_dbgr_ctx->pid == 0) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    struct cmd_debug_thrinfo_packet* tp;
    struct cmd_debug_thrinfo_response resp;
    struct sys_proc_thrinfo_args args;
    tp = (struct cmd_debug_thrinfo_packet*)packet->data;
    if (!tp) {
        net_send_status(fd, CMD_DATA_NULL);
        return 1;
    }

    args.lwpid = tp->lwpid;
    sys_proc_cmd(current_dbgr_ctx->pid, SYS_PROC_THRINFO, &args);

    resp.lwpid = args.lwpid;
    resp.priority = args.priority;
    memcpy(resp.name, args.name, sizeof(resp.name));

    net_send_status(fd, CMD_SUCCESS);
    networkSendData(fd, &resp, sizeof(struct cmd_debug_thrinfo_packet));

    return 0;
}

// Function Handles single-stepping over instructions in the current debugging context
int debugger_do_single_step(int fd, struct cmd_packet* packet) {
    if (current_dbgr_ctx->pid == 0) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    if (ptrace(PT_STEP, current_dbgr_ctx->pid, (void*)1, 0)) {
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    net_send_status(fd, CMD_SUCCESS);

    return 0;
}

int debugger_connect(struct debug_context* dbgctx, struct sockaddr_in* client) {
    // we are now debugging
    g_debugging = 1;

    // connect to server
    struct sockaddr_in server;
    server.sin_len = sizeof(server);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = client->sin_addr.s_addr;
    server.sin_port = sceNetHtons(DEBUG_PORT);
    memset(server.sin_zero, NULL, sizeof(server.sin_zero));

    dbgctx->dbgfd = sceNetSocket("interrupt", AF_INET, SOCK_STREAM, 0);
    if (dbgctx->dbgfd <= 0)
        return 1;

    if (sceNetConnect(dbgctx->dbgfd, (struct sockaddr*)&server, sizeof(server)))
        return 1;

    return 0;
}

int debugger_cleanup(struct debug_context* dbgctx) {
    struct __dbreg64 dbreg64;
    uint32_t* lwpids;
    int nlwps;


    // clean up stuff
    curdbgcli->debugging = 0;

    // delete references
    g_debugging = 0;
    curdbgcli = NULL;
    current_dbgr_ctx = NULL;

    // disable all breakpoints
    for (int i = 0; i < MAX_BREAKPOINTS; i++) {
        sys_proc_rw(
            dbgctx->pid,
            dbgctx->breakpoints[i].address,
            &dbgctx->breakpoints[i].original,
            1, 1
        );
    }

    // reset all debug registers
    nlwps = ptrace(PT_GETNUMLWPS, dbgctx->pid, NULL, 0);
    lwpids = (uint32_t*)pfmalloc(nlwps * sizeof(uint32_t));
    if (lwpids) {
        memset(&dbreg64, NULL, sizeof(struct __dbreg64));

        if (!ptrace(PT_GETLWPLIST, dbgctx->pid, (void*)lwpids, nlwps)) {
            for (int i = 0; i < nlwps; i++) {
                ptrace(
                    PT_SETDBREGS,
                    lwpids[i],
                    &dbreg64,
                    NULL
                );
            }
        }

        free(lwpids);
    }

    ptrace(PT_CONTINUE, dbgctx->pid, (void*)1, NULL);
    ptrace(PT_DETACH, dbgctx->pid, NULL, NULL);

    sceNetSocketClose(dbgctx->dbgfd);
    return 1;
}

int debug_handle(int fd, struct cmd_packet* packet) {
    switch (packet->cmd) {
        case CMD_DEBUG_ATTACH:      return debugger_attach(fd, packet);
        case CMD_DEBUG_DETACH:      return debugger_detach(fd, packet);
        case CMD_DEBUG_BREAKPT:     return debugger_handle_breakpoint(fd, packet);
        case CMD_DEBUG_WATCHPT:     return debugger_handle_watchpoint(fd, packet);
        case CMD_DEBUG_THREADS:     return debugger_handle_threads(fd, packet);
        case CMD_DEBUG_STOPTHR:     return debugger_suspend_thread(fd, packet);
        case CMD_DEBUG_RESUMETHR:   return debugger_resume_thread(fd, packet);
        case CMD_DEBUG_GETREGS:     return debugger_get_regs(fd, packet);
        case CMD_DEBUG_SETREGS:     return debugger_set_regs(fd, packet);
        case CMD_DEBUG_GETFPREGS:   return debugger_get_fpregs(fd, packet);
        case CMD_DEBUG_SETFPREGS:   return debugger_set_fpregs(fd, packet);
        case CMD_DEBUG_GETDBGREGS:  return debugger_get_dbregs(fd, packet);
        case CMD_DEBUG_SETDBGREGS:  return debugger_set_dbregs(fd, packet);
        case CMD_DEBUG_STOPGO:      return debugger_stopgo_handle(fd, packet);
        case CMD_DEBUG_THRINFO:     return debugger_get_thread_info(fd, packet);
        case CMD_DEBUG_SINGLESTEP:  return debugger_do_single_step(fd, packet);
        default: return 0;
    };
}
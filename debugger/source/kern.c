#include "../include/kern.h"

int kern_base_handle(int fd, struct cmd_packet* packet) {
    uint64_t kernbase;
    sys_kern_base(&kernbase);
    net_send_status(fd, CMD_SUCCESS);
    networkSendData(fd, &kernbase, sizeof(uint64_t));
    return 0;
}

int kern_read_handle(int fd, struct cmd_packet* packet) {
    struct cmd_kern_read_packet* rp;
    rp = (struct cmd_kern_read_packet*)packet->data;
    if (!rp) {
        net_send_status(fd, CMD_DATA_NULL);
        return 1;
    }

    void* data = pfmalloc(rp->length);
    if (!data) {
        net_send_status(fd, CMD_DATA_NULL);
        return 1;
    }

    sys_kern_rw(rp->address, data, rp->length, 0);
    net_send_status(fd, CMD_SUCCESS);
    networkSendData(fd, data, rp->length);
    free(data);
    return 0;

}

int kern_write_handle(int fd, struct cmd_packet* packet) {
    struct cmd_kern_write_packet* wp;
    wp = (struct cmd_kern_write_packet*)packet->data;
    if (!wp) {
        net_send_status(fd, CMD_DATA_NULL);
        return 1;
    }

    void* data = pfmalloc(wp->length);
    if (!data) {
        net_send_status(fd, CMD_DATA_NULL);
        return 1;
    }

    net_send_status(fd, CMD_SUCCESS);
    networkReceiveData(fd, data, wp->length, 1);
    sys_kern_rw(wp->address, data, wp->length, 1);
    net_send_status(fd, CMD_SUCCESS);
    free(data);
    return 0;
}

int kern_handle(int fd, struct cmd_packet* packet) {
    int cmdPktType = packet->cmd;
    if (cmdPktType == CMD_KERN_BASE)  return kern_base_handle(fd, packet);
    if (cmdPktType == CMD_KERN_READ)  return kern_read_handle(fd, packet);
    if (cmdPktType == CMD_KERN_WRITE) return kern_write_handle(fd, packet);
    return 1;
}

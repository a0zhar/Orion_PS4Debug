#include "../include/net.h"

#define PS4_SYSCALL_EXEC 93
int net_select(int fd, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, struct timeval* timeout) {
    return syscall(
        PS4_SYSCALL_EXEC,
        fd,
        readfds,
        writefds,
        exceptfds,
        timeout
    );
}
#define NET_MAX_LENGTH 8192


int networkSendData(int fd, void* data, int length) {
    int left = length;
    int offset = 0;
    errno = NULL;

    while (left > 0) {
        int nextSendLen = (left > NET_MAX_LENGTH) ? NET_MAX_LENGTH : left;
        int sent = write(fd, data + offset, nextSendLen);

        if (sent <= 0) {
            if (errno && errno != EWOULDBLOCK)
                return sent;
        }
        else {
            offset += sent;
            left -= sent;
        }
    }

    return offset;
}


int networkReceiveData(int fd, void* data, int length, int force) {
    int left = length;
    int offset = 0;

    errno = NULL;

    while (left > 0) {
        int nextReadLen = (left > NET_MAX_LENGTH) ? NET_MAX_LENGTH : left;
        int recv = read(fd, data + offset, nextReadLen);

        if (recv <= 0) {
            if (!force) return offset;
            if (errno && errno != EWOULDBLOCK)
                return recv;
        }
        else {
            offset += recv;
            left -= recv;
        }
    }

    return offset;
}

int net_send_status(int fd, uint32_t status) {
    uint32_t d = status;
    return networkSendData(fd, &d, sizeof(uint32_t));
}

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "upatch-ioctl.h"
#include "upatch-socket.h"

static int ioctl_fd = -1;

static int hijacker_ioctl_init()
{    
    if (ioctl_fd != -1)
        return 0;

    ioctl_fd = open(UPATCH_HIJACKER_DEV_PATH, 0);
    if (ioctl_fd == -1)
        return -errno;
    return 0;
}

static int hijacker_socket_init()
{    
    if (access(UPATCH_SOCKET_PATH, F_OK) != 0)
        return -errno;
    return 0;
}

int upatch_hijacker_init()
{
    if (access(UPATCH_HIJACKER_DEV_PATH, F_OK) == 0)
        return hijacker_ioctl_init();
    return hijacker_socket_init();
}

static int get_ino(const char *filename, unsigned long *ino)
{
    struct stat path_stat;
    if (stat(filename, &path_stat) == -1)
        return -errno;
    *ino = path_stat.st_ino;
    return 0;
}

static int hijacker_ioctl_handler(int dev_fd, const char *prey_name,
    const char *hijacker_name, int if_register)
{
    int ret;
    struct upatch_hijack_msg msg;

    msg.prey_name = prey_name;
    ret = get_ino(msg.prey_name, &msg.prey_ino);

    if (ret)
        return ret;

    msg.hijacker_name = hijacker_name;
    ret = get_ino(msg.hijacker_name, &msg.hijacker_ino);
    if (ret)
        return ret;

    if (if_register)
        ret = ioctl(dev_fd, UPATCH_HIJACKER_REGISTER, &msg);
    else
        ret = ioctl(dev_fd, UPATCH_HIJACKER_UNREGISTER, &msg);

    if (ret == -1)
        ret = -errno;
    return ret;
}

static int hijacker_socket_handler(const char *prey_name,
    const char *hijacker_name, int if_register)
{
    int ret, execute_res, socket_fd;
    struct sockaddr_un addr;
    struct upatch_socket_msg msg;

    socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_fd == -1)
        return -errno;

    msg.magic = UPATCH_SOCKET_MAGIC;
    if (strlen(prey_name) + 1 > UPATCH_ENTRY_MAX_LEN)
        return -EINVAL;
    strncpy((char *)&msg.prey_name, prey_name, UPATCH_ENTRY_MAX_LEN - 1);

    ret = 0;
    if (!if_register)
        msg.prey_ino = 0;
    else
        ret = get_ino((char *)&msg.prey_name, &msg.prey_ino);

    if (ret)
        return ret;

    if (strlen(hijacker_name) + 1 > UPATCH_ENTRY_MAX_LEN)
        return -EINVAL;
    strncpy((char *)&msg.hijacker_name, hijacker_name, UPATCH_ENTRY_MAX_LEN - 1);

    ret = 0;
    if (!if_register)
        msg.hijacker_ino = 0;
    else
        ret = get_ino((char *)&msg.hijacker_name, &msg.hijacker_ino);
    if (ret)
        return ret;

    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, UPATCH_SOCKET_PATH, sizeof(addr.sun_path) - 1);
    ret = connect(socket_fd, (const struct sockaddr *) &addr,
        sizeof(struct sockaddr_un));
    if (ret == -1)
        return -errno;

    ret = write(socket_fd, &msg, sizeof(msg));
    if (ret != sizeof(msg))
        return -EIO;

    ret = read(socket_fd, &execute_res, sizeof(execute_res));
    if (ret != sizeof(execute_res))
        return -EIO;

    close(socket_fd);
    return execute_res;
}

int upatch_hijacker_register(const char *prey_name, const char *hijacker_name)
{
    if (ioctl_fd != -1)
        return hijacker_ioctl_handler(ioctl_fd, prey_name, hijacker_name, 1);
    return hijacker_socket_handler(prey_name, hijacker_name, 1);
}

int upatch_hijacker_unregister(const char *prey_name, const char *hijacker_name)
{
    if (ioctl_fd != -1)
        return hijacker_ioctl_handler(ioctl_fd, prey_name, hijacker_name, 0);
    return hijacker_socket_handler(prey_name, hijacker_name, 0);
}

void upatch_hijacker_cleanup(void)
{
    if (ioctl_fd != -1)
        close(ioctl_fd);
    ioctl_fd = -1;
}

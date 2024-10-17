#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "../my_firewall.h"
#define NETLINK_USER 31
#define MAX_PAYLOAD 1024

int main(int argc, char *argv[]) {
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct firewall_rule rule;
    int sock_fd;
    struct iovec iov;
    struct msghdr msg;

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();
    src_addr.nl_groups = 0;

    sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (sock_fd < 0) {
        perror("socket");
        exit(1);
    }

    bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0; // Kernel PID
    dest_addr.nl_groups = 0;

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(sizeof(struct firewall_rule));
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    if (argc > 1 && strcmp(argv[1], "add") == 0) {
        nlh->nlmsg_type = NLMSG_ADD_RULE;
    } else if (argc > 1 && strcmp(argv[1], "del") == 0) {
        nlh->nlmsg_type = NLMSG_DEL_RULE;
    } else {
        fprintf(stderr, "Usage: %s [add|del] src_ip dst_ip src_port dst_port protocol\n", argv[0]);
        exit(1);
    }

    rule.src_ip = inet_addr(argv[2]);
    rule.dst_ip = inet_addr(argv[3]);
    rule.src_port = htons(atoi(argv[4]));
    rule.dst_port = htons(atoi(argv[5]));
    rule.protocol = atoi(argv[6]);

    memcpy(NLMSG_DATA(nlh), &rule, sizeof(rule));

    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    sendmsg(sock_fd, &msg, 0);

    close(sock_fd);
    free(nlh);
    return 0;
}
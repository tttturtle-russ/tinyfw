#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/uio.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>

#define MAX_PAYLOAD 1024

// 假设 firewall_rule_user 结构体已经定义在 tinywall.h 中
#include "../public.h"

/* >-----------------rule operations-----------------<*/
// 增加规则
void rule_add(int sock_fd, struct nlmsghdr *nlh, struct sockaddr_nl *dest_addr)
{
    struct firewall_rule_user rule;
    char src_ip[16], dst_ip[16];
    int src_port_min, src_port_max, dst_port_min, dst_port_max, protocol;

    printf("Enter source IP: ");
    scanf("%s", src_ip);
    printf("Enter smask: ");
    scanf("%d", &rule.smask);
    printf("Enter destination IP: ");
    scanf("%s", dst_ip);
    printf("Enter smask: ");
    scanf("%d", &rule.dmask);
    printf("Enter min source port: ");
    scanf("%d", &src_port_min);
    printf("Enter max source port: ");
    scanf("%d", &src_port_max);
    printf("Enter min destination port: ");
    scanf("%d", &dst_port_min);
    printf("Enter max destination port: ");
    scanf("%d", &dst_port_max);
    printf("Enter protocol (1 for ICMP, 6 for TCP, 17 for UDP,): ");
    scanf("%d", &protocol);
    printf("Enter action (1 for accept, 0 for drop): ");
    scanf("%c", &rule.action);
    printf("Enter logging (0 for no logging, 1 for logging): ");
    scanf("%c", &rule.logging);

    rule.src_ip = inet_addr(src_ip);
    rule.dst_ip = inet_addr(dst_ip);
    rule.src_port_min = htons(src_port_min);
    rule.src_port_max = htons(src_port_max);
    rule.dst_port_min = htons(dst_port_min);
    rule.dst_port_max = htons(dst_port_max);
    rule.protocol = protocol;

    nlh->nlmsg_type = TINYWALL_TYPE_ADD_RULE;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = 1;
    nlh->nlmsg_pid = getpid();
    memcpy(NLMSG_DATA(nlh), &rule, sizeof(rule));

    struct iovec iov = {.iov_base = (void *)nlh, .iov_len = nlh->nlmsg_len};
    struct msghdr msg = {.msg_name = (void *)dest_addr, .msg_namelen = sizeof(*dest_addr), .msg_iov = &iov, .msg_iovlen = 1};

    if (sendmsg(sock_fd, &msg, 0) < 0)
    {
        perror("sendmsg");
        exit(1);
    }

    printf("Rule added successfully.\n");
}

// 移除规则
void rule_remove(int sock_fd, struct nlmsghdr *nlh, struct sockaddr_nl *dest_addr)
{
    printf("Enter rule ID to remove: ");
    unsigned int rule_id;
    scanf("%u", &rule_id);
    nlh->nlmsg_type = TINYWALL_TYPE_DEL_RULE;
    nlh->nlmsg_flags = rule_id;
    struct iovec iov = {.iov_base = (void *)nlh, .iov_len = nlh->nlmsg_len};
    struct msghdr msg = {.msg_name = (void *)dest_addr, .msg_namelen = sizeof(*dest_addr), .msg_iov = &iov, .msg_iovlen = 1};

    sendmsg(sock_fd, &msg, 0);
}

// 列出规则
void rules_list(int sock_fd, struct nlmsghdr *nlh, struct sockaddr_nl *dest_addr)
{
    nlh->nlmsg_type = TINYWALL_TYPE_LIST_RULES;

    struct iovec iov = {.iov_base = (void *)nlh, .iov_len = nlh->nlmsg_len};
    struct msghdr msg = {.msg_name = (void *)dest_addr, .msg_namelen = sizeof(*dest_addr), .msg_iov = &iov, .msg_iovlen = 1};

    sendmsg(sock_fd, &msg, 0);
}

// 清空规则
void rules_clear(int sock_fd, struct nlmsghdr *nlh, struct sockaddr_nl *dest_addr)
{
    nlh->nlmsg_type = TINYWALL_TYPE_CLEAR_RULES;
    struct iovec iov = {.iov_base = (void *)nlh, .iov_len = nlh->nlmsg_len};
    struct msghdr msg = {.msg_name = (void *)dest_addr, .msg_namelen = sizeof(*dest_addr), .msg_iov = &iov, .msg_iovlen = 1};
    sendmsg(sock_fd, &msg, 0);
}

int main()
{
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    int sock_fd;

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();
    src_addr.nl_groups = 0;

    sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (sock_fd < 0)
    {
        perror("socket");
        // printf("here!");
        exit(1);
    }

    bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0; // Kernel PID
    dest_addr.nl_groups = 0;

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(sizeof(struct firewall_rule_user));
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    while (1)
    {
        printf("\nMenu:\n");
        printf("0. EXIT\n");
        printf("1. Add Rule\n");
        printf("2. Remove Rule\n");
        printf("3. List Rules\n");
        printf("4. Clear Rules\n");
        printf("Choose an option: ");

        int choice;
        scanf("%d", &choice);

        switch (choice)
        {
        case 1:
            rule_add(sock_fd, nlh, &dest_addr);
            break;
        case 2:
            rule_remove(sock_fd, nlh, &dest_addr);
            break;
        case 3:
            rules_list(sock_fd, nlh, &dest_addr);
            break;
        case 4:
            rules_clear(sock_fd, nlh, &dest_addr);
            break;
        case 0:
            goto exit;
        default:
            printf("Invalid choice. Please try again.\n");
        }
    }

exit:
    close(sock_fd);
    free(nlh);
    return 0;
}
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
void rule_add(int sock_fd, struct nlmsghdr *nlh, struct sockaddr_nl *dest_addr, struct firewall_rule_user *rule)
{
    nlh->nlmsg_type = TINYWALL_TYPE_ADD_RULE;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = 1;
    nlh->nlmsg_pid = getpid();

    // 设置消息长度
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(firewall_rule_user));
    // 将规则数据拷贝到消息中
    memcpy(NLMSG_DATA(nlh), rule, sizeof(firewall_rule_user));
    // 构造消息头和数据
    struct iovec iov = {.iov_base = (void *)nlh, .iov_len = nlh->nlmsg_len};
    struct msghdr msg = {.msg_name = (void *)dest_addr, .msg_namelen = sizeof(*dest_addr), .msg_iov = &iov, .msg_iovlen = 1};
    printf("Sending message to kernel...\n");
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

// 从文件中读取规则并添加
void add_rules_from_file(int sock_fd, struct nlmsghdr *nlh, struct sockaddr_nl *dest_addr, const char *filename)
{
    FILE *file = fopen(filename, "r");
    if (!file)
    {
        perror("fopen");
        exit(1);
    }
    printf("Reading rules from %s\n", filename);
    char line[256];

    while (fgets(line, sizeof(line), file))
    {
        firewall_rule_user rule;
        char src_ip_str[16], dst_ip_str[16];
        unsigned short smask, dmask, src_port_min, src_port_max, dst_port_min, dst_port_max = 0;
        int n = sscanf(line, "%15s %hu %15s %hu %hu %hu %hu %hu %hu %hu %hu",
                       &src_ip_str, &smask,
                       &dst_ip_str, &dmask,
                       &src_port_min, &src_port_max,
                       &dst_port_min, &dst_port_max,
                       &rule.protocol, &rule.action, &rule.logging);

        if (n != 11)
        {
            fprintf(stderr, "Invalid rule format: %s", line);
            continue;
        }

        if (inet_pton(AF_INET, src_ip_str, &rule.src_ip) <= 0)
        {
            fprintf(stderr, "Invalid source IP address: %s\n", src_ip_str);
            continue;
        }

        if (inet_pton(AF_INET, dst_ip_str, &rule.dst_ip) <= 0)
        {
            fprintf(stderr, "Invalid destination IP address: %s\n", dst_ip_str);
            continue;
        }
        rule.smask = htons(smask);
        rule.dmask = htons(dmask);
        rule.src_port_min = htons(src_port_min);
        rule.src_port_max = htons(src_port_max);
        rule.dst_port_min = htons(dst_port_min);
        rule.dst_port_max = htons(dst_port_max);

        printf("src_ip: %s\n", inet_ntoa(*(struct in_addr *)&rule.src_ip));
        printf("port rage: %hu->%hu  %hu->%hu\n", ntohs(rule.src_port_min), ntohs(rule.src_port_max), ntohs(rule.dst_port_min), ntohs(rule.dst_port_max));
        printf("protocol: %hu action: %hu\n", rule.protocol, rule.action);

        rule_add(sock_fd, nlh, dest_addr, &rule);
    }

    fclose(file);
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
        exit(1);
    }

    if (bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0)
    {
        perror("bind");
        exit(1);
    }

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0; // Kernel PID
    dest_addr.nl_groups = 0;

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    if (!nlh)
    {
        perror("malloc");
        exit(1);
    }
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

        int choice = 0;
    menu:
        scanf("%d", &choice);

        switch (choice)
        {
        case 1:
            printf("Enter rule filename:\n");
            char filename[256];
            scanf("%s", filename);
            add_rules_from_file(sock_fd, nlh, &dest_addr, filename);
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
        case 5:{
            firewall_rule_user test;
            test.src_ip = 0x01020304;
            test.dst_ip = 0x05060708;
            test.src_port_min = 0x090a;
            test.src_port_max = 0x0b0c;
            test.dst_port_min = 0x0d0e;
            test.dst_port_max = 0x0f10;
            test.protocol = 0x1112;
            test.smask = 0x1213;
            test.dmask = 0x1314;
            test.action = 0x1516;
            test.logging = 0x1718;
            printf("src_ip: %s\n", inet_ntoa(*(struct in_addr *)&test.src_ip));
            printf("port rage: %hu->%hu  %hu->%hu\n", ntohs(test.src_port_min), ntohs(test.src_port_max), ntohs(test.dst_port_min), ntohs(test.dst_port_max));
            rule_add(sock_fd, nlh, &dest_addr, &test);
            break;
        }
            
        default:
            printf("Invalid choice. Please try again.\n");
            goto menu;
        }
    }

exit:
    close(sock_fd);
    free(nlh);
    return 0;
}
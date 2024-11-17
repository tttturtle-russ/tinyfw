#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/uio.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>

#define MAX_PAYLOAD 1024

// 假设 tinywall_rule_user 结构体已经定义在 tinywall.h 中
#include "../public.h"

/* >----------------------------------rule operations----------------------------------<*/
// 增加规则
int rule_add(int sock_fd, struct nlmsghdr *nlh, struct sockaddr_nl *dest_addr, struct tinywall_rule_user *rule)
{
    nlh->nlmsg_type = TINYWALL_TYPE_ADD_RULE;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = 1;
    nlh->nlmsg_pid = getpid();

    // 设置消息长度
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(tinywall_rule_user));
    // 将规则数据拷贝到消息中
    memcpy(NLMSG_DATA(nlh), rule, sizeof(tinywall_rule_user));
    // 构造消息头和数据
    struct iovec iov = {.iov_base = (void *)nlh, .iov_len = nlh->nlmsg_len};
    struct msghdr msg = {.msg_name = (void *)dest_addr, .msg_namelen = sizeof(*dest_addr), .msg_iov = &iov, .msg_iovlen = 1};
    printf("Sending message to kernel...\n");
    if (sendmsg(sock_fd, &msg, 0) < 0)
    {
        perror("sendmsg");
        return -2;
    }

    printf("Rule added successfully.\n");
    return 0;
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
int load_rules_from_file(int sock_fd, struct nlmsghdr *nlh, struct sockaddr_nl *dest_addr, const char *filename)
{
    int ret = 0;
    FILE *file = fopen(filename, "r");
    if (!file)
    {
        perror("fopen");
        return -1;
    }
    printf("Reading rules from %s\n", filename);
    char line[256];

    while (fgets(line, sizeof(line), file))
    {
        tinywall_rule_user rule;
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
        rule.protocol = htons(rule.protocol);
        rule.action = htons(rule.action);
        rule.logging = htons(rule.logging);
        printf("src_ip: %s\n", inet_ntoa(*(struct in_addr *)&rule.src_ip));
        printf("port rage: %hu->%hu  %hu->%hu\n", ntohs(rule.src_port_min), ntohs(rule.src_port_max), ntohs(rule.dst_port_min), ntohs(rule.dst_port_max));
        printf("protocol: %hu action: %hu\n", rule.protocol, rule.action);
        ret = rule_add(sock_fd, nlh, dest_addr, &rule);
        if (ret == -2)
        {
            printf("Error adding rule\n");
            return ret;
        }
    }

    fclose(file);
    return ret;
}

// 将规则表保存为文件
void rules_store(int sock_fd, struct nlmsghdr *nlh, struct sockaddr_nl *dest_addr)
{
    nlh->nlmsg_type = TINYWALL_TYPE_STORE_RULES;
    // 发送缓冲区
    struct iovec iov = {.iov_base = (void *)nlh, .iov_len = nlh->nlmsg_len};
    struct msghdr msg = {.msg_name = (void *)dest_addr, .msg_namelen = sizeof(*dest_addr), .msg_iov = &iov, .msg_iovlen = 1};

    // 接收缓冲区
    char buffer[65535];
    struct iovec iov_recv = {buffer, sizeof(buffer)};
    struct msghdr msg_recv = {NULL};
    struct nlmsghdr *nlh_recv = NULL;
    int ret;
    int count = 0;
    // 从内核接受数据
    msg_recv.msg_name = (void *)&dest_addr;
    msg_recv.msg_namelen = sizeof(dest_addr);
    msg_recv.msg_iov = &iov_recv;
    msg_recv.msg_iovlen = 1;
    // 发送store命令
    sendmsg(sock_fd, &msg, 0);
    while (1)
    {
        int num;
        ret = recvmsg(sock_fd, &msg_recv, 0);
        if (ret < 0)
        {
            perror("recvmsg");
            break;
        }

        nlh = (struct nlmsghdr *)buffer;

        // 规则数量
        num = nlh->nlmsg_flags;
        while (NLMSG_OK(nlh, ret))
        {
            if (nlh->nlmsg_type == NLMSG_DONE)
            {
                tinywall_rule_user *rule = (tinywall_rule_user *)NLMSG_DATA(nlh);

                // 打开文件
                FILE *fp = fopen("rule_table.txt", "a");
                if (fp == NULL)
                {
                    perror("fopen");
                    break;
                }

                // 写入规则
                fprintf(fp, "%s %d %s %d %d %d %d %d %d %d %d\n",
                        inet_ntoa(*(struct in_addr *)&rule->src_ip),
                        ntohs(rule->smask),
                        inet_ntoa(*(struct in_addr *)&rule->dst_ip),
                        ntohs(rule->dmask),
                        ntohs(rule->src_port_min),
                        ntohs(rule->src_port_max),
                        ntohs(rule->dst_port_min),
                        ntohs(rule->dst_port_max),
                        ntohs(rule->protocol),
                        ntohs(rule->action),
                        ntohs(rule->logging));
                count++;
                fclose(fp);
                printf("Rule added to rule_table.txt\n");
            }
            nlh = NLMSG_NEXT(nlh, ret);
        }
        printf("num: %d\n", num);
        printf("count: %d\n", count);
        if (count == num)
            break;
    }
}

void log_show(int sock_fd, struct nlmsghdr *nlh, struct sockaddr_nl *dest_addr)
{
    nlh->nlmsg_type = TINYWALL_TYPE_LOG_SHOW;
    struct iovec iov = {.iov_base = (void *)nlh, .iov_len = nlh->nlmsg_len};
    struct msghdr msg = {.msg_name = (void *)dest_addr, .msg_namelen = sizeof(*dest_addr), .msg_iov = &iov, .msg_iovlen = 1};
    sendmsg(sock_fd, &msg, 0);
}

void load_kernel_modules()
{
    // 加载 tinywall.ko 和 tinywall_nl.ko
    if (system("sudo insmod tinywall.ko") != 0)
    {
        perror("Failed to load tinywall.ko");
        exit(1);
    }
    if (system("sudo insmod tinywall_nl.ko") != 0)
    {
        perror("Failed to load tinywall_nl.ko");
        exit(1);
    }
}

void unload_kernel_modules()
{
    // 卸载 tinywall.ko 和 tinywall_nl.ko
    if (system("sudo rmmod tinywall_nl.ko") != 0)
    {
        perror("Failed to unload tinywall_nl.ko");
        exit(1);
    }
    if (system("sudo rmmod tinywall.ko") != 0)
    {
        perror("Failed to unload tinywall.ko");
        exit(1);
    }
}
int main(int argc, char** argv)
{
    if (argc != 2)
    {
        printf("Usage: %s [command]\n", argv[0]);
        exit(1);
    }
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    int sock_fd;
    int ret = 0;
    load_kernel_modules();
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
    nlh->nlmsg_len = NLMSG_SPACE(sizeof(struct tinywall_rule_user));
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    if (!strcmp(argv[1],"load")){
        if (argc != 3) {
            printf("Usage: %s load <rule_file>\n", argv[0]);
            exit(1);
        }
        char* file = argv[2];
        ret = load_rules_from_file(sock_fd, nlh, &dest_addr, file);
        if (ret == -1)
            {
                printf("Error: file doesn't exist\n");
                goto exit;
            }
            else if (ret == -2)
            {
                printf("Error: socket发送rule失败!");
                goto exit;
            }
    }
    else if (!strcmp(argv[1], "remove")){
        rule_remove(sock_fd, nlh, &dest_addr);
    }
    else if (!strcmp(argv[1], "list")){
        rules_list(sock_fd, nlh, &dest_addr);
    }
    else if (!strcmp(argv[1], "clear")){
        rules_clear(sock_fd, nlh, &dest_addr);
    }
    else if (!strcmp(argv[1], "store")){
        rules_store(sock_fd, nlh, &dest_addr);
    }else {
        printf("Invalid command\n");
        exit(1);
    }

    // while (1)
    // {
    // menu:
    //     printf("\nMenu:\n");
    //     printf("0. EXIT\n");
    //     printf("1. Load Rule\n");
    //     printf("2. Remove Rule\n");
    //     printf("3. List Rules\n");
    //     printf("4. Clear Rules\n");
    //     printf("5. Store Rules\n");
    //     printf("6. Show logs\n");
    //     printf("Choose an option: ");

    //     int choice = 0;
    //     scanf("%d", &choice);

    //     switch (choice)
    //     {
    //     case 0:
    //         goto exit;
    //     case 1:
    //         printf("Enter rule filename:\n");
    //         char filename[256];
    //         scanf("%s", filename);
    //         ret = load_rules_from_file(sock_fd, nlh, &dest_addr, filename);
    //         if (ret == -1)
    //         {
    //             printf("Error: file doesn't exist\n");
    //             goto menu;
    //         }
    //         else if (ret == -2)
    //         {
    //             printf("Error: socket发送rule失败!");
    //             goto exit;
    //         }
    //         break;
    //     case 2:
    //         rule_remove(sock_fd, nlh, &dest_addr);
    //         break;
    //     case 3:
    //         rules_list(sock_fd, nlh, &dest_addr);
    //         break;
    //     case 4:
    //         rules_clear(sock_fd, nlh, &dest_addr);
    //         break;
    //     case 5:
    //         rules_store(sock_fd, nlh, &dest_addr);
    //         break;
    //     case 6:
    //         log_show(sock_fd, nlh, &dest_addr);
    //         break;
    //     default:
    //         printf("Invalid choice. Please try again.\n");
    //         goto menu;
    //     }
    // }

exit:
    close(sock_fd);
    free(nlh);
    unload_kernel_modules();
    return 0;
}
// my_firewall_netlink.c
#include "my_firewall.h"
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/net_namespace.h>
#include <net/sock.h>

#define NETLINK_USER 31

struct sock *nl_sk = NULL;

// Netlink消息接收函数
static void nl_recv_msg(struct sk_buff *skb) {
    struct nlmsghdr *nlh;
    int pid;
    struct sk_buff *skb_out;
    int msg_size;
    char *msg = "Firewall rule updated";
    int res;

    msg_size = strlen(msg);

    nlh = (struct nlmsghdr *)skb->data;
    printk(KERN_INFO MODULE_NAME ": Received netlink message payload: %s\n", (char *)nlmsg_data(nlh));
    pid = nlh->nlmsg_pid; // PID of sending process

    skb_out = nlmsg_new(msg_size, 0);
    if (!skb_out) {
        printk(KERN_ERR MODULE_NAME ": Failed to allocate new skb\n");
        return;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    strncpy(nlmsg_data(nlh), msg, msg_size);

    res = nlmsg_unicast(nl_sk, skb_out, pid);
    if (res < 0)
        printk(KERN_INFO MODULE_NAME ": Error while sending back to user\n");
}

// Netlink通信初始化
static int __init firewall_netlink_init(void) {
    struct netlink_kernel_cfg cfg = {
        .input = nl_recv_msg,
    };

    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
    if (!nl_sk) {
        printk(KERN_ALERT MODULE_NAME ": Error creating socket.\n");
        return -10;
    }

    printk(KERN_INFO MODULE_NAME ": Netlink module loaded.\n");
    return 0;
}

// Netlink通信退出
static void __exit firewall_netlink_exit(void) {
    netlink_kernel_release(nl_sk);
    printk(KERN_INFO MODULE_NAME ": Netlink module unloaded.\n");
}

module_init(firewall_netlink_init);
module_exit(firewall_netlink_exit);

// MODULE_LICENSE("GPL");
// MODULE_AUTHOR("sxk");
// MODULE_DESCRIPTION("Custom Netfilter Firewall Module with Netlink Interface");
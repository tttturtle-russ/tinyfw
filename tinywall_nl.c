// tinywall_nl.c
#include "tinywall.h"
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/net_namespace.h>
#include <net/sock.h>

#define NETLINK_USER 31

struct sock *nl_sk = NULL;

// Netlink消息接收函数
static void nl_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    firewall_rule rule;

    nlh = nlmsg_hdr(skb);
    memcpy(&rule, nlmsg_data(nlh), sizeof(rule));

    if (nlh->nlmsg_type == NLMSG_ADD_RULE)
    {
        tinywall_rule_add(&rule);
    }
    else if (nlh->nlmsg_type == NLMSG_DEL_RULE)
    {
        tinywall_rule_remove(&rule);
    }
    else if (nlh->nlmsg_type == NLMSG_LIST_RULE)
    {
        tinywall_rules_list();
    }
}

static void nl_send_msg(int type, firewall_rule *rule)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    int msg_size = NLMSG_SPACE(sizeof(firewall_rule));

    skb = alloc_skb(msg_size, GFP_KERNEL);
    if (!skb)
    {
        printk(KERN_ALERT MODULE_NAME ": Error allocating skb.\n");
    }
}
// Netlink通信初始化
static int __init firewall_netlink_init(void)
{
    struct netlink_kernel_cfg cfg = {
        .input = nl_recv_msg,
    };

    // initiate the netlink socket
    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
    if (!nl_sk)
    {
        printk(KERN_ALERT MODULE_NAME ": Error creating socket.\n");
        return -10;
    }

    printk(KERN_INFO MODULE_NAME ": Netlink module loaded.\n");
    return 0;
}

// Netlink通信退出
static void __exit firewall_netlink_exit(void)
{
    // release the netlink socket
    netlink_kernel_release(nl_sk);
    printk(KERN_INFO MODULE_NAME ": Netlink module unloaded.\n");
}

module_init(firewall_netlink_init);
module_exit(firewall_netlink_exit);

// MODULE_LICENSE("GPL");
// MODULE_AUTHOR("sxk");
// MODULE_DESCRIPTION("Custom Netfilter Firewall Module with Netlink Interface");
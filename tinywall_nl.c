// tinywall_nl.c
#include "tinywall.h"
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/net_namespace.h>
#include <net/sock.h>

struct sock *nl_sk = NULL;

// Netlink消息接收函数
static void nl_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    struct firewall_rule_user *rule;

    nlh = nlmsg_hdr(skb);
    rule = (struct firewall_rule_user *)nlmsg_data(nlh);
    unsigned int rule_id_to_delete = nlh->nlmsg_flags;

    if (nlh->nlmsg_type == TINYWALL_TYPE_ADD_RULE)
    {
        printk(KERN_INFO MODULE_NAME ": Received a new rule to add.\n");
        printk(KERN_INFO MODULE_NAME ": Add a new rule: %pI4:%d-%d smask:%d -> %pI4:%d-%d dmask:%d, proto: %u\n",
               &rule->src_ip, ntohs(rule->src_port_min), ntohs(rule->src_port_max),
               &rule->smask,
               &rule->dst_ip, ntohs(rule->dst_port_min), ntohs(rule->dst_port_max),
               &rule->dmask,
               rule->protocol);
        tinywall_rule_add(rule);
    }
    else if (nlh->nlmsg_type == TINYWALL_TYPE_DEL_RULE)
    {
        printk(KERN_INFO MODULE_NAME ": Received a rule to delete.\n");
        printk(KERN_INFO MODULE_NAME ": delete the rule with ID: %d\n", rule_id_to_delete);
        tinywall_rule_remove(rule_id_to_delete);
    }
    else if (nlh->nlmsg_type == TINYWALL_TYPE_LIST_RULES)
    {
        printk(KERN_INFO MODULE_NAME ": Received a request to list rules.\n");
        tinywall_rules_list();
    }
    else if (nlh->nlmsg_type == TINYWALL_TYPE_CLEAR_RULES)
    {
        printk(KERN_INFO MODULE_NAME ": Received a request to clear rules.\n");
        tinywall_rules_clear();
    }
    else
    {
        printk(KERN_INFO MODULE_NAME ": Unknown message type: %d\n", nlh->nlmsg_type);
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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("sxk");
MODULE_DESCRIPTION("Custom Netfilter Firewall Module with Netlink Interface");
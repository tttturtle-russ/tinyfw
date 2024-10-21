// tinywall_nl.c
#include "tinywall.h"
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/net_namespace.h>
#include <net/sock.h>

struct sock *nl_sk = NULL;

/* >-----------------内核处理输入部分-----------------<*/
static void nl_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    struct firewall_rule *rule;

    // check the skb and nlh size
    if (!skb || skb->len < sizeof(*nlh))
    {
        printk(KERN_ERR "Invalid skb or nlh size\n");
        return;
    }

    nlh = nlmsg_hdr(skb);
    // if (nlh->nlmsg_len < sizeof(*rule))
    // {
    //     printk(KERN_ERR "Message too short\n");
    //     return;
    // }
    rule = (struct firewall_rule *)NLMSG_DATA(nlh);
    unsigned int rule_id_to_delete = nlh->nlmsg_flags;

    // 确保 rule 结构体中的 IP 地址是有效的
    if (!rule->src_ip || !rule->dst_ip)
    {
        printk(KERN_ERR "Invalid IP addresses\n");
        return;
    }

    // 将 __be32 类型的 IP 地址转换为 struct in_addr 类型
    struct in_addr src_ip, dst_ip;
    src_ip.s_addr = rule->src_ip;
    dst_ip.s_addr = rule->dst_ip;
    if (nlh->nlmsg_type == TINYWALL_TYPE_ADD_RULE)
    {
        printk(KERN_INFO MODULE_NAME ": Netlink message received.\n");
        printk(KERN_INFO MODULE_NAME ": Add a new rule: %pI4:%d-%d smask:%d -> %pI4:%d-%d dmask:%d, proto: %u, action: %u, logging: %u\n",
               &src_ip, ntohs(rule->src_port_min), ntohs(rule->src_port_max), ntohs(rule->smask),
               &dst_ip, ntohs(rule->dst_port_min), ntohs(rule->dst_port_max), ntohs(rule->dmask),
               ntohs(rule->protocol), ntohs(rule->action), ntohs(rule->logging));
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

/* >-----------------内核发送部分-----------------<*/
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

/* >-----------------netlink init()-----------------<*/
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

/* >-----------------netlink_exit()-----------------<*/
static void __exit firewall_netlink_exit(void)
{
    // release the netlink socket
    netlink_kernel_release(nl_sk);
    printk(KERN_INFO MODULE_NAME ": Netlink module unloaded.\n");
}

/* >-----------------module init()/exit()-----------------<*/
module_init(firewall_netlink_init);
module_exit(firewall_netlink_exit);

/* >-----------------module license-----------------<*/
MODULE_LICENSE("GPL");
MODULE_AUTHOR("sxk");
MODULE_DESCRIPTION("Custom Netfilter Firewall Module with Netlink Interface");
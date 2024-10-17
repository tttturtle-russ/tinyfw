// tinywall.c
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include "tinywall.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("sxk");
MODULE_DESCRIPTION("Custom Netfilter Firewall Module");

// 初始化规则链表和锁
struct tinywall_rule_table rule_list;
// spinlock_t rule_lock = __SPIN_LOCK_UNLOCKED(rule_lock);

// 添加规则函数
int tinywall_rule_add(firewall_rule_user *new_rule)
{
    if (!new_rule)
        return -ENOMEM;
    firewall_rule *rule = kmalloc(sizeof(*rule), GFP_KERNEL);
    if (!rule)
        return -ENOMEM;
    rule->src_ip = new_rule->src_ip;
    rule->dst_ip = new_rule->dst_ip;
    rule->src_port = new_rule->src_port;
    rule->dst_port = new_rule->dst_port;
    rule->protocol = new_rule->protocol;

    write_lock(&rule_list.lock);
    list_add(&rule->list, &rule_list.head);
    rule_list.rule_count++;
    write_unlock(&rule_list.lock);

    printk(KERN_INFO MODULE_NAME ": Added rule: %pI4:%d -> %pI4:%d, proto: %u\n",
           &rule->src_ip, ntohs(rule->src_port),
           &rule->dst_ip, ntohs(rule->dst_port),
           rule->protocol);
    return 0;
}

// 删除规则函数
int tinywall_rule_remove(struct firewall_rule_user *rule_to_del)
{
    struct firewall_rule *rule;
    int found = 0;

    read_lock(&rule_list.lock);
    list_for_each_entry(rule, &rule_list.head, list)
    {
        if (rule->src_ip == rule_to_del->src_ip &&
            rule->dst_ip == rule_to_del->dst_ip &&
            rule->src_port == rule_to_del->src_port &&
            rule->dst_port == rule_to_del->dst_port &&
            rule->protocol == rule_to_del->protocol)
        {
            list_del(&rule->list);
            rule_list.rule_count--;
            kfree(rule);
            found = 1;
            printk(KERN_INFO MODULE_NAME ": Removed rule: %pI4:%d -> %pI4:%d, proto: %u\n",
                   &rule->src_ip, ntohs(rule->src_port),
                   &rule->dst_ip, ntohs(rule->dst_port),
                   rule->protocol);
            break;
        }
    }
    read_unlock(&rule_list.lock);
    return found ? 0 : -ENOENT;
}

void tinywall_rules_list(void)
{
    struct firewall_rule *rule;
    write_lock(&rule_list.lock);
    list_for_each_entry(rule, &rule_list.head, list)
    {
        printk(KERN_INFO MODULE_NAME ": Rule: %pI4:%d -> %pI4:%d, proto: %u\n",
               &rule->src_ip, ntohs(rule->src_port),
               &rule->dst_ip, ntohs(rule->dst_port),
               rule->protocol);
    }
    write_unlock(&rule_list.lock);
    return;
}

// Netfilter钩子函数
static unsigned int firewall_hook(void *priv,
                                  struct sk_buff *skb,
                                  const struct nf_hook_state *state)
{
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    firewall_rule *rule;
    int match = 0;

    if (!skb)
        return NF_ACCEPT;

    ip_header = ip_hdr(skb);
    if (!ip_header)
        return NF_ACCEPT;

    // 只处理TCP协议
    if (ip_header->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    tcp_header = tcp_hdr(skb);
    if (!tcp_header)
        return NF_ACCEPT;

    // 检查连接状态（示例：仅允许已建立的连接）
    if (!(tcp_header->syn || tcp_header->fin || tcp_header->rst))
    {
        // 这里可以结合连接跟踪进行更复杂的状态检查
    }

    write_lock(&rule_list.lock);
    list_for_each_entry(rule, &rule_list.head, list)
    {
        if ((rule->src_ip == ip_header->saddr || rule->src_ip == 0) &&
            (rule->dst_ip == ip_header->daddr || rule->dst_ip == 0) &&
            (rule->src_port == tcp_header->source || rule->src_port == 0) &&
            (rule->dst_port == tcp_header->dest || rule->dst_port == 0) &&
            (rule->protocol == ip_header->protocol || rule->protocol == 0))
        {
            match = 1;
            break;
        }
    }
    write_unlock(&rule_list.lock);

    if (match)
    {
        printk(KERN_INFO MODULE_NAME ": Packet matched rule, dropping.\n");
        return NF_DROP;
    }

    return NF_ACCEPT;
}

// 定义Netfilter钩子
static struct nf_hook_ops firewall_nfho = {
    .hook = firewall_hook,
    .pf = PF_INET,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

// 模块初始化
static int __init firewall_init(void)
{
    int ret;

    // 注册Netfilter钩子
    ret = nf_register_net_hook(&init_net, &firewall_nfho);
    if (ret)
    {
        printk(KERN_ERR MODULE_NAME ": Failed to register nethook\n");
        return ret;
    }

    printk(KERN_INFO MODULE_NAME ": Firewall module loaded.\n");
    return 0;
}

// 模块退出
static void __exit firewall_exit(void)
{
    struct firewall_rule *rule, *tmp;

    // 注销Netfilter钩子
    nf_unregister_net_hook(&init_net, &firewall_nfho);

    // 清空规则链表
    write_lock(&rule_list.lock);
    list_for_each_entry_safe(rule, tmp, &rule_list.head, list)
    {
        list_del(&rule->list);
        kfree(rule);
    }
    write_unlock(&rule_list.lock);

    printk(KERN_INFO MODULE_NAME ": Firewall module unloaded.\n");
}

module_init(firewall_init);
module_exit(firewall_exit);

EXPORT_SYMBOL(tinywall_rules_list);
EXPORT_SYMBOL(tinywall_rule_remove);
EXPORT_SYMBOL(tinywall_rule_add);
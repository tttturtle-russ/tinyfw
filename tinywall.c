// tinywall.c
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/types.h>
#include "tinywall.h"

// 初始化规则链表和锁
struct tinywall_rule_table *rule_table = NULL;
// 初始化连接表
struct tinywall_conntable *conn_table = NULL;

/* >-----------------规则表部分-----------------<*/
// RULE TABLE INIT FUNCTION
struct tinywall_rule_table *tinywall_rule_table_init(void)
{
    // 初始化规则链表和锁
    rule_table = kmalloc(sizeof(struct tinywall_rule_table), GFP_KERNEL);
    if (!rule_table)
        return NULL;
    INIT_LIST_HEAD(&rule_table->head);
    rwlock_init(&rule_table->lock);
    rule_table->rule_count = 0;
    return rule_table;
}

// RULE TABLE ADD FUNCTION
int tinywall_rule_add(firewall_rule_user *new_rule)
{
    if (!new_rule)
        return -ENOMEM;
    firewall_rule *rule = kmalloc(sizeof(*rule), GFP_KERNEL);
    if (!rule)
        return -ENOMEM;
    rule->src_ip = new_rule->src_ip;
    rule->dst_ip = new_rule->dst_ip;
    rule->src_port_min = new_rule->src_port_min;
    rule->src_port_max = new_rule->src_port_max;
    rule->dst_port_min = new_rule->dst_port_min;
    rule->dst_port_max = new_rule->dst_port_max;
    rule->protocol = new_rule->protocol;

    write_lock(rule_table->lock);
    list_add(&rule->list, rule_table->head);
    rule_table->rule_count++;
    write_unlock(rule_table->lock);

    printk(KERN_INFO MODULE_NAME ": Added rule: %pI4:%d-%d smask:%d -> %pI4:%d-%d dmask:%d, proto: %u\n",
           &rule->src_ip, ntohs(rule->src_port_min), ntohs(rule->src_port_max),
           &rule->smask,
           &rule->dst_ip, ntohs(rule->dst_port_min), ntohs(rule->dst_port_max),
           &rule->dmask,
           rule->protocol);
    return 0;
}

// RULE DEL FUNCTION
int tinywall_rule_remove(unsigned int rule_id_to_del)
{
    struct firewall_rule *rule;
    bool found = 0;
    int rule_number = 0;
    write_lock(rule_table->lock);
    list_for_each_entry(rule, rule_table->head, list)
    {
        rule_number++;
        if (rule_number == rule_id_to_del)
        {
            list_del(&rule->list);
            printk(KERN_INFO MODULE_NAME ": Deleted rule %d\n", rule_number);
            kfree(rule);
            found = 1;
            break;
        }
    }
    write_unlock(rule_table->lock);
    if (!found)
    {
        printk(KERN_ERR MODULE_NAME ": Rule %d not found\n", rule_id_to_del);
        return -EINVAL;
    }
    return 0;
}

// RULE LIST FUNCTION
void tinywall_rules_list(void)
{
    struct firewall_rule *rule;
    bool has_rules = false;
    int rule_number = 0; // 用于记录规则的序号

    read_lock(rule_table->lock);

    // 遍历 rule_table
    list_for_each_entry(rule, rule_table->head, list)
    {
        has_rules = true;
        rule_number++;
        printk(KERN_INFO MODULE_NAME ": Rule %d: %pI4:%d-%d smask:%d -> %pI4:%d-%d dmask:%d, proto: %u\n",
               rule_number,
               &rule->src_ip, ntohs(rule->src_port_min), ntohs(rule->src_port_max), rule->smask,
               &rule->dst_ip, ntohs(rule->dst_port_min), ntohs(rule->dst_port_max), rule->dmask,
               rule->protocol);
    }

    // 如果没有规则，输出 "NO RULES"
    if (!has_rules)
    {
        printk(KERN_INFO MODULE_NAME ": NO RULES\n");
    }

    read_unlock(rule_table->lock);
    return;
}

// RULE CLEAR FUNCTION
void tinywall_rules_clear(void)
{
    struct firewall_rule *rule, *tmp;

    write_lock(rule_table->lock);
    list_for_each_entry_safe(rule, tmp, rule_table->head, list)
    {
        list_del(&rule->list);
        kfree(rule);
    }
    write_unlock(rule_table->lock);
}

/* >-----------------连接表部分-----------------<*/
/* CONNTABLE INIT FUNCTIONS */
struct tinywall_conntable *tinywall_conntable_init()
{
    struct tinywall_conntable *table = kvzalloc(sizeof(*table), GFP_KERNEL);
    if (!table)
        return NULL;

    hash_init(table->hashtable);
    rwlock_init(&table->lock);
    return table;
}

/* >-----------------子模块部分-----------------<*/
static unsigned int firewall_hook(void *priv,
                                  struct sk_buff *skb,
                                  const struct nf_hook_state *state)
{
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    struct icmphdr *icmp_header;
    firewall_rule *rule;
    int match = -1; // 匹配动作

    /*空数据包或者空ip头*/
    if (!skb)
    {
        return NF_ACCEPT;
    }

    ip_header = ip_hdr(skb);
    if (!ip_header)
    {
        return NF_ACCEPT;
    }

    // 处理ICMP协议
    /*TODO_1:每一个有效ACCEPT都要在连接表中新建连接
    TODO_2:根据rule.logging字段是否记录日志*/
    if (ip_header->protocol == IPPROTO_ICMP)
    {
        icmp_header = (struct icmphdr *)((unsigned char *)ip_header + (ip_header->ihl * 4));
        if (!icmp_header)
        {
            // printk("null icmp_header");
            return NF_ACCEPT;
        }
        // 检测是否匹配上规则
        read_lock(rule_table->lock);
        list_for_each_entry(rule, rule_table->head, list)
        {
            if (((rule->src_ip == ip_header->saddr || rule->src_ip == 0) ||
                 (rule->src_ip & rule->smask) == (ip_header->saddr & rule->smask)) &&
                ((rule->dst_ip == ip_header->daddr || rule->dst_ip == 0) ||
                 (rule->dst_ip & rule->dmask) == (ip_header->daddr & rule->dmask)) &&
                (rule->protocol == ip_header->protocol || rule->protocol == 0))
            {
                match = rule->action;
                break;
            }
        }
        read_unlock(rule_table->lock);

        if (match == NF_ACCEPT)
        {
            printk(KERN_INFO MODULE_NAME ": Packet matched rule, rule's action is NF_ACCEPT.\n");
            return NF_ACCEPT;
        }
        else if (match == NF_DROP)
        {
            printk(KERN_INFO MODULE_NAME ": Packet matched rule, rule's action is NF_DROP.\n");
            return NF_DROP;
        }
    }

    // 处理TCP协议
    /*TODO_1:每一个有效ACCEPT都要在连接表中新建连接
    TODO_2:根据rule.logging字段是否记录日志*/
    if (ip_header->protocol == IPPROTO_TCP)
    {
        tcp_header = tcp_hdr(skb);
        if (!tcp_header)
        {
            printk(KERN_ERR MODULE_NAME ": TCP header is NULL\n");
            return NF_ACCEPT;
        }
        // 检测是否匹配上规则
        read_lock(&rule_table->lock);
        list_for_each_entry(rule, rule_table->head, list)
        {
            if (((rule->src_ip == ip_header->saddr || rule->src_ip == 0) ||
                 (rule->src_ip & rule->smask) == (ip_header->saddr & rule->smask)) &&
                ((rule->dst_ip == ip_header->daddr || rule->dst_ip == 0) ||
                 (rule->dst_ip & rule->dmask) == (ip_header->daddr & rule->dmask)) &&
                (ntohs(tcp_header->source) >= rule->src_port_min && ntohs(tcp_header->source) <= rule->src_port_max) &&
                (ntohs(tcp_header->dest) >= rule->dst_port_min && ntohs(tcp_header->dest) <= rule->dst_port_max) &&
                (rule->protocol == ip_header->protocol || rule->protocol == 0))
            {
                match = rule->action;
                break;
            }
        }
        read_unlock(&rule_table->lock);

        if (match == NF_ACCEPT)
        {
            printk(KERN_INFO MODULE_NAME ": Packet matched rule, rule's action is NF_ACCEPT.\n");
            return NF_ACCEPT;
        }
        else if (match == NF_DROP)
        {
            printk(KERN_INFO MODULE_NAME ": Packet matched rule, rule's action is NF_DROP.\n");
            return NF_DROP;
        }
        return NF_ACCEPT;
    }

    // 处理UDP协议
    /*TODO_1:每一个有效ACCEPT都要在连接表中新建连接
    TODO_2:根据rule.logging字段是否记录日志*/
    // 处理UDP协议
    if (ip_header->protocol == IPPROTO_UDP)
    {
        udp_header = udp_hdr(skb);
        if (!udp_header)
        {
            printk(KERN_ERR MODULE_NAME ": UDP header is NULL\n");
            return NF_ACCEPT;
        }

        // 检测是否匹配上规则
        read_lock(&rule_table->lock);
        list_for_each_entry(rule, rule_table->head, list)
        {
            if (((rule->src_ip == ip_header->saddr || rule->src_ip == 0) ||
                 (rule->src_ip & rule->smask) == (ip_header->saddr & rule->smask)) &&
                ((rule->dst_ip == ip_header->daddr || rule->dst_ip == 0) ||
                 (rule->dst_ip & rule->dmask) == (ip_header->daddr & rule->dmask)) &&
                (ntohs(udp_header->source) >= rule->src_port_min && ntohs(udp_header->source) <= rule->src_port_max) &&
                (ntohs(udp_header->dest) >= rule->dst_port_min && ntohs(udp_header->dest) <= rule->dst_port_max) &&
                (rule->protocol == ip_header->protocol || rule->protocol == 0))
            {
                match = rule->action;
                break;
            }
        }
        read_unlock(&rule_table->lock);

        if (match == NF_ACCEPT)
        {
            printk(KERN_INFO MODULE_NAME ": Packet matched rule, rule's action is NF_ACCEPT.\n");
            return NF_ACCEPT;
        }
        else if (match == NF_DROP)
        {
            printk(KERN_INFO MODULE_NAME ": Packet matched rule, rule's action is NF_DROP.\n");
            return NF_DROP;
        }
        return NF_ACCEPT;
    }
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

    /* 初始化规则表 */
    tinywall_rule_table_init();

    /* 初始化连接表 */
    tinywall_conntable_init();
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
    write_lock(rule_table->lock);
    list_for_each_entry_safe(rule, tmp, rule_table->head, list)
    {
        list_del(&rule->list);
        kfree(rule);
    }
    write_unlock(rule_table->lock);

    printk(KERN_INFO MODULE_NAME ": Firewall module unloaded.\n");
}

module_init(firewall_init);
module_exit(firewall_exit);

EXPORT_SYMBOL(tinywall_rules_list);
EXPORT_SYMBOL(tinywall_rule_remove);
EXPORT_SYMBOL(tinywall_rule_add);
EXPORT_SYMBOL(tinywall_rules_clear);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sun Xiaokai suxiaokai34@gmail.com");
MODULE_DESCRIPTION("A Tiny Netfilter Firewall Module");
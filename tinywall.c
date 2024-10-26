// tinywall.c
#include "tinywall.h"
static int default_timeout_tcp = 300;
static int default_timeout_udp = 180;
static int default_timeout_icmp = 100;
static int default_timeout_others = 100;

#ifdef __BIG_ENDIAN__
#define htonll(x) (x)
#define ntohll(x) (x)
#else
#define htonll(x) (((__u64)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) (((__u64)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#endif

#define ktime_add_sec(kt, sval) (ktime_add_ns((kt), (sval) * NSEC_PER_SEC))
// 初始化规则链表和锁
static struct tinywall_rule_table rule_table;
// 初始化连接表
struct tinywall_conn_table conn_table;

/* >----------------------------------规则表部分----------------------------------<*/
// RULE TABLE INIT FUNCTION
void tinywall_rule_table_init(void)
{
    // 初始化规则链表和锁
    INIT_LIST_HEAD(&rule_table.head);
    rwlock_init(&rule_table.lock);
    rule_table.rule_count = 0;
    return;
}

// RULE TABLE ADD FUNCTION
int tinywall_rule_add(firewall_rule *new_rule)
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
    rule->action = new_rule->action;
    rule->smask = new_rule->smask;
    rule->dmask = new_rule->dmask;
    rule->logging = new_rule->logging;
    printk("tinywall_rule_add");
    write_lock(&rule_table.lock);
    list_add(&rule->list, &rule_table.head);
    rule_table.rule_count++;
    write_unlock(&rule_table.lock);

    // 将 __be32 类型的 IP 地址转换为 struct in_addr 类型
    struct in_addr src_ip, dst_ip;
    src_ip.s_addr = rule->src_ip;
    dst_ip.s_addr = rule->dst_ip;
    printk(KERN_INFO MODULE_NAME ": Add a new rule: %pI4:%d-%d smask:%d -> %pI4:%d-%d dmask:%d, proto: %u, action: %u, logging: %u\n",
           &src_ip, ntohs(rule->src_port_min), ntohs(rule->src_port_max), ntohs(rule->smask),
           &dst_ip, ntohs(rule->dst_port_min), ntohs(rule->dst_port_max), ntohs(rule->dmask),
           ntohs(rule->protocol), ntohs(rule->action), ntohs(rule->logging));
    return 0;
}

// RULE DEL FUNCTION
int tinywall_rule_remove(unsigned int rule_id)
{
    firewall_rule *rule;
    bool found = 0;
    int rule_number = 0;
    printk("tinywall_rule_remove: rule_id=%d\n", rule_id);
    write_lock(&rule_table.lock);
    list_for_each_entry(rule, &rule_table.head, list)
    {
        rule_number++;
        if (rule_number == rule_id)
        {
            list_del(&rule->list);
            printk(KERN_INFO MODULE_NAME ": Deleted rule %d\n", rule_number);
            kfree(rule);
            found = 1;
            break;
        }
    }
    write_unlock(&rule_table.lock);
    if (!found)
    {
        printk(KERN_ERR MODULE_NAME ": Rule %d not found\n", rule_id);
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

    read_lock(&rule_table.lock);
    // 遍历 rule_table
    list_for_each_entry(rule, &rule_table.head, list)
    {
        has_rules = true;
        rule_number++;
        struct in_addr src_ip, dst_ip; // 将 __be32 类型的 IP 地址转换为 struct in_addr 类型
        src_ip.s_addr = rule->src_ip;
        dst_ip.s_addr = rule->dst_ip;
        printk(KERN_INFO MODULE_NAME ":[%d]: %pI4:%d-%d smask:%d -> %pI4:%d-%d dmask:%d, proto: %u, action: %u, logging: %u\n",
               rule_number,
               &src_ip, ntohs(rule->src_port_min), ntohs(rule->src_port_max), ntohs(rule->smask),
               &dst_ip, ntohs(rule->dst_port_min), ntohs(rule->dst_port_max), ntohs(rule->dmask),
               ntohs(rule->protocol), ntohs(rule->action), ntohs(rule->logging));
    }

    // 如果没有规则，输出 "NO RULES"
    if (!has_rules)
    {
        printk(KERN_INFO MODULE_NAME ": NO RULES\n");
    }

    read_unlock(&rule_table.lock);
    return;
}

// RULE CLEAR FUNCTION
void tinywall_rules_clear(void)
{

    struct firewall_rule *rule, *tmp;

    write_lock(&rule_table.lock);
    list_for_each_entry_safe(rule, tmp, &rule_table.head, list)
    {
        list_del(&rule->list);
        kfree(rule);
    }
    printk(KERN_INFO MODULE_NAME ": Cleared all rules\n");
    write_unlock(&rule_table.lock);
}

// RULE TABLE DESTROY FUNCTION
void tinywall_rule_table_destroy(void)
{
    struct firewall_rule *rule, *tmp;

    // 清空规则链表
    write_lock(&rule_table.lock);
    list_for_each_entry_safe(rule, tmp, &rule_table.head, list)
    {
        list_del(&rule->list);
        kfree(rule);
    }
    write_unlock(&rule_table.lock);
}
struct firewall_rule *tinywall_rule_get(int num)
{
    struct firewall_rule *rule;
    int i = 0;

    read_lock(&rule_table.lock);
    list_for_each_entry(rule, &rule_table.head, list)
    {
        if (i == num)
            return rule;
        i++;
    }
    read_unlock(&rule_table.lock);
    return NULL;
}

/* >----------------------------------连接表部分----------------------------------<*/
/* CONNTABLE INIT FUNCTIONS */
void tinywall_conn_table_init(void)
{
    int i = 0;
    // INIT_LIST_HEAD(&conn_table->table);
    for (i = 0; i < HASH_SIZE; i++)
    {
        INIT_HLIST_HEAD(&conn_table.table[i]);
    }
    rwlock_init(&conn_table.lock);
    conn_table.conn_count = 0;
    return;
}

struct tinywall_conn *tinywall_connection_create(struct iphdr *iph)
{
    struct tinywall_conn *conn = kmalloc(sizeof(*conn), GFP_KERNEL);
    if (!conn)
        return NULL;
    conn->saddr = iph->saddr;
    conn->daddr = iph->daddr;
    conn->protocol = iph->protocol;
    switch (iph->protocol)
    {
    case IPPROTO_TCP:
        struct tcphdr *tcph = (void *)iph + iph->ihl * 4;
        conn->tcp.sport = tcph->source;
        conn->tcp.dport = tcph->dest;
        conn->timeout =
            htonll(ktime_add_sec(ktime_get_real(), default_timeout_tcp));
        break;
    case IPPROTO_UDP:
        struct udphdr *udph = (void *)iph + iph->ihl * 4;
        conn->udp.sport = udph->source;
        conn->udp.dport = udph->dest;
        conn->timeout =
            htonll(ktime_add_sec(ktime_get_real(), default_timeout_udp));
        break;
    case IPPROTO_ICMP:
        struct icmphdr *icmph = (void *)iph + iph->ihl * 4;
        conn->icmp.type = icmph->type;
        conn->icmp.code = icmph->code;
        conn->timeout = htonll(ktime_add_sec(ktime_get_real(), default_timeout_icmp));
        break;
    default:
        conn->timeout =
            conn->timeout = htonll(ktime_add_sec(ktime_get_real(), default_timeout_others));
    }
}

// hash lookup function
struct tinywall_conn *tinywall_conn_lookup(struct tinywall_conn *conn)
{
    if (!conn)
    {
        printk(KERN_ERR MODULE_NAME ": conn is NULL\n");
        return NULL;
    }
    read_lock(&conn_table.lock);
    size_t hash = tinywall_hash(conn);
    struct tinywall_conn *entry;
    hlist_for_each_entry(entry, &conn_table.table[hash], node)
    {
        if (entry->saddr == conn->saddr &&
            entry->daddr == conn->daddr &&
            entry->protocol == conn->protocol &&
            (entry->protocol == IPPROTO_TCP ? (entry->tcp.sport == conn->tcp.sport && entry->tcp.dport == conn->tcp.dport) : (entry->protocol == IPPROTO_UDP ? (entry->udp.sport == conn->udp.sport && entry->udp.dport == conn->udp.dport) : (entry->icmp.type == conn->icmp.type && entry->icmp.code == conn->icmp.code))))
        {
            return entry;
        }
    }
    read_unlock(&conn_table.lock);
    return NULL;
}

// 销毁连接表
static void tinywall_conntable_destroy(void)
{
    int i;
    struct tinywall_conn *conn;
    struct hlist_node *tmp;
    // 获取写锁
    write_lock(&conn_table.lock);

    // 遍历哈希表中的每个桶
    for (i = 0; i < HASH_SIZE; i++)
    {
        // 遍历桶中的每个连接项
        hlist_for_each_entry_safe(conn, tmp, &conn_table.table[i], node)
        {
            // 从哈希表中删除连接项
            hlist_del(&conn->node);

            // 释放连接项占用的内存
            kfree(conn);
        }
    }

    // 释放哈希表本身（如果它是动态分配的）
    // 注意：这里假设哈希表是静态分配的，不需要释放
    // 如果是动态分配的，可以使用 kfree(table->table);

    // 释放读写锁
    write_unlock(&conn_table.lock);

    // 重置连接计数
    conn_table.conn_count = 0;
}
/* >----------------------------------子模块部分----------------------------------<*/
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
        // printk("not tcp");
        return NF_ACCEPT;
    }

    if (ip_header->protocol == IPPROTO_TCP)
    {
        tcp_header = tcp_hdr(skb);
        if (!tcp_header)
        {
            printk(KERN_ERR MODULE_NAME ": TCP header is NULL\n");
            return NF_ACCEPT;
        }
        // 检测是否匹配上规则
        firewall_rule *rule;
        read_lock(&rule_table.lock);
        list_for_each_entry(rule, &rule_table.head, list)
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
        read_unlock(&rule_table.lock);

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
    // 默认通过
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
    // 初始化规则表
    tinywall_rule_table_init();
    // 初始化连接表
    tinywall_conn_table_init();
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
    // 注销Netfilter钩子
    nf_unregister_net_hook(&init_net, &firewall_nfho);
    // 销毁规则表
    tinywall_rule_table_destroy();
    //  销毁连接表
    tinywall_conntable_destroy();
    printk(KERN_INFO MODULE_NAME ": Firewall module unloaded.\n");
}

module_init(firewall_init);
module_exit(firewall_exit);

EXPORT_SYMBOL(tinywall_rules_list);
EXPORT_SYMBOL(tinywall_rule_remove);
EXPORT_SYMBOL(tinywall_rule_add);
EXPORT_SYMBOL(tinywall_rules_clear);
EXPORT_SYMBOL(tinywall_rule_get);
EXPORT_SYMBOL(rule_table);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sun Xiaokai suxiaokai34@gmail.com");
MODULE_DESCRIPTION("A Tiny Netfilter Firewall Module");
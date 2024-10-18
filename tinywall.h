// tinywall.h
// 内核中用到的数据结构
#ifndef TINYWALL_H
#define TINYWALL_H
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include "public.h"

#define MODULE_NAME "tinywall"

/* >-----------------rule entity-----------------<*/
typedef struct firewall_rule
{
    __be32 src_ip;
    __be32 dst_ip;
    __be32 smask;
    __be32 dmask;
    __be16 src_port_min;
    __be16 src_port_max;
    __be16 dst_port_min;
    __be16 dst_port_max;
    __u8 protocol;
    __u8 action;
    __u8 logging;
    struct list_head list;
} firewall_rule;

/* >-----------------conn entity-----------------<*/
struct xwall_connection
{
    __be32 saddr;
    __be32 daddr;
    __u8 protocol;
    union
    {
        struct
        {
            __u8 type;
            __u8 code;
        } icmp;
        struct
        {
            __be16 sport;
            __be16 dport;
            __u8 state;
        } tcp;
        struct
        {
            __be16 sport;
            __be16 dport;
        } udp;
    };
    __be64 timeout; // ktime_t
    struct hlist_node node;
};

/* >-----------------规则表-----------------<*/
struct tinywall_rule_table
{
    rwlock_t lock; // 读写锁
    __u32 rule_count;
    struct list_head *head; // 链表头
};

/* >-----------------连接表-----------------<*/
struct tinywall_conntable
{
    rwlock_t lock;
    unsigned int conn_num;
    DECLARE_HASHTABLE(hashtable, TINY_HASHTABLE_BITS);
};
// 函数声明
int tinywall_rule_add(firewall_rule_user *new_rule);

int tinywall_rule_remove(unsigned int rule_id);

void tinywall_rules_list(void);

void tinywall_rules_clear(void);

#endif // MY_FIREWALL_H

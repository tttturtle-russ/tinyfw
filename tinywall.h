// tinywall.h
#ifndef TINYWALL_H
#define TINYWALL_H
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/list.h>
#include "public.h"

#define MODULE_NAME "tinywall"

typedef struct firewall_rule
{
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 protocol;
    struct list_head list;
} firewall_rule, *firewall_rule_ops;

// 全局规则链表和锁
struct tinywall_rule_table {
    rwlock_t lock;          // 读写锁
    __u32  rule_count;
    struct list_head head;  // 链表头
};
// spinlock_t rule_lock;

// 函数声明
int tinywall_rule_add( firewall_rule_user *new_rule);

int tinywall_rule_remove(unsigned int rule_id);

void tinywall_rules_list(void);

void tinywall_rules_clear(void);

#endif // MY_FIREWALL_H

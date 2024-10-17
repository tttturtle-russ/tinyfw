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


// 全局规则链表和锁
struct tinywall_rule_table {
    rwlock_t lock;          // 读写锁
    __u32  rule_count;
    struct list_head head;  // 链表头
};
// spinlock_t rule_lock;

// 函数声明
int tinywall_rule_add( firewall_rule *new_rule);
int tinywall_rule_remove( firewall_rule *rule_to_del);
void tinywall_rules_list(void);

#endif // MY_FIREWALL_H

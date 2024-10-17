// tinywall.h
#ifndef MY_FIREWALL_H
#define MY_FIREWALL_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/list.h>
#include <linux/spinlock.h>

#define MODULE_NAME "my_firewall"

#define NLMSG_ADD_RULE 1     // 添加规则
#define NLMSG_DEL_RULE 2     // 删除规则    
#define NLMSG_LIST_RULE 3     // 列出规则
#define NLMSG_MAX_SIZE 1024

// 定义过滤规则结构
typedef struct firewall_rule {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 protocol;
    struct list_head list;
}   firewall_rule,*firewall_rule_ops;

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

// my_firewall.h
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

// 定义过滤规则结构
struct firewall_rule {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 protocol;
    struct list_head list;
};

// 全局规则链表和锁
extern struct list_head rule_list;
extern spinlock_t rule_lock;

// 函数声明
int add_rule(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, __u8 protocol);
int remove_rule(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, __u8 protocol);

#endif // MY_FIREWALL_H

#define NLMSG_ADD_RULE 1   // 添加规则
#define NLMSG_DEL_RULE 2   // 删除规则
#define NLMSG_LIST_RULES 3 // 列出规则
#define NLMSG_MAX_SIZE 1024

// 定义过滤规则结构
typedef struct firewall_rule
{
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 protocol;
    struct list_head list;
} firewall_rule, *firewall_rule_ops;

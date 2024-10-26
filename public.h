#define NLMSG_MAX_SIZE 65535
#define NETLINK_USER 31
#define HASH_SIZE 1024
// 定义过滤规则结构

// 用户空间的 firewall_rule 结构体（没有 struct list_head）
typedef struct tinywall_rule_user
{
    __be32 src_ip;
    __be32 dst_ip;
    __be16 smask;
    __be16 dmask;
    __be16 src_port_min;
    __be16 src_port_max;
    __be16 dst_port_min;
    __be16 dst_port_max;
    __be16 protocol;
    __be16 action;
    __be16 logging;
} tinywall_rule_user;

// 定义规则操作
enum TINYWALL_REQUEST_TYPE
{
    TINYWALL_TYPE_ADD_RULE,
    TINYWALL_TYPE_DEL_RULE,
    TINYWALL_TYPE_LIST_RULES,
    TINYWALL_TYPE_CLEAR_RULES,
    TINYWALL_TYPE_STORE_RULES,
    TINYWALL_TYPE_LOAD_RULES,
};

// 定义防火墙返回类型
enum TINYWALL_RESPONSE_TYPE
{
    TINYWALL_TYPE_OK,
    TINYWALL_TYPE_ERROR,
    TINYWALL_TYPE_RULE,
    TINYWALL_TYPE_LOG,
    TINYWALL_TYPE_MLOG,
    TINYWALL_TYPE_CONN,
    TINYWALL_TYPE_NAT
};

// 定义防火墙返回结构
struct TINYWALL_response
{
    __u8 type;
    __be32 len;
    __u8 msg[0];
};

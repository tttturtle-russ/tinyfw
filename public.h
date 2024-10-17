#define NLMSG_MAX_SIZE 1024
// 定义过滤规则结构


// 用户空间的 firewall_rule 结构体（没有 struct list_head）
typedef struct firewall_rule_user {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 protocol;
} firewall_rule_user;

//定义规则操作
enum TINYWALL_REQUEST_TYPE {
    TINYWALL_TYPE_ADD_RULE,
    TINYWALL_TYPE_DEL_RULE,
    TINYWALL_TYPE_LIST_RULES,
    TINYWALL_TYPE_SAVE_RULES,
    TINYWALL_TYPE_LOAD_RULES,
    TINYWALL_TYPE_CLEAR_RULES
};

//定义防火墙返回类型
enum TINYWALL_RESPONSE_TYPE {
    TINYWALL_TYPE_OK,
    TINYWALL_TYPE_ERROR,
    TINYWALL_TYPE_RULE,
    TINYWALL_TYPE_LOG,
    TINYWALL_TYPE_MLOG,
    TINYWALL_TYPE_CONN,
    TINYWALL_TYPE_NAT
};

// 定义防火墙返回结构
struct TINYWALL_response {
    __u8 type;
    __be32 len;
    __u8 msg[0];
};

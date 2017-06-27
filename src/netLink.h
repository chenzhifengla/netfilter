/**
 * netLink运行在内核，用来向用户态进程发送消息并接收用户态消息
 */

#define NETLINK_TEST 20 // 自定义的netlink协议号
#define NETLINK_TEST_CONNECT 0x10  // 自定义的netlink客户端发送连接请求时type
#define NETLINK_TEST_DISCONNECT 0x11   // 自定义的netlink客户端发送断开连接请求时type
#define NETLINK_TEST_REPLY  0x12   // 自定义的netlink内核回复的消息类型
#define NETLINK_TEST_ACCPT 0x13  // 自定义的netlink客户端发送的指令，允许数据包通过
#define NETLINK_TEST_DISCARD 0x14   // 丢弃数据包

int createNetlink(void);

int sendMsgNetlink(char *message);

int deleteNetlink(void);

typedef struct {
    int flag; // 是否通过，0表示accept，1表示discard
    rwlock_t lock;  // 读写锁，用来控制对flag的访问
} UserCmd;
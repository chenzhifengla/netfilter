/**
 * netLink运行在内核，用来向用户态进程发送消息并接收用户态消息
 */

#ifndef NET_FILTER_NET_LINK_H
#define NET_FILTER_NET_LINK_H

#define NET_LINK_PROTOCOL 20 // 自定义的NET_LINK协议号
#define NET_LINK_CONNECT 0x10  // 自定义的NET_LINK客户端发送连接请求时type
#define NET_LINK_DISCONNECT 0x11   // 自定义的NET_LINK客户端发送断开连接请求时type
#define NET_LINK_REPLY  0x12   // 自定义的NET_LINK内核回复的消息类型
#define NET_LINK_ACCEPT 0x13  // 自定义的NET_LINK客户端发送的指令，允许数据包通过
#define NET_LINK_DISCARD 0x14   // 丢弃数据包

/**
 * 表示用户对该数据包返回的操作指令
 */
enum Cmd {
    ACCEPT,
    DISCARD,
};

typedef struct {
    enum Cmd cmd;
    rwlock_t lock;  // 读写锁，用来控制cmd的访问
} UserCmd;

/**
 * 表示客户端的连接信息
 */
typedef struct {
    __u32 pid;  // 客户端pid
    rwlock_t lock;  // 读写锁，用来控制pid的访问
} UserInfo;

/**
 * 用来对内核完成量超时的计数
 */
typedef struct {
    int times;  // 次数
    rwlock_t lock;  // 读写锁，用来控制times的访问
} CompletionTimeout;

/**
 * 在内核中创建netLink，当用户态传来消息时触发绑定的接收消息函数
 * @return 创建成功:0,创建失败:1
 */
int createNetLink(void);

/**
 * 在内核中删除创建的netLink
 */
void deleteNetLink(void);

/**
 * 通过netLink往用户态发消息
 * @param message 消息
 * @param len 消息长度(strlen值)
 * @return 发送成功:0,发送失败:1
 */
int sendMsgNetLink(char *message, int len);

#endif //NET_FILTER_NET_LINK_H
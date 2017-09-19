#include <linux/init.h>  
#include <linux/module.h>  
#include <linux/timer.h>  
#include <linux/time.h>  
#include <linux/types.h>  
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/version.h>

#include "log.h"
#include "netLink.h"

static struct sock *nl_sk;  // 内核套接字
static struct {
    __u32 pid;  // 客户端pid
    rwlock_t lock;  // 读写锁，用来控制pid的访问
} user_proc;

UserCmd userCmd;    // 用户指令

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
struct netlink_kernel_cfg cfg;   // netLink内核配置参数
#endif

int sendMsgNetLink(char *message, int len) {
    // 向进程号为pid的用户态进程发送消息message

    struct sk_buff *skb;    // 定义套接字缓冲区
    int message_size;   // 表示消息的长度
    int total_size;   // 表示netLink消息首部加载荷的长度
    struct nlmsghdr *nlh;   // netLink首部
    sk_buff_data_t old_tail;    // 记录填充消息前skb的尾部，sk_buff_data_t类型表示偏移量或者指针
    int ret;    // 单播消息发送的返回值

    if (!message || !nl_sk) {
        // 异常情况，直接返回
        return -1;
    }

    // 先判断有无netLink客户端连接
    read_lock_bh(&user_proc.lock);  // 获取读锁
    if (!user_proc.pid){
        read_unlock_bh(&user_proc.lock);    // 释放读锁
        return -1;  // 如果pid=0,直接返回
    }
    read_unlock_bh(&user_proc.lock);    // 释放读锁

    message_size = len + 1; // 获取字符串消息长度
    total_size = NLMSG_SPACE(message_size);    // 获取总长度，NLMSG_SPACE宏会计算消息加上首部再对齐后的长度

    skb = alloc_skb(total_size, GFP_ATOMIC); //申请一个skb,长度为total_size,优先级为GFP_ATOMIC
    if (!skb) {
        ERROR("my_net_link:alloc_skb error");
        return -1;
    }
    old_tail = skb->tail;   // 记录填充消息前skb的尾部偏移量或指针

    // 先获取skb中消息的首部地址，根据内核版本变动
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 16)
    // 参数分别为套接字缓冲区，请求的端口id，消息序列号，消息类型，消息载荷长度，消息标志
    nlh = nlmsg_put(skb, 0, 0, NET_LINK_TEST_REPLY, total_size - sizeof(struct nlmsghdr), 0);
#else
    nlh = NLMSG_PUT(skb, 0, 0, NET_LINK_TEST_REPLY, total_size - sizeof(struct nlmsghdr));
#endif

    // 填充nlh的载荷部分，NLMSG_DATA宏用于取得nlh载荷部分首地址
    strncpy(NLMSG_DATA(nlh), message, len);
    DEBUG("my_net_link:send message '%s'.\n", (char *) NLMSG_DATA(nlh));

    //nlh->nlmsg_len = skb->tail - old_tail;  // 获取当前skb中填充消息的长度
    // 为python客户端尝试另一种填充长度的方法
    nlh->nlmsg_len = message_size + sizeof(struct nlmsghdr);

    // 设置控制字段
    //NET_LINK_CB(skb).pid = 0;  // 消息发送者为内核，所以pid为0
    //NET_LINK_CB(skb).dst_pid = pid;  // 消息接收者的pid
    NET_LINK_CB(skb).dst_group = 0;    // 目标为进程时，设置为0

    read_lock_bh(&user_proc.lock);  // 获取读锁
    if (!user_proc.pid){
        read_unlock_bh(&user_proc.lock);    // 释放读锁
        return -1; // 如果客户端断开了连接，直接返回
    }
    // 发送单播消息，参数分别为nl_sk(内核套接字), skb(套接字缓冲区), pid(目的进程), MSG_DONTWAIT(不阻塞)
    ret = netlink_unicast(nl_sk, skb, user_proc.pid, MSG_DONTWAIT); // 发送单播消息
    read_unlock_bh(&user_proc.lock);    // 释放读锁

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 16)
    // 如果内核版本过小，需要做一个出错时跳转标签
    nlmsg_failure:
#endif

    return ret;
}

/**
 * 内核态netLink收到用户态发来的消息时触发此回调函数
 * @param skb
 */
static void recvMsgNetLink(struct sk_buff *skb) {
    struct nlmsghdr *nlh;   // 指向netLink消息首部的指针

    DEBUG("recvMsgNetlink is triggerd\n");

    if (skb->len >= NLMSG_SPACE(0)) {
        nlh = nlmsg_hdr(skb);   // 获取netLink消息首部指针
        DEBUG("nlh->nlmsg_len = %d, sizeof(struct nlmsghdr)=%lu, skb->len=%d, nlh->nlmsg_len=%d",
              nlh->nlmsg_len, sizeof(struct nlmsghdr), skb->len, nlh->nlmsg_len);
        if ((nlh->nlmsg_len >= sizeof(struct nlmsghdr)) && (skb->len >= nlh->nlmsg_len)){
            // 如果首部完整
            if (nlh->nlmsg_type == NET_LINK_TEST_CONNECT){
                // 如果消息类型为请求连接
                INFO("netLink client connect");
                INFO("netLink client pid is %d", nlh->nlmsg_pid);
                write_lock_bh(&user_proc.lock);     // 获取写锁
                user_proc.pid = nlh->nlmsg_pid;
                write_unlock_bh(&user_proc.lock);   // 释放写锁
                sendMsgNetlink("you have connected to the kernel!");  // 向客户端发送回复消息
            }
            else if (nlh->nlmsg_type == NET_LINK_TEST_DISCONNECT){
                // 如果消息类型为释放连接
                INFO("netLink client disconnect");
                sendMsgNetlink("you have disconnected to the kernel!");  // 向客户端发送回复消息
                write_lock_bh(&user_proc.lock);     // 获取写锁
                user_proc.pid = 0;  // 将pid置0
                write_unlock_bh(&user_proc.lock);   // 释放写锁
            }
            else if (nlh->nlmsg_type == NET_LINK_TEST_ACCPT) {
                INFO("netLink accept");
            }
            else if (nlh->nlmsg_type == NET_LINK_TEST_DISCARD) {
                INFO("netLink discard");
                write_lock_bh(&userCmd.lock);
                userCmd.flag = 1;
                write_unlock_bh(&userCmd.lock);
            }
            else {
                // 如果消息类型为其他指令,有待操作
                sendMsgNetlink("other command!");
            }
        }
        else{
            INFO("netLink message too short");
        }

//        memcpy(str, NLMSG_DATA(nlh), sizeof(str));  // 获取netLink消息主体
//        INFO("netLink message received:%s\n", str);
    }
}

int createNetLink(void) {
    // 初始化读写锁
    DEBUG("init read/write lock\n");
    rwlock_init(&user_proc.lock);

    // 对不同版本的内核调用不同的函数
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    // kernel 3.10
    cfg.groups = 0; // 0表示单播，1表示多播
    cfg.flags = 0;
    cfg.input = recvMsgNetlink;    // 回调函数，当收到消息时触发
    cfg.cb_mutex = NULL;

    // 创建服务，init_net表示网络设备命名空间指针，NET_LINK_TEST表示协议类型，cfg指向netLink的配置结构体
    nl_sk = netlink_kernel_create(&init_net, NET_LINK_TEST, &cfg);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)
    // kernel 2.6.18
    nl_sk = netlink_kernel_create(&init_net, NET_LINK_TEST, 0, recvMsgNetlink, NULL, THIS_MODULE);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 16)
    // kernel 2.6.16
    nl_sk = netlink_kernel_create(NET_LINK_TEST, 0, recvMsgNetlink, NULL, THIS_MODULE);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10)
    // kernel 2.6.10
    nl_sk = netlink_kernel_create(NET_LINK_TEST, 0, recvMsgNetlink, THIS_MODULE);
#else
    // 其他更低版本
    nl_sk = netlink_kernel_create(NET_LINK_TEST, recvMsgNetlink);
#endif

    if (!nl_sk) {
        // netLink创建失败
        return 1;
    }

    write_lock_bh(&user_proc.lock);     // 获取写锁
    // 初始时将客户端pid置0
    DEBUG("set client pid to 0\n");
    user_proc.pid = 0;
    write_unlock_bh(&user_proc.lock);   // 释放写锁
    return 0;
}

void deleteNetLink(void) {
    if (nl_sk) {
        DEBUG("release netLink socket!\n");
        netlink_kernel_release(nl_sk);
    }
    return 0;
}

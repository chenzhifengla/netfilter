//
// Created by yingzi on 2017/9/12.
//

#ifndef NET_FILTER_CONF_H
#define NET_FILTER_CONF_H

// 0表示桥接，1表示NAT
#define BRIDGE 0
// 源IP
#define SOURCE_IP "10.108.166.12"
// 目的IP
#define TARGET_IP "10.205.41.44"
// -1表示从左往右，0表示双向，1表示从右往左
#define DIRECTION 0
// 匹配串头
#define TAG_HEAD "<?xml>"
// 匹配串尾
#define TAG_TAIL "</xml>"
// 内核等待时间(ms)
#define KERNEL_WAIT_MILISEC 100
// 用户态与内核态通信的最大消息长度
#define MAX_MSG_LEN 100000
// 内核对客户端回复的轮询时间间隔
#define POLL_MILISEC 50
// 内核对客户端回复的轮询次数
#define POLL_TIMES 10


#endif //NET_FILTER_CONF_H

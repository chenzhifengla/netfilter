//
// Created by yingzi on 2017/9/12.
//

#ifndef NET_FILTER_CONF_H
#define NET_FILTER_CONF_H

// 0表示桥接，1表示NAT
#define BRIDGE 0
// 源IP
#define SOURCE_IP "10.108.166.210"
// 目的IP
#define TARGET_IP "10.205.41.48"
// -1表示从左往右，0表示双向，1表示从右往左
#define DIRECTION 0
// 匹配串头
#define TAG_HEAD "<xml type=\"event\""
// 匹配串尾
#define TAG_TAIL "</xml>"
// 关键事件的标志
#define IMPORTANT_FLAG "important=\"1\""
// 内核等待时间(ms)
#define KERNEL_WAIT_MILISEC 200

#endif //NET_FILTER_CONF_H

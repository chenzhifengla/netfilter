#include<linux/init.h>
#include<linux/kernel.h>
#include<linux/module.h>
#include<linux/netfilter.h>
#include<linux/netfilter_ipv4.h>
#include<linux/ip.h>
#include<linux/inet.h>
#include<linux/skbuff.h>
#include<linux/tcp.h>
#include<linux/udp.h>
#include<linux/time.h>
#include <linux/timer.h>
#include <linux/timex.h>
#include <linux/rtc.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/netfilter_bridge.h>

#include "conf.h"
#include "log.h"
#include "netFilter.h"
#include "dealConf.h"
#include "netLink.h"

extern UserCmd userCmd; // netLink中的全局变量，表示用户指令

extern UserInfo userInfo;   // netlink中的全局变量，表示用户PID信息

extern TimeoutStruct timeoutStruct; // 对内核完成量超时次数的计数

struct timeval startTime, endTime;
unsigned long timeSec;
unsigned long timeUSec;

/**
 * 完成量，内核态发数据后阻塞等netlink收消息唤醒
 */
//DECLARE_COMPLETION(msgCompletion);
extern struct completion msgCompletion;

/**
 * netFilter钩子
 */
static struct nf_hook_ops nfho_single;

int initNetFilter(void){
    // 绑定钩子函数
    DEBUG("bind netFilter hook func\n");
    nfho_single.hook = (nf_hookfn *) hook_func;

    // 根据桥接和NAT选择不同的挂载方式
    if (BRIDGE == 0) {
        // 数据流入网桥前触发
        INFO("trigger before data into the bridge\n");
        nfho_single.hooknum = NF_BR_PRE_ROUTING;
        nfho_single.pf = PF_BRIDGE;
        nfho_single.priority = NF_BR_PRI_FIRST;
//        nfho_single.priority = NF_BR_PRI_BRNF;
    }
    else if (BRIDGE == 1) {
        // 数据流入网络层前触发
        INFO("triggr before data into network layer\n");
        nfho_single.hooknum = NF_INET_PRE_ROUTING;
        nfho_single.pf = PF_INET;
        nfho_single.priority = NF_IP_PRI_FILTER;
    }
    else {
        WARNING("illegal parameter BRIDGE = %d\n", BRIDGE);
        return 1;
    }

    //注册一个netFilter钩子
    INFO("register netFilter hook!\n");
    nf_register_hook(&nfho_single);

    return 0;
}

void releaseNetFilter(void){
    INFO("unRegister netFilter hook!");
    nf_unregister_hook(&nfho_single);   // 卸载钩子
}

unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in,
                       const struct net_device *out, int (*okfn)(struct sk_buff *)) {
    struct ethhdr *eth; // 以太网帧首部指针
    struct iphdr *iph;  // ip数据报首部指针

    struct udphdr *udp_head; // udp报文首部长度
    int udp_head_len;   // 首部长度

    char *data; // data是数据指针游标，从UDP body开始
    int data_len;

    // 事件范围
    char *tag_head;
    char *tag_tail;
    unsigned long tag_len;

    // 关键事件标志
    char *important_flag_pos;
//    int important_flag;

    // 1. 判断是否已经有客户端连接
    read_lock_bh(&userInfo.lock);
    if (userInfo.pid == 0) {
        read_unlock_bh(&userInfo.lock);
        return NF_ACCEPT;
    }
    read_unlock_bh(&userInfo.lock);

    // 2. 判断是否为无效或者空数据包
    eth = eth_hdr(skb); // 获得以太网帧首部指针
    if(!skb || !eth) {
        return NF_ACCEPT;
    }

    // 3. 过滤掉发往本地主机的数据、以太网广播报文、以太网多播报文、本地主机环回报文，只留下发往其他主机的报文
    if(skb->pkt_type != PACKET_OTHERHOST) {
        return NF_ACCEPT;
    }

    // IP head和body长度
    iph = ip_hdr(skb);  // 获得ip数据报首部指针，或者iph = (struct iphdr *) data;

    // 4. 按源IP和目的IP过滤IP数据报
    if (iph->saddr != in_aton(SOURCE_IP)
        || iph->daddr != in_aton(TARGET_IP)) {
        // 比较配置中ip与获取ip的16进制形式
        return NF_ACCEPT;
    }

    // 5. 过滤掉非UDP协议
    if (iph->protocol != IPPROTO_UDP) {
        return NF_ACCEPT;
    }

    // UDP head和body长度
    skb_set_transport_header(skb, sizeof(struct iphdr));
    udp_head = udp_hdr(skb);
    udp_head_len = sizeof(struct udphdr);

    // data指向UDP报文body
    data = (char*)udp_head + udp_head_len;
    data_len = ntohs(udp_head->len) - sizeof(struct udphdr);
//    DEBUG("udp data is %.*s", data_len, data);
//    DEBUG("udp data[0]=%d,%x", *data, *data);
//    DEBUG("udp data[1]=%d,%x", *(data + 1), *(data + 1));
//    DEBUG("udp data[2]=%d,%x", *(data + 2), *(data + 2));
//    DEBUG("udp data[3]=%d,%x", *(data + 3), *(data + 3));
//    DEBUG("udp data[4]=%d,%x", *(data + 4), *(data + 4));


//    DEBUG_LEN(data, data_len);
//    DEBUG("udp data len:%d", data_len);

    // 6. 在data中搜索匹配head
    tag_head = searchStr(data, data_len, TAG_HEAD, sizeof(TAG_HEAD) - 1);
    if (tag_head == NULL) {
        DEBUG("search head failed!");
        return NF_ACCEPT;
    }
    else {
        DEBUG("search head success!");
    }

    // 在data中继续搜索匹配tail
    tag_tail = searchStr(tag_head + (sizeof(TAG_HEAD) - 1), data_len - (tag_head - data) - (sizeof(TAG_HEAD) - 1), TAG_TAIL, sizeof(TAG_TAIL) - 1);
    if (tag_tail == NULL) {
        DEBUG("search tail failed!");
        return NF_ACCEPT;
    }
    else {
        DEBUG("search tail success!");
    }

    // 确定事件长度
    tag_len = tag_tail - tag_head + (sizeof(TAG_TAIL) - 1);

    // 判断事件是不是关键事件
    important_flag_pos = isImportantEvent(tag_head, tag_len);

    // 7. 发送消息
//    sendMsgNetLink(tag_head, tag_len);

    // 8. 消息发出后对关键事件使用完成量进行超时阻塞，非关键事件直接通过
    if (important_flag_pos != NULL) {
        INFO("important event:%.*s", (int)tag_len, tag_head);
        sendMsgNetLink(tag_head, tag_len);

#ifdef LOG_TIME
        do_gettimeofday(&startTime);
#endif
        if (wait_for_completion_timeout(&msgCompletion, KERNEL_WAIT_MILISEC) == 0) {
#ifdef LOG_TIME
            do_gettimeofday(&endTime);
            DEBUG("start sec is %d", startTime.tv_sec);
            DEBUG("end sec is %d", endTime.tv_sec);

            timeUSec = (endTime.tv_sec - startTime.tv_sec) * 1000000 + endTime.tv_usec - startTime.tv_usec;
            timeSec = timeUSec / 1000000;
            timeUSec -= timeSec * 1000000;
            DEBUG("wait %ld s, %ld us, timeout", timeSec, timeUSec);
#endif

            write_lock_bh(&timeoutStruct.lock);
            ++timeoutStruct.timeoutTimes;
            write_unlock_bh(&timeoutStruct.lock);
            WARNING("event %.*s wait response timeout", (int)tag_len, tag_head);
            return NF_ACCEPT;
        }
        else {
#ifdef LOG_TIME
            do_gettimeofday(&endTime);
            DEBUG("start sec is %d", startTime.tv_sec);
            DEBUG("end sec is %d", endTime.tv_sec);

            timeUSec = (endTime.tv_sec - startTime.tv_sec) * 1000000 + endTime.tv_usec - startTime.tv_usec;
            timeSec = timeUSec / 1000000;
            timeUSec -= timeSec * 1000000;
#endif
            WARNING("recvd response");
#ifdef LOG_TIME
            DEBUG("wait %ld s, %ld us", timeSec, timeUSec);
#endif
        }

        // 直接读userCmd
        read_lock_bh(&userCmd.lock);
        if (userCmd.userCmdEnum == DISCARD) {
            INFO("drop event %.*s", (int)tag_len, tag_head);
            read_unlock_bh(&userCmd.lock);
            return NF_DROP;
        }
        else {
            INFO("accept event %.*s", (int)tag_len, tag_head);
            read_unlock_bh(&userCmd.lock);
            return NF_ACCEPT;
        }
    }
    else {
        DEBUG("unimportant event:%.*s", (int)tag_len, tag_head);
        sendMsgNetLink(tag_head, tag_len);
        return NF_ACCEPT;
    }
}

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
    DEBUG("register netFilter hook!\n");
    nf_register_hook(&nfho_single);
    return 0;
}

void releaseNetFilter(void){
    DEBUG("unregister netFilter hook!");
    nf_unregister_hook(&nfho_single);   // 卸载钩子
}

unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in,
                       const struct net_device *out, int (*okfn)(struct sk_buff *)) {
    char *data; // data是数据指针游标，从skb->data表示的ip数据报开始

    struct ethhdr *eth; // 以太网帧首部指针

    struct iphdr *iph;  // ip数据报首部指针
    int ip_head_len;    // 首部长度
    int ip_body_len;    // 数据长度

    struct tcphdr *tcp_head; // tcp报文首部指针
    int tcp_head_len;   // 首部长度
    int tcp_body_len;   // 数据长度

    struct udphdr *udp_head; // udp报文首部长度
    int udp_head_len;   // 首部长度
    int udp_body_len;   // 数据长度

    int userCmdAns = 0; // 用户指令标志

    eth = eth_hdr(skb); // 获得以太网帧首部指针
    iph = ip_hdr(skb);  // 获得ip数据报首部指针，或者iph = (struct iphdr *) data;

    if(!skb || !iph || !eth || !skb->data)
        return NF_ACCEPT;

    // 过滤掉广播数据
    if(skb->pkt_type == PACKET_BROADCAST)
        return NF_ACCEPT;

    data = skb->data;   // 将data指向ip数据报首部

//    MSG("skb->len=%d, skb->data_len=%d", skb->len, skb->data_len);
//    MSG("skb->mac_len=%d", skb->mac_len);
//    MSG("skb->head=%x,skb->data=%x,skb->tail=%u,skb->end=%u", skb->head, skb->data, skb->tail, skb->end);
//    MSG("skb_mac_header=%x,skb_network_header=%x,skb_transport_header=%x", skb_mac_header(skb), skb_network_header(skb), skb_transport_header(skb));

    ip_head_len = iph->ihl * 4;     // 获得首部长度
    ip_body_len = ntohs(iph->tot_len) - ip_head_len;   //获得数据部分长度,注意总长度为网络大端序，需转成小端序

    if (iph->saddr != in_aton(SOURCE_IP)
        || iph->daddr != in_aton(TARGET_IP)) {
        // 比较配置中ip与获取ip的16进制形式
        return NF_ACCEPT;
    }

    data += ip_head_len;    // 将data指向TCP/UDP报文首部

    switch (iph->protocol) {    // 根据TCP还是UDP进行不同的处理
        case IPPROTO_ESP:
        case IPPROTO_AH:
//            MSG("ESP AND AH:%s ---> %s", in_ntoa(sip, iph->saddr), in_ntoa(dip, iph->daddr));
            break;
        case IPPROTO_TCP: {
            //获取tcp头，并计算其长度
//            tcphead = (struct tcphdr *) data;
//            tcp_head_len = tcphead->doff * 4;
//            tcp_body_len = ip_body_len - tcp_head_len;
//
//            data += tcp_head_len;   // 将data指向TCP数据部分
//            strncpy(tcp_udp_body, data, tcp_body_len);
//            tcp_udp_body[tcp_body_len] = '\0';

//            MSG("TCP:%s:%d ---> %s:%d::%s", in_ntoa(sip, iph->saddr), ntohs(tcphead->source), in_ntoa(dip, iph->daddr), ntohs(tcphead->dest), tcp_udp_body);
        }
        case IPPROTO_UDP: {
            //获取udp头部，并计算其长度
            udphead = (struct udphdr *) data;
            udp_head_len = sizeof(struct udphdr);
            udp_body_len = ntohs(udphead->len) - udp_head_len;

            data += udp_head_len;   // 将data指向UDP数据部分
//            strncpy(tcp_udp_body, data, udp_body_len);
//            tcp_udp_body[udp_body_len] = '\0';


            // udp body长度小于最小要求长度，直接通过
            //if (udp_body_len < MIN_SIZE)
            //    return NF_ACCEPT;

//            extract(xmldest, "message", tcp_udp_body, 0, 100);
//            if(strcmp(xmldest,"B")==0)
//                return NF_DROP;


//            MSG("UDP:%s:%d ---> %s:%d::%s", in_ntoa(sip, iph->saddr), ntohs(udphead->source), in_ntoa(dip, iph->daddr), ntohs(udphead->dest),tcp_udp_body);

            // 先将指针重置为accept
            write_lock_bh(&userCmd.lock);
            userCmd.flag = 0;
            write_unlock_bh(&userCmd.lock);

            MSG(data, udp_body_len);
            // 将消息发往用户态后sleep 500ms
            mdelay(KERNEL_WAIT_MILISEC);

            // 尝试读取结果
            userCmdAns = 0;
            read_lock_bh(&userCmd.lock);
            userCmdAns = userCmd.flag;
            read_unlock_bh(&userCmd.lock);

            if (userCmdAns == 1) return NF_DROP;

            break;
        }
        case IPPROTO_ICMP:{
            // icmp协议
//            MSG("ICMP:%s ---> %s", in_ntoa(sip, iph->saddr), in_ntoa(dip, iph->daddr));
            break;
        }
        case IPPROTO_IGMP:{
//            MSG("IGMP:%s ---> %s", in_ntoa(sip, iph->saddr), in_ntoa(dip, iph->daddr));
            break;
        }
        case IPPROTO_PUP:{
//            MSG("PUP:%s ---> %s", in_ntoa(sip, iph->saddr), in_ntoa(dip, iph->daddr));
            break;
        }
        case IPPROTO_IDP:{
//            MSG("IDP:%s ---> %s", in_ntoa(sip, iph->saddr), in_ntoa(dip, iph->daddr));
            break;
        }
        case IPPROTO_IP:{
//            MSG("IP:%s ---> %s", in_ntoa(sip, iph->saddr), in_ntoa(dip, iph->daddr));
            break;
        }
        case IPPROTO_RAW:{
//            MSG("RAW:%s ---> %s", in_ntoa(sip, iph->saddr), in_ntoa(dip, iph->daddr));
            break;
        }
        case IPPROTO_GRE: {
//            MSG("GRE:%s ---> %s", in_ntoa(sip, iph->saddr), in_ntoa(dip, iph->daddr));
            break;
        }
        default: {  // 如果有其他可能情况，给出提示
//            MSG("Other Protocol=%d, %s ---> %s", iph->protocol, in_ntoa(sip, iph->saddr), in_ntoa(dip, iph->daddr));
            break;
        }
    }

    return NF_ACCEPT;
}



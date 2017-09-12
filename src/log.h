//
// Created by yingzi on 2017/9/12.
//

#ifndef NETFILTER_LOG_H
#define NETFILTER_LOG_H

/**
 * log主要用来提供日志宏定义，便于统一修改日志等级
 */

#define DEBUG(...) printk(KERN_DEBUG "DEBUG:" __VA_ARGS__)
#define INFO(...) printk(KERN_INFO "INFO:" __VA_ARGS__)
#define WARNING(...) printk(KERN_WARNING "WARING:" __VA_ARGS__)
#define ERROR(...) printk(KERN_ERR "ERROR:" __VA_ARGS__)

extern char mymessagebuf[100000];  // 放置缓冲区定义
#define MSG(...) sprintf(mymessagebuf, __VA_ARGS__);sendMsgNetlink(mymessagebuf);

#endif //NETFILTER_LOG_H
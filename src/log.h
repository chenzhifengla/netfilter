//
// Created by yingzi on 2017/9/12.
//

/**
 * log主要用来提供日志宏定义，便于统一修改日志等级
 */

#ifndef NET_FILTER_LOG_H
#define NET_FILTER_LOG_H

#include "conf.h"

#define DEBUG(...) printk(KERN_DEBUG "DEBUG:" __VA_ARGS__)
#define INFO(...) printk(KERN_INFO "INFO:" __VA_ARGS__)
#define WARNING(...) printk(KERN_WARNING "WARING:" __VA_ARGS__)
#define ERROR(...) printk(KERN_ERR "ERROR:" __VA_ARGS__)

// MSG宏用于将指定长度字符串通过netLink发送到用户态
#define MSG(msg, len) sendMsgNetLink(msg, len);

// MSG_FORMAT宏用于将格式化字符串发送到用户态，无需指定字符串长度
extern char messageBuf[MAX_MSG_LEN];
#define MSG_FORMAT(...) snprintf(messageBuf, MAX_MSG_LEN, __VA_ARGS__);sendMsgNetLink(messageBuf, MAX_MSG_LEN - 1);


#endif //NET_FILTER_LOG_H
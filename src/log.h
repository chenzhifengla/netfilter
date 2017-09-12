/**
 * log主要用来提供日志宏定义，便于统一修改日志等级
 */

#define DEBUG(...) printk(KERN_DEBUG "DEBUG:" __VA_ARGS__)
#define NOTICE(...) printk(KERN_NOTICE "INFO:" __VA_ARGS__)
#define WARNING(...) printk(KERN_WARNING "WARING:" __VA_ARGS__)
#define ERROR(...) printk(KERN_ERR "ERROR:" __VA_ARGS__)

char mymessagebuf[100000];  // 放置缓冲区定义
#define MSG(...) sprintf(mymessagebuf, __VA_ARGS__);sendMsgNetlink(mymessagebuf);
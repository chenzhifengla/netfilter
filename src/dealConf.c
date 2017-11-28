#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/gfp.h>
#include <linux/err.h>
#include <linux/syscalls.h>

#include "log.h"
#include "dealConf.h"

/**
 * 将无符号单个字符转换成字符串表示的数字
 * @param str 目的字符串，需要预先分配空间
 * @param c 无符号单个字符
 * @return 目的字符串
 */
static char *char2string(char *str, unsigned char c) {
    int num;
    num = (int) c;  // 先将无符号字符转成整数

    // 根据整数位数不同按位取出放置在数组中
    if (num >= 100) {
        str[0] = num / 100 + '0';
        num %= 100;
        str[1] = num / 10 + '0';
        num %= 10;
        str[2] = num + '0';
        str[3] = '\0';
    } else if (num >= 10) {
        str[0] = num / 10 + '0';
        num %= 10;
        str[1] = num + '0';
        str[2] = '\0';
    } else {
        str[0] = num + '0';
        str[1] = '\0';
    }
    return str;
}

char *in_ntoa(char *sip, __u32 in) {
    // 此函数用来将16进制的ip地址in转换成点分十进制格式保存在sip中

    unsigned char *p = (char *) &in;
    char str[10];
    int i;

    strcpy(sip, "\"");  // 以双引号开始
    for (i = 0; i < 3; i++) {
        // 循环将单个字符转成数字并以点号分隔
        strcat(sip, char2string(str, *(p + i)));
        strcat(sip, ".");
    }
    // 转换最后一个字符，并加双引号结尾
    strcat(sip, char2string(str, *(p + 3)));
    strcat(sip, "\"");

    return sip;
}
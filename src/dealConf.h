/**
 * dealConf主要用来提供配置读取、数据包合法检查与提取、ip格式转换等功能
 */

#ifndef NET_FILTER_DEAL_CONF_H
#define NET_FILTER_DEAL_CONF_H


/**
 * 将保存在整数in中的16进制格式ip地址转成点分10进制的字符串保存在sip中并返回该地址
 * @param sip 预先分配的保存结果的字符串指针
 * @param in 16进制格式ip地址字符串
 * @return 10进制ip字符串
 */
char *in_ntoa(char *sip, __u32 in);

#endif //NET_FILTER_DEAL_CONF_H
/**
 * dealConf主要用来提供配置读取、数据包合法检查与提取、ip格式转换等功能
 */

/**
 * 判断数据包是否满足预订格式
 * @param data 数据包指针
 * @param len 数据包长度
 * @return 满足:1,不满足0
 */
int isMatch(char* data, int len);

/**
 * 将保存在整数in中的16进制格式ip地址转成点分10进制的字符串保存在sip中并返回该地址
 * @param sip 预先分配的保存结果的字符串指针
 * @param in 16进制格式ip地址字符串
 * @return 10进制ip字符串
 */
char *in_ntoa(char *sip, __u32 in);
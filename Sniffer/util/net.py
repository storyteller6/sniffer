import socket
#导入解包加密包的模块
import struct



def parse_ip(data):
    # IP header
    ip_header = data[0:20]

    '''
        将二进制数据按照指定的格式解析为对应的Python对象并返回
        “!”：表示使用网络字节序进行解析
        ”B“：表示解析一个unsigned char（1字节无符号整数）
        ”H“：表示解析一个unsigned short（2字节无符号整数）
        ”4s“：表示解析一个长度为4的bytes对象
        （0）B：版本（1）+首部长度（1）
        （1）B：服务类型
        （2）H：总长度
        （3）H：标识
        （4）H：标志（1）+片偏移（3）
        （5）B：生存时间
        （6）B：协议
        （7）H：首部检验和
        （8）4s：源地址
        （9）4s：目的地址   
    '''
    parse_ip_header = struct.unpack('!BBHHHBBH4s4s', ip_header)

    # 版本（1）+首部长度（1）
    version_ihl = parse_ip_header[0]
    version = version_ihl >> 4
    ihl = 4 * (version_ihl & 0xF)
    # 总长度
    total_length = parse_ip_header[2]
    # 生存时间
    ttl = parse_ip_header[5]
    # 协议
    protocol = parse_ip_header[6]
    # 源地址
    source_addr = socket.inet_ntoa(parse_ip_header[8])
    # 目的地址
    destination_addr = socket.inet_ntoa(parse_ip_header[9])

    return version, ihl, total_length, ttl, protocol, source_addr, destination_addr
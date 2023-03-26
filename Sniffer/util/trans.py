#导入解包加密包的模块
import struct



def parse_icmp(data, ihl):
    # icmp header
    icmp_header = data[ihl : ihl + 4]

    '''
        将二进制数据按照指定的格式解析为对应的Python对象并返回
        “!”：表示使用网络字节序进行解析
        ”B“：表示解析一个unsigned char（1字节无符号整数）
        ”H“：表示解析一个unsigned short（2字节无符号整数）
        （0）：类型
        （1）：代码
        （2）：校验和
    '''
    parse_icmp_header = struct.unpack('!BBH', icmp_header)
    # 类型
    type = parse_icmp_header[0]
    # 代码
    code = parse_icmp_header[1]
    # 校验和
    checksum = parse_icmp_header[2]

    return type, code, checksum



def parse_tcp(data, ihl):
    #tcp header
    tcp_header = data[ihl: ihl + 20]

    '''
        将二进制数据按照指定的格式解析为对应的Python对象并返回
        “!”：表示使用网络字节序进行解析
        ”H“：表示解析一个unsigned short（2字节无符号整数）
        “L”：一个无符号长整型（unsigned long），占据4个字节
        ”B“：表示解析一个unsigned char（1字节无符号整数）
        （0）H：源端口号
        （1）H：目的端口号
        （2）L：序号
        （3）L：确认序号
        （4）（5）B+B：首部长度+保留位+6个标志
        （6）H：窗口大小
        （7）H：校验和
    '''
    parse_tcp_header = struct.unpack('!HHLLBBHHH', tcp_header)

    # 源端口号
    source_port = parse_tcp_header[0]
    # 目的端口号
    destination_port = parse_tcp_header[1]
    # 序号
    sequence = parse_tcp_header[2]
    # 确认序号
    ack_sequence = parse_tcp_header[3]
    # 首部长度
    temp = parse_tcp_header[4]
    thl = 4 * (temp >> 4)
    #窗口大小
    window_size = parse_tcp_header[6]

    return source_port, destination_port, sequence, ack_sequence, thl, window_size



def parse_udp(data, ihl):
    #udp header
    udphl = ihl + 8
    udp_header = data[ihl: udphl]

    '''
        将二进制数据按照指定的格式解析为对应的Python对象并返回
        “!”：表示使用网络字节序进行解析
        ”H“：表示解析一个unsigned short（2字节无符号整数）
        （0）H：源端口号
        （1）H：目的端口号
        （2）H：总长度
        （3）H：校验和
    '''
    udph = struct.unpack('!HHHH', udp_header)

    # 源端口号
    source_port = udph[0]
    # 目的端口号
    destination_port = udph[1]
    # 总长度
    total_length = udph[2]
    # 校验和
    checksum = udph[3]

    return udphl, source_port, destination_port, total_length, checksum


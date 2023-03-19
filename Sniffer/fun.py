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

    print("IP:")
    print(('版本: {version}, 首部长度: {header_length}, 总长度: {length}, TTL: {ttl}, '
           '协议: {protocol}, 源地址: {source}, 目的地址: {destination}').format(
        version = version, header_length = ihl, length = total_length,
        ttl = ttl, protocol = protocol, source = source_addr,
        destination = destination_addr
    ))

    return ihl, protocol


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

    print("ICMP:")
    print(('类型: %d, 代码: %d, 校验和: %d'
        % (type, code, checksum)))


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

    print("TCP:")
    print(('源端口号: {source_port}, 目的端口号: {destination_port}, 序号: {sequence}, '
           '确认序号: {ack_sequence}, 首部长度: {thl}, 窗口大小: {window_size}').format(
        source_port = source_port, destination_port = destination_port,
        sequence = sequence, ack_sequence = ack_sequence,
        thl = thl, window_size = window_size
    ))


def parse_udp(data, ihl):
    #udp header
    udp_header = data[ihl: ihl + 8]

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

    print("UDP:")
    print(('源端口号: {source_port}, 目的端口号: {destination_port}, '
           '总长度: {total_length}, 校验和: {checksum}').format(
        source_port = source_port, destination_port = destination_port,
        total_length = total_length, checksum = checksum
    ))


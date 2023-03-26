from util import app, net, trans



def ip_fun(data):
    # ip
    version, ihl, total_length, ttl, protocol, source_addr, destination_addr = net.parse_ip(data)

    print("--------------------------------------------------------------------------------")
    print("IP:")
    print(('版本: {version}, 首部长度: {header_length}, 总长度: {length}, TTL: {ttl}, '
           '协议: {protocol}, 源地址: {source}, 目的地址: {destination}').format(
        version=version, header_length=ihl, length=total_length,
        ttl=ttl, protocol=protocol, source=source_addr,
        destination=destination_addr
    ))



def udp_fun(data):
    # ip
    version, ihl, total_length, ttl, protocol, source_addr, destination_addr = net.parse_ip(data)
    # udp
    if protocol == 17:
        udphl, source_port, destination_port, total_length, checksum = trans.parse_udp(data, ihl)

        print("--------------------------------------------------------------------------------")
        print("UDP:")
        print(('源端口号: {source_port}, 目的端口号: {destination_port}, '
               '总长度: {total_length}, 校验和: {checksum}').format(
            source_port = source_port, destination_port = destination_port,
            total_length = total_length, checksum = checksum
        ))



def tcp_fun(data):
    # ip
    version, ihl, total_length, ttl, protocol, source_addr, destination_addr = net.parse_ip(data)
    # tcp
    if protocol == 6:
        source_port, destination_port, sequence, ack_sequence, thl, window_size = trans.parse_tcp(data, ihl)

        print("--------------------------------------------------------------------------------")
        print("TCP:")
        print(('源端口号: {source_port}, 目的端口号: {destination_port}, 序号: {sequence}, '
               '确认序号: {ack_sequence}, 首部长度: {thl}, 窗口大小: {window_size}').format(
            source_port=source_port, destination_port=destination_port,
            sequence=sequence, ack_sequence=ack_sequence,
            thl=thl, window_size=window_size
        ))



def icmp_fun(data):
    # ip
    version, ihl, total_length, ttl, protocol, source_addr, destination_addr = net.parse_ip(data)
    # icmp
    if protocol == 1:
        type, code, checksum = trans.parse_icmp(data, ihl)

        print("--------------------------------------------------------------------------------")
        print("ICMP:")
        print(('类型: %d, 代码: %d, 校验和: %d'
            % (type, code, checksum)))



def http_fun(data):
    # ip
    version, ihl, total_length, ttl, protocol, source_addr, destination_addr = net.parse_ip(data)
    # tcp
    if protocol == 6:
        source_port, destination_port, sequence, ack_sequence, thl, window_size = trans.parse_tcp(data, ihl)
        # HTTP
        if destination_port == 80:
            app.parse_http(ihl+thl, data)



def dns_fun(data):
    # ip
    version, ihl, total_length, ttl, protocol, source_addr, destination_addr = net.parse_ip(data)
    # udp
    if protocol == 17:
        udphl, source_port, destination_port, total_length, checksum = trans.parse_udp(data, ihl)
        # DNS
        if destination_port == 53:
            print("--------------------------------------------------------------------------------")
            app.parse_DNS(udphl, data)

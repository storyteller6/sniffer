import fun
import socket

flag = 1



if __name__ == '__main__':

    '''
        这里创建一个socket，用于接收和发送IP数据包，也包括TCP、UDP、ICMP 和其他协议的数据包
        它的recvfrom()方法从socket接收数据，并返回数据和源地址
        数据部分包括IP数据报、TCP/UDP数据
        在Linux环境下，创建socket时，第一个参数可设置为socket.AF_PACKET，调用recvfrom()方法就可返回MAC头
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 0)
    '''
        绑定使用的网卡
        1.获取本机IP地址
        2.绑定，将端口号设置为0,表示让操作系统自动选择一个空闲的端口号来绑定该socket
    '''
    HOST = socket.gethostbyname(socket.gethostname())
    print("HOST: ", HOST)
    s.bind((HOST, 0))
    # 设置套接字选项是IP的，使用套接字选项IP_HDRINC,1
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    # 启用混杂模式，捕获数据包
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    # 开始捕获数据包
    while flag:
        print("--------------------------------------------------------------------------------")
        try:
            data, addr = s.recvfrom(65535)

            ihl, protocol = fun.parse_ip(data)

            if protocol == 1:
                fun.parse_icmp(data, ihl)
            elif protocol == 6:
                fun.parse_tcp(data, ihl)
            elif protocol == 17:
                fun.parse_udp(data, ihl)
            else:
                print("其他协议！")
        except KeyboardInterrupt:
            print("退出！！！")
            break

    # 关闭混杂模式
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    s.close()


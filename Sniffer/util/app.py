import dns.message
import dns.rdataclass
import dns.rdatatype

def parse_http(thl, data):
    http_data = data[thl:]
    method = ""
    path = ""
    protocol = ""

    # 解析HTTP请求
    try:
        request_lines = http_data.split(b'\r\n')
        method, path, protocol = request_lines[0].split(b' ')

        print("--------------------------------------------------------------------------------")
        print("HTTP:")
        print(('请求方法: {method}, URL: {path}, 协议版本: {protocol}').format(
            method=method, path=path, protocol=protocol
        ))
    except ValueError:
        pass
        #print("ValueError!")



def parse_DNS(udphl, data):
    dns_data = data[udphl:]

    #解析DNS
    try:
        dns_msg = dns.message.from_wire(dns_data)
        print("DNS:")
        for question in dns_msg.question:
            print('DNS Query: ', question.name)
        for answer in dns_msg.answer:
            print('DNS Response: ', answer.to_text())
    except:
        print('解析DNS失败！')

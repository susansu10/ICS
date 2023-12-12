from scapy.all import *
import matplotlib.pyplot as plt

pcap = rdpcap('normal_1hr.pcapng')

S_IP = '192.168.1.19'
T_IP = '192.168.1.23'

# 先把 source_ip = 192.168.1.19, target_ip = 192.168.1.23的封包抓出來
# 把他們存成 all_pkt.txt
with open('all_pkt.txt', 'w') as f:
    for pkt in pcap:
        if 'IP' in pkt :
            source_ip = pkt['IP'].src
            target_ip = pkt['IP'].dst
            if source_ip == S_IP and target_ip == T_IP:
                # print(pkt.summary())
                f.write(f"{pkt.summary()}\n")
        
                if 'TCP' in pkt and pkt['TCP'].flags & 0x18 and len(pkt) == 69:
                    if 'Raw' in pkt:
                        f.write(f"[ Target : {pkt.summary()} ]\n")
                
f.close()

# 把是 response 且 len = 69的封包抓出來
# 存成 target_pkt.txt
with open('target_pkt.txt', 'w') as f:
    for pkt in pcap:
        if 'IP' in pkt :
            source_ip = pkt['IP'].src
            target_ip = pkt['IP'].dst
            if source_ip == S_IP and target_ip == T_IP:
                if 'TCP' in pkt and pkt['TCP'].flags & 0x18 and len(pkt) == 69:
                    if 'Raw' in pkt:
                        f.write(f"{pkt.summary()}\n")
f.close()

# 把是 response 且 len = 69的封包的 payload 抓出來
# 判斷 register 0 的值
# 存成 target_payload.txt
# 將 register 0 的值存成 register_0_value
register_0_value = []
with open('target_payload.txt', 'w') as f:
    for pkt in pcap:
        if 'IP' in pkt :
            source_ip = pkt['IP'].src
            target_ip = pkt['IP'].dst
            if source_ip == S_IP and target_ip == T_IP:
                if 'TCP' in pkt and pkt['TCP'].flags & 0x18 and len(pkt) == 69:
                    if 'Raw' in pkt:
                        modbus_payload = pkt['Raw'].load.hex()
                        f.write(f"{modbus_payload}, {len(modbus_payload)}\n")
                        for i in range(len(modbus_payload)):
                            f.write(f"{modbus_payload[i]}, ")
                        f.write("\n")
                        for i in range(18, 22):
                            f.write(f"{modbus_payload[i]}, ")
                        f.write("\n")
                        hex_string = ""
                        for i in range(18, 22):
                            hex_string += str(modbus_payload[i])
                            
                        register_0_value.append(int(hex_string, 16))
                        f.write(f"{hex_string}, {int(hex_string, 16)} \n")

# print(register_0_value)


# 畫圖
plt.figure(figsize=(30, 10))

timestamps = list(range(len(register_0_value)))

plt.plot(timestamps, register_0_value, marker='o', linestyle='-', color='b', label='Register 0 Values')

plt.title('Register 0 Values Over Time')
plt.xlabel('times')
plt.ylabel('Register 0 Value')
plt.legend()
plt.savefig('./register_0_trend.png')
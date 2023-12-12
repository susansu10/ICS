# ICS - project

題目要求 :
- 讀取 normal_1hr.pcapng
- 畫出 PLC 192.168.1.19 register 0 (水位) 每一秒數值的趨勢圖
- 過濾 source_IP= 192.168.1.19, target_IP=192.168.23, modbus protocol才進行分析
- 進一步判斷某筆封包為 request, start addr=0才進入處理
- 再讀符合條件之下一筆封包(response)，addr=0 (第一個值)
- 值應該是：10913, 11175, 11421, 11500, ...


1. project.py
    - Main Program
2. all_pkt.txt
    - Store all pkt.s_ip = '192.168.1.19' and pkt.d_ip = '192.168.1.23'
    - Also judge what is target reponse pkt
3. target_pkt.txt
    - Store the target pkt we need to analysis
4. target_payload.txt
    - Store the target pkt payload and also analysis the register 0 value we need
5. register_0_trend
    - Draw IP = '192.168.1.19' register 0 value trend

hii

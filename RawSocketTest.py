from scapy.all import *
import threading
import time
import sys

#イーサネットフレーム送信関数
def send_frame(interface, src_mac_addr, payload, is_jumbo):
    if is_jumbo == True:
        payload = "A"*1504 #Windows 10では、FCSフィールドを検出できないため、データフィールドをかさ増し(1504byte)
    else:
        pass
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff", src=src_mac_addr, type=0x88B5) / Raw(load=payload) #宛先のMACアドレスはブロードキャスト、送信元は指定したMACアドレス、タイプフィールドはIPv4
    sendp(ether_frame, iface=interface, verbose=0)

#イーサネットフレーム受信関数
def receive_frame(interface, src_mac_addr, timeout=2):
    def packet_handler(packet):
        if packet.haslayer(Ether): #イーサネットレイヤーが存在するか
            eth = packet.getlayer(Ether)
            if eth.src != src_mac_addr: # 送信元MACアドレスがターゲットMACアドレスと一致するか確認
                print(f"Received frame: {packet.summary()}\n")
                print("-----Packet detail---------------")
                packet.show()

    sniff(iface=interface, prn=packet_handler, timeout=timeout)

def is_jumbo(jumbo_mode):
    if jumbo_mode.lower() == "on":
        return True
    elif jumbo_mode.lower() == "off":
        return False
    else:
        print(f"Usage  : python3 {sys.argv[0]} [interface_name] [src_mac_address] [payload] [jumbo frame mode: on/off]")
        print(f"Example: python3 {sys.argv[0]} \"イーサネット 2\" 00:00:00:00:00:00 \"Message\" off" )
        exit(1)

#メイン関数
def main():
    if len(sys.argv) != 5:
        print(f"Usage  : python3 {sys.argv[0]} [interface_name] [src_mac_address] [payload] [jumbo frame mode: on/off]")
        print(f"Example: python3 {sys.argv[0]} \"イーサネット 2\" 00:00:00:00:00:00 \"Message\" off" )
        exit(1)

    interface = sys.argv[1] #インターフェイス名を指定
    src_mac_addr = sys.argv[2] #自分のMACアドレス
    payload = sys.argv[3] #ペイロードを指定
    jumbo_mode = sys.argv[4] #ジャンボフレームにするかどうか

    is_jumbo_mode = is_jumbo(jumbo_mode)

    # 受信スレッドを立ち上げ
    receive_thread = threading.Thread(target=receive_frame, args=(interface, src_mac_addr))
    receive_thread.start()
    time.sleep(1) # 受信側が準備できるように少し待つ
    
    # 送信スレッドを立ち上げ
    send_thread = threading.Thread(target=send_frame, args=(interface, src_mac_addr, payload, is_jumbo_mode))
    send_thread.start()

    send_thread.join()
    receive_thread.join()

if __name__ == "__main__":
    main()

from scapy.all import *
import threading
import time
import sys

#イーサネットフレーム送信関数
def send_frame(interface, src_mac_addr, payload):
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff", src=src_mac_addr, type=0x0800) / payload #宛先のMACアドレスはブロードキャスト、送信元は指定したMACアドレス、タイプフィールドはIPv4
    sendp(ether_frame, iface=interface, verbose=0)

#イーサネットフレーム受信関数
def receive_frame(interface, src_mac_addr, timeout=5):
    def packet_handler(packet):
        if packet.haslayer(Ether): #イーサネットレイヤーが存在するか
            eth = packet.getlayer(Ether)
            if eth.src != src_mac_addr: # 送信元MACアドレスがターゲットMACアドレスと一致するか確認
                print(f"Received frame: {packet.summary()}\n")
                print("-----Packet detail---------------")
                packet.show()

    sniff(iface=interface, prn=packet_handler, timeout=timeout)

#メイン関数
def main():
    if len(sys.argv) != 4:
        print(f"Usage  : python3 {sys.argv[0]} [interface_name] [src_mac_address] [payload]")
        print(f"Example: python3 {sys.argv[0]} \"イーサネット 2\" 00:00:00:00:00:00 \"Message\"" )
        exit(1)

    interface = sys.argv[1] #インターフェイス名を指定
    src_mac_addr = sys.argv[2] #自分のMACアドレス
    payload = sys.argv[3] #ペイロードを指定

    # 受信スレッドを立ち上げ
    receive_thread = threading.Thread(target=receive_frame, args=(interface, src_mac_addr))
    receive_thread.start()
    time.sleep(1) # 受信側が準備できるように少し待つ
    
    # 送信スレッドを立ち上げ
    send_thread = threading.Thread(target=send_frame, args=(interface, src_mac_addr, payload))
    send_thread.start()

    send_thread.join()
    receive_thread.join()

if __name__ == "__main__":
    main()

# Raw-Socket-Programming
セキュリティ・ミニキャンプ 2024 in 沖縄の課題用プログラム
windows用。

### 概要
環境に合わせて設定し、イーサネットフレームの送受信をテストする。

### 使い方
※root権限のコマンドプロンプトで実行してください
```
python3 ./RawSocketTest.py [interface_name] [src_mac_address] [payload]
```

### 必要なもの
- Python
  - https://www.python.org/downloads/
- Scapy
  - ``` pip install scapy ``` 
- Npcap
  - https://npcap.com/dist/npcap-1.79.exe

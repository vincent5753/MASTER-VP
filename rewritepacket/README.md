# 改寫封包
## 環境
```
sudo apt install tcpreplay
```
## 改寫封包(pcap) / rewrite packet(pcap)
```
tcprewrite -v -i ~/240125-pfcp_req.pcap --enet-dmac=ca:8c:18:a3:c3:43 --dstipmap=10.244.0.5/32:10.244.0.19/32 --fixcsum -o ~/240125-pfcp_req-rewrite-test-upf-2.pcap
```
`-v` 詳細輸出 (Verbose)</br>
`-i` 輸入檔案 (Input file)</br>
`--enet-dmac` 更改目標 MAC 位置 (Change DST MAC address)</br>
`--dstipmap` 將目標 IP 位置從 A 改為 B (Change DST IP address from A to B)</br>
`--fixcsum` 自動計算 L2(IP)、L3(TCP/UDP) 的 checksum (Calculate checksum of L2(IP)、L3(TCP/UDP) Header for modified packet)

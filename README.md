# MASTER-VP
## 介紹 / Intro
`getpodveth.sh` 輸入 `pod 名稱` 並輸出宿主機上對應的 `veth` 網卡

## 使用 / Usage
簡單地執行 `getpodveth.sh` 並將 `pod 名稱` 做為參數執行
```
bash getpodveth.sh $pod1 $pod2 ...etc
```

範例 / Example:
```
bash getpodveth.sh free5gc-upf-deployment-74d59fbdd-dwplg free5gc-amf-deployment-5d69874b88-m8cdm ...
```

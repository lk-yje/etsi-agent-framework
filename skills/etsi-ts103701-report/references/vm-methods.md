# VM 设备特别方法

> 来自真实测试记录，VM 网络摄像机端口扫描专用。

## 端口减法扫描

```bash
# Step 1: DUT 启动前，扫描宿主机端口作为基线
nmap -Pn -n -sS -sV --open -v -p- <HOST_IP> -oN baseline_tcp.txt

# Step 2: 启动 DUT 后再次扫描
nmap -Pn -n -sS -sV --open -v -p- <HOST_IP> -oN dut_tcp.txt

# Step 3: 对比两次结果，新增端口 = DUT 端口
diff <(grep '/tcp' baseline_tcp.txt | awk '{print $1}') \
     <(grep '/tcp' dut_tcp.txt | awk '{print $1}')
```

## UDP 进程端口排查

UDP 扫描不准确时，在 DUT 宿主机上通过进程关联排查。

### 宿主机为 Windows

```bash
netstat -ano | findstr <KNOWN_TCP_PORT>
netstat -ano | findstr <PID>
```

### 宿主机为 Linux

```bash
netstat -tlnp | grep <KNOWN_TCP_PORT>
ss -tlnp | grep <KNOWN_TCP_PORT>
netstat -pntul | grep <PID>
ss -tulpn | grep <PID>
```

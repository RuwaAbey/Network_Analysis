## 1. Introdunction and getting started 

a. Display the traffic in defualt format

```bash
tcpdump
```
b. Manual of tcpdump

```bash
man tcpdump
```

c. The -c specify the number of packets

```bash
tcpdump -c 10 
```

d. The -# shows the ine numbers in the traffic display.

```bash
tcpdump -c 10 -# 
```

e. The -A shows the actual data packets captured in ASCII

```bash
tcpdump -c 10 -A 
```
f. The -XX shows the both hexadecimal and ASCII side by side

```bash
tcpdump -c 10 -XX 
```

g. The -tttt shows the date and time in the format of YYYY-MM-DD HH:MM:SS.frac

```bash
tcpdump -c 10 -tttt 
```

## 2. Start Building the Logging Tool Script

a. The -D option shows all the network inerfaces

```bash
tcpdump -D 
```

b. Ping the localhost

```bash
ping localhost
```

c. The -i can spcecify the network interface

```bash
sudo tcpdump -c 10 -i lo 
```

d. The port can specify the port 

```bash
tcpdump -c 10 -#XXtttt port 443 
```

e. host/src/dst

```bash
sudo tcpdump -c 10 -#XXtttt host coursera.org
        1. host
        2. src
        3. dst
```

f. Give access to everyone for the respective folder you are working on so that third party write access is enabled.

```bash
chmod 777 ../TCPDUMP-logging-tool/ 
```

## 3. Save Captured Packets in a DUmp File

a. The -w option writes captures data to dump file

```bash
sudo tcpdump -c 10 -#XXtttt host coursera.org -w capture.pcap
```
As shown below the third party user tcpdump can writes in to our working folder.

```bash
drwxrwxrwx 2 ruwa    ruwa     4096 Mar 21 05:51 .
drwxrwxr-x 7 ruwa    ruwa     4096 Mar 20 18:27 ..
-rw-r--r-- 1 tcpdump tcpdump 10596 Mar 21 05:52 capture.pcap
-rw-rw-r-- 1 ruwa    ruwa      869 Mar 21 05:49 README.md
-rwxrwxr-x 1 ruwa    ruwa       74 Mar 21 05:51 watchdog.sh
```

b. The -r option reads captured data from dump files as if it was capturing it

```bash
tcpdump -r capture.pcap 
```

c. When reading dump files, you can apply different formatting options to get different views

```bash
tcpdump -r capture.pcap -#XXtttt
```

d. Wireshark is a useful application to analyze captured data

## 4. Create sequenced Dump Files

a. The -G option sets a time limit on the dump file, after that time limit is up, the content of the file is erased to start over. (time in seconds)

``` bash
sudo tcpdump host coursera.org -w capture.pcap -G 15
 ```

b. The -C option sets a size limit on the dump file, given in million of bytes(1MB)

```bash
sudo tcpdump host coursera.org -w capture.pcap -C 1
```
*creates a new pcap after every 1MB

```bash
total 1876
drwxrwxrwx 2 ruwa    ruwa       4096 Mar 21 06:36 .
drwxrwxr-x 7 ruwa    ruwa       4096 Mar 20 18:27 ..
-rw-r--r-- 1 tcpdump tcpdump 1004627 Mar 21 06:36 capture.pcap
-rw-r--r-- 1 tcpdump tcpdump  897024 Mar 21 06:36 capture.pcap1
-rw-rw-r-- 1 ruwa    ruwa       2251 Mar 21 06:33 README.md
-rwxrwxr-x 1 ruwa    ruwa         64 Mar 21 06:29 watchdog.sh
```

c. Creates a new file after every 1MB and rewrite the pcap file created for every 10 seconds.

```bash
sudo tcpdump host coursera.org -w capture.pcap -G 10 -C 1
```

## 5. Decrypt and Analyze Captured Traffic

```bash
export SSLKEYLOGFILE=/home/coder/coursera/sslkeys
/usr/bin/google-chrome-stable &
sudo tcpdump host coursera.org -w capture.pcap -G 10 -C 1
```

a. Set the environmental variable SSLKEYLOGFILE to the path where you want the web browsers to capture the private keys used in SSL encryption

```bash
export SSLKEYLOGFILE=/home/coder/coursera/sslkeys
```
b. In Wireshark, set the Protocol TLS Pre-master secret log file to decrypt encrypted traffic capture

- Go to
- Edit -> Preference -> Protocols -> Sroll down to TLS (Transport Layer Security) 
- Go to last shell which is (Pre)-Master-Secret log filename
- Add the keyfile

*only the HTTP are encrpyted here





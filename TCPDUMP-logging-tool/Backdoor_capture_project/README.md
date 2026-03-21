### Checking for spy who capture TCP traffic coming thorugh SSH

You suspect that someone is trying to open SSH sessions into your workstation and decided to set up a surveillance script to catch any TCP traffic coming through as SSH.

### 1.Create a shell script file called checkspy.sh and give it +x access.

### 2. Capture all packets coming though as SSH (port 22).

a. In order to catch SSH traffic you need to monitor port 22

b. Since we are only testing this locally, you need to change your interface option.

c. You can test your script by opening a terminal window and execute SSH localhost. (It probably won't succeed unless you have an SSH server running but it will generate SSH traffic)

```bash
ssh localhost
```

### 3. Dump the captured packet in files called proof.pcap.

### 4. Make sure the dump files are no bigger than 2,000,000 bytes and contain no longer than 10 minutes of capture

### 5. Optionally: Analyze the dump file with Wireshark.
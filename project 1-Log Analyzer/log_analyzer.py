
keywords = ["failed", "error", "invalid", "unauthorized", "denied"]

count = 0
ip_counter = {} #ip count

with open("sample_log.txt", "r") as log_file:

    print("Suspicious activities found:\n")

    for line in log_file:
        for word in keywords:
            if word in line.lower():

                print(line.strip())
                count += 1

                words = line.split()

                for item in words:
                    if "." in item: #ip as .  inbetween numbers
                        ip = item
                        if ip in ip_counter:
                            ip_counter[ip] += 1
                        else:
                            ip_counter[ip] = 1

                break

print("\nTotal suspicious events:", count)

print("\nIP Activity Summary:")
for ip, attempts in ip_counter.items():
    print(ip, "->", attempts, "attempts")
    
print("\nPossible Attacks:")

for ip, attempts in ip_counter.items():
    if attempts >= 3:
        print("ALERT: Possible brute force attack from", ip)    
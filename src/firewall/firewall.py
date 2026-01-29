import random

def generate_random_ip():
    return f"192.168.1.{random.randint(0,25)}"

def check_firewall_rules(ip, rules):
    for rule_ip, action in rules.items():
        if ip == rule_ip:
            return action
    return "allow"

def main():
    #ip addresses for testing rules
    fw_rules = {
        "192.168.1.1":"block",
        "192.168.1.19":"block",
        "192.168.1.22":"block",
        "192.168.1.18":"block",
        "192.168.1.4":"block",
    }

    for _ in range(12):
        ip_address = generate_random_ip()
        action = check_firewall_rules(ip_address, fw_rules)
        randomNum = random.randint(0,999)
        print(f"IP: {ip_address}, Action: {action}, Random: {randomNum}")

#main guard to ensure when executed main is pulled
if __name__ == "__main__":
    main()

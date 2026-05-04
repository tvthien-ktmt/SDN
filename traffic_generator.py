#!/usr/bin/env python3
# traffic_generator.py
# Chay trong Mininet (Linux) de sinh traffic thu thap data
#
# Cach dung:
#   sudo python3 traffic_generator.py --mode normal   => sinh traffic binh thuong
#   sudo python3 traffic_generator.py --mode attack   => sinh traffic tan cong DDoS

import argparse
import time
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.topo import Topo
from mininet.log import setLogLevel


# ================================================================
# Topology: 1 switch, 4 hosts
#
#   h1 (10.0.0.1)  ─┐
#   h2 (10.0.0.2)  ─┤
#                    s1 ──── Controller (Ryu)
#   h3 (10.0.0.3)  ─┤
#   h4 (10.0.0.4)  ─┘
# ================================================================
class SimpleTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1', protocols='OpenFlow13')
        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        h3 = self.addHost('h3', ip='10.0.0.3/24')
        h4 = self.addHost('h4', ip='10.0.0.4/24')
        for h in [h1, h2, h3, h4]:
            self.addLink(h, s1)


def collect_normal_traffic(net, duration=3000):
    """
    Sinh traffic BINH THUONG - nhieu loai khac nhau
    Dam bao data_collector.py dang chay voi CURRENT_LABEL = 0
    """
    h1, h2, h3, h4 = net.get('h1', 'h2', 'h3', 'h4')

    print("\n[NORMAL] Bat dau sinh traffic binh thuong...")
    print("[NORMAL] Dam bao data_collector.py: CURRENT_LABEL = 0")
    print(f"[NORMAL] Thu thap trong {duration} giay ({duration//60} phut)...\n")

    # Khoi dong iperf3 server tren h3 va h1 de client ket noi
    h3.cmd('iperf3 -s -D')  # -D: chay nen (daemon)
    h1.cmd('iperf3 -s -D')
    time.sleep(1)

    end_time = time.time() + duration

    while time.time() < end_time:
        # 1. Ping binh thuong giua cac host
        h1.cmd('ping -c 10 10.0.0.2 &')
        h3.cmd('ping -c 10 10.0.0.4 &')
        time.sleep(5)

        # 2. iperf TCP nhe
        h2.cmd('iperf3 -c 10.0.0.3 -t 5 -b 1M &')
        time.sleep(6)

        # 3. iperf UDP nhe
        h4.cmd('iperf3 -c 10.0.0.1 -u -t 5 -b 512K &')
        time.sleep(6)

        remaining = int(end_time - time.time())
        print(f"[NORMAL] Con lai: {remaining} giay...")

    # Cleanup
    for h in [h1, h2, h3, h4]:
        h.cmd('pkill ping 2>/dev/null')
        h.cmd('pkill iperf3 2>/dev/null')
    print("[NORMAL] HOAN THANH thu thap traffic binh thuong!")


def collect_attack_traffic(net, duration=3000):
    """
    Sinh traffic TAN CONG DDoS
    Dam bao data_collector.py dang chay voi CURRENT_LABEL = 1
    """
    h1, h2, h3, h4 = net.get('h1', 'h2', 'h3', 'h4')

    print("\n[ATTACK] Bat dau sinh traffic tan cong DDoS...")
    print("[ATTACK] Dam bao data_collector.py: CURRENT_LABEL = 1")
    print(f"[ATTACK] Thu thap trong {duration} giay ({duration//60} phut)...\n")

    h3.cmd('iperf3 -s &')
    h4.cmd('iperf3 -s &')
    time.sleep(1)

    end_time = time.time() + duration

    while time.time() < end_time:
        # 1. ICMP Flood (ping flood) tu h1 -> h4
        print("[+] ICMP Flood: h1 -> h4 (50000 goi)...")
        h1.cmd('ping -c 50000 -i 0.001 10.0.0.4 &')

        # 2. UDP Flood bang hping3 (tu h2 -> h3)
        # Dung luong random, max toc do (--flood)
        print("[+] hping3 UDP Flood: h2 -> h3 port 80...")
        h2.cmd('hping3 --udp -p 80 --flood --rand-source 10.0.0.3 &')

        # 3. TCP SYN Flood bang hping3 (tu h1 -> h3)
        # Bắn gói SYN liên tục làm tràn bảng kết nối
        print("[+] hping3 TCP SYN Flood: h1 -> h3 port 80...")
        h1.cmd('hping3 -S -p 80 --flood --rand-source 10.0.0.3 &')

        # 4. TCP ACK Flood bang hping3 (tu h2 -> h4)
        # Bắn gói ACK giả mạo làm tốn tài nguyên xử lý của firewall/switch
        print("[+] hping3 TCP ACK Flood: h2 -> h4 port 80...")
        h2.cmd('hping3 -A -p 80 --flood --rand-source 10.0.0.4 &')

        # 5. TCP FIN Flood bang hping3 (tu h1 -> h4)
        # Bắn gói FIN giả mạo để phá hoại kết nối
        print("[+] hping3 TCP FIN Flood: h1 -> h4 port 80...")
        h1.cmd('hping3 -F -p 80 --flood --rand-source 10.0.0.4 &')

        time.sleep(15)

        # Tat hping3 va ping de chuan bi vong lap tiep theo
        h1.cmd('pkill hping3 2>/dev/null')
        h2.cmd('pkill hping3 2>/dev/null')
        time.sleep(2)

        remaining = int(end_time - time.time())
        print(f"[ATTACK] Con lai: {remaining} giay...\n")

    # Cleanup
    for h in [h1, h2, h3, h4]:
        h.cmd('pkill ping 2>/dev/null')
        h.cmd('pkill iperf3 2>/dev/null')
        h.cmd('pkill hping3 2>/dev/null')

    print("[ATTACK] HOAN THANH thu thap traffic tan cong!")


def main():
    parser = argparse.ArgumentParser(description='Mininet Traffic Generator for DDoS Dataset')
    parser.add_argument('--mode', choices=['normal', 'attack'], required=True,
                        help='normal: safe traffic | attack: DDoS traffic')
    parser.add_argument('--duration', type=int, default=3000,
                        help='Thoi gian thu thap (giay). Default=3000 (50 phut). Vi du: 7200 = 2 tieng')
    args = parser.parse_args()

    setLogLevel('info')

    print("=" * 60)
    print(f"  CHE DO:   {'BINH THUONG (label=0)' if args.mode == 'normal' else 'TAN CONG (label=1)'}")
    print(f"  THOI GIAN: {args.duration} giay ({args.duration//60} phut)")
    print("=" * 60)

    topo = SimpleTopo()
    net = Mininet(
        topo=topo,
        controller=RemoteController('c0', ip='127.0.0.1', port=6653),
        switch=OVSSwitch
    )

    net.start()
    print("[*] Doi 3 giay de switch ket noi voi Ryu...")
    time.sleep(3)

    # Kiem tra ket noi co ban
    print("[*] Kiem tra ping co ban...")
    result = net.ping([net.get('h1'), net.get('h2')], timeout=2)
    if result > 0:
        print("[!] CANH BAO: Ping giua h1-h2 co mat goi. Kiem tra lai Ryu controller!")
    else:
        print("[OK] Ping thanh cong, bat dau thu thap...")

    # Sinh traffic theo mode
    if args.mode == 'normal':
        collect_normal_traffic(net, args.duration)
    else:
        collect_attack_traffic(net, args.duration)

    net.stop()
    print("\n[DONE] Da dung Mininet. Kiem tra file collected_data.csv")


if __name__ == '__main__':
    main()

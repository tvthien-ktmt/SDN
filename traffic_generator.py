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


def collect_normal_traffic(net):
    """
    Sinh traffic BINH THUONG - nhieu loai khac nhau
    Dam bao data_collector.py dang chay voi CURRENT_LABEL = 0
    """
    h1, h2, h3, h4 = net.get('h1', 'h2', 'h3', 'h4')

    print("\n[NORMAL] Bat dau sinh traffic binh thuong...")
    print("[NORMAL] Dam bao data_collector.py: CURRENT_LABEL = 0")
    print("[NORMAL] Thu thap trong 300 giay (5 phut)...\n")

    end_time = time.time() + 300  # Thu thap 5 phut (du de co ~200 mau)

    while time.time() < end_time:
        # 1. Ping bình thường giữa các host
        print("[+] h1 ping h2 (10 goi)...")
        h1.cmd('ping -c 10 10.0.0.2 &')

        print("[+] h3 ping h4 (10 goi)...")
        h3.cmd('ping -c 10 10.0.0.4 &')

        time.sleep(5)

        # 2. iperf TCP nhe (bandwidth thap)
        print("[+] iperf TCP: h2 -> h3 (5 giay, 1Mbps)...")
        h2.cmd('iperf3 -c 10.0.0.3 -t 5 -b 1M &')

        time.sleep(8)

        # 3. iperf UDP nhe
        print("[+] iperf UDP: h4 -> h1 (5 giay, 512Kbps)...")
        h4.cmd('iperf3 -c 10.0.0.1 -u -t 5 -b 512K &')

        time.sleep(8)

        remaining = int(end_time - time.time())
        print(f"[NORMAL] Con lai: {remaining} giay...\n")

    print("[NORMAL] HOAN THANH thu thap traffic binh thuong!")


def collect_attack_traffic(net):
    """
    Sinh traffic TAN CONG DDoS
    Dam bao data_collector.py dang chay voi CURRENT_LABEL = 1
    """
    h1, h2, h3, h4 = net.get('h1', 'h2', 'h3', 'h4')

    print("\n[ATTACK] Bat dau sinh traffic tan cong DDoS...")
    print("[ATTACK] Dam bao data_collector.py: CURRENT_LABEL = 1")
    print("[ATTACK] Thu thap trong 300 giay (5 phut)...\n")

    # Cai dat iperf server tren h3, h4
    h3.cmd('iperf3 -s &')
    h4.cmd('iperf3 -s &')
    time.sleep(1)

    end_time = time.time() + 300  # Thu thap 5 phut (du de co ~200 mau)

    while time.time() < end_time:
        # 1. ICMP Flood (ping flood) tu h1 -> h4
        # Dung -f (flood) hoac nhieu goi ping nhanh
        print("[+] ICMP Flood: h1 -> h4 (50000 goi)...")
        h1.cmd('ping -c 50000 -i 0.001 10.0.0.4 &')

        # 2. UDP Flood tu nhieu nguon -> h3
        print("[+] UDP Flood: h2 -> h3 (bandwidth cao)...")
        h2.cmd('iperf3 -c 10.0.0.3 -u -t 15 -b 100M &')

        # 3. TCP SYN Flood (neu co hping3)
        # Neu khong co hping3, dung iperf
        print("[+] TCP Flood: h1 -> h3 (bandwidth cao)...")
        h1.cmd('iperf3 -c 10.0.0.3 -t 15 -b 50M -P 10 &')

        time.sleep(15)

        # Tat iperf de tranh tiep tuc
        h1.cmd('pkill iperf3 2>/dev/null')
        h2.cmd('pkill iperf3 2>/dev/null')
        time.sleep(2)

        remaining = int(end_time - time.time())
        print(f"[ATTACK] Con lai: {remaining} giay...\n")

    # Cleanup
    for h in [h1, h2, h3, h4]:
        h.cmd('pkill ping 2>/dev/null')
        h.cmd('pkill iperf3 2>/dev/null')

    print("[ATTACK] HOAN THANH thu thap traffic tan cong!")


def main():
    parser = argparse.ArgumentParser(description='Mininet Traffic Generator for DDoS Dataset')
    parser.add_argument('--mode', choices=['normal', 'attack'], required=True,
                        help='normal: thu thap traffic binh thuong | attack: thu thap traffic tan cong')
    args = parser.parse_args()

    setLogLevel('info')

    print("=" * 60)
    print(f"  CHE DO: {'BINH THUONG (label=0)' if args.mode == 'normal' else 'TAN CONG (label=1)'}")
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
        collect_normal_traffic(net)
    else:
        collect_attack_traffic(net)

    net.stop()
    print("\n[DONE] Da dung Mininet. Kiem tra file collected_data.csv")


if __name__ == '__main__':
    main()

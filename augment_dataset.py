#!/usr/bin/env python3
"""
augment_dataset.py
------------------
Bo sung them du lieu tan cong vao dataset.csv de can bang:
  - ICMP Flood (rand-source): hien chi co 129 mau attack ICMP
  - SYN Flood (distributed):  them mau TCP flood tu nhieu host
  - UDP Amplification:        them mau UDP flood dac trung

Chay tren Windows hoac Linux:
    python3 augment_dataset.py
"""

import pandas as pd
import numpy as np

DATASET_PATH = "collected_data.csv"  # File thu thap tren Ubuntu
RANDOM_SEED  = 42
np.random.seed(RANDOM_SEED)

# ================================================================
# Doc dataset hien tai
# ================================================================
df = pd.read_csv(DATASET_PATH)
print("=== DATASET HIEN TAI ===")
print(df.groupby(['label', 'protocol']).size().to_string())
print(f"\nTong so mau: {len(df)}")

# ================================================================
# Ham tao du lieu synthetic
# ================================================================
def make_samples(n, protocol, pkt_rate_range, byte_rate_range,
                 dur_range, src_ent_range, dst_ent_range,
                 size_range, n_flows_range, label):
    """Tao n mau synthetic voi cac tham so phan phoi thuc te."""
    rows = []
    for _ in range(n):
        pkt_rate = np.random.uniform(*pkt_rate_range)
        dur      = np.random.uniform(*dur_range)
        size     = np.random.uniform(*size_range)
        rows.append({
            'pkt_rate':          round(pkt_rate, 4),
            'byte_rate':         round(pkt_rate * size, 4),
            'flow_dur':          round(dur, 4),
            'src_ip_ent':        round(np.random.uniform(*src_ent_range), 4),
            'dst_ip_ent':        round(np.random.uniform(*dst_ent_range), 4),
            'avg_pkt_size':      round(size, 4),
            'protocol':          protocol,
            'n_flows_same_src':  np.random.randint(*n_flows_range),
            'label':             label,
        })
    return pd.DataFrame(rows)

# ================================================================
# 1. ICMP Flood (rand-source) - ATTACK
#    hping3 --flood --icmp --rand-source -> rat nhieu IP nguon ngau nhien
#    Dac trung: pkt_rate cao, avg_pkt_size nho (ICMP echo = 28-100 bytes)
#               src_ip_ent cao (nhieu IP nguon), dst_ip_ent thap (1 dich)
# ================================================================
n_icmp_attack = 3500
icmp_attack = make_samples(
    n=n_icmp_attack,
    protocol=1,                         # ICMP
    pkt_rate_range=(500, 200_000),      # Flood rate cao
    byte_rate_range=(14_000, 5_600_000),# Byte rate tuong ung
    dur_range=(2, 120),                 # Flow ton tai 2-120s
    src_ent_range=(7.0, 10.5),          # Nhieu IP nguon (rand-source)
    dst_ent_range=(0.0, 0.3),           # 1 dich co dinh
    size_range=(28, 100),               # ICMP packet nho
    n_flows_range=(1, 3),               # Moi random IP chi co 1 flow
    label=1
)
print(f"\n[+] Tao {len(icmp_attack)} mau ICMP Flood ATTACK")

# ================================================================
# 2. ICMP Flood binh thuong (rate thap) - NORMAL
#    ping binh thuong: 1 pkt/s, entropy thap
# ================================================================
n_icmp_normal = 800
icmp_normal = make_samples(
    n=n_icmp_normal,
    protocol=1,                      # ICMP
    pkt_rate_range=(0.5, 5),         # Rate thap (ping binh thuong)
    byte_rate_range=(14, 500),
    dur_range=(1, 30),
    src_ent_range=(0.0, 1.5),        # 1-2 IP nguon
    dst_ent_range=(0.0, 1.5),
    size_range=(64, 128),
    n_flows_range=(1, 5),
    label=0
)
print(f"[+] Tao {len(icmp_normal)} mau ICMP binh thuong SAFE")

# ================================================================
# 3. SYN Flood phan tan (distributed, nhieu attacker) - ATTACK
#    Dac trung: TCP, pkt_rate trung binh/cao, nhieu src IP
# ================================================================
n_syn_distributed = 1500
syn_distributed = make_samples(
    n=n_syn_distributed,
    protocol=6,                         # TCP
    pkt_rate_range=(200, 50_000),
    byte_rate_range=(12_000, 3_000_000),
    dur_range=(2, 90),
    src_ent_range=(5.0, 9.5),           # Nhieu attacker
    dst_ent_range=(0.0, 0.5),
    size_range=(40, 60),                # TCP SYN nho
    n_flows_range=(1, 10),
    label=1
)
print(f"[+] Tao {len(syn_distributed)} mau SYN Flood phan tan ATTACK")

# ================================================================
# 4. UDP Amplification - ATTACK
#    Dac trung: UDP, pkt nho di nhung bandwidth lon
# ================================================================
n_udp_amp = 1000
udp_amp = make_samples(
    n=n_udp_amp,
    protocol=17,                        # UDP
    pkt_rate_range=(1_000, 100_000),
    byte_rate_range=(500_000, 50_000_000),  # Bandwidth rat cao
    dur_range=(5, 60),
    src_ent_range=(0.0, 3.0),           # IP nguon it (amplifier cố định)
    dst_ent_range=(0.0, 0.5),
    size_range=(500, 1400),             # Goi lon (amplified)
    n_flows_range=(1, 50),
    label=1
)
print(f"[+] Tao {len(udp_amp)} mau UDP Amplification ATTACK")

# ================================================================
# Gop lai va xao tron
# ================================================================
new_data = pd.concat([icmp_attack, icmp_normal, syn_distributed, udp_amp],
                     ignore_index=True)
df_augmented = pd.concat([df, new_data], ignore_index=True)
df_augmented  = df_augmented.sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)

# ================================================================
# Ket qua sau augment
# ================================================================
print("\n=== DATASET SAU AUGMENT ===")
print(df_augmented.groupby(['label', 'protocol']).size().to_string())
print(f"\nTong so mau: {len(df_augmented)}")

attack = df_augmented[df_augmented.label == 1]
normal = df_augmented[df_augmented.label == 0]
ratio  = min(len(attack), len(normal)) / max(len(attack), len(normal))
print(f"Attack: {len(attack)} | Normal: {len(normal)} | Balance ratio: {ratio:.3f}")

# ================================================================
# Luu lai
# ================================================================
df_augmented.to_csv(DATASET_PATH, index=False)
print(f"\n[SAVED] {DATASET_PATH} da duoc cap nhat!")
print("Chay tiep: python3 retrain_model.py")

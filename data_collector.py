# data_collector.py
# Ryu app de thu thap flow stats va luu vao CSV de train model
# Chay: ryu-manager data_collector.py
#
# Features thu thap:
#   pkt_rate       - so goi tin / giay
#   byte_rate      - so byte / giay
#   flow_dur       - thoi gian flow (giay)
#   avg_pkt_size   - kich thuoc goi trung binh (byte/packet)
#   protocol       - giao thuc (1=ICMP, 6=TCP, 17=UDP, 0=unknown)
#   n_flows_same_src - so flow cung src IP trong cung window quet
#
# Quy trinh:
#   1. Chay file nay thay vi detection_system.py
#   2. Chay traffic_generator.py ben Mininet
#   3. Script tu dong luu flow stats + label vao collected_data.csv
#
# Label duoc xac dinh qua bien CURRENT_LABEL:
#   CURRENT_LABEL = 0  => dang thu thap traffic BINH THUONG
#   CURRENT_LABEL = 1  => dang thu thap traffic TAN CONG DDoS

import csv
import math
import os
import time
import pandas as pd

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub

# ================================================================
# *** THAY DOI BIEN NAY KHI CHUYEN GIA DOAN THU THAP ***
#   0 = Thu thap traffic BINH THUONG (ping, iperf nhe)
#   1 = Thu thap traffic TAN CONG (hping3, iperf flood)
# ================================================================
CURRENT_LABEL = 0

OUTPUT_CSV = 'collected_data.csv'
COLLECT_INTERVAL = 3  # Thu thap moi 3 giay


class DataCollector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DataCollector, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.mac_to_port = {}
        self.sample_count = 0

        # Tao file CSV neu chua ton tai
        if not os.path.exists(OUTPUT_CSV):
            with open(OUTPUT_CSV, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'pkt_rate', 'byte_rate', 'flow_dur',
                    'avg_pkt_size', 'protocol', 'n_flows_same_src',
                    'label'
                ])
            self.logger.info("Created new file: %s", OUTPUT_CSV)
        else:
            existing = pd.read_csv(OUTPUT_CSV)
            self.sample_count = len(existing)
            self.logger.info("Appending to existing file: %s (%d rows)", OUTPUT_CSV, self.sample_count)

        label_name = "BINH THUONG (SAFE)" if CURRENT_LABEL == 0 else "TAN CONG DDoS (ATTACK)"
        self.logger.info("=== DATA COLLECTOR READY ===")
        self.logger.info("=== COLLECTING LABEL: %s ===", label_name)

        self.monitor_thread = hub.spawn(self._monitor)

    # ----------------------------------------------------------
    # Cai dat table-miss flow de goi tin len controller
    # ----------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
            self.logger.info("Switch connected: dpid=%s", datapath.id)
        elif ev.state == CONFIG_DISPATCHER:
            self.datapaths.pop(datapath.id, None)

    # ----------------------------------------------------------
    # PacketIn: L2 forwarding de ping hoat dong
    # ----------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        from ryu.lib.packet import packet, ethernet, ether_types
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(datapath=datapath, priority=1,
                                    match=match, instructions=inst,
                                    idle_timeout=20, hard_timeout=60)
            datapath.send_msg(mod)

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)

    # ----------------------------------------------------------
    # Monitor: Yeu cau flow stats dinh ky
    # ----------------------------------------------------------
    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                self._request_stats(dp)
            hub.sleep(COLLECT_INTERVAL)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    # ----------------------------------------------------------
    # Thu thap va luu flow stats vao CSV
    # ----------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        if not body:
            return

        new_rows = []

        # Tinh n_flows_same_src: dem so flow theo tung src IP
        src_ip_count = {}
        for stat in body:
            if stat.packet_count == 0 or stat.priority == 0:
                continue
            src_ip = stat.match.get('ipv4_src', None)
            if src_ip:
                src_ip_count[src_ip] = src_ip_count.get(src_ip, 0) + 1

        for stat in body:
            if stat.packet_count == 0:
                continue
            if stat.priority == 0:  # Bo qua table-miss
                continue

            duration = stat.duration_sec + stat.duration_nsec / 1e9
            if duration <= 0:
                duration = 0.001

            pkt_rate  = stat.packet_count / duration
            byte_rate = stat.byte_count / duration

            # Chi luu cac flow co hoat dong thuc su
            if pkt_rate < 0.01 and byte_rate < 1:
                continue

            # Feature moi: avg_pkt_size
            avg_pkt_size = stat.byte_count / stat.packet_count if stat.packet_count > 0 else 0

            # Feature moi: protocol (lay tu match field)
            protocol = stat.match.get('ip_proto', 0)  # 1=ICMP, 6=TCP, 17=UDP

            # Feature moi: n_flows_same_src
            src_ip = stat.match.get('ipv4_src', None)
            n_flows_same_src = src_ip_count.get(src_ip, 1) if src_ip else 1

            new_rows.append([
                round(pkt_rate, 6),
                round(byte_rate, 6),
                round(duration, 3),
                round(avg_pkt_size, 3),
                int(protocol),
                int(n_flows_same_src),
                CURRENT_LABEL
            ])

        if new_rows:
            with open(OUTPUT_CSV, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerows(new_rows)
            self.sample_count += len(new_rows)
            label_name = "SAFE" if CURRENT_LABEL == 0 else "ATTACK"
            self.logger.info(
                "[%s] Saved %d samples | Total: %d rows",
                label_name, len(new_rows), self.sample_count
            )

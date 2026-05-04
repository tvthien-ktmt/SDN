# detection_system.py - DDoS Detection with Random Forest + Ryu
# Cai tien:
#   1. Log gon gang: chi hien tong hop SAFE, khong spam tung flow
#   2. Table 1: bang luat chan rieng biet, ro rang tung loai tan cong
#   3. Tu dong ghi log vao file ddos_detection.log
import pandas as pd
import joblib
import math
import logging
from logging.handlers import RotatingFileHandler
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub

# === SETUP FILE LOGGING ===
# Tu dong ghi tat ca log vao ddos_detection.log
# Max 5MB moi file, giu lai 3 file gan nhat
_file_handler = RotatingFileHandler(
    'ddos_detection.log',
    maxBytes=5 * 1024 * 1024,  # 5 MB
    backupCount=3,
    encoding='utf-8'
)
_file_handler.setLevel(logging.DEBUG)
_file_handler.setFormatter(logging.Formatter(
    '[%(asctime)s] %(levelname)-8s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
))
# Gan vao root logger de bat tat ca log cua Ryu
logging.getLogger().addHandler(_file_handler)

# Giai ma protocol number -> ten
PROTO_NAME = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 0: 'OTHER'}


class DDoSDetection(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDoSDetection, self).__init__(*args, **kwargs)

        # Load AI model
        try:
            self.model = joblib.load('ddos_model.sav')
            n_feat = self.model.n_features_in_
            feat_map = {
                8: ['pkt_rate', 'byte_rate', 'flow_dur',
                    'src_ip_ent', 'dst_ip_ent',
                    'avg_pkt_size', 'protocol', 'n_flows_same_src'],
                5: ['pkt_rate', 'byte_rate', 'flow_dur', 'src_ip_ent', 'dst_ip_ent'],
                3: ['pkt_rate', 'byte_rate', 'flow_dur'],
            }
            self.feature_names = feat_map.get(
                n_feat,
                ['pkt_rate', 'byte_rate', 'flow_dur', 'src_ip_ent', 'dst_ip_ent',
                 'avg_pkt_size', 'protocol', 'n_flows_same_src']
            )
            self.logger.info("=== AI MODEL LOADED: %d features ===", n_feat)
        except Exception as e:
            self.model = None
            self.feature_names = ['pkt_rate', 'byte_rate', 'flow_dur',
                                  'src_ip_ent', 'dst_ip_ent',
                                  'avg_pkt_size', 'protocol', 'n_flows_same_src']
            self.logger.error("=== ERROR: ddos_model.sav NOT FOUND: %s ===", e)

        self.datapaths    = {}
        self.mac_to_port  = {}
        self.blocked_ips  = set()   # IP da bi chan (tranh log lap)
        self.blocked_rules = []     # Danh sach luat chan hien tai (cho hien thi)

        # Bang tra cuu MAC -> IP va MAC-pair -> Protocol
        # Dung de resolve flow L2 (khong co ipv4_src) ve dung IP/protocol
        # Vi du: hping3 --rand-source tao L2 flow, can biet MAC cua h1 la 10.0.0.1
        self.mac_to_ip    = {}      # {mac_addr: ip_addr}
        self.mac_to_proto = {}      # {(src_mac, dst_mac): ip_proto}

        self.monitor_thread = hub.spawn(self._monitor)
        self.logger.info("=== DDoS DETECTION SYSTEM READY ===")
        self.logger.info("    Table 0: Forwarding rules (priority 1)")
        self.logger.info("    Table 1: Block rules     (priority 1000)")

    # -------------------------------------------------------
    # Setup: Cai table-miss (Table 0) va goto Table 1
    # -------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        # Table 0 miss: chuyen len controller
        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst    = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod     = parser.OFPFlowMod(datapath=datapath, priority=0,
                                     match=match, instructions=inst,
                                     table_id=0)
        datapath.send_msg(mod)
        self.logger.info("Switch %s: Ready (Table 0 + Table 1 initialized)", datapath.id)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
                self.logger.info("Switch connected: dpid=%s", datapath.id)
        elif ev.state == CONFIG_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    # -------------------------------------------------------
    # PacketIn: Cai flow L3 (IPv4) hoac L2 (ARP)
    # -------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match['in_port']

        from ryu.lib.packet import packet, ethernet, ether_types, ipv4 as ipv4_lib
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst_mac = eth.dst
        src_mac = eth.src
        dpid    = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        # === Ghi nho MAC -> IP va MAC-pair -> Protocol ===
        # Lam truoc khi kiem tra out_port de dam bao luon ghi nho
        from ryu.lib.packet import ipv4 as ipv4_lib
        ip_pkt_early = pkt.get_protocol(ipv4_lib.ipv4)
        if ip_pkt_early is not None:
            self.mac_to_ip[src_mac] = ip_pkt_early.src
            self.mac_to_ip[dst_mac] = ip_pkt_early.dst
            self.mac_to_proto[(src_mac, dst_mac)] = ip_pkt_early.proto

        out_port = self.mac_to_port[dpid].get(dst_mac, ofproto.OFPP_FLOOD)
        actions  = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            ip_pkt = pkt.get_protocol(ipv4_lib.ipv4)
            if ip_pkt is not None:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=0x0800,
                    ipv4_src=ip_pkt.src,
                    ipv4_dst=ip_pkt.dst,
                    ip_proto=ip_pkt.proto
                )
            else:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_dst=dst_mac,
                    eth_src=src_mac
                )
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod  = parser.OFPFlowMod(
                datapath=datapath, priority=1,
                match=match, instructions=inst,
                idle_timeout=20, hard_timeout=60
            )
            datapath.send_msg(mod)

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)

    # -------------------------------------------------------
    # Monitor: request stats moi 5 giay
    # -------------------------------------------------------
    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                self._request_stats(dp)
            hub.sleep(5)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req    = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    def calculate_entropy(self, data_list):
        if not data_list or len(data_list) < 2:
            return 0
        counts = pd.Series(data_list).value_counts()
        probs  = counts / len(data_list)
        return -sum(probs * probs.apply(math.log2))

    # -------------------------------------------------------
    # FlowStats handler - gon log + Table 1 block rules
    # -------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        if self.model is None:
            self.logger.error("No model loaded, skipping detection.")
            return

        body = ev.msg.body
        if not body:
            return

        # --- Pre-compute entropy va n_flows_same_src ---
        src_ip_count = {}
        for stat in body:
            if stat.packet_count == 0 or stat.priority == 0:
                continue
            src_ip = stat.match.get('ipv4_src', None)
            if src_ip:
                src_ip_count[src_ip] = src_ip_count.get(src_ip, 0) + 1

        src_ips = [stat.match.get('ipv4_src')
                   for stat in body if 'ipv4_src' in stat.match]
        dst_ips = [stat.match.get('ipv4_dst')
                   for stat in body if 'ipv4_dst' in stat.match]
        src_ent = self.calculate_entropy(src_ips)
        dst_ent = self.calculate_entropy(dst_ips)

        # --- Phan loai tung flow ---
        safe_count   = 0
        attack_flows = []

        for stat in body:
            if stat.packet_count == 0 or stat.priority == 0:
                continue

            # Lay IP/protocol tu match field (L3 flow)
            src_ip   = stat.match.get('ipv4_src', None)
            dst_ip   = stat.match.get('ipv4_dst', None)
            protocol = stat.match.get('ip_proto', 0)

            # === FALLBACK: Resolve tu bang mac_to_ip neu la L2 flow ===
            # Truong hop: hping3 --rand-source -> switch cai L2 flow (theo MAC)
            # -> flow stats khong co ipv4_src -> can tra cuu bang MAC
            eth_src_m = stat.match.get('eth_src', None)
            eth_dst_m = stat.match.get('eth_dst', None)
            attacker_mac = eth_src_m  # Luu MAC ke tan cong de block

            if src_ip is None and eth_src_m and eth_src_m in self.mac_to_ip:
                src_ip = self.mac_to_ip[eth_src_m]
            if dst_ip is None and eth_dst_m and eth_dst_m in self.mac_to_ip:
                dst_ip = self.mac_to_ip[eth_dst_m]
            if protocol == 0 and eth_src_m and eth_dst_m:
                protocol = self.mac_to_proto.get((eth_src_m, eth_dst_m), 0)

            duration = stat.duration_sec + stat.duration_nsec / 1e9
            if duration <= 0:
                duration = 0.001

            pkt_rate         = stat.packet_count / duration
            byte_rate        = stat.byte_count / duration
            avg_pkt_size     = stat.byte_count / stat.packet_count
            n_flows_same_src = src_ip_count.get(src_ip, 1) if src_ip else 1

            all_vals = {
                'pkt_rate':          pkt_rate,
                'byte_rate':         byte_rate,
                'flow_dur':          duration,
                'src_ip_ent':        src_ent,
                'dst_ip_ent':        dst_ent,
                'avg_pkt_size':      avg_pkt_size,
                'protocol':          protocol,
                'n_flows_same_src':  n_flows_same_src,
            }
            feature_vals = [all_vals[f] for f in self.feature_names]
            features     = pd.DataFrame([feature_vals], columns=self.feature_names)
            prediction   = self.model.predict(features)[0]

            ip_label    = src_ip if src_ip else "Unknown"
            proto_name  = PROTO_NAME.get(int(protocol), f"PROTO-{int(protocol)}")

            if prediction == 1 and pkt_rate > 0.5:
                attack_flows.append((
                    ip_label, proto_name, pkt_rate, byte_rate,
                    src_ip, dst_ip, protocol, attacker_mac, ev.msg.datapath
                ))
            else:
                safe_count += 1

        # -------------------------------------------------------
        # HIEN THI: Gon gang, ro rang
        # -------------------------------------------------------
        separator = "=" * 60

        # Dong tong hop SAFE (1 dong duy nhat thay vi spam tung flow)
        if safe_count > 0:
            self.logger.info(
                "[SCAN] %d flows SAFE | src_entropy=%.3f | dst_entropy=%.3f",
                safe_count, src_ent, dst_ent
            )

        # Xu ly tung flow TAN CONG
        for (ip_label, proto_name, pkt_rate, byte_rate,
             src_ip, dst_ip, protocol, attacker_mac, datapath) in attack_flows:
            self.logger.warning(separator)
            self.logger.warning("  !!!  DDoS ATTACK DETECTED  !!!")
            self.logger.warning("  Attacker IP : %s", ip_label)
            if attacker_mac:
                self.logger.warning("  Attacker MAC: %s", attacker_mac)
            if dst_ip:
                self.logger.warning("  Victim IP   : %s  <-- dang bi tan cong", dst_ip)
            self.logger.warning("  Protocol    : %s", proto_name)
            self.logger.warning("  Pkt Rate    : %s pkt/s", f"{pkt_rate:,.0f}")
            self.logger.warning("  Byte Rate   : %s B/s  (~%.1f Mbps)",
                                f"{byte_rate:,.0f}", byte_rate * 8 / 1_000_000)
            self.logger.warning("  Action      : BLOCKING via Table 1 rule")
            self.logger.warning(separator)

            self._install_block_rule(
                datapath, src_ip, dst_ip, int(protocol),
                ip_label, proto_name, attacker_mac
            )

        # Neu khong co flow nao (switch trong) - chi in 1 dong, khong in bang
        if safe_count == 0 and not attack_flows:
            if self.blocked_rules:
                self.logger.info("[SCAN] No active flows (all blocked). Rules active: %d",
                                 len(self.blocked_rules))
            else:
                self.logger.info("[SCAN] No active flows on switch.")

    # -------------------------------------------------------
    # Cai luat BLOCK vao Table 1 (ro rang tung loai tan cong)
    # -------------------------------------------------------
    def _install_block_rule(self, datapath, src_ip, dst_ip, protocol,
                            ip_label, proto_name, attacker_mac=None):
        import datetime
        parser  = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Tao rule key de tranh cai trung
        mac_key = attacker_mac if attacker_mac else src_ip
        rule_key = f"{mac_key}:{protocol}"

        existing_keys = [f"{r['raw_mac']}:{r['raw_proto']}" for r in self.blocked_rules]
        if rule_key in existing_keys:
            return

        victim_str = f" -> Victim: {dst_ip}" if dst_ip else ""

        # === Xay dung match rule ===
        if src_ip and src_ip != "Unknown":
            # Co IP cu the: chan theo IP + protocol
            if protocol in (1, 6, 17):
                match = parser.OFPMatch(
                    eth_type=0x0800,
                    ipv4_src=src_ip,
                    ip_proto=protocol
                )
                rule_desc = f"DROP {proto_name} from {src_ip}{victim_str}"
            else:
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
                rule_desc = f"DROP ALL from {src_ip}{victim_str}"

        elif attacker_mac:
            # Khong co IP cu the (hping3 --rand-source)
            # CHAN THEO MAC cua ke tan cong - chinh xac hon chan toan bo IPv4
            if protocol in (1, 6, 17):
                match = parser.OFPMatch(
                    eth_src=attacker_mac,
                    eth_type=0x0800,
                    ip_proto=protocol
                )
                rule_desc = f"DROP {proto_name} from MAC {attacker_mac}{victim_str}"
            else:
                match = parser.OFPMatch(eth_src=attacker_mac, eth_type=0x0800)
                rule_desc = f"DROP ALL from MAC {attacker_mac}{victim_str}"

        else:
            # Khong biet gi ca: chan toan bo IPv4 theo protocol
            if protocol in (1, 6, 17):
                match = parser.OFPMatch(eth_type=0x0800, ip_proto=protocol)
                rule_desc = f"DROP ALL {proto_name}{victim_str}"
            else:
                match = parser.OFPMatch(eth_type=0x0800)
                rule_desc = f"DROP ALL IPv4{victim_str}"

        # Cai vao switch voi priority cao (1000) - khong co actions = DROP
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=1000,
            match=match,
            command=ofproto.OFPFC_ADD,
            instructions=[],
            hard_timeout=120,
            idle_timeout=60
        )
        datapath.send_msg(mod)

        # Luu vao danh sach de hien thi
        now = datetime.datetime.now().strftime("%H:%M:%S")
        display_ip = src_ip if src_ip else f"MAC:{attacker_mac}" if attacker_mac else "Unknown"
        self.blocked_rules.append({
            'ip':        display_ip,
            'victim':    dst_ip if dst_ip else "-",
            'proto':     proto_name,
            'raw_ip':    src_ip,
            'raw_mac':   mac_key,
            'raw_proto': protocol,
            'time':      now,
            'desc':      rule_desc
        })

        # Hien thi bang sau khi them rule moi
        self.logger.warning("  [TABLE 1 RULE ADDED] %s (timeout: 120s)", rule_desc)
        self.logger.warning("--- [TABLE 1 - BLOCK RULES] (Active: %d) ---", len(self.blocked_rules))
        for rule in self.blocked_rules:
            self.logger.warning("  DROP | Attacker: %-20s | Victim: %-15s | Proto: %-5s | %s",
                                rule['ip'], rule['victim'], rule['proto'], rule['time'])
        self.logger.warning("-------------------------------")

        if len(self.blocked_rules) > 10:
            self.blocked_rules = self.blocked_rules[-10:]

    def unblock_ip(self, src_ip):
        self.blocked_ips.discard(src_ip)
        self.blocked_rules = [r for r in self.blocked_rules if r['raw_ip'] != src_ip]
        self.logger.info("IP %s removed from block list", src_ip)
# detection_system.py - Fixed DDoS Detection with Random Forest + Ryu
import pandas as pd
import joblib
import math
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub


class DDoSDetection(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDoSDetection, self).__init__(*args, **kwargs)

        # Load AI model
        try:
            self.model = joblib.load('ddos_model.sav')
            n_feat = self.model.n_features_in_
            # Map so feature -> danh sach feature name tuong ung
            feat_map = {
                8: ['pkt_rate', 'byte_rate', 'flow_dur',
                    'src_ip_ent', 'dst_ip_ent',
                    'avg_pkt_size', 'protocol', 'n_flows_same_src'],
                5: ['pkt_rate', 'byte_rate', 'flow_dur', 'src_ip_ent', 'dst_ip_ent'],
                3: ['pkt_rate', 'byte_rate', 'flow_dur'],
            }
            self.feature_names = feat_map.get(
                n_feat,
                ['pkt_rate', 'byte_rate', 'flow_dur', 'src_ip_ent', 'dst_ip_ent']
            )
            self.logger.info("=== AI MODEL LOADED: %d features: %s ===",
                             n_feat, self.feature_names)
        except Exception as e:
            self.model = None
            self.feature_names = ['pkt_rate', 'byte_rate', 'flow_dur',
                                  'src_ip_ent', 'dst_ip_ent',
                                  'avg_pkt_size', 'protocol', 'n_flows_same_src']
            self.logger.error("=== ERROR: ddos_model.sav NOT FOUND: %s ===", e)

        self.datapaths = {}
        self.mac_to_port = {}      # For L2 forwarding
        self.blocked_ips = set()   # Track already-blocked IPs

        # FIX 1: Start monitoring thread
        self.monitor_thread = hub.spawn(self._monitor)
        self.logger.info("=== DDoS DETECTION SYSTEM READY ===")

    # -------------------------------------------------------
    # FIX 2: Add table-miss flow entry so packets reach controller
    # Without this, switch drops unknown packets and Mininet ping fails
    # -------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow: send all unmatched packets to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)
        self.logger.info("Switch %s: table-miss flow installed", datapath.id)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
                self.logger.info("Switch registered: dpid=%s", datapath.id)
        elif ev.state == CONFIG_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
                self.logger.info("Switch removed: dpid=%s", datapath.id)

    # -------------------------------------------------------
    # FIX 3: Handle PacketIn for L2 forwarding (makes ping work!)
    # -------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        # Parse packet
        from ryu.lib.packet import packet, ethernet, ether_types
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return  # Ignore LLDP

        dst_mac = eth.dst
        src_mac = eth.src
        dpid = datapath.id

        # Learn MAC -> port mapping
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        # Determine output port
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install flow rule to avoid future PacketIn for this flow
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac, eth_src=src_mac)
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=1,
                match=match,
                instructions=inst,
                idle_timeout=20,
                hard_timeout=60
            )
            datapath.send_msg(mod)

        # Send the current packet
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)

    # -------------------------------------------------------
    # Monitor: Request flow stats every 5 seconds
    # -------------------------------------------------------
    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                self._request_stats(dp)
            hub.sleep(5)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    # -------------------------------------------------------
    # Entropy calculation
    # -------------------------------------------------------
    def calculate_entropy(self, data_list):
        if not data_list or len(data_list) < 2:
            return 0
        counts = pd.Series(data_list).value_counts()
        probs = counts / len(data_list)
        return -sum(probs * probs.apply(math.log2))

    # -------------------------------------------------------
    # FIX 4: Flow stats handler - correct thresholds + always show status
    # -------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        if self.model is None:
            self.logger.error("No model loaded, skipping detection.")
            return

        body = ev.msg.body
        if not body:
            return

        self.logger.info("--- Scanning traffic flows on Switch... ---")

        # Pre-compute n_flows_same_src: count flows per source IP in this window
        src_ip_count = {}
        for stat in body:
            if stat.packet_count == 0 or stat.priority == 0:
                continue
            src_ip = stat.match.get('ipv4_src', None)
            if src_ip:
                src_ip_count[src_ip] = src_ip_count.get(src_ip, 0) + 1

        # Legacy entropy (kept for old 5-feature model compatibility)
        src_ips = [stat.match.get('ipv4_src')
                   for stat in body if 'ipv4_src' in stat.match]
        dst_ips = [stat.match.get('ipv4_dst')
                   for stat in body if 'ipv4_dst' in stat.match]
        src_ent = self.calculate_entropy(src_ips)
        dst_ent = self.calculate_entropy(dst_ips)

        for stat in body:
            # Skip table-miss and zero-packet flows
            if stat.packet_count == 0:
                continue
            # Skip table-miss entry (priority=0, no specific match)
            if stat.priority == 0:
                continue

            src_ip = stat.match.get('ipv4_src', None)
            duration = stat.duration_sec + stat.duration_nsec / 1e9
            if duration <= 0:
                duration = 0.001  # Avoid division by zero

            # === Core features ===
            pkt_rate     = stat.packet_count / duration
            byte_rate    = stat.byte_count / duration

            # === New features (Tier 1) ===
            # avg_pkt_size: DDoS dung goi nho (~60B), binh thuong lon (~1000B)
            avg_pkt_size = stat.byte_count / stat.packet_count if stat.packet_count > 0 else 0
            # protocol: lay tu match field (1=ICMP, 6=TCP, 17=UDP, 0=unknown)
            protocol     = stat.match.get('ip_proto', 0)
            # n_flows_same_src: nhieu flow cung src = dau hieu DDoS
            n_flows_same_src = src_ip_count.get(src_ip, 1) if src_ip else 1

            # Build feature dict - compatible with old (5-feat) and new (6-feat) models
            all_vals = {
                'pkt_rate':          pkt_rate,
                'byte_rate':         byte_rate,
                'flow_dur':          duration,
                'avg_pkt_size':      avg_pkt_size,
                'protocol':          protocol,
                'n_flows_same_src':  n_flows_same_src,
                # Legacy entropy features (always 0 but needed for old model)
                'src_ip_ent':        src_ent,
                'dst_ip_ent':        dst_ent,
            }
            feature_vals = [all_vals[f] for f in self.feature_names]
            features = pd.DataFrame([feature_vals], columns=self.feature_names)

            prediction = self.model.predict(features)[0]

            # -------------------------------------------------------
            # FIX: Old threshold was pkt_rate > 100 - WRONG!
            # Dataset shows attack flows often have pkt_rate near 0,
            # and safe flows can have pkt_rate > 100 too.
            # Solution: Trust the model prediction directly.
            # Add a minimal sanity threshold (pkt_rate > 0.5) to ignore
            # idle/residual flows that produce false positives.
            # -------------------------------------------------------
            ip_label = src_ip if src_ip else "Unknown"

            if prediction == 1 and pkt_rate > 0.5:
                # Check if already blocked to avoid log spam
                if src_ip and src_ip not in self.blocked_ips:
                    self.logger.warning(
                        "!!! DDoS ATTACK DETECTED !!! Source: %s | "
                        "pkt_rate: %.2f pkt/s | byte_rate: %.2f B/s",
                        ip_label, pkt_rate, byte_rate
                    )
                    self.blocked_ips.add(src_ip)
                    self.block_attack(ev.msg.datapath, src_ip)
                elif src_ip is None:
                    self.logger.warning(
                        "!!! DDoS ATTACK DETECTED (Unknown IP) !!! "
                        "pkt_rate: %.2f | byte_rate: %.2f",
                        pkt_rate, byte_rate
                    )
                    self.block_attack(ev.msg.datapath, None)
            else:
                # FIX: Always show SAFE status, even for Unknown IP flows
                self.logger.info(
                    "Flow [%s] | pkt_rate: %.2f pkt/s | byte_rate: %.2f B/s "
                    "| duration: %.2fs | Status: SAFE",
                    ip_label, pkt_rate, byte_rate, duration
                )

    # -------------------------------------------------------
    # Block attacker IP via OpenFlow DROP rule
    # -------------------------------------------------------
    def block_attack(self, datapath, src_ip):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        if src_ip:
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
            self.logger.error("=== BLOCKED IP: %s (for 60 seconds) ===", src_ip)
        else:
            # Fallback: drop all IPv4 traffic temporarily
            match = parser.OFPMatch(eth_type=0x0800)
            self.logger.error("=== BLOCKING UNKNOWN ATTACK FLOWS ===")

        # Empty instructions = DROP
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=1000,
            match=match,
            command=ofproto.OFPFC_ADD,
            instructions=[],
            hard_timeout=60,
            idle_timeout=30
        )
        datapath.send_msg(mod)

    # -------------------------------------------------------
    # Cleanup: remove IP from blocked set after timeout
    # (called optionally - blocked_ips is just for log dedup)
    # -------------------------------------------------------
    def unblock_ip(self, src_ip):
        self.blocked_ips.discard(src_ip)
        self.logger.info("IP %s removed from block list", src_ip)
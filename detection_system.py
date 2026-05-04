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
        # 1. Nạp "Bộ não" AI
        try:
            self.model = joblib.load('ddos_model.sav')
            self.logger.info("--- THÀNH CÔNG: ĐÃ NẠP MÔ HÌNH AI ---")
        except:
            self.logger.error("--- LỖI: KHÔNG TÌM THẤY FILE ddos_model.sav ---")

        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.logger.info("--- HỆ THỐNG AI ĐÃ SẴN SÀNG TRỰC CHIẾN ---")

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(3) # Quét hệ thống mỗi 3 giây

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    def calculate_entropy(self, data_list):
        if not data_list or len(data_list) < 2: return 0
        counts = pd.Series(data_list).value_counts()
        probs = counts / len(data_list)
        return -sum(probs * probs.apply(math.log2))

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.logger.info("--- Đang quét các luồng dữ liệu trên Switch... ---")
        
        # Lấy danh sách IP để tính Entropy
        src_ips = [stat.match.get('ipv4_src') for stat in body if 'ipv4_src' in stat.match]
        dst_ips = [stat.match.get('ipv4_dst') for stat in body if 'ipv4_dst' in stat.match]
        src_ent = self.calculate_entropy(src_ips)
        dst_ent = self.calculate_entropy(dst_ips)

        for stat in body:
            # Bỏ qua các luồng tĩnh hoặc không có gói tin
            if stat.packet_count == 0: continue
            
            src_ip = stat.match.get('ipv4_src', 'Unknown')
            duration = stat.duration_sec + stat.duration_nsec / 1e9
            
            # Tính toán các đặc trưng (Features)
            pkt_rate = stat.packet_count / duration if duration > 0 else 0
            byte_rate = stat.byte_count / duration if duration > 0 else 0
            
            # Tạo DataFrame để AI dự đoán (Giúp mất cảnh báo UserWarning)
            features = pd.DataFrame([[pkt_rate, byte_rate, duration, src_ent, dst_ent]], 
                                    columns=['pkt_rate', 'byte_rate', 'flow_dur', 'src_ip_ent', 'dst_ip_ent'])
            
            prediction = self.model.predict(features)[0]

            # Ngưỡng (Threshold) để xác nhận tấn công thực sự
            if prediction == 1 and pkt_rate > 100: 
                self.logger.warning(f"!!! PHÁT HIỆN DDOS !!! Nguồn: {src_ip} | Pkt_rate: {pkt_rate:.2f}")
                self.block_attack(ev.msg.datapath, src_ip)
            else:
                # Chỉ in log khi có IP cụ thể để tránh rác màn hình
                if src_ip != 'Unknown':
                    self.logger.info(f"Luồng từ: {src_ip} | Pkt_rate: {pkt_rate:.2f} | Trạng thái: An toàn")


    def block_attack(self, datapath, src_ip):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        # Nếu có IP thì chặn theo IP, nếu Unknown thì mình chặn theo cổng nhận gói tin (in_port)
        if src_ip != 'Unknown':
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
            self.logger.error(f"--- ĐÃ CHẶN IP {src_ip} TRONG 60 GIÂY ---")
        else:
            # Nếu là Unknown, ta chặn tạm thời dựa trên các thông số Ethernet để giảm tải
            match = parser.OFPMatch(eth_type=0x0800) 
            self.logger.error(f"--- ĐANG CHẶN CÁC LUỒNG TẤN CÔNG KHÔNG XÁC ĐỊNH ---")

        instructions = [] # Không có lệnh forward = DROP (Chặn)
        mod = parser.OFPFlowMod(
            datapath=datapath, 
            priority=1000, 
            match=match, 
            command=ofproto.OFPFC_ADD, 
            instructions=instructions, 
            hard_timeout=60
        )
        datapath.send_msg(mod)
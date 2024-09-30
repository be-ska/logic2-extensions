# MAVLink 2 High Level Analyzer

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
import generated_mavlink2_all as mavlink

class MAVLink2(HighLevelAnalyzer):
    # Global variables
    mav = mavlink.MAVLink(None)
    buff = bytearray()
    packet_length = 0
    parse_state = 0
    message = None
    error = None
    start_frame = None
    header_v1 = b'\xfe'
    header_v2 = b'\xfd'
    header_length = 0

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'mavlink': {
            'format': 'sys ID: {{data.sys_id}}, comp ID: {{data.comp_id}}, msg ID: {{data.msg_id}}'
        }
    }

    def __init__(self):
        pass
    
    # parse a byte
    def parse_mavlink(self, byte):
        if self.parse_state == 0:
            # wait header
            if byte == self.header_v1:
                self.buff.clear()
                self.buff += byte
                self.parse_state = 1
                self.header_length = 7
                return 1
            elif byte == self.header_v2:
                self.buff.clear()
                self.buff += byte
                self.parse_state = 1
                self.header_length = 11
                return 1
        elif self.parse_state == 1:
            # check packet length
            self.packet_length = int.from_bytes(byte, "big")
            self.buff += byte
            self.parse_state = 2
        elif self.parse_state == 2:
            self.buff += byte
            if len(self.buff) > self.packet_length+self.header_length:
                self.parse_state = 0
                msg = None
                try:
                    msg = self.mav.decode(self.buff)
                except mavlink.MAVError as e:
                    print("MAVLink parsing error:", e)
                    return 2
                if msg is not None:
                    self.message = msg
                    return 0
        return 3
                
    def decode(self, frame: AnalyzerFrame):
        # receive incoming byte from Logic
        res = self.parse_mavlink(frame.data['data'])
        if res == 0:
            # message parsed
            return AnalyzerFrame('mavlink', self.start_frame, frame.end_time, {
                'sys_id': self.message.get_srcSystem(),
                'comp_id': self.message.get_srcComponent(),
                'msg_id': self.message.get_msgId(),
                'payload' : self.message.get_payload(),
                'print' : str(self.message)
            })
        elif res == 1:
            self.start_frame = frame.start_time

        

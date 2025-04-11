# Align P2 High Level Analyzer
# Try reverse engineering this pretty weird protocol

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
from enum import Enum

class P2(HighLevelAnalyzer):
    # Parse state
    class ParseState(Enum):
        HEADER = 0
        OPERATION = 1
        LENGTH = 2
        SENDER_ID = 3
        RECEIVER_ID = 4
        DATA = 5
        CRC = 6

    class Operation(Enum):
        CMD = b'\xAA'
        RES = b'\xAB'
        BRO = b'\xAC'

    class hardwareID(Enum):
        APP = b'\xFF'
        PC = b'\xFE'
        ALL = b'\x00'
        FC = b'\x01'
        PCU = b'\x02'
        DV = b'\x03'
        RGB = b'\x04'
        RES = b'\x10'

    class broadcastCMD(Enum):
        heartbeat = b'\x01'
        text = b'\x02'
        radio = b'\x03'
        attitude = b'\x04'
        GPS = b'\x05'
        wp_update = b'\xF3'
        wp_failure = b'\xF6'
        wp_target = b'\xF7'
        set = b'\x06'
        tune_servo = b'\x07'
        tune_ccpm = b'\x08'
        ranging = b'\x09'
        attitude_data = b'\x0A'
        int_target = b'\x0B'
        vibe = b'\x0C'
        NED_vel = b'\x0F'
        radio_data = b'\x10'
        pcu_flow = b'\x11'
        pcu_info = b'\x12'
        GCS_heartbeat = b'\x13'
        rth_state = b'\x14'
        rpm = b'\x15'
        dv_cmd = b'\x16'
        fcu_info = b'\x17'
        rgb_info = b'\x18'
        fcu_misc = b'\x19'

    class CommandCMD(Enum):
        parm_request = b'\x01'
        parm_set = b'\x02'
        save_rom = b'\x03'
        set_gimbal = b'\x04'
        req_gimbal = b'\x05'
        firmware1 = b'\x06'
        firmware2 = b'\x07'
        firmware3 = b'\x08'
        firmware4 = b'\x09'
        pcu_flow_ctrl = b'\x0A'
        starter_ctrl = b'\x0B'
        choke_ctrl = b'\x0C'
        pcu_led_ctrl = b'\x0D'
        starter_cmd = b'\x0E'
        rth_request = b'\x0F'
        point_resume = b'\x10'
        set_actuaotr = b'\x11'
        get_firmware = b'\x12'

    # Global variables
    buff = bytearray()
    packet_length = 0
    parse_state = ParseState.HEADER
    start_frame = None
    header = b'\x77'

    # operation bytes
    command = b'\xAA'
    response = b'\xAB'
    broadcast = b'\xAC'
    operation_byte = b'\x00'

    def __init__(self):
        pass
    
    # parse a byte
    def parse_P2(self, byte):
        if self.parse_state == self.ParseState.HEADER:
            # wait header
            if byte == self.header:
                self.buff.clear()
                self.buff += byte
                self.parse_state = self.ParseState.OPERATION
                return 1
            
        elif self.parse_state == self.ParseState.OPERATION:
            # check operation
            self.operation_byte = byte
            self.buff += byte
            self.parse_state = self.ParseState.LENGTH

        elif self.parse_state == self.ParseState.LENGTH:
            # check packet length
            self.packet_length = int.from_bytes(byte, "big")
            self.buff += byte
            self.parse_state = self.ParseState.SENDER_ID

        elif self.parse_state == self.ParseState.SENDER_ID:
            self.buff += byte
            self.parse_state = self.ParseState.RECEIVER_ID

        elif self.parse_state == self.ParseState.RECEIVER_ID:
            self.buff += byte
            self.parse_state = self.ParseState.DATA

        elif self.parse_state == self.ParseState.DATA:
            self.buff += byte
            if len(self.buff) > self.packet_length+9:
                self.parse_state = self.ParseState.HEADER
                return 0
        return 2
                
    def decode(self, frame: AnalyzerFrame):
        # receive incoming byte from Logic
        res = self.parse_P2(frame.data['data'])
        if res == 0:
            # message parsed

            # analyzer frame name as operation byte
            try:
                analyzer_name = self.Operation(self.operation_byte).name
            except ValueError:
                analyzer_name = 'UNK'
                pass

            # sender id
            try:
                sender_byte = bytes([self.buff[3]])  # Convert single byte to bytes object
                sender_id = self.hardwareID(sender_byte).name
            except ValueError:
                sender_id = 'UNK'
                pass

            # receiver id
            try:
                receiver_byte = bytes([self.buff[4]])  # Convert single byte to bytes object
                receiver_id = self.hardwareID(receiver_byte).name
            except ValueError:
                receiver_id = 'UNK'
                pass

            # command
            if analyzer_name == 'BRO':
                try:
                    cmd_byte = bytes([self.buff[5]])  # Convert single byte to bytes object
                    cmd = self.broadcastCMD(cmd_byte).name
                except ValueError:
                    cmd = 'UNK'
                    pass
            elif analyzer_name == 'CMD':
                try:
                    cmd_byte = bytes([self.buff[5]])  # Convert single byte to bytes object
                    cmd = self.CommandCMD(cmd_byte).name
                except ValueError:
                    cmd = 'UNK'
                    pass
            else:
                cmd = 'UNK'
            
            return AnalyzerFrame(analyzer_name, self.start_frame, frame.end_time, {
                'length': self.packet_length,
                'sender': sender_id,
                'receiver': receiver_id,
                'cmd' : cmd
            })
        elif res == 1:
            self.start_frame = frame.start_time

        

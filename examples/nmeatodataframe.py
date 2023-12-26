import argparse
from datetime import datetime
import math
import pandas as pd

from pynmeagps.nmeareader import NMEAReader
from pynmeagps.nmeamessage import NMEAMessage
import pynmeagps.exceptions as nme
from pynmeagps.nmeatypes_core import (
    ERR_LOG,
    ERR_RAISE,
    GET,
    NMEA_HDR,
    VALCKSUM,
    VALMSGID,
)

class NMEAFrame:

    # only those properties that are relevant across messages need to be a class member by itself
    #utc_date = datetime.date
    utc_time : datetime.time
    complete: bool

    def __init__(self):
        # dictionary of messages by identity (talker+msg_id) for non-muxed messages
        self.messages = dict()

        # satellites in view message is special because of muxing (multiple per frame expected)
        self.sv_in_view_message = {'GP': [], 'GL': [], 'GA': [], 'GB': []}

        # state across messages
        self.utc_time = None
        #TODO self.utc_date -> add date support later
        self.num_messages = 0
        self.complete = False

        # preprocessed data
        self.sv_in_view_message_snrs = {'GP': [], 'GL': [], 'GA': [], 'GB': []}
        self.observations = []

    def __str__(self):
        output = ""
        if self.is_complete():
            output += "Complete data frame"
        else:
            output += "Incomplete data frame"

        return output

    def push_back_message(self, msg: NMEAMessage) -> bool:
        """ Add a message to the data frame
        :param msg: Instance of nmea message to add to the data frame
        :return True if duplicate detected
        """
        if not isinstance(msg, NMEAMessage):
            raise TypeError('Given object is not a NMEA message')

        if msg.msgID == 'GSV':
            # Mux handling: Insertion in data strcuture with checks (msgNum and numMsg)
            if msg.talker in self.sv_in_view_message.keys():
                if len(self.sv_in_view_message[msg.talker]) == 0:
                    if msg.numMsg > 0 and msg.numMsg < 10:
                        self.sv_in_view_message[msg.talker] = [None]*msg.numMsg
                    else:
                        raise nme.NMEAStreamError('GSV numMsg out of range')
                elif len(self.sv_in_view_message[msg.talker]) != msg.numMsg:
                    raise nme.NMEAStreamError('GSV numMsg inconsistent')
                if 0 < msg.msgNum and msg.msgNum <= len(self.sv_in_view_message[msg.talker]):
                    if self.sv_in_view_message[msg.talker][msg.msgNum-1] is not None:
                        return True
                    self.sv_in_view_message[msg.talker][msg.msgNum-1] = msg
                    self.num_messages += 1
                else:
                    raise nme.NMEAStreamError('GSV msgNum out of range')
            else:
                raise nme.NMEAStreamError('GSV unexpected talker {msg.talker}')

            # process observations / snrs
            num_per_msg = math.ceil(msg.numSV / msg.numMsg)
            for idx in range(1,num_per_msg+1):
                az = getattr(msg, f"az_{idx:02d}", None)
                cno = getattr(msg, f"cno_{idx:02d}", None)
                elv = getattr(msg, f"elv_{idx:02d}", None)
                svid = getattr(msg, f"svid_{idx:02d}", None)

                if not (az is None or cno is None or elv is None or svid is None):
                    if svid != "" and elv != "" and az != "":
                        observation = {
                            'svid': f"{msg.talker.lower()}_{svid:02d}",
                            'elv': elv,
                            'az': az,
                            'snr': cno
                        }
                        self.observations.append(observation)
                        if cno != "":
                            self.sv_in_view_message_snrs[msg.talker].append(cno) # or - 30
                else:
                    raise nme.NMEAStreamError(f"GSV idx {idx} not found with {msg.numSV} / {msg.numMsg}")

        else:
            if msg.identity in self.messages.keys():
                # same message was already captured
                return True
            else:
                self.messages[msg.identity] = msg
                self.num_messages += 1
                if msg.identity in ["GPGGA"]:
                    if self.utc_time is None:
                        self.utc_time = msg.time
                    elif msg.time != self.utc_time:
                        raise nme.NMEAStreamError(f"Inconsistent UTC time inside frame detected for message identity={msg.identity}")
                    
    def get_message_as_dict(self, identity: str) -> dict: 
        if identity in self.messages.keys():
            msg_dict = self.messages[identity].payload_dict
            # add identity as prefix
            prefix = identity.lower()
            if prefix.startswith("psat"):
                prefix = prefix[4:]
            return {f"{prefix}_{key}": value for key, value in msg_dict.items()}
        else:
            return None
        
    def get_messages_as_dict(self, allowed: list) -> dict:
        full_dict = dict()
        if allowed is None:
            for identity in self.messages.keys():
                msg_dict = self.get_message_as_dict(identity)
                full_dict.update(msg_dict)
        else:
            for identity in allowed:
                msg_dict = self.get_message_as_dict(identity)
                if msg_dict is None:
                    raise nme.NMEAStreamError(f"Missing message in frame {identity}")
                full_dict.update(msg_dict)
        return full_dict
    
    def get_satellites_in_view_snrs_as_dict(self) -> dict:
        # sort snrs and add sv_ prefix
        retval = dict()
        for key, snr_list in self.sv_in_view_message_snrs.items():
            snr_list.sort()
            retval[f"{key.lower()}gsv_snr"] = snr_list
        return retval

    def is_complete(self):
        #for key, value in enumerate(sv_in_view_message):
        return True
        #TODO return self.gpgga_message is not None

def open_nmea(inputfile: str, new_frame_msg_id : str = 'GPGGA', included_msg_ids: [str] = ["GPGGA"], num_msg: int = None, verbose = False) -> pd.DataFrame:
    """
    Processes NMEA File and returns dataframe
    new_frame_msg_id: Exceptions can occur when UTC within frame is inconsistent and this is chosen incorrectly
    """

    if verbose:
        print(f"\nOpening file {inputfile}...\n")
    msgcount = 0
    errcount = 0
    data_arr = []
    df = None
    try:
        with open(inputfile, 'rb') as file:
            nmea_frame = NMEAFrame()

            for line in file:
                # parse and create message object
                errormsg = None
                message = None
                try:
                    message = NMEAReader.parse(line, msgmode=GET, validate=VALCKSUM+VALMSGID)
                except (
                    nme.NMEAMessageError,
                    nme.NMEATypeError,
                    nme.NMEAParseError,
                    nme.NMEAStreamError,
                ) as err:
                    errormsg = str(err)

                # message objects processing to output data
                if message is not None or errormsg is None:
                    # trigger new frame at e.g. GPGGA (depends on receiver). 
                    if message.identity == new_frame_msg_id and nmea_frame.num_messages > 0:
                        # create a dictionary representing line in pandas DataFrame
                        try:
                            data = nmea_frame.get_messages_as_dict(included_msg_ids)
                            data.update(nmea_frame.get_satellites_in_view_snrs_as_dict())
                            data_arr.append(data)
                        except (
                            nme.NMEAStreamError
                        ) as err:
                            errormsg = str(err)
                        # create new, empty NMEAFrame - also if previous one had missing messages
                        nmea_frame = NMEAFrame()
                    try:
                        is_full = nmea_frame.push_back_message(message)
                        if is_full:
                            errormsg = "Full before expected"
                    except (
                        nme.NMEAStreamError
                    ) as err:
                        errormsg = str(err)
                    
                if errormsg is not None:
                    errcount += 1
                    if verbose:
                        print(f"{line} ({errormsg} , utc {nmea_frame.utc_time})")
                
                msgcount += 1
                if num_msg is not None and msgcount > num_msg:
                    print(f"\nReached specified maximum message count {num_msg}, stopping...")
                    break
        if (data_arr):
            df = pd.DataFrame(data_arr)
        print(f"\nProcessing Complete. {msgcount} message(s) processed, {errcount} message(s) failed to parse")
        return df
    except FileNotFoundError:
        print(f"Error: File '{inputfile}' not found.")
    return df
        

def main():
    parser = argparse.ArgumentParser(description='Parse NMEA data from a file and annotate it.')
    parser.add_argument('inputfile', type=str, help='Path to the file containing raw NMEA data')
    parser.add_argument('-f', '--frame_start', default='GPGGA', type=str, help='NMEA message where a frame starts')
    parser.add_argument('-n', '--num_msg', type=int, help='Number of lines to parse')

    args = parser.parse_args()

    df = open_nmea(args.inputfile, args.frame_start, None, args.num_msg)
    print(df)

if __name__ == "__main__":
    main()
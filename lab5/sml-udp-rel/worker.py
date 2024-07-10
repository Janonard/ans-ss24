"""
 Copyright 2024 Computer Networks Group @ UPB

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 """

from lib.gen import GenInts, GenMultipleOfInRange
from lib.test import CreateTestData, RunIntTest
from lib.worker import *
from lib.comm import *
from scapy.all import Packet, ByteField, IntField, FieldListField
import socket

NUM_ITER   = 3
CHUNK_SIZE = 64
TIMEOUT = 1

class SwitchML(Packet):
    name = "SwitchMLPacket"
    fields_desc = [
        ByteField("rank", 0),
        ByteField("chunk", 0),
        ByteField("ack", 0),
        FieldListField("data", None, IntField("elem",0))
    ]


def AllReduce(soc, rank, data, result):
    """
    Perform reliable in-network all-reduce over UDP

    :param str    soc: the socket used for all-reduce
    :param int   rank: the worker's rank
    :param [int] data: the input vector for this worker
    :param [int]  res: the output vector

    This function is blocking, i.e. only returns with a result or error
    """

    ack = 0xff
    for i in range(0, len(data), CHUNK_SIZE):
        # Create packet
        chunk = int(i / CHUNK_SIZE)
        payload = bytes(SwitchML(rank=rank, chunk=chunk, ack=ack, data=data[i:i+CHUNK_SIZE]))
        ack = chunk

        while True:
            # Send packet
            unreliable_send(soc, payload, ("10.0.1.1", 0x4200))

            # Receive packet
            try:
                rec_packet, _ = unreliable_receive(soc, 1024)
            except socket.timeout:
                # Timeout occurred
                Log("Timeout")
                continue
            
            rec_packet = SwitchML(rec_packet)
            if rec_packet.rank != 0xFF or rec_packet.chunk != chunk:
                Log("Illegal/duplicate packet")
                continue

            # Store results
            result[i:i+CHUNK_SIZE] = rec_packet.data
            Log(rec_packet.data)
            break

    # Send ackknowledge
    payload = bytes(SwitchML(rank=rank, chunk=0xff, ack=ack))
    send(soc, payload, ("10.0.1.1", 0x4200))

def main():
    rank = GetRankOrExit()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((f"10.0.0.{rank+1}", 0x4200))
    s.settimeout(TIMEOUT)

    Log("Started...")
    for i in range(NUM_ITER):
        num_elem = GenMultipleOfInRange(2, 2048, 2 * CHUNK_SIZE) 
        data_out = GenInts(num_elem)
        data_in = GenInts(num_elem, 0)
        CreateTestData("udp-rel-iter-%d" % i, rank, data_out)
        AllReduce(s, rank, data_out, data_in)
        RunIntTest("udp-rel-iter-%d" % i, rank, data_in, True)
    Log("Done")

    s.close()

if __name__ == '__main__':
    main()
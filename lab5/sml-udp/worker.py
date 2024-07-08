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

NUM_ITER   = 8     # TODO: Make sure your program can handle larger values
CHUNK_SIZE = 16  # TODO: Define me

class SwitchML(Packet):
    name = "SwitchMLPacket"
    fields_desc = [
        ByteField("rank", 0),
        FieldListField("data", None, IntField("elem",0))
    ]


def AllReduce(soc, rank, data, result):
    """
    Perform in-network all-reduce over UDP

    :param str    soc: the socket used for all-reduce
    :param int   rank: the worker's rank
    :param [int] data: the input vector for this worker
    :param [int]  res: the output vector

    This function is blocking, i.e. only returns with a result or error
    """

    for i in range(0, len(data), CHUNK_SIZE):
        # Send packet
        payload = bytes(SwitchML(rank=rank, data=data[i:i+CHUNK_SIZE]))
        send(soc, payload, ("10.0.1.1", 0x4200))

        # Receive answer
        rec_packet, _ = receive(soc, 1024)
        result[i:i+CHUNK_SIZE] = SwitchML(rec_packet).data
        Log(SwitchML(rec_packet).data)

def main():
    rank = GetRankOrExit()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((f"10.0.0.{rank+1}", 0x4200))

    Log("Started...")
    for i in range(NUM_ITER):
        num_elem = CHUNK_SIZE*3 #GenMultipleOfInRange(2, 2048, 2 * CHUNK_SIZE) # You may want to 'fix' num_elem for debugging
        data_out = GenInts(num_elem)
        data_in = GenInts(num_elem, 0)
        CreateTestData("udp-iter-%d" % i, rank, data_out)
        AllReduce(s, rank, data_out, data_in)
        RunIntTest("udp-iter-%d" % i, rank, data_in, True)
    Log("Done")

    s.close()

if __name__ == '__main__':
    main()
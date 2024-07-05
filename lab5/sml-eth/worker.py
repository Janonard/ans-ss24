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
from scapy.all import Packet, ByteField, IntField, FieldListField, Ether, get_if_hwaddr, srp, Raw

NUM_ITER   = 1     # TODO: Make sure your program can handle larger values
CHUNK_SIZE = 16  # TODO: Define me

class SwitchML(Packet):
    name = "SwitchMLPacket"
    fields_desc = [
        ByteField("rank", 0),
        FieldListField("data", None, IntField("elem",0))
    ]

def AllReduce(iface, rank, data, result):
    """
    Perform in-network all-reduce over ethernet

    :param str  iface: the ethernet interface used for all-reduce
    :param int   rank: the worker's rank
    :param [int] data: the input vector for this worker
    :param [int]  res: the output vector

    This function is blocking, i.e. only returns with a result or error
    """
    
    for i in range(0, len(data), CHUNK_SIZE):
        # Create packet
        packet = Ether(src=get_if_hwaddr(iface), dst="08:00:00:00:01:01", type=0x4200) / SwitchML(rank=rank, data=data[i:i+CHUNK_SIZE])

        # Send packet and wait for answer
        answer = srp(packet, iface=iface, verbose=False)
        raw_data = answer[0][0][1][Raw].load
        result[i:i+CHUNK_SIZE] = SwitchML(raw_data).data
        Log(SwitchML(raw_data).data)

def main():
    iface = 'eth0'
    rank = GetRankOrExit()
    Log("Started...")
    for i in range(NUM_ITER):
        num_elem = GenMultipleOfInRange(2, 2048, 2 * CHUNK_SIZE) # You may want to 'fix' num_elem for debugging
        data_out = GenInts(num_elem)
        data_in = GenInts(num_elem, 0)
        CreateTestData("eth-iter-%d" % i, rank, data_out)
        AllReduce(iface, rank, data_out, data_in)
        RunIntTest("eth-iter-%d" % i, rank, data_in, True) 
    Log("Done")

if __name__ == '__main__':
    main()
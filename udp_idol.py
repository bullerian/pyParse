import argparse
import json
import re
import threading
from c_files import lext
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP


SUCCESS_RETVAL = 0
ERROR_RETVAL = -1
DEFAULT_TIMEOUT = 1
DEFAULT_INTERFACE = conf.iface

RE_EVEN_STR_LEN = r"^(..)*$"
RE_ODD_STR_LEN = r"^.(..)*$"
RE_FIRST_LTR_CAPITAL = r"^[A-Z].*"
RE_LAST_WORD_IS_END = r".*\b(end)$"
RE_NON_WHITE_SPAC_STR = r'^\S.*$'

Addressants_re = {"Ivasyk": (RE_EVEN_STR_LEN,),
                  "Dmytryk": (RE_ODD_STR_LEN, RE_FIRST_LTR_CAPITAL),
                  "Lesia": (RE_LAST_WORD_IS_END,)}

Missfit_addressant = 'Ostap'
General_rule = RE_NON_WHITE_SPAC_STR

Servers = {}

DATAGRAM_PORT_STR = '9000'
SNIFF_FILTER_STR = 'udp and port ' + DATAGRAM_PORT_STR


class InputWrapper:
    def __init__(self, path):
        self._path = path
        self._is_open = False

    def __enter__(self):
        self.open_f()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close_f()

    def __iter__(self):
        if self._is_open:
            return self

    def next(self):
        new_packet = lext.getNextLine()
        if new_packet:
            return new_packet.rstrip('\n')
        else:
            raise StopIteration

    def open_f(self):
        if lext.openFile(self._path) != SUCCESS_RETVAL:
            raise IOError
        self._is_open = True

    def close_f(self):
        lext.closeFile()
        self._is_open = False


def is_rules_apply(rules, packet):
    """
    Check if packet satisfies all rules
    :param rules: list of rules
    :param packet: packet to inspect
    :return: true or false
    """
    return all(x(packet) for x in rules)


class Addressant:
    def __init__(self, name, address, payload):
        self.name = name
        self.address = address
        self.payload = payload

    def ping(self):
        pass

    def send(self):
        pass


def is_all_rules_apply(packet, rules):
    return all(re.match(pattern, packet) for pattern in rules)


def factory(packet, missfit_name, general_rule):
    addresants = []
    packet_taken = 0
    general_re = re.compile(general_rule)

    if not general_re.match(packet):
        return addresants

    for name, rules in Addressants_re.items():
        if is_all_rules_apply(packet, rules):
            packet_taken += 1
            if name in Servers:
                addresants.append(Addressant(name, Servers[name], packet))
            else:
                print("Error adressant's name '{}' isn't present in "
                      "JSON file".format(name))
    if packet_taken == 0:
        addresants.append(Addressant(missfit_name,
                                     Servers[missfit_name],
                                     packet))
    return addresants


def get_servers(servers_path):
    with (open(servers_path)) as srv:
        return json.load(srv)

def sniffed_handler(packet):
    pass


def sniffer():
    sniffer_thread = threading.Thread(target=sniff,
                                      name='sniffer',
                                      kwargs={'filter': SNIFF_FILTER_STR,
                                              'prn': sniffed_handler,
                                              'iface': DEFAULT_INTERFACE})
    return sniffer_thread


def main(f_args):
    global Servers
    global General_rule
    global Missfit_addressant
    sniffer_thread = None

    packet_stream = InputWrapper(f_args.path)
    counter = 0
    Servers = get_servers(f_args.servers)

    sniffer_thread = sniffer()

    #sniffer_thread.start()

    tmp = IP(dst='192.168.1.100')
    tmp.show()

    with packet_stream:
        for new_packet in packet_stream:
            addrs_list = factory(new_packet, Missfit_addressant, General_rule)
            for addrs_obj in addrs_list:
                counter += 1
                print('{}. {}\t{}'.format(counter, addrs_obj.name,
                                          addrs_obj.payload))
            counter = 0

    return SUCCESS_RETVAL

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Sort packets with regexp '
                                                 'and retransmit them over '
                                                 'network using UDP')

    parser.add_argument("path",
                        type=str,
                        help="Path to input file")
    parser.add_argument("servers",
                        type=str,
                        help="Path to servers .json file")
    parser.add_argument("-t",
                        '--timeout',
                        type=int,
                        metavar='seconds',
                        default=DEFAULT_TIMEOUT,
                        help="ping timeout in seconds")

    arguments = parser.parse_args()

    main(arguments)

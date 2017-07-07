import argparse
import json
import re
import threading
from c_files import lext
from scapy.all import *
from scapy.layers.inet import IP, UDP, ICMP
import random
from Queue import Queue as queue

SUCCESS_RETVAL = 0
ERROR_RETVAL = -1
DEFAULT_TIMEOUT = 1
INTERFACE_DEFAULT = conf.iface

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

DATAGRAM_PORT = 9000

THREAD_POOL_SIZE = 4


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


def is_rules_apply(rules, _packet):
    """
    Check if packet satisfies all rules
    :param rules: list of rules
    :param _packet: packet to inspect
    :return: true or false
    """
    return all(x(_packet) for x in rules)


class Addressant:
    PORT_MAXVAL = 65535
    ERROR_RETVAL = -1
    SUCCESS_RETVAL = 0

    def __init__(self,
                 name,
                 address,
                 payload,
                 timeout,
                 interface=None):
        self.name = name
        self._id = random.randint(1, Addressant.PORT_MAXVAL)
        self._payload = payload
        self._ip_frame = IP(dst=address)
        self._iface = interface
        self._timeout = timeout

    def _ping(self):
        ans, unans = sr(self._ip_frame / ICMP(),
                        iface=self._iface,
                        timeout=self._timeout,
                        verbose=False)
        if unans:
            print('Host IP:{} is not responding'.format(
                self._ip_frame.getfieldval('dst')))
            return self.ERROR_RETVAL

    def _send(self):
        datagram = (self._ip_frame /
                    UDP(dport=DATAGRAM_PORT,
                        sport=self._id) /
                    self._payload)
        send(datagram, verbose=False)
        return self._id

    def start_transmit(self):
        if self._ping() == self.ERROR_RETVAL:
            return ERROR_RETVAL

        return self._send()


def factory(new_packet, missfit_name, general_rule, task_q, timeout):
    addr_obj = []
    packet_taken = 0
    general_re = re.compile(general_rule)

    if not general_re.match(new_packet):
        return

    for name, rules in Addressants_re.items():
        if is_all_rules_apply(new_packet, rules):
            packet_taken += 1
            if name in Servers:
                addr_obj.append(Addressant(name,
                                           Servers[name],
                                           new_packet,
                                           timeout=timeout))
            else:
                print("Error adressant's name '{}' isn't present in "
                      "JSON file".format(name))
    if packet_taken == 0:
        addr_obj.append(Addressant(missfit_name,
                                   Servers[missfit_name],
                                   new_packet,
                                   timeout=timeout))

    [task_q.put(obj) for obj in addr_obj]


def is_all_rules_apply(_packet, rules):
    return all(re.match(pattern, _packet) for pattern in rules)


def get_servers(servers_path):
    with (open(servers_path)) as srv:
        print("+++ Servers file loaded")
        return json.load(srv)


class SnifferThread(threading.Thread):
    SNIFF_TIMEOUT_SEC = 4

    def __init__(self,
                 interface,
                 result_q,
                 stop_event,
                 destination_port=None,
                 timeout=SNIFF_TIMEOUT_SEC,
                 name='SnifferThread'):
        threading.Thread.__init__(self)
        self._destination_port = destination_port
        self._iface = interface
        self.__stop_event = stop_event
        self._sniff_tim_out = timeout
        self.__name = name
        self._result_q = result_q

    def _sniffed_handler(self, caught_packet):
        self._result_q.put(caught_packet)

    def __filter(self, pkt):
        return UDP in pkt and pkt[UDP].dport == self._destination_port

    def run(self):
        while not self.__stop_event.isSet():
            sniff(lfilter=self.__filter,
                  prn=self._sniffed_handler,
                  iface=self._iface,
                  timeout=self._sniff_tim_out)
        thread.exit()


class ThreadPool:
    def __init__(self, task_queue, result_queue):
        self._task_q = task_queue
        self._result_q = result_queue

    def _worker(self):
        print("+++ Worker started")
        while True:
            the_addressant = self._task_q.get(timeout=0.3)
            retval = the_addressant.start_transmit()
            if retval > 0:
                self._result_q.put(retval)
                self._task_q.task_done()
            if self._task_q.empty():
                thread.exit()

    def crate_thread_pool(self):
        for thr_num in range(THREAD_POOL_SIZE):
            threading.Thread(target=self._worker,
                             name='Thread_{}'.format(thr_num)).start()
        print("+++ Pool created")


def main(f_args):
    global Servers
    global General_rule
    global Missfit_addressant

    task_q = queue()
    sent_q = queue()
    sniff_q = queue()

    print("+++ Started")
    packet_stream = InputWrapper(f_args.path)
    Servers = get_servers(f_args.servers)

    sniffer_kill_event = threading.Event()
    my_sniffer = SnifferThread(INTERFACE_DEFAULT,
                               sniff_q,
                               sniffer_kill_event,
                               destination_port=DATAGRAM_PORT)
    my_sniffer.start()

    ThreadPool(task_q, sent_q).crate_thread_pool()

    with packet_stream:
        for new_packet in packet_stream:
            factory(new_packet,
                    Missfit_addressant,
                    General_rule,
                    task_q,
                    timeout=f_args.timeout)

    print("Please wait")
    task_q.join()

    print("+++ Workers are dead")

    sniffed_list = []
    sent_list = []

    while not sniff_q.empty():
        sniffed_list.append(sniff_q.get()[UDP].getfieldval('sport'))

    while not sent_q.empty():
        sent_list.append((sent_q.get()))

    sniffer_kill_event.set()

    s = set(sniffed_list)
    diff = [x for x in sent_list if x not in s]
    for unsent in diff:
        print("Packet with id {} wasn't send".format(unsent))

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

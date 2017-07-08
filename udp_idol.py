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
DATAGRAM_PORT = 9000
THREAD_POOL_SIZE = 4

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


class InputWrapper:
    """
    Wrapper for SWIG generated module, created from C shared object.
    Creates generator object that returns packet (line), and strips '\n' at
    the end
    """
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
    :param rules: tuple of rules
    :param _packet: packet to inspect
    :return: true or false
    """
    return all(x(_packet) for x in rules)


class Addressant:
    """
    Class is used for transmitting raw UDP datagram to network host.
    Before transmission host presence is checked by sending ICMP ping.
    Every instance gets its unique ID. ID can be from 1 to 2^16 to match
    range of ports available in PC.
    ID is installed in UDPs frame source port.
    """
    PORT_MAXVAL = 65535
    ERROR_RETVAL = -1
    SUCCESS_RETVAL = 0

    def __init__(self,
                 name,
                 address,
                 payload,
                 timeout,
                 interface=None):
        """
        Initializes class instance
        :param name: Addressants name (have to match key in the servers file)
        :param address: IPv4 address of host
        :param payload: payload which to be sent
        :param timeout: ping timeout in seconds
        :param interface: interface for data transmission (will send to all
        interfaces by default
        """
        self.name = name
        self._id = random.randint(1, Addressant.PORT_MAXVAL)
        self._payload = payload
        self._ip_frame = IP(dst=address)
        self._iface = interface
        self._timeout = timeout

    def _ping(self):
        """
        Ping the host with ICMP. If host is unreachable prints error message.
        :return: None on success and ERROR_RETVAL on failure
        """
        ans, unans = sr(self._ip_frame / ICMP(),
                        iface=self._iface,
                        timeout=self._timeout,
                        verbose=False)
        if unans:
            print('Host IP:{} is not responding'.format(
                self._ip_frame.getfieldval('dst')))
            return self.ERROR_RETVAL

    def _send(self):
        """
        Craft packet with UDP datagram and raw payload. Install ID of
        instance in source port of UDP header. Send the packet.
        :return: ID of instance
        """
        datagram = (self._ip_frame /
                    UDP(dport=DATAGRAM_PORT,
                        sport=self._id) /
                    self._payload)
        send(datagram, verbose=False)
        return self._id

    def start_transmit(self):
        """
        Ping with ICMP. If host is present send packet with payload.
        :return: ID of instance on success, ERROR_RETVAL on failure.
        """
        if self._ping() == self.ERROR_RETVAL:
            return ERROR_RETVAL

        return self._send()


def factory(new_packet, missfit_name, general_rule, task_q, timeout):
    """
    Processes packet and creates instances of Addressant class based on
    regexps located in Addressants_re.
    Also applies rejection based on general rule, if it is provided.
    Creates Addressant class object from packet rejected by all regexps in
    Addressants_re.
    All created objects of Addressant class are put to the task_q queue.
    :param new_packet: packet to process (string)
    :param missfit_name: name string of missfit receiver (have to match key in
     the servers file)
    :param general_rule: general rule for all packets to match
    :param task_q: Queue where created objects will be put
    :param timeout: timeout argument for Addressant
    :return: None
    """
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
    """
    Check is all regexps match given packet
    :param _packet: packet to check
    :param rules: regexp patterns tuple
    :return: True if all regexps are matched else False
    """
    return all(re.match(pattern, _packet) for pattern in rules)


def get_servers(servers_path):
    """
    Parse JSON file that contains dictionary in form server_name:server_address
    :param servers_path: path to file
    :return: servers dictionary
    """
    with (open(servers_path)) as srv:
        print("+++ Servers file loaded")
        return json.load(srv)


class SnifferThread(threading.Thread):
    """
    When started as thread listens for specific packets. When specific
    packet is present it is added to queue.
    """
    # TODO: make class singleton
    SNIFF_TIMEOUT_SEC = 4

    def __init__(self,
                 result_q,
                 stop_event,
                 interface=None,
                 name='SnifferThread',
                 destination_port=None):
        """
        Initializes SnifferThread object
        :param interface: interface to listen to (listen to all ifaces by
        default
        :param result_q: queue for placing sender port integer values of
        captured UDP packets
        :param stop_event: thread event that terminates SnifferThread
        :param destination_port: port value for packets filter
        :param name: thread name ('SnifferThread' by default)
        """
        threading.Thread.__init__(self)
        self._destination_port = destination_port
        self._iface = interface
        self.__stop_event = stop_event
        self.__name = name
        self._result_q = result_q

    def _sniffed_handler(self, caught_packet):
        """
        Handler for captured packets.
        Puts packets to queue.
        :param caught_packet: captured packet
        :return: None
        """
        self._result_q.put(caught_packet)

    def __filter(self, pkt):
        """
        Filter function for sniff()
        :param pkt: captured packet
        :return: True if pkt has UDP layer and UDPs layer dport is eqv to
        self._destination_port else False
        """
        return UDP in pkt and pkt[UDP].dport == self._destination_port

    def run(self):
        """
        While self.__stop_event isn't set thread will call sniff().
        Thread exits when self.__stop_event is set and
        SNIFF_TIMEOUT_SEC is expired
        :return: None
        """
        while not self.__stop_event.isSet():
            sniff(lfilter=self.__filter,
                  prn=self._sniffed_handler,
                  iface=self._iface,
                  timeout=self.SNIFF_TIMEOUT_SEC)
        thread.exit()


class ThreadPool:
    """
    Thread pool
    """
    def __init__(self, task_queue, result_queue):
        """
        Initialize ThreadPool instance
        :param task_queue: queue for the tasks
        :param result_queue: queue for the results
        """
        self._task_q = task_queue
        self._result_q = result_queue

    def _worker(self):
        """
        Tries to get task from task_q. Exits whet queue is empty.
        Puts retval of Addressant object
        :return: None
        """
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
        """
        Creates THREAD_POOL_SIZE threads and starts them
        :return: None
        """
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

    try:
        packet_stream = InputWrapper(f_args.path)
    except (OSError, IOError):
        print("Can't open input file. Terminating.")
        return ERROR_RETVAL

    try:
        Servers = get_servers(f_args.servers)
    except (IOError):
        print("Can't open servers file. Terminating.")
        return ERROR_RETVAL
    except (Exception):
        print("Problems with servers file. Terminating.")
        return ERROR_RETVAL

    sniffer_kill_event = threading.Event()
    my_sniffer = SnifferThread(interface=INTERFACE_DEFAULT,
                               result_q=sniff_q,
                               stop_event=sniffer_kill_event,
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

    print("Please wait. Still processing")
    task_q.join()
    print("+++ Workers are dead")

    sniffed_list = []
    sent_list = []

    while not sniff_q.empty():
        sniffed_list.append(sniff_q.get()[UDP].getfieldval('sport'))

    while not sent_q.empty():
        sent_list.append((sent_q.get()))

    sniffer_kill_event.set()

    sniff_set = set(sniffed_list)
    diff = [x for x in sent_list if x not in sniff_set]

    unsent_packets = len(diff)
    if unsent_packets:
        for _id in diff:
            print("Packet with id {} wasn't sent".format(_id))
    else:
        print("{} packets was successfully sent".format(len(sniffed_list)))

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
                        choices=range(1, 10),
                        metavar='seconds (1-10)',
                        default=DEFAULT_TIMEOUT,
                        help="ping timeout in seconds")

    arguments = parser.parse_args()

    main(arguments)

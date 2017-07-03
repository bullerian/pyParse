import argparse

FILE_NAME_SUFFIX = ".txt"
ERROR_RETVAL = -1
SUCCESS_RETVAL = 0

# Rules (Yes, I use lambda instead of def. It's more convenient in this case
EVEN_SYMBOL_COUNT = lambda x: (len(x) % 2 == 0)
ODD_SYMBOL_COUNT = lambda x: ((len(x) % 2) == 1)
# NOTE: istitle() gives false-negative on "I'll" or "C'mon".
# have to break to letters and use isupper() on first letter
FIRST_LETTER_UPPERCASE = lambda x: x.split()[0][0].isupper()
END_IS_LAST_WORD = lambda x: x.split()[-1].lower() == 'end'
LEN_GT_ZERO = lambda x: len(x)

ivan_rule = [EVEN_SYMBOL_COUNT]
dmytro_rule = [ODD_SYMBOL_COUNT, FIRST_LETTER_UPPERCASE]
orest_rule = []
lesia_rule = [END_IS_LAST_WORD]

receivers = [("ivan", ivan_rule),
             ("dmytro", dmytro_rule),
             ("lesia", lesia_rule)]
misfit = ("ostap", orest_rule)

general_rule = [LEN_GT_ZERO]


def sort(raw_data_list, receiver_list, misfit_rcv=None, global_rule=None):
    """
    Processes packet list and adds items to dictionary based on provided
     predicates in rule list.
    Also applies rejection based on general rule, if it is provided.
    Drops (by default) packets if they did't satisfy any rule.
    Will append items rejected by all rules to misfitsRcv if it is provided.
    :param raw_data_list: list of input packets
    :param receiver_list: receivers list that contains tuple in form
     ("name", [rule list])
    :param misfit_rcv: tuple in form ("name", [rule list]) for packet that
     doesn't match any rule in rcv list
    :param global_rule: general rule that all packets must apply
    :return: dict with names as keys and list of packets as value of keys
            if misfit is present than its packets will be added to dict
    """
    packet_dict = dict()

    # set misfit variables if misfit parameters are provided
    if misfit_rcv:
        misfitName = misfit_rcv[0]
        packet_dict[misfitName] = list()

    for packet in raw_data_list:

        if global_rule and not is_rules_apply(global_rule, packet):
            continue

        packet_taken = 0

        for name, rule in receiver_list:
            # add empty list as new key in dictionary
            # key == rule name
            if name not in packet_dict:
                packet_dict[name] = list()

            # check packet against all rules
            # if one rule fails abort
            if is_rules_apply(rule, packet):
                packet_dict[name].append(packet)
                packet_taken += 1

        # if misfit packet has receiver
        # else misfit packet will be dropped
        if misfit_rcv and not packet_taken:
            # if misfits packet has rules they can be checked here
            packet_dict[misfitName].append(packet)

    return packet_dict


def is_rules_apply(rule_list, packet):
    """
    Check if packet satisfies all rules
    :param rule_list: list of rules
    :param packet: packet to inspect
    :return: true or false
    """
    return all(x(packet) for x in rule_list)


def save_files(filled_dict):
    """
    Creates one file per every key in dictionary.
    Writes all of dicts value items as separate lines
    to file named as key + FILE_NAME_SUFFIX
    :param filled_dict: dictionary that contains names as keys and lists of
     strings as values
    :return: none
    """
    for key, lst in filled_dict.iteritems():
        with (open(key + FILE_NAME_SUFFIX, 'w+')) as out_file:
            out_file.writelines(["%s\n" % item for item in lst])


def get_splited_file(pth, delim):
    """
    Opens file and splits it to list of packets by provided delimiter
    :param pth: path to file
    :param delim: delimiter string
    :return: list of packets for processing
    """
    with (open(pth, 'r')) as in_file:
        line_list = in_file.read().split(delim)

    return line_list


def main(path, delimiter):
    """
    Splits lines by delimiter, then sorts them based on rule set and adds them
     to dictionary. Then sorted line lists get saved to separate files.
    For now rules are hard-coded, but script can be modified to accept separate
     rule list. Written and tested on Python 2.7.12
    :param path: path to input text file
    :param delimiter: delimiter for line splitting
    :return: SUCCESS_RETVAL on success or ERROR_RETVAL on failure
    """
    try:
        splited_list = get_splited_file(path, delimiter)
    except IOError as e:
        print('Unable to open input file. Error message: ' + e.message)
        return ERROR_RETVAL
    except Exception:
        print('Unknown error occurred')
        return ERROR_RETVAL

    processed_packet_dict = sort(splited_list, receivers, misfit, general_rule)

    try:
        save_files(processed_packet_dict)
    except IOError as e:
        print('Unable to save processed file(s). Error message: ' + e.message)
        return ERROR_RETVAL
    except Exception:
        print('Unknown error occurred')
        return ERROR_RETVAL

    return SUCCESS_RETVAL

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Rule-based sorting')

    # Optional delimiter arg
    parser.add_argument("-d",
                        "--delimiter",
                        type=str,
                        help='Delimiter string ("\\n" by default)')
    parser.add_argument("path", type=str, help="Path to input file")

    args = parser.parse_args()

    delimiter = '\n'
    if args.delimiter:
        delimiter = args.delimiter

    main(args.path, delimiter)

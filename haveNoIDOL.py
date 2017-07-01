import argparse

FILE_NAME_SUFFIX = ".txt"
ERROR_RETVAL = -1
SUCCESS_RETVAL = 0

Irule = [lambda x: (len(x) % 2 == 0)]
# NOTE: istitle() gives false-negative on "I'll" or "C'mon".
# have to break to letters and use isupper() on first letter
Drule = [lambda x: ((len(x) % 2) == 1), lambda x: x.split()[0][0].isupper()]
Orule = []
Lrule = [lambda x: x.split()[-1].lower() == 'end']

receivers = [("ivan", Irule), ("dmytro", Drule), ("lesia", Lrule)]
misfit = ("ostap", Orule)

generalRules = [lambda x: len(x)]


def sort(rawDataList, rcv, misfitRcv=None, gnrRule=None):
    """
    Processes string list and adds items to dictionary based on provided predicates in rule list.
    Also applies rejection based on general rule, if it is provided.
    Drops (by default) packets if they did't satisfy any rule.
    Will append items rejected by all rules to misfitsRcv if it is provided.
    :param rawDataList: list of input strings
    :param rcv: receivers list that contains tuple in form ("name", [rule list])
    :param misfitRcv: tuple in form ("name", [rule list]) for packet that doesn't match any rule in rcv list
    :param gnrRule: general rule that all packets must apply
    :return: dict with names as keys and list of packets as value of keys
            if misfit is present than its packets will be added to dict
    """
    pdict = dict()

    # set misfit variables if misfit parameters are provided
    if misfitRcv:
        misfitName = misfitRcv[0]
        pdict[misfitName] = list()

    for packet in rawDataList:

        if gnrRule and not isRulesApplyToPacket(gnrRule, packet):
            continue

        pTaken = 0

        for name, rule in rcv:
            # add empty list as new key in dictionary
            # key == rule name
            if name not in pdict:
                pdict[name] = list()

            # check packet against all rules
            # if one rule failes abort
            if isRulesApplyToPacket(rule, packet):
                pdict[name].append(packet)
                pTaken += 1

        # if misfit packet has receiver
        # else misfit packet will be dropped
        if not pTaken and misfitRcv:
            # if misfits packet has rules they can be checked here
            pdict[misfitName].append(packet)

    return pdict


def isRulesApplyToPacket(ruleList, packet):
    """
    Check if packet satisfies all rules
    :param ruleList: list of rules
    :param packet: string inspect
    :return: 
    """
    return all(x(packet) for x in ruleList)


def save_files(filledDict):
    """
    Creates one file per every key in dictionary.
    Writes all of dicts value items as separate lines
    to file named as key + FILE_NAME_SUFFIX
    :param filledDict: dictionary that contains names as keys and lists of strings as values
    :return: none
    """
    for key, lst in filledDict.iteritems():
        with (open(key + FILE_NAME_SUFFIX, 'w+')) as out_file:
            out_file.writelines(["%s\n" % item for item in lst])



def get_splited_file(pth, delim):
    with (open(pth, 'r')) as in_file:
        line_list = in_file.read().split(delim)

    return line_list


def main(path, delimiter):
    """
    Splits lines by delimiter, then sorts them based on rule set and adds them to dictionary.
    Then sorted line lists get saved to separate files.
    For now rules are hard-coded, but script can be modified to accept separate rule list.
    Written and tested on Python 2.7.12
    :param path: path to input text file
    :param delimiter: delimiter for line splitting
    :return: 0 on success or -1 on failure
    """
    try:
        splitedList = get_splited_file(path, delimiter)
    except IOError as e:
        print('Unable to open input file. Error message: ' + e.message)
        return ERROR_RETVAL
    except Exception:
        print('Unknown error occurred')
        return ERROR_RETVAL

    processedPacketDict = sort(splitedList, receivers, misfit, generalRules)

    try:
        save_files(processedPacketDict)
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
    parser.add_argument("-d", "--delimiter", type=str, help='Delimiter string ("\\n" by default)')
    parser.add_argument("path", type=str, help="Path to input file")

    args = parser.parse_args()

    delimiter = '\n'
    if args.delimiter:
        delimiter = args.delimiter

    main(args.path, delimiter)

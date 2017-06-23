FILE_NAME_SUFFIX = ".txt"

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
    Also applies rejection based on fail of general rule, if general rule is provided.
    Drops (by default) packets if they did't satisfy any rule.
    Will append strings rejected by all rules to misfitsRcv if it is provied
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
        misfitList = list()
        pdict[misfitName] = []

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
                pTaken = pTaken + 1

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
        f = open(key + FILE_NAME_SUFFIX, 'w+')

        f.writelines(["%s\n" % item for item in lst])


def get_splited_file(pth, delim):
    fileDescriptor = open(pth, 'r')

    return fileDescriptor.read().split(delim)


def main(path, delimiter='\n'):
    """

    :param path: path to input file
    :param delimiter: delimiter for file
    :return:
    """
    splitedList = get_splited_file(path, delimiter)

    save_files(sort(splitedList, receivers, misfit, generalRules))


if __name__ == '__main__':
    main("messages.txt")

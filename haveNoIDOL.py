FILE_NAME_SUFFIX = ".txt"

Irule = [lambda x: (len(x) % 2)]
Drule = [lambda x: ((len(x) % 2) is 1), lambda x: x.split()[0].istitle()]
Orule = [lambda x: True]
Lrule = [lambda x: x.split()[-1].lower() == 'end']

receivers = [("ivan", Irule), ("dmytro", Drule), ("lesia", Lrule)]
misfit =("ostap", Orule)


generalRules = [lambda x: len(x)]

test = list()

def sort(rawDataList, rcv, misfitRcv, gnrRule):
    """


    :param source:
    :param rcv:
    :param misfitRcv:
    :param gnrRule: general rule that all packets must apply
    :return:
    """
    pdict = dict()

    # set misfit variables if misfit parameters are provided
    if misfitRcv:
        misfitName = misfitRcv[0]
        misfitList = list()
        pdict[misfitName]=[]

    for packet in rawDataList:
        
        if not isRulesApplyToPacket(gnrRule, packet):
            continue
            
        pTaken = 0
        
        for name, rule in rcv:
            # add empty list as new key in dictionary
            # key == rule name
            if name not in pdict:
                pdict[name]=list()

            # check packet against all rules
            # if one rule failes abort
            if isRulesApplyToPacket(rule, packet):
                pdict[name].append(packet)
                pTaken=pTaken+1
        
        # if misfit packet has receiver
        # else misfit packet will be dropped
        if not pTaken and misfitRcv:
            # if misfits packet has rules they can be checked here
            misfitList.append(packet)

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

    for key, list in filledDict.iteritems():
        f=open(key+FILE_NAME_SUFFIX, 'w+')

        f.writelines(["%s\n" % item  for item in list])


def get_splited_file(pth, delim = '\n'):
    fileDescriptor = open(pth, 'r')

    return fileDescriptor.read().split(delim)


def main(path, delimiter):
    splitedList=get_splited_file(path, delimiter)
    

    save_files(sort(splitedList, receivers, misfit, generalRules))


if __name__ == '__main__':
   main()
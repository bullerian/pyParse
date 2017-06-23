inFile = ''
FILE_NAME_SUFFIX = ".txt"

Irule = [lambda x: (len(x) % 2)]
Drule = [lambda x: ((len(x) % 2) is 1), lambda x: x.split()[0].istitle()]
Orule = list()
Lrule = [lambda x: x.split()[-1].lower() == 'end']

receivers = [("ivan", Irule), ("dmytro", Drule), ("lesia", Lrule)]
misfit =[("ostap", Orule)]

generalRules = [lambda x: len(x)]

test = list()

def getfile(path):
    """
    Open file in readonly mode, save file descriptor
    to inFile global var
    :param path: path to file
    :return: none
    """
    global inFile
    inFile = open(path, 'r')


def split_stream(fs, delim='\n', bufsize=1024):
    """
    Splits stream of data by delim.
    Reads buffsize bytes per one call.
    Yields delimited string
    :param fs: file descriptor
    :param delim: delimiter variable
    :param bufsize: size of read buffer
    :return: if delimiter is found yields splited string
            or empty string if it's not found
    """

    prev = ''
    while True:
        s = fs.read(bufsize)
        if not s:
            break
        split = s.split(delim)
        if len(split) > 1:
            yield prev + split[0]
            prev = split[-1]
            for x in split[1:-1]:
                yield x
        else:
            prev += s
    if prev:
        yield prev


def sort(rcv, misfitRcv, gnrRule):
    """

    :param rcv:
    :param misfitRcv:
    :param gnrRule:
    :return:
    """
    pdict = dict()

    isAllRulesApply=True

    for packet in split_stream(inFile):
        for gnr in gnrRule:
            # proceed if generall
            if not gnr(packet):
                continue
                for name, rule in rcv:
                    # add empty list as new key in dictionary
                    # key == rule name
                    if not pdict.has_key(name):
                        pdict[name]=list()

                    # check packet against all rules
                    # if one rule failes abort
                    for predicate in rule:
                        if not (predicate(packet)):
                            isAllRulesApply=False
                            break

                    if isAllRulesApply:
                        pdict[name].append(packet)

    return pdict


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


def main():
    getfile('messages.txt')
    save_files(sort(receivers, misfit, generalRules))


if __name__ == '__main__':
   main()
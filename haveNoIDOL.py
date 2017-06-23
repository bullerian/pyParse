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
    global inFile
    inFile = open(path, 'r')


def split_stream(fs, delim='\n', bufsize=1024):
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
    pdict = dict()
    pdict[misfitRcv.pop()]

    for packet in split_stream(inFile):
        for gnr in gnrRule:
            if gnr(packet):
                for name, rule in rcv:

                    if not pdict.has_key(name):
                        pdict[name]=list()

                    #isRulestrue = True

                    for predicate in rule:
                        if not (predicate(packet)):
                            #isRulestrue = False
                            continue
#                    if isRulestrue:
                    pdict[name].append(packet)
                        #isRulestrue = True

    return pdict


def save_files(filledDict):

    for key, list in filledDict.iteritems():
        f=open(key+FILE_NAME_SUFFIX, 'w+')

        f.writelines(["%s\n" % item  for item in list])


def main():
    getfile('messages.txt')
    save_files(sort(receivers, misfit))


if __name__ == '__main__':
   main()
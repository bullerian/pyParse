Script for the IDOL task

Splits lines by delimiter, then sorts them based on rule set and adds them to dictionary. Can reject lines by general rule. Also it can save so called 'misfit' lines (the ones that doesn't fit any rule). Then sorted line lists get saved to separate files in current directory.
    For now rules are hard-coded, but script can be modified to accept separate rule list.
Written and tested on Python 2.7.12


USAGE: python haveNoIDOL.py [-h] [-d DELIMITER] path

    -h   -- display help
    -d   -- delimiter ('\n' by default)
    path -- path to target text file

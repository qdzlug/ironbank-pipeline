from pipeline import constants as Constants
from pipeline import *
import subprocess
import os

def findFile():
    """
    Find a download.{json,yaml,yml} file
    :return: filepath
    """
    command = ['find', '-type', 'f', '-regextype', 'sed',
               '-regex', '"\\./download.\\(json\\|yaml\\|yml\\)"']

    result = subprocess.Popen(command, stdout=subprocess.PIPE).communicate()[0].decode('UTF-8')

    return os.path.abspath(result.split('\n')[0])


def fileExists():
    return findFile()


def main():
    fileExists()

if __name__ == "__main__":
    main()
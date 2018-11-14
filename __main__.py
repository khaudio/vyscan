#!/usr/bin/env python

from collections import deque
from subprocess import Popen, PIPE, STDOUT
import sys
import os

"""
A simple script that upgrades, updates, and runs a clamav scan recursively
on a directory.
"""


def run_subprocess(command, dir=''):
    """Runs a subprocess and returns stdout and stderr as lists split by line"""
    proc = Popen(command.split() + [dir], stdout=PIPE, stderr=STDOUT)
    output = proc.communicate()
    return [line for line in output[0].decode().split('\n')]


def upgrade():
    """Checks brew for latest version of clamav, and upgrades it if needed"""
    latest = run_subprocess('brew info clamav')[0].split()[-2].strip(',')
    installed = run_subprocess('clamscan --version')[0].split()[1].split('/')[0]
    if latest != installed:
        print('Upgrading clamav')
        run('brew upgrade clamav')


def update():
    """Updates virus definitions"""
    run_subprocess('freshclam -v')


def scan(directory):
    """
    Checks if directory exists and scans it recursively.
    Returns verbose output of the scan.
    """
    if not os.path.exists(directory):
        raise ValueError('Directory not found')
    scanned = run_subprocess('clamscan -vr', directory)
    return scanned


def parse(scanned):
    """
    Parses results of scan, prints the filepath of any infected files,
    and returns number of infected files.
    """
    infected, viewingFiles, found = None, False, deque()
    for line in scanned[::-1]:
        if 'Infected files' in line:
            infected = int(line.lstrip('Infected files: '))
        elif 'SCAN SUMMARY' in line:
            viewingFiles = True
        elif viewingFiles:
            filepath, delimiter, status = line.lstrip('Scanning ').partition(': ')
            if filepath and status and status != 'OK':
                found.append(filepath)
    if infected:
        print('ALERT:\t{infected} infected files found:')
        print(tuple(filepath for filepath in found[::-1]))
    else:
        print('No infected files found')
    return not infected


if __name__ == '__main__':
    directory = sys.argv[-1]
    upgrade()
    update()
    parse(scan(directory))

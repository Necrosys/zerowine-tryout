#!/usr/bin/env python
#-*- coding: utf-8 -*-
"""
    libhash
    by Chae Jong Bin
"""

__description__ = 'libhash'
__author__ = 'Chae Jong Bin'

import hashlib


class LibHash(object):

    def __init__(self):
        self.md5 = ''
        self.sha1 = ''
        self.sha224 = ''
        self.sha256 = ''
        self.sha384 = ''
        self.sha512 = ''

    def readDataFromFile(self, fileName):
        f = file(fileName, "rb")
        data = f.read()
        f.close()

        return data

    def generateXml(self):
        xmlString = ""

        for algorithm in self.__dict__.keys():
            xmlString += "<%s>%s</%s>\n" \
                % (algorithm, self.__dict__[algorithm], algorithm)

        return xmlString

    def generateHashFromData(self, data, algorithm):
        temp = getattr(hashlib, algorithm)
        self.__dict__[algorithm] = temp(data).hexdigest()

    def generateHashFromFile(self, fileName, algorithm):
        data = self.readDataFromFile(fileName)

        self.generateHashFromData(data, algorithm)

    def generateHashesFromData(self, data):
        for algorithm in self.__dict__.keys():
            self.generateHashFromData(data, algorithm)

    def generateHashesFromFile(self, fileName):
        data = self.readDataFromFile(fileName)

        self.generateHashesFromData(data)

    def readHashFromData(self, data, algorithm):
        self.generateHashFromData("", algorithm)

        for temp in data.splitlines():
            # Compare length
            if len(self.__dict__[algorithm]) == len(temp):
                self.__dict__[algorithm] = temp

    def readHashFromFile(self, fileName, algorithm):
        data = self.readDataFromFile(fileName)

        self.readHashFromData(data, algorithm)

    def readHashesFromData(self, data):
        for algorithm in self.__dict__.keys():
            self.readHashFromData(data, algorithm)

    def readHashesFromFile(self, fileName):
        data = self.readDataFromFile(fileName)

        self.readHashesFromData(data)

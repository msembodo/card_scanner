from __future__ import print_function
from smartcard.Exceptions import NoCardException, CardConnectionException
from smartcard.System import readers
from smartcard.util import toHexString, toBytes
import sys
import copy
import logging
from datetime import datetime
from xml.dom.minidom import parse
import json
import ntpath

logging.basicConfig(level=logging.INFO,
                    format="[%(asctime)s] [%(levelname)s] %(message)s",
                    datefmt="%H:%M:%S", stream=sys.stdout)

logger = logging.getLogger(__name__)

class CardScanner:
    connection = None
    verifcodeLogBuffer = None

    # constants
    READ_RECORD_ABSOLUTE = 0x04
    MAX_RESPONSE_LEN = 250

    # initialized by constructor
    runAsModule = False
    fullScript = False

    # options (will be overwritten by VerifClient settings);
    # change accordingly when run standalone;
    # this non-regression engine is developed with 'DAKOTA 4.2' as model.
    readerNumber = 1 # reader index starts from 0
    opt_chv1_disabled = True
    opt_use_adm2 = False
    opt_use_adm3 = False
    opt_use_adm4 = False
    opt_read_content_3g = False
    adm1 = '4331324131364442'
    adm2 = '933F57845F706921'
    adm3 = '933F57845F706921'
    adm4 = '933F57845F706921'
    chv1 = '39333033FFFFFFFF'
    chv2 = '39343438FFFFFFFF'

    destinationFolder = '.'

    pcomOutFile = None
    pcomOutFileName = 'script.pcom'

    profileBaseName = 'script'
    
    fileSystemXml = ''
    fileSystemOutJson = ''
    fileSystemOutHtml = ''
    htmlFile = None

    # APDU params
    verify2gAdm1p1 = 0x00
    verify2gAdm1p2 = 0x00 # default = 0x00; SIMBIOS = 0x14
    verify2gAdm1p3 = 0x08
    # --
    verify2gAdm2p1 = 0x00
    verify2gAdm2p2 = 0x05 # default = 0x05; SIMBIOS = 0x13
    verify2gAdm2p3 = 0x08
    # --
    verify2gAdm3p1 = 0x00
    verify2gAdm3p2 = 0x06 # default = 0x06; SIMBIOS = 0x16
    verify2gAdm3p3 = 0x08
    # --
    verify2gAdm4p1 = 0x00
    verify2gAdm4p2 = 0x07 # default = 0x07; SIMBIOS = 0x17
    verify2gAdm4p3 = 0x08
    # --
    verify2gChv1p1 = 0x00
    verify2gChv1p2 = 0x01
    verify2gChv1p3 = 0x08
    # --
    verify2gChv2p1 = 0x00
    verify2gChv2p2 = 0x02
    verify2gChv2p3 = 0x08
    # --
    verify3gAdm1p1 = 0x00
    verify3gAdm1p2 = 0x0A
    verify3gAdm1p3 = 0x08
    # --
    verify3gAdm2p1 = 0x00
    verify3gAdm2p2 = 0x0B
    verify3gAdm2p3 = 0x08
    # --
    verify3gAdm3p1 = 0x00
    verify3gAdm3p2 = 0x0C
    verify3gAdm3p3 = 0x08
    # --
    verify3gAdm4p1 = 0x00
    verify3gAdm4p2 = 0x0D
    verify3gAdm4p3 = 0x08
    # --
    verify3gGlobalPin1p1 = 0x00
    verify3gGlobalPin1p2 = 0x01
    verify3gGlobalPin1p3 = 0x08
    # --
    verify3gLocalPin1p1 = 0x00
    verify3gLocalPin1p2 = 0x81
    verify3gLocalPin1p3 = 0x08

    # APDU templates
    select2g = [0xA0, 0xA4, 0x00, 0x00, 0x02]
    getResponse2g = [0xA0, 0xC0, 0x00, 0x00, 0x0F]
    readHeader2g = [0xA0, 0xE8, 0x00, 0x00, 0x17]
    verifyPIN2g = [0xA0, 0x20, 0x00, 0x00, 0x00]
    readRecord2g = [0xA0, 0xB2, 0x00, 0x00, 0x00]
    readBinary2g = [0xA0, 0xB0, 0x00, 0x00, 0x00]
    readOsLock = [0xA0, 0xBC, 0x00, 0x00, 0x01]

    select3g = [0x00, 0xA4, 0x00, 0x04, 0x02]
    getResponse3g = [0x00, 0xC0, 0x00, 0x00, 0x0F]
    verifyPIN3g = [0x00, 0x20, 0x00, 0x00, 0x00]
    readRecord3g = [0x00, 0xB2, 0x00, 0x00, 0x00]
    readBinary3g = [0x00, 0xB0, 0x00, 0x00, 0x00]

    def __init__(self, runAsModule, fullScript):
        self.runAsModule = runAsModule
        self.fullScript = fullScript

    def formatFileId(self, fileId):
        if len(fileId) == 4:
            formatted = fileId
            return formatted
        if len(fileId) == 8:
            formatted = fileId[:4] + '/' + fileId[4:]
            return formatted
        if len(fileId) == 12:
            formatted = fileId[:4] + '/' + fileId[4:8] + '/' + fileId[8:]
            return formatted
        if len(fileId) == 16:
            formatted = fileId[:4] + '/' + fileId[4:8] + '/' + fileId[8:12] + '/' + fileId[12:]
            return formatted
        if len(fileId) == 20:
            formatted = fileId[:4] + '/' + fileId[4:8] + '/' + fileId[8:12] + '/' + fileId[12:16] + '/' + fileId[16:]
            return formatted

    def filterHex(self, hexString):
        temp = ''
        hexString = hexString.upper()
        for a in hexString:
            if a >= '0' and a <= '9':
                temp = temp + a
            elif a >= 'A' and a <= 'F':
                temp = temp + a
        return temp

    def hexStringToBytes(self, hexString):
        hexString = self.filterHex(hexString)
        length = len(hexString)
        i = length - 2
        temp = []
        # convert from end to beginning
        while i >= 0:
            temp.append(int(hexString[i: i + 2], 16))
            i -= 2
        # handle last byte if only 1 digit
        if i == -1:
            temp.append(int(hexString[0:1], 16))
        # reverse
        i = len(temp)
        result = []
        while i > 0:
            i -= 1
            result.append(temp[i])
        return result

    def initSCard(self):
        if len(readers()) == 0:
            logger.error('No smartcard reader(s) detected.')
            return -1
        reader = readers()[self.readerNumber]
        try:
            self.connection = reader.createConnection()
            self.connection.connect()
            logger.info('%s; ATR: %s' % (reader, toHexString(self.connection.getATR())))
            self.pcomOutFile.writelines("\n.POWER_ON")
            self.pcomOutFile.writelines('\n')
            return 0
        except NoCardException:
            logger.error('Error initializing card; may be wrong reader or card not inserted.')
            return -1
        
    def sendApdu(self, apduHeader, apduData, print2screen=False, out2Pcom=True):
        try:
            if type(apduHeader) == str:
                apduHeader = self.hexStringToBytes(apduHeader)
            if type(apduData) == str:
                apduData = self.hexStringToBytes(apduData)
            apdu = apduHeader
            pcomOutString = toHexString(apdu).replace(' ', '')
            if apduData:
                apdu = apdu + apduData
                pcomOutString = pcomOutString + ' ' + toHexString(apduData).replace(' ', '')
            
            if apduHeader[1] == 0x20:
                apduString = toHexString(apduHeader) + ' ' + self.filterHex(toHexString(apduData))
                self.verifcodeLogBuffer['apdu_string'] = apduString
            
            if print2screen:
                print('Command: ' + toHexString(apdu))
            
            response, sw1, sw2 = self.connection.transmit(apdu)
            
            if apduHeader[1] == 0x20:
                self.verifcodeLogBuffer['status_word'] = '%.2X %.2X' % (sw1, sw2)
                if not (sw1 == 0x90 and sw2 == 0x00):
                    self.verifcodeLogBuffer['verifcode_success'] = False

            if response:
                pcomOutString = pcomOutString + ' [' + toHexString(response).replace(' ', '') + ']'
                if print2screen:
                    print('Output : ' + toHexString(response))
            
            pcomOutString = pcomOutString + ' (%.2X%.2X)' % (sw1, sw2)
            if out2Pcom:
                self.pcomOutFile.writelines(pcomOutString)
                self.pcomOutFile.writelines('\n')

            if print2screen:
                print('Status : %.2X %.2X' % (sw1, sw2))
                print()
            return response, sw1, sw2
        
        except CardConnectionException:
            return -1, 'A communications error with the smart card has been detected', None

    def cmdReadHeader(self, number, readMode):
        apduHeader = copy.deepcopy(self.readHeader2g)
        apduHeader[2] = int(number)
        apduHeader[3] = int(readMode)
        response, sw1, sw2 = self.sendApdu(apduHeader, None, out2Pcom=False)
        return response, sw1, sw2

    def countLockBuffer(self):
        lockOffsetCount = 0
        while lockOffsetCount < 256:
            sw1, sw2 = self.cmdReadOsLock(lockOffsetCount, False)
            if not (sw1 == 0x90 and sw2 == 0x00):
                break
            lockOffsetCount += 1
        return lockOffsetCount

    def cmdReadOsLock(self, offset, printMode):
        apduHeader = copy.deepcopy(self.readOsLock)
        apduHeader[3] = offset
        if printMode:
            response, sw1, sw2 = self.sendApdu(apduHeader, None, out2Pcom=True)
        else:
            response, sw1, sw2 = self.sendApdu(apduHeader, None, out2Pcom=False)
        return sw1, sw2

    def cmdSelect2g(self, path, print2screen=False, out2Pcom=True):
        path = self.filterHex(path)
        i = 0
        while i < (len(path) - 4):
            if not print2screen:
                if out2Pcom:
                    self.sendApdu(self.select2g, path[i:i + 4])
                else:
                    self.sendApdu(self.select2g, path[i:i + 4], out2Pcom=False)
            else:
                self.sendApdu(self.select2g, path[i:i + 4], print2screen=True)
            i += 4
        getResponse2g = copy.deepcopy(self.getResponse2g)
        if not print2screen:
            if out2Pcom:
                response, sw1, sw2 = self.sendApdu(self.select2g, path[i:]) # shall return 9fxx
            else:
                response, sw1, sw2 = self.sendApdu(self.select2g, path[i:], out2Pcom=False) # shall return 9fxx
            if sw1 == 0x94 and sw2 == 0x04:
                return response, sw1, sw2
            getResponse2g[4] = sw2
            if out2Pcom:
                response, sw1, sw2 = self.sendApdu(getResponse2g, None)
            else:
                response, sw1, sw2 = self.sendApdu(getResponse2g, None, out2Pcom=False)
        else:
            response, sw1, sw2 = self.sendApdu(self.select2g, path[i:], print2screen=True) # shall return 9fxx
            getResponse2g[4] = sw2
            response, sw1, sw2 = self.sendApdu(getResponse2g, None, print2screen=True)
        return response, sw1, sw2

    def cmdSelect3g(self, path, print2screen=False):
        path = self.filterHex(path)
        i = 0
        while i < (len(path) - 4):
            if not print2screen:
                self.sendApdu(self.select3g, path[i:i + 4])
            else:
                self.sendApdu(self.select3g, path[i:i + 4], print2screen=True)
            i += 4
        getResponse3g = copy.deepcopy(self.getResponse3g)
        if not print2screen:
            response, sw1, sw2 = self.sendApdu(self.select3g, path[i:]) # shall return 61xx
            getResponse3g[4] = sw2
            response, sw1, sw2 = self.sendApdu(getResponse3g, None)
        else:
            response, sw1, sw2 = self.sendApdu(self.select3g, path[i:], print2screen=True) # shall return 61xx
            getResponse3g[4] = sw2
            response, sw1, sw2 = self.sendApdu(getResponse3g, None, print2screen=True)
        return response, sw1, sw2

    def getValueByTag(self, tag, tlvObject):
        for byte in tlvObject:
            index = tlvObject.index(byte)
            if byte == tag:
                index += 1
                length = tlvObject[index]
                index += 1
                value = tlvObject[index:index+length]
                break
        return value

    def getTlvObjects(self, tlvBytes):
        tlvList = []
        tracker = 0
        for idx, byte in enumerate(tlvBytes):
            if idx < tracker:
                continue
            index = idx
            index += 1
            length = tlvBytes[index]
            index += 1
            tlvObject = [byte, length]
            tlvEnd = index + length
            value = tlvBytes[index:tlvEnd]
            for i in value:
                tlvObject.append(i)
            tlvList.append(tlvObject)
            tracker = tlvEnd
        return tlvList

    def cmdReadRecord2g(self, recNumber, mode, recSize, print2screen=False):
        header = copy.deepcopy(self.readRecord2g)
        header[2] = recNumber % 0x100
        header[3] = mode % 0x100
        header[4] = recSize % 0x100
        if not print2screen:
            response, sw1, sw2 = self.sendApdu(header, None)
        else:
            response, sw1, sw2 = self.sendApdu(header, None, print2screen=True)
        return response, sw1, sw2

    def cmdReadRecord3g(self, recNumber, mode, recSize, print2screen=False):
        header = copy.deepcopy(self.readRecord3g)
        header[2] = recNumber % 0x100
        header[3] = mode % 0x100
        header[4] = recSize % 0x100
        if not print2screen:
            response, sw1, sw2 = self.sendApdu(header, None)
        else:
            response, sw1, sw2 = self.sendApdu(header, None, print2screen=True)
        return response, sw1, sw2

    def cmdReadBinary2g(self, offset, length, print2screen=False):
        header = copy.deepcopy(self.readBinary2g)
        # make sure offset is not longer than 64K-1
        header[2] = ((int(offset) % 0x10000) >> 8)
        header[3] = (int(offset) % 0x10000) & 0x00FF
        # make sure length is not longer than 255
        header[4] = int(length) % 0x100
        if not print2screen:
            response, sw1, sw2 = self.sendApdu(header, None)
        else:
            response, sw1, sw2 = self.sendApdu(header, None, print2screen=True)
        return response, sw1, sw2

    def cmdReadBinary3g(self, offset, length, print2screen=False):
        header = copy.deepcopy(self.readBinary3g)
        header[2] = ((int(offset) % 0x10000) >> 8)
        header[3] = (int(offset) % 0x10000) & 0x00FF
        header[4] = int(length) % 0x100
        if not print2screen:
            response, sw1, sw2 = self.sendApdu(header, None)
        else:
            response, sw1, sw2 = self.sendApdu(header, None, print2screen=True)
        return response, sw1, sw2

    def booleanStrToInt(self, booleanStr):
        if str(booleanStr) == 'true':
            return 1
        else:
            return 0

    def parseConfigXml(self):
        config_file = 'config.xml'
        try:
            DOMTree = parse(config_file)
        except IOError, e:
            return False, 'Error parsing config.xml: ' + str(e.strerror)
        
        verifConfig = DOMTree.documentElement

        self.readerNumber = int(verifConfig.getElementsByTagName('readerNumber')[0].childNodes[0].data)
        if self.readerNumber == -1:
            return False, 'no terminal/reader detected'
        else:
            self.opt_chv1_disabled = self.booleanStrToInt(verifConfig.getAttribute('chv1Disabled'))
            self.opt_use_adm2 = self.booleanStrToInt(verifConfig.getAttribute('useAdm2'))
            self.opt_use_adm3 = self.booleanStrToInt(verifConfig.getAttribute('useAdm3'))
            self.opt_use_adm4 = self.booleanStrToInt(verifConfig.getAttribute('useAdm4'))
            self.opt_read_content_3g = self.booleanStrToInt(verifConfig.getAttribute('usimIn3GMode'))

        self.adm1 = str(verifConfig.getElementsByTagName('codeAdm1')[0].childNodes[0].data)
        if self.opt_use_adm2:
            self.adm2 = str(verifConfig.getElementsByTagName('codeAdm2')[0].childNodes[0].data)
        if self.opt_use_adm3:
            self.adm3 = str(verifConfig.getElementsByTagName('codeAdm3')[0].childNodes[0].data)
        if self.opt_use_adm4:
            self.adm4 = str(verifConfig.getElementsByTagName('codeAdm4')[0].childNodes[0].data)
        self.chv1 = str(verifConfig.getElementsByTagName('codeChv1')[0].childNodes[0].data)
        self.chv2 = str(verifConfig.getElementsByTagName('codeChv2')[0].childNodes[0].data)

        customApdu = verifConfig.getElementsByTagName('customApdu')[0]
        customVerify2g = customApdu.getElementsByTagName('verify2g')[0]
        customVerify3g = customApdu.getElementsByTagName('verify3g')[0]

        customVerify2gAdm1 = customVerify2g.getElementsByTagName('verify2gAdm1')[0]
        customVerify2gAdm2 = customVerify2g.getElementsByTagName('verify2gAdm2')[0]
        customVerify2gAdm3 = customVerify2g.getElementsByTagName('verify2gAdm3')[0]
        customVerify2gAdm4 = customVerify2g.getElementsByTagName('verify2gAdm4')[0]
        customVerify2gChv1 = customVerify2g.getElementsByTagName('verify2gChv1')[0]
        customVerify2gChv2 = customVerify2g.getElementsByTagName('verify2gChv2')[0]

        customVerify3gAdm1 = customVerify3g.getElementsByTagName('verify3gAdm1')[0]
        customVerify3gAdm2 = customVerify3g.getElementsByTagName('verify3gAdm2')[0]
        customVerify3gAdm3 = customVerify3g.getElementsByTagName('verify3gAdm3')[0]
        customVerify3gAdm4 = customVerify3g.getElementsByTagName('verify3gAdm4')[0]
        customVerify3gGlobalPin1 = customVerify3g.getElementsByTagName('verify3gGlobalPin1')[0]
        customVerify3gLocalPin1 = customVerify3g.getElementsByTagName('verify3gLocalPin1')[0]

        self.verify2gAdm1p1 = int(customVerify2gAdm1.getAttribute('p1'), 16)
        self.verify2gAdm1p2 = int(customVerify2gAdm1.getAttribute('p2'), 16)
        self.verify2gAdm1p3 = int(customVerify2gAdm1.getAttribute('p3'), 16)

        self.verify2gAdm2p1 = int(customVerify2gAdm2.getAttribute('p1'), 16)
        self.verify2gAdm2p2 = int(customVerify2gAdm2.getAttribute('p2'), 16)
        self.verify2gAdm2p3 = int(customVerify2gAdm2.getAttribute('p3'), 16)

        self.verify2gAdm3p1 = int(customVerify2gAdm3.getAttribute('p1'), 16)
        self.verify2gAdm3p2 = int(customVerify2gAdm3.getAttribute('p2'), 16)
        self.verify2gAdm3p3 = int(customVerify2gAdm3.getAttribute('p3'), 16)

        self.verify2gAdm4p1 = int(customVerify2gAdm4.getAttribute('p1'), 16)
        self.verify2gAdm4p2 = int(customVerify2gAdm4.getAttribute('p2'), 16)
        self.verify2gAdm4p3 = int(customVerify2gAdm4.getAttribute('p3'), 16)

        self.verify2gChv1p1 = int(customVerify2gChv1.getAttribute('p1'), 16)
        self.verify2gChv1p2 = int(customVerify2gChv1.getAttribute('p2'), 16)
        self.verify2gChv1p3 = int(customVerify2gChv1.getAttribute('p3'), 16)

        self.verify2gChv2p1 = int(customVerify2gChv2.getAttribute('p1'), 16)
        self.verify2gChv2p2 = int(customVerify2gChv2.getAttribute('p2'), 16)
        self.verify2gChv2p3 = int(customVerify2gChv2.getAttribute('p3'), 16)

        self.verify3gAdm1p1 = int(customVerify3gAdm1.getAttribute('p1'), 16)
        self.verify3gAdm1p2 = int(customVerify3gAdm1.getAttribute('p2'), 16)
        self.verify3gAdm1p3 = int(customVerify3gAdm1.getAttribute('p3'), 16)

        self.verify3gAdm2p1 = int(customVerify3gAdm2.getAttribute('p1'), 16)
        self.verify3gAdm2p2 = int(customVerify3gAdm2.getAttribute('p2'), 16)
        self.verify3gAdm2p3 = int(customVerify3gAdm2.getAttribute('p3'), 16)

        self.verify3gAdm3p1 = int(customVerify3gAdm3.getAttribute('p1'), 16)
        self.verify3gAdm3p2 = int(customVerify3gAdm3.getAttribute('p2'), 16)
        self.verify3gAdm3p3 = int(customVerify3gAdm3.getAttribute('p3'), 16)

        self.verify3gAdm4p1 = int(customVerify3gAdm4.getAttribute('p1'), 16)
        self.verify3gAdm4p2 = int(customVerify3gAdm4.getAttribute('p2'), 16)
        self.verify3gAdm4p3 = int(customVerify3gAdm4.getAttribute('p3'), 16)

        self.verify3gGlobalPin1p1 = int(customVerify3gGlobalPin1.getAttribute('p1'), 16)
        self.verify3gGlobalPin1p2 = int(customVerify3gGlobalPin1.getAttribute('p2'), 16)
        self.verify3gGlobalPin1p3 = int(customVerify3gGlobalPin1.getAttribute('p3'), 16)

        self.verify3gLocalPin1p1 = int(customVerify3gLocalPin1.getAttribute('p1'), 16)
        self.verify3gLocalPin1p2 = int(customVerify3gLocalPin1.getAttribute('p2'), 16)
        self.verify3gLocalPin1p3 = int(customVerify3gLocalPin1.getAttribute('p3'), 16)

        return True, 'Parsing config.xml complete'

    def parseScriptSettings(self):
        settingsFile = 'script-settings.json'
        with open(settingsFile, "r") as json_file:
            settingsData = json.load(json_file)
        if settingsData['useSaveFS']:
            self.fileSystemXml = settingsData['fileSystemXml']
            saveFsLength = len(ntpath.basename(self.fileSystemXml))
            self.profileBaseName = ntpath.basename(self.fileSystemXml)[:saveFsLength-4]
        else:
            self.fileSystemXml = ''
        self.destinationFolder = settingsData['destinationFolder']

    def initializeVerifcodeLogBuffer(self, verifcodeMsg):
        self.verifcodeLogBuffer = { \
            'verifcode_msg': verifcodeMsg, \
            'apdu_string': '', \
            'verifcode_success': True, \
            'status_word': '' \
        }

    def printVerifCodeLog(self):
        if self.verifcodeLogBuffer['verifcode_success']:
            logger.info('%s %s <- %s' % ( \
                self.verifcodeLogBuffer['verifcode_msg'], \
                self.verifcodeLogBuffer['apdu_string'], \
                self.verifcodeLogBuffer['status_word'] \
            ))
        else:
            logger.error('%s %s <- %s' % ( \
                self.verifcodeLogBuffer['verifcode_msg'], \
                self.verifcodeLogBuffer['apdu_string'], \
                self.verifcodeLogBuffer['status_word'] \
            ))

    def pinVerification2g(self):
        self.initializeVerifcodeLogBuffer('Verify ADM1..')
        header = copy.deepcopy(self.verifyPIN2g)
        header[2] = self.verify2gAdm1p1
        header[3] = self.verify2gAdm1p2
        header[4] = self.verify2gAdm1p3
        self.sendApdu(header, self.adm1)
        self.printVerifCodeLog()

        if self.opt_use_adm2:
            self.initializeVerifcodeLogBuffer('Verify ADM2..')
            header = copy.deepcopy(self.verifyPIN2g)
            header[2] = self.verify2gAdm2p1
            header[3] = self.verify2gAdm2p2
            header[4] = self.verify2gAdm2p3
            self.sendApdu(header, self.adm2)
            self.printVerifCodeLog()
        
        if self.opt_use_adm3:
            self.initializeVerifcodeLogBuffer('Verify ADM3..')
            header = copy.deepcopy(self.verifyPIN2g)
            header[2] = self.verify2gAdm3p1
            header[3] = self.verify2gAdm3p2
            header[4] = self.verify2gAdm3p3
            self.sendApdu(header, self.adm3)
            self.printVerifCodeLog()
        
        if self.opt_use_adm4:
            self.initializeVerifcodeLogBuffer('Verify ADM4..')
            header = copy.deepcopy(self.verifyPIN2g)
            header[2] = self.verify2gAdm4p1
            header[3] = self.verify2gAdm4p2
            header[4] = self.verify2gAdm4p3
            self.sendApdu(header, self.adm4)
            self.printVerifCodeLog()
        
        if not self.opt_chv1_disabled:
            self.initializeVerifcodeLogBuffer('Verify CHV1..')
            header = copy.deepcopy(self.verifyPIN2g)
            header[2] = self.verify2gChv1p1
            header[3] = self.verify2gChv1p2
            header[4] = self.verify2gChv1p3
            self.sendApdu(header, self.chv1)
            self.printVerifCodeLog()
        else:
            logger.info('CHV1 is disabled; verification not required.')
            self.pcomOutFile.writelines('; CHV1 is disabled. No CHV1 verification required.\n')
        
        self.initializeVerifcodeLogBuffer('Verify CHV2..')
        header = copy.deepcopy(self.verifyPIN2g)
        header[2] = self.verify2gChv2p1
        header[3] = self.verify2gChv2p2
        header[4] = self.verify2gChv2p3
        self.sendApdu(header, self.chv2)
        self.printVerifCodeLog()

    def pinVerification3g(self):
        self.initializeVerifcodeLogBuffer('Verify ADM1..')
        header = copy.deepcopy(self.verifyPIN3g)
        header[2] = self.verify3gAdm1p1
        header[3] = self.verify3gAdm1p2
        header[4] = self.verify3gAdm1p3
        self.sendApdu(header, self.adm1)
        self.printVerifCodeLog()

        if self.opt_use_adm2:
            self.initializeVerifcodeLogBuffer('Verify ADM2..')
            header = copy.deepcopy(self.verifyPIN3g)
            header[2] = self.verify3gAdm2p1
            header[3] = self.verify3gAdm2p2
            header[4] = self.verify3gAdm2p3
            self.sendApdu(header, self.adm2)
            self.printVerifCodeLog()
        
        if self.opt_use_adm3:
            self.initializeVerifcodeLogBuffer('Verify ADM3..')
            header = copy.deepcopy(self.verifyPIN3g)
            header[2] = self.verify3gAdm3p1
            header[3] = self.verify3gAdm3p2
            header[4] = self.verify3gAdm3p3
            self.sendApdu(header, self.adm3)
            self.printVerifCodeLog()

        if self.opt_use_adm4:
            self.initializeVerifcodeLogBuffer('Verify ADM4..')
            header = copy.deepcopy(self.verifyPIN3g)
            header[2] = self.verify3gAdm4p1
            header[3] = self.verify3gAdm4p2
            header[4] = self.verify3gAdm4p3
            self.sendApdu(header, self.adm4)
            self.printVerifCodeLog()

        if not self.opt_chv1_disabled:
            self.initializeVerifcodeLogBuffer('Verify Global PIN..')
            header = copy.deepcopy(self.verifyPIN3g)
            header[2] = self.verify3gGlobalPin1p1
            header[3] = self.verify3gGlobalPin1p2
            header[4] = self.verify3gGlobalPin1p3
            self.sendApdu(header, self.chv1)
            self.printVerifCodeLog()
        else:
            logger.info('GPIN is disabled. No GPIN verification required.')
            self.pcomOutFile.writelines('; GPIN is disabled. No GPIN verification required.\n')

        self.initializeVerifcodeLogBuffer('Verify Local PIN..')
        header = copy.deepcopy(self.verifyPIN3g)
        header[2] = self.verify3gLocalPin1p1
        header[3] = self.verify3gLocalPin1p2
        header[4] = self.verify3gLocalPin1p3
        self.sendApdu(header, self.chv2)
        self.printVerifCodeLog()

    def parseFileSystemXml(self, fileSystemXml):
        try:
            DOMTree = parse(fileSystemXml)
        except IOError, e:
            return False, 'Error parsing file system xml: ' + str(e.strerror), None
        
        logger.info('Parsing input xml')

        arrayOfDBFile = DOMTree.documentElement
        dbFiles = arrayOfDBFile.getElementsByTagName('DBFile')

        fileSystemList = []

        for dbFile in dbFiles:
            name = dbFile.getElementsByTagName('NAME')[0].childNodes[0].data
            fileId = dbFile.getElementsByTagName('FILEID')[0].childNodes[0].data
            try:
                path = dbFile.getElementsByTagName('PATH')[0].childNodes[0].data
            except IndexError:
                path = ''

            dbFileDict = {'name': name.encode('ascii', 'ignore'), 'absolutePath': (path.replace('|', '') + fileId).encode('ascii', 'ignore')}
            fileSystemList.append(dbFileDict)

        return True, 'success populating file system', fileSystemList

    def getNameByPath(self, fileSystemList, path):
        efName = ''
        for fsDict in fileSystemList:
            if fsDict['absolutePath'] == path:
                efName = fsDict['name']
                break
        return efName

    def swapIccid(self, iccid):
        charList = iccid.split()
        swappedIccid = ''
        for byteChar in charList:
            byteChar = list(byteChar)
            byteChar[0], byteChar[1] = byteChar[1], byteChar[0]
            swappedIccid += ''.join(byteChar)
        
        return swappedIccid

    def createDocumentHeader(self):
        self.htmlFile.writelines("""<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
            <html>
            <head>
            <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
            <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1" />
            <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
            <title>Card Report</title>
            <style type="text/css">
            html,
            body {
                height: 100%;
            }
            html {
                font-size: 16px;
            }
            body {
                margin: 0px;
                padding: 0px;
                overflow-x: hidden;
                min-width: 320px;
                background: #F9F9F9;
                font-family: Arial, Helvetica, sans-serif;
                font-size: 13px;
                line-height: 1.33;
                color: #212121;
                font-smoothing: antialiased;
            }
            div {
                margin-top: 10px;
                margin-left: 40px;
                margin-right: 40px;
            }
            h1,
            h2,
            h3,
            h4,
            h5 {
                font-family: Arial, Helvetica, sans-serif;
                line-height: 1.33em;
                margin: calc(2rem -  0.165em ) 0em 1rem;
                font-weight: 400;
                padding: 0em;
            }
            table {
                border-collapse: collapse;
            }
            th,
            td {
                border: 2px solid black;
                padding: 4px;
            }
            th.error {
                background-color: firebrick;
                color: #F9F9F9;
            }
            th.warning {
                background-color: darkorange;
                color: #F9F9F9;
            }
            td.error {
                background-color: #FDEDEC;
                color: #17202A;
            }
            td.warning {
                background-color: #FEF9E7;
                color: #17202A;
            }
            td.data {
                font-family: consolas, Monaco, monospace;
                font-size: 13px;
            }
            ul {
                margin: 0px;
                padding: 15px;
            }
            </style>
            </head>
            <body>""")

    def createDocumentFooter(self):
        self.htmlFile.writelines('\n</body></html>')

    def createTableHeader(self):
        self.htmlFile.writelines('\n<div><table><tbody>')

    def createTableFooter(self):
        self.htmlFile.writelines('\n</tbody></table></div>')

    def proceed(self):
        # when using VerifClient, go with user configuration
        if self.runAsModule:
            self.parseConfigXml()
            self.parseScriptSettings()
            if self.fullScript:
                self.pcomOutFileName = self.profileBaseName + '__full.pcom'
            else:
                self.pcomOutFileName = self.profileBaseName + '__light.pcom'
        
        self.pcomOutFile = open(self.destinationFolder + '\\' + self.pcomOutFileName, 'w')
        
        # power on
        if not self.initSCard() == 0:
            if self.runAsModule:
                return False, 'Error initializing card'
            sys.exit(-1)

        dateTimeNow = datetime.now()
        generation_date = dateTimeNow.strftime("%Y-%m-%d %H:%M")
        self.pcomOutFile.writelines('; Generated with CardScanner on ' + generation_date + '\n')

        # verify security codes (2G) for 'full' script
        if self.fullScript:
            self.pinVerification2g()

        # execute ex-OT read header proprietary command
        supportReadHeader = True
        cardFileList = ['3F00'] # initiate file list with MF
        curCardFilePath = ''
        curCardFileType = ''
        curCardDF = '3F00'
        curCardFileID = ''
        curCardIndex = 0
        prevCardIndex = 0
        prevCardMFIndex = 0
        readIndex = 1
        while readIndex < 256:
            rdHdrResp, rdHdrSW1, rdHdrSW2 = self.cmdReadHeader(readIndex, 0x04)
            if rdHdrSW1 == 0x90 and rdHdrSW2 == 0x00:
                curCardFileID = toHexString(rdHdrResp[0:2])
                curCardFileID = curCardFileID.replace(" ", "")
                curCardFilePath = curCardDF + curCardFileID
                cardFileList.append(curCardFilePath)
                sel2gResp, sel2gSW1, sel2gSW2 = self.cmdSelect2g(curCardFilePath, out2Pcom=False)
                curCardFileType = sel2gResp[6]
                if curCardFileType == 0x04:
                    self.cmdSelect2g(curCardDF, out2Pcom=False)
                else:
                    if curCardDF == '3F00':
                        curCardDF = curCardDF + curCardFileID
                        prevCardMFIndex = curCardIndex
                        readIndex = 0
                    else:
                        curCardDF = curCardDF + curCardFileID
                        prevCardIndex = curCardIndex
                        readIndex = 0
            else:
                if (rdHdrSW1 == 0x94 and rdHdrSW2 == 0x02) or (rdHdrSW1 == 0x6A and rdHdrSW2 == 0x83):
                    # select parents, no need to check result
                    path = self.filterHex(curCardDF)
                    i = 0
                    while i < (len(path) - 4):
                        self.sendApdu(self.select2g, path[i:i + 4], out2Pcom=False)
                        i += 4
                        curCardDF = path[0:i]
                        if curCardDF == '3F00':
                            readIndex = prevCardMFIndex + 1
                        else:
                            readIndex = prevCardIndex + 1
                else:
                    # read header is not supported by the card
                    supportReadHeader = False
                    logger.error('Error reading header at ' + curCardFilePath) # indicate where it fails reading header and exit
                    break
            curCardIndex = readIndex
            readIndex += 1
        
        fileSystemXmlAvailable = False
        if self.fileSystemXml != '':
            fileSystemXmlAvailable = True
            parseFileSystemOk, parseFileSystemMsg, fileSystemList = self.parseFileSystemXml(self.fileSystemXml)
            if not parseFileSystemOk:
                logger.error(parseFileSystemMsg)
                if self.runAsModule:
                    return False, parseFileSystemMsg
                sys.exit(-1) # or return with message
        if not supportReadHeader:
            # populate cardFileList from input xml for USIM 1.x or SIMBIOS cards
            cardFileList = [] # reset list
            logger.info('Populating file system from input xml')
            if fileSystemXmlAvailable:
                for ef in fileSystemList:
                    cardFileList.append(ef['absolutePath'])

        if len(cardFileList) == 0:
            logger.error('Please provide correct file system xml')
            if self.runAsModule:
                return False, 'Please provide correct file system xml'
            sys.exit(-1) # or return with message

        # initialize list that contains all files in card and their parameters
        fileDetails = []

        # scan card in 2G mode
        logger.info('Scanning in 2G mode')
        for ef in cardFileList:
            # create dictionary of file properties; this is done only once
            fileProperties = {'filePath': ef}
            if fileSystemXmlAvailable:
                # look-up dictionary for file names
                fileProperties['fileName'] = self.getNameByPath(fileSystemList, ef)
            else:
                fileProperties['fileName'] = ''

            if self.formatFileId(ef):
                self.pcomOutFile.writelines('\n; ' + self.formatFileId(ef) + ': ' + fileProperties['fileName'] + '\n')
            else:
                logger.error('TypeError: probably found AID instead of DF (or path is too long)')
                if self.runAsModule:
                    return False, 'TypeError: probably found AID instead of DF (or path is too long)'
                sys.exit(-1) # or return with message
            sel2gResp, sel2gSW1, sel2gSW2 = self.cmdSelect2g(ef)
            
            # application DFs (USIM, ISIM, etc.) may fail to be selected for SIMBIOS in 2G mode;
            # in that case EF properties will be retrieved in 3G mode
            if sel2gSW1 == 0x90 and sel2gSW2 == 0x00:
                # 2G get response (only for debugging)
                # fileProperties['2gGetResponse'] = toHexString(sel2gResp)

                # type of file
                if sel2gResp[6] == 0x01:
                    fileTypeStr = 'MF'
                if sel2gResp[6] == 0x02:
                    fileTypeStr = 'DF'
                if sel2gResp[6] == 0x04:
                    fileTypeStr = 'EF'
                fileProperties['fileType'] = fileTypeStr
                
                if fileProperties['fileType'] == 'EF':
                    # structure of file
                    if sel2gResp[13] == 0x00:
                        fileStructureStr = 'transparent'
                    if sel2gResp[13] == 0x01:
                        fileStructureStr = 'linear fixed'
                    if sel2gResp[13] == 0x03:
                        fileStructureStr = 'cyclic'
                    fileProperties['fileStructure'] = fileStructureStr

                    # file size
                    fileProperties['fileSize'] = int("%0.2X" % sel2gResp[2] + "%0.2X" % sel2gResp[3], 16)

                    # record size
                    if fileProperties['fileStructure'] == 'linear fixed' or fileProperties['fileStructure'] == 'cyclic':
                        fileProperties['fileRecordSize'] = sel2gResp[14]
                        # number of record
                        fileProperties['numberOfRecord'] = fileProperties['fileSize'] / fileProperties['fileRecordSize']
                    
                    # file status
                    invalidated = False
                    fileStatusStr = ''
                    if (sel2gResp[11] & 0x01) == 0x00:
                        fileStatusStr += 'invalidated'
                        invalidated = True
                    if invalidated:
                        if (sel2gResp[11] & 0x04) == 0x00:
                            fileStatusStr += '; not readable or updatable when invalidated'
                        if (sel2gResp[11] & 0x04) == 0x04:
                            fileStatusStr += '; readable or updatable when invalidated'
                        fileProperties['fileStatus'] = fileStatusStr

                    # 2G access conditions
                    fileProperties['2gAcc'] = '%0.2X %0.2X %0.2X' % (sel2gResp[8], sel2gResp[9], sel2gResp[10])

                    # file contents
                    if not self.opt_read_content_3g:
                        if fileProperties['fileStructure'] == 'linear fixed' or fileProperties['fileStructure'] == 'cyclic':
                            recordList = []
                            readableContent = True
                            for i in range(fileProperties['numberOfRecord']):
                                rdRec2gResp, rdRec2gSW1, rdRec2gSW2 = self.cmdReadRecord2g(i+1, self.READ_RECORD_ABSOLUTE, fileProperties['fileRecordSize'])
                                if rdRec2gResp == -1: # possible due to reader communication error
                                    logger.error(rdRec2gSW1) # rdRec2gSW1 contains the error
                                    if self.runAsModule:
                                        return False, rdRec2gSW1
                                    sys.exit(-1) # or return with message
                                else:
                                    if rdRec2gSW1 != 0x90 and rdRec2gSW2 != 00:
                                        # stop reading record, as EF may be invalidated and not readable
                                        readableContent = False
                                        # break
                                    recordList.append(toHexString(rdRec2gResp))
                            if readableContent:
                                fileProperties['fileContent'] = recordList
                        
                        if fileProperties['fileStructure'] == 'transparent':
                            transparentContentBuffer = ''
                            readableContent = True
                            # handle length more than one APDU
                            index = 0
                            while index < fileProperties['fileSize']:
                                if (index + self.MAX_RESPONSE_LEN) > fileProperties['fileSize']:
                                    tmpLen = fileProperties['fileSize'] - index
                                else:
                                    tmpLen = self.MAX_RESPONSE_LEN
                                rdBin2gResp, rdBin2gSW1, rdBin2gSW2 = self.cmdReadBinary2g(index, tmpLen)
                                if rdBin2gResp == -1: # possible due to reader communication error
                                    logger.error(rdBin2gSW1) # rdBin2gSW1 contains the error
                                    if self.runAsModule:
                                        return False, rdBin2gSW1
                                    sys.exit(-1) # or return with message
                                else:
                                    if rdBin2gSW1 != 0x90 and rdBin2gSW2 != 00:
                                        # stop reading binary content, as EF may be invalidated and not readable
                                        readableContent = False
                                if transparentContentBuffer == '':
                                    transparentContentBuffer = toHexString(rdBin2gResp)
                                else:
                                    transparentContentBuffer = transparentContentBuffer + ' ' + toHexString(rdBin2gResp)
                                index += tmpLen
                            if readableContent:
                                fileProperties['fileContent'] = transparentContentBuffer

            fileDetails.append(fileProperties)

        # cycle card
        self.initSCard()

        # verify security codes (3G) for 'full' script
        if self.fullScript:
            self.pinVerification3g()

        # scan card in 3G mode
        logger.info('Scanning in 3G mode')
        efIndex = 0
        for ef in cardFileList:
            self.pcomOutFile.writelines('\n; ' + self.formatFileId(ef) + ': ' + fileDetails[efIndex]['fileName'] + '\n')
            sel3gResp, sel3gSW1, sel3gSW2 = self.cmdSelect3g(ef)

            if sel3gSW1 == 0x62 and sel3gSW2 == 0x83:
                if not 'fileStatus' in fileDetails[efIndex]:
                    fileDetails[efIndex]['fileStatus'] = 'invalidated'

            if sel3gSW1 == 0x90 and sel3gSW2 == 0x00:
                # 3G get response (only for debugging)
                fileDetails[efIndex]['3gGetResponse'] = toHexString(sel3gResp)

                # File Control Parameters as per TS 102 221
                fcp = self.getValueByTag(0x62, sel3gResp)
                fcpObjects = self.getTlvObjects(fcp)

                # type of file
                # FCP tag '82' (File Descriptor)
                propInfo = []
                pinStatusTemplateDO = []
                for i in fcpObjects:
                    if i[0] == 0xA5:
                        propInfo = i
                        break
                for i in fcpObjects:
                    if i[0] == 0xC6:
                        pinStatusTemplateDO = i # mandatory for MF/DF
                        break
                if pinStatusTemplateDO:
                    if propInfo:
                        typeIsMf = False
                        propInfoValue = self.getValueByTag(0xA5, propInfo)
                        propInfoObjects = self.getTlvObjects(propInfoValue)
                        for i in propInfoObjects:
                            if i[0] == 0x80:
                                # tag '80' (UICC characteristics) is mandatory for MF
                                typeIsMf = True
                                break
                        if typeIsMf:
                            fileTypeStr = 'MF'
                        else:
                            fileTypeStr = 'DF'
                else:
                    fileTypeStr = 'EF'
                
                if not 'fileType' in fileDetails[efIndex]:
                    fileDetails[efIndex]['fileType'] = fileTypeStr

                if fileDetails[efIndex]['fileType'] == 'EF':
                    # structure of file
                    fileDescriptor = []
                    for i in fcpObjects:
                        if i[0] == 0x82:
                            fileDescriptor = i
                            break
                    fileDescriptorValue = self.getValueByTag(0x82, fileDescriptor)
                    fileDescriptorByte = fileDescriptorValue[0]
                    if (fileDescriptorByte & 0x01) == 0x01:
                        fileStructureStr = 'transparent'
                    if (fileDescriptorByte & 0x02) == 0x02:
                        fileStructureStr = 'linear fixed'
                    if (fileDescriptorByte & 0x06) == 0x06:
                        fileStructureStr = 'cyclic'
                    if not 'fileStructure' in fileDetails[efIndex]:
                        fileDetails[efIndex]['fileStructure'] = fileStructureStr

                    # file size
                    fileSizeObj = []
                    for i in fcpObjects:
                        if i[0] == 0x80:
                            fileSizeObj = i
                            break

                    if fileSizeObj:
                        fileSizeValue = self.getValueByTag(0x80, fileSizeObj)
                        if len(fileSizeValue) == 2:
                            fileSize = int("%0.2X" % fileSizeValue[0] + "%0.2X" % fileSizeValue[1], 16)
                        if len(fileSizeValue) == 3:
                            fileSize = int("%0.2X" % fileSizeValue[0] + "%0.2X" % fileSizeValue[1] + "%0.2X" % fileSizeValue[2], 16)
                    else:
                        fileSize = 'UNDEFINED' # somehow unable to parse
                    
                    if not 'fileSize' in fileDetails[efIndex]:
                        fileDetails[efIndex]['fileSize'] = fileSize
                    
                    # record size & number of record
                    if fileDetails[efIndex]['fileStructure'] == 'linear fixed' or fileDetails[efIndex]['fileStructure'] == 'cyclic':
                        recordSize = int("%0.2X" % fileDescriptorValue[2] + "%0.2X" % fileDescriptorValue[3], 16)
                        numberOfRecord = fileDescriptorValue[4]
                        if not 'fileRecordSize' in fileDetails[efIndex]:
                            fileDetails[efIndex]['fileRecordSize'] = recordSize
                        if not 'numberOfRecord' in fileDetails[efIndex]:
                            fileDetails[efIndex]['numberOfRecord'] = numberOfRecord
                        
                    # SFI
                    sfiObj = []
                    for i in fcpObjects:
                        if i[0] == 0x88:
                            sfiObj = i
                            break
                    if sfiObj:
                        sfiValue = self.getValueByTag(0x88, sfiObj)
                        if sfiValue:
                            sfiValueShifted = sfiValue[0] >> 3
                            fileDetails[efIndex]['sfi'] = '%0.2X' % (sfiValueShifted)

                    # access condition

                    # file contents
                    if self.opt_read_content_3g:
                        if fileDetails[efIndex]['fileStructure'] == 'linear fixed' or fileDetails[efIndex]['fileStructure'] == 'cyclic':
                            recordList = []
                            readableContent = True
                            for i in range(fileDetails[efIndex]['numberOfRecord']):
                                rdRec3gResp, rdRec3gSW1, rdRec3gSW2 = self.cmdReadRecord3g(i+1, self.READ_RECORD_ABSOLUTE, fileDetails[efIndex]['fileRecordSize'])
                                if rdRec3gSW1 != 0x90 and rdRec3gSW2 != 00:
                                    # stop reading record, as EF may be invalidated and not readable
                                    readableContent = False
                                    # break
                                recordList.append(toHexString(rdRec3gResp))
                            if readableContent:
                                if not 'fileContent' in fileDetails[efIndex]:
                                    fileDetails[efIndex]['fileContent'] = recordList

                        if fileDetails[efIndex]['fileStructure'] == 'transparent':
                            transparentContentBuffer = ''
                            readableContent = True
                            # handle length more than one APDU
                            index = 0
                            while index < fileDetails[efIndex]['fileSize']:
                                if (index + self.MAX_RESPONSE_LEN) > fileDetails[efIndex]['fileSize']:
                                    tmpLen = fileDetails[efIndex]['fileSize'] - index
                                else:
                                    tmpLen = self.MAX_RESPONSE_LEN
                                rdBin3gResp, rdBin3gSW1, rdBin3gSW2 = self.cmdReadBinary3g(index, tmpLen)
                                if rdBin3gSW1 != 0x90 and rdBin3gSW2 != 00:
                                    # stop reading binary content, as EF may be invalidated and not readable
                                    readableContent = False
                                if transparentContentBuffer == '':
                                    transparentContentBuffer = toHexString(rdBin3gResp)
                                else:
                                    transparentContentBuffer = transparentContentBuffer + ' ' + toHexString(rdBin3gResp)
                                index += tmpLen
                            if readableContent:
                                if not 'fileContent' in fileDetails[efIndex]:
                                    fileDetails[efIndex]['fileContent'] = transparentContentBuffer

            efIndex += 1

        # read OS locks
        # cycle card
        self.initSCard()
        logger.info('Reading OS locks')
        self.pcomOutFile.writelines('; OS locks\n')

        osLockBufferCount = self.countLockBuffer()
        lockOffset = 0
        while lockOffset < osLockBufferCount:
            self.cmdReadOsLock(lockOffset, True)
            lockOffset += 1
        
        # print('DEBUG -- fileDetails:')
        # print(fileDetails)
        
        # dump file system to json
        if self.fullScript:
            for ef in fileDetails:
                if ef['filePath'] == '3F002FE2':
                    iccid = ef['fileContent']
                    break
            outTimeStamp = dateTimeNow.strftime("%Y%m%d%H%M")
            self.fileSystemOutJson = self.destinationFolder + '\\' + self.swapIccid(iccid) + '__' + outTimeStamp + '.json'
            with open(self.fileSystemOutJson, 'w') as json_file:
                json.dump(fileDetails, json_file, indent=2)

            # dump file system to html
            self.fileSystemOutHtml = self.destinationFolder + '\\' + self.swapIccid(iccid) + '__' + outTimeStamp + '.html'
            with open(self.fileSystemOutHtml, 'w') as self.htmlFile:
                self.createDocumentHeader()
                self.htmlFile.writelines('\n<div><h1>Card Serial #: ' + self.swapIccid(iccid) + '</h1></div>')
                for ef in fileDetails:
                    self.htmlFile.writelines('\n<div><h2>' + self.formatFileId(ef['filePath']) + ': ' + ef['fileName'] + '</h2></div>')
                    self.createTableHeader()
                    if ef.has_key('fileType'):
                        self.htmlFile.writelines('\n<tr><td>File type</td>')
                        self.htmlFile.writelines('<td>' + ef['fileType'] + '</td></tr>')
                    if ef.has_key('sfi'):
                        self.htmlFile.writelines('\n<tr><td>SFI</td>')
                        self.htmlFile.writelines('<td>' + ef['sfi'] + '</td></tr>')
                    if ef.has_key('fileStructure'):
                        self.htmlFile.writelines('\n<tr><td>File structure</td>')
                        self.htmlFile.writelines('<td>' + ef['fileStructure'] + '</td></tr>')
                    if ef.has_key('2gAcc'):
                        self.htmlFile.writelines('\n<tr><td>2G access condition</td>')
                        self.htmlFile.writelines('<td>' + ef['2gAcc'] + '</td></tr>')
                    if ef.has_key('3gGetResponse'):
                        self.htmlFile.writelines('\n<tr><td>File control parameter</td>')
                        self.htmlFile.writelines('<td>' + ef['3gGetResponse'] + '</td></tr>')
                    if ef.has_key('fileSize'):
                        self.htmlFile.writelines('\n<tr><td>File size</td>')
                        self.htmlFile.writelines('<td>' + str(ef['fileSize']) + '</td></tr>')
                    if ef.has_key('fileRecordSize'):
                        self.htmlFile.writelines('\n<tr><td>Record size</td>')
                        self.htmlFile.writelines('<td>' + str(ef['fileRecordSize']) + '</td></tr>')
                    if ef.has_key('numberOfRecord'):
                        self.htmlFile.writelines('\n<tr><td>Number of record</td>')
                        self.htmlFile.writelines('<td>' + str(ef['numberOfRecord']) + '</td></tr>')
                    self.createTableFooter()
                    if ef.has_key('fileContent'):
                        self.htmlFile.writelines('\n<div>File content:</div>')
                        self.createTableHeader()
                        if ef['fileStructure'] == 'transparent':
                            self.htmlFile.writelines('\n<tr><td class="data">' + ef['fileContent'] + '</td></tr>')
                        if ef['fileStructure'] == 'linear fixed' or ef['fileStructure'] == 'cyclic':
                            recordNumber = 0
                            for record in ef['fileContent']:
                                recordNumber += 1
                                self.htmlFile.writelines('\n<tr><td class="data">' + str(recordNumber) + '</td>')
                                self.htmlFile.writelines('<td class="data">' + record + '</td></tr>')
                        self.createTableFooter()
                    
                self.htmlFile.writelines('\n<div><i>Generated with CardScanner on ' + generation_date + '</i></div>')
                self.createDocumentFooter()

        return True, "Scanning success"

# main program
if __name__ == '__main__':
    readerNumber = 0
    adm1 = ''
    adm2 = ''
    adm3 = ''
    adm4 = ''
    chv1 = ''
    chv2 = ''
    pcomOutFileName = ''

    import argparse
    parser = argparse.ArgumentParser('scanner')
    parser.add_argument("--readers", action="store_true", help="display list of available readers")
    parser.add_argument("--reader", type=int, default=0, help="reader number")
    parser.add_argument("--adm1", help="issuer security code 1 (initiate full script operation)")
    parser.add_argument("--adm2", help="issuer security code 2")
    parser.add_argument("--adm3", help="issuer security code 3")
    parser.add_argument("--adm4", help="issuer security code 4")
    parser.add_argument("--chv1", help="pin 1")
    parser.add_argument("--chv2", help="pin 2")
    parser.add_argument("--content3g", action="store_true", help="read content in 3G mode")
    parser.add_argument("-i", "--input", help="file system xml")
    parser.add_argument("-o", "--output", help="script output name")
    parser.add_argument("--adm1p2", help="custom P2 for ADM1 (2G mode)")
    parser.add_argument("--adm2p2", help="custom P2 for ADM2 (2G mode)")
    parser.add_argument("--adm3p2", help="custom P2 for ADM3 (2G mode)")
    parser.add_argument("--adm4p2", help="custom P2 for ADM4 (2G mode)")
    
    args = parser.parse_args()

    if args.readers:
        if not len(readers()) == 0:
            readerIndex = 0
            for reader in readers():
                print("%s: %s" % (readerIndex, reader))
                readerIndex += 1
        else:
            logger.error('No smartcard reader(s) detected.')
        sys.exit()
    
    readerNumber = args.reader
    adm1 = args.adm1
    adm2 = args.adm2
    adm3 = args.adm3
    adm4 = args.adm4
    chv1 = args.chv1
    chv2 = args.chv2
    pcomOutFileName = args.output
    fileSystemXml = args.input
    adm1p2 = args.adm1p2
    adm2p2 = args.adm2p2
    adm3p2 = args.adm3p2
    adm4p2 = args.adm4p2

    scanner = CardScanner(runAsModule=False, fullScript=False)

    scanner.readerNumber = readerNumber
    if adm1:
        scanner.fullScript = True
        scanner.adm1 = adm1
    if adm2:
        scanner.opt_use_adm2 = True
        scanner.adm2 = adm2
    if adm3:
        scanner.opt_use_adm3 = True
        scanner.adm3 = adm3
    if adm4:
        scanner.opt_use_adm4 = True
        scanner.adm4 = adm4
    if chv1:
        scanner.opt_chv1_disabled = False
        scanner.chv1 = chv1
    if chv2:
        scanner.chv2 = chv2
    if adm1p2:
        scanner.verify2gAdm1p2 = int(adm1p2, 16)
    if adm2p2:
        scanner.verify2gAdm2p2 = int(adm2p2, 16)
    if adm3p2:
        scanner.verify2gAdm3p2 = int(adm3p2, 16)
    if adm4p2:
        scanner.verify2gAdm4p2 = int(adm4p2, 16)
    
    if pcomOutFileName:
        scanner.pcomOutFileName = pcomOutFileName
    else:
        scanner.pcomOutFileName = 'script.pcom'

    if fileSystemXml:
        scanner.fileSystemXml = fileSystemXml

    if args.content3g:
        scanner.opt_read_content_3g = True

    scanner.proceed()

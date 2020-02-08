import sys
from smartcard.util import toHexString, toBytes

def getValueByTag(tag, tlvString):
    # print 'tag: ' + hex(tag)
    tlvBytes = toBytes(tlvString)
    for byte in tlvBytes:
        index = tlvBytes.index(byte)
        if byte == tag:
            index += 1
            length = tlvBytes[index]
            # print 'length: ' + str(length)
            index += 1
            value = tlvBytes[index:index+length]
            break
    return value

def getTlvObjects(tlvBytes):
    tlvList = []
    tracker = 0
    for byte in tlvBytes:
        if tlvBytes.index(byte) < tracker:
            continue
        index = tlvBytes.index(byte)
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

fcp = getValueByTag(0x62, '62 21 82 02 78 21 83 02 7F 4F A5 04 83 02 E2 AC 8A 01 05 8B 03 2F 06 02 C6 09 90 01 40 83 01 01 83 01 81')
# print 'value: ' +  toHexString(fileTypeTlv)

tlvObjects = getTlvObjects(fcp)
for i in tlvObjects:
    for j in i:
        print hex(j)[2:].zfill(2).upper(),
    print
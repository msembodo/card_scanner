def getTlvObjects(tlvBytes):
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

# fcp = [0x82,0x05,0x46,0x21,0x00,0x2B,0x64,0x83,0x02,0x6F,0x81,0x8A,0x01,0x05,0x8B,0x03,0x6F,0x06,0x0D,0x80,0x02,0x10,0xCC,0x88,0x01,0xA8]
# fcp = [0x82,0x05,0x46,0x21,0x00,0x2C,0x64,0x83,0x02,0x6F,0x80,0x8A,0x01,0x05,0x8B,0x03,0x6F,0x06,0x0D,0x80,0x02,0x11,0x30,0x88,0x01,0xA0]
fcp = [0x82,0x05,0x46,0x21,0x00,0x2C,0x64,0x83,0x02,0x6F,0x80,0x8A,0x01,0x05,0x8B,0x03,0x6F,0x06,0x0D,0x80,0x02,0x11,0x30,0x88,0x01,0xA0] # debug
fcpObjects = getTlvObjects(fcp)
for i in fcpObjects:
    print str(i)
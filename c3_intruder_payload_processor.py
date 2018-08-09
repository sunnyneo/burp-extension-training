# References
# https://github.com/PortSwigger/example-intruder-payloads/blob/master/python/IntruderPayloads.py
# https://github.com/PortSwigger/example-intruder-payloads
from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadProcessor
from burp import IIntruderPayloadGenerator
from exceptions_fix import FixBurpExceptions

# load file with payloads 
payloadFile = open('XSS-JHADDIX.txt', 'r')
PAYLOADS = payloadFile.readlines()
payloadFile.close()

class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory, IIntruderPayloadProcessor):

    #
    # implement IBurpExtender
    #
    def registerExtenderCallbacks(self, callbacks):
        
        self._extensionName = 'C3 Intruder Payload Processor'

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName(self._extensionName)

        # register ourselves as an Intruder payload generator
        callbacks.registerIntruderPayloadGeneratorFactory(self)

        # register ourselves as an Intruder payload processor
        callbacks.registerIntruderPayloadProcessor(self)

        # print out for extension loaded
        print("C3 Intruder Payload Processor Loaded")

        return
    #
    # implement IIntruderPayloadGeneratorFactory
    #
    def getGeneratorName(self):
        return "C3 Intruder Payload Generator"

    def createNewInstance(self, attack):
        # return a new IIntruderPayloadGenerator to generate payloads for this attack
        return IntruderPayloadGenerator(self)

    #
    # implement IIntruderPayloadProcessor
    #
    def getProcessorName(self):
        return "C3 Encode Payload"

    def processPayload(self,currentPayload, originalPayload, baseValue):
        # work on transform current payload in the payload list
        print("Base Value: " + baseValue)
        payload = currentPayload
        
        encodedPayload = self._helpers.urlEncode(self._helpers.base64Encode(self._helpers.bytesToString(payload)));

        return encodedPayload

#
# class to generate payloads from a simple list
#

class IntruderPayloadGenerator(IIntruderPayloadGenerator):
    def __init__(self, extender):
        self._extender = extender
        self._helpers = extender._helpers
        self._payloadIndex = 0
        self._baseList = ["userid=1", "location=http://127.0.0.1:5000/3/","browser=Gecko"]
        self._baseIndex = 0

    def hasMorePayloads(self):
        return self._payloadIndex < len(PAYLOADS)

    # make an index for the decoded internal parameters
    # manually rebuild the request with payload inserted 
    # only move payload index when all internal parameters have been subbed in before
    def getNextPayload(self, baseValue):
        
        payload = ""
        baseLength = len(self._baseList)
        for i in range(baseLength):
            if i == self._baseIndex:
                name = self._baseList[i].split('=')[0]
                payload += name + "=" + PAYLOADS[self._payloadIndex]

            else:
                payload += self._baseList[i]

            if i != (baseLength - 1):
                payload += "!!!"
        
        self._baseIndex += 1

        if self._baseIndex == 3 :
            self._payloadIndex = self._payloadIndex + 1
            self._baseIndex = 0            

        return payload

    def reset(self):
        self._payloadIndex = 0    

FixBurpExceptions()



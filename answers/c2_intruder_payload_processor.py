# References
# https://github.com/PortSwigger/example-intruder-payloads/blob/master/python/IntruderPayloads.py
# https://github.com/PortSwigger/example-intruder-payloads

from burp import IBurpExtender
from burp import IBurpExtenderCallbacks
from burp import IIntruderPayloadProcessor
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator
from exceptions_fix import FixBurpExceptions

# load file with payloads 
payloadFile = open('XSS-JHADDIX.txt', 'r')
PAYLOADS = payloadFile.readlines()
payloadFile.close()

class BurpExtender(IBurpExtender, IIntruderPayloadProcessor, IIntruderPayloadGeneratorFactory):
    
    #
    # implement IBurpExtender
    #
    def registerExtenderCallbacks(self, callbacks):
        
        self._extensionName = "C2 Intruder Payload Processor"
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        

        # register ourselves as an Intruder payload generator
        callbacks.registerIntruderPayloadGeneratorFactory(self)

        # register ourselves as an Intruder payload processor
        callbacks.registerIntruderPayloadProcessor(self)

        # print out for extension loaded
        print(self._extensionName + " Loaded")
        return

    #
    # implement IIntruderPayloadGeneratorFactory
    #
    def getGeneratorName(self):
        return "C2 Intruder Payload Generator"

    def createNewInstance(self, attack):
        # return a new IIntruderPayloadGenerator to generate payloads for this attack
        return IntruderPayloadGenerator(self)

    #
    # implement IIntruderPayloadProcessor
    #
    def getProcessorName(self):
        return self._extensionName

    def processPayload(self,currentPayload, originalPayload, baseValue):
        # baseValue is the original value in the request
        # process current payload in the payload list

        payload = currentPayload
        
        encodedPayload = self._helpers.urlEncode("11" +
            self._helpers.base64Encode(self._helpers.bytesToString(payload)));

        return encodedPayload

#
# class to generate payloads from a simple list
#
class IntruderPayloadGenerator(IIntruderPayloadGenerator):
    def __init__(self, extender):
        self._extender = extender
        self._helpers = extender._helpers
        self._payloadIndex = 0

    def hasMorePayloads(self):
        return self._payloadIndex < len(PAYLOADS)

    def getNextPayload(self, baseValue):
        payload = PAYLOADS[self._payloadIndex]
        self._payloadIndex = self._payloadIndex + 1

        return payload

    def reset(self):
        self._payloadIndex = 0    

FixBurpExceptions()



from burp import IBurpExtender
from burp import IBurpExtenderCallbacks
from burp import IIntruderPayloadProcessor
from exceptions_fix import FixBurpExceptions


class BurpExtender(IBurpExtender, IIntruderPayloadProcessor):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        

        # Register methods for error reporting
        callbacks.setExtensionName('C3 Intruder Payload Processor')
        callbacks.registerIntruderPayloadProcessor(self)

        # print out for extension loaded
        print("C3 Intruder Payload Processor Loaded")

        return

    def getProcessorName(self):
        return "Encode Payload"

    def processPayload(self,currentPayload, originalPayload, baseValue):
        # work on transform current payload in the payload list
        print("Base Value: " + baseValue)
        payload = currentPayload
        
        encodedPayload = self._helpers.urlEncode("11" +
            self._helpers.base64Encode(self._helpers.bytesToString(payload)));

        return encodedPayload

FixBurpExceptions()



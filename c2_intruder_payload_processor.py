from burp import IBurpExtender
from burp import IBurpExtenderCallbacks
from burp import IIntruderPayloadProcessor
from exceptions_fix import FixBurpExceptions


class BurpExtender(IBurpExtender, IIntruderPayloadProcessor):
    def registerExtenderCallbacks(self, callbacks):
        
        self._extensionName = "C2 Intruder Payload Processor"
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        

        # Register methods for error reporting
        callbacks.setExtensionName(self._extensionName)
        callbacks.registerIntruderPayloadProcessor(self)

        # print out for extension loaded
        print(self._extensionName + " Loaded")
        return

    def getProcessorName(self):
        return self._extensionName

    def processPayload(self,currentPayload, originalPayload, baseValue):
        # baseValue is the original value in the request
        # process current payload in the payload list

        payload = currentPayload
        
        encodedPayload = self._helpers.urlEncode("11" +
            self._helpers.base64Encode(self._helpers.bytesToString(payload)));

        return encodedPayload

FixBurpExceptions()



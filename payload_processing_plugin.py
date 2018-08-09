from burp import IBurpExtender
from burp import IBurpExtenderCallbacks
from burp import IIntruderPayloadProcessor
from exceptions_fix import FixBurpExceptions


class BurpExtender(IBurpExtender, IIntruderPayloadProcessor):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        

        # Register methods for error reporting
        callbacks.setExtensionName('Intruder Payload Processor')
        callbacks.registerIntruderPayloadProcessor(self)

        # print out for extension loaded
        print("Intruder Payload Processor Loaded")

        return

    def getProcessorName(self):
        return "Substitute Special Characters"

    def processPayload(self,currentPayload, originalPayload, baseValue):
        
        payload = currentPayload
        print(payload)

        return payload



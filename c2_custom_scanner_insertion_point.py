# References
# https://portswigger.net/blog/sample-burp-suite-extension-custom-scan-insertion-points
# https://github.com/PortSwigger/example-custom-scan-insertion-points/blob/master/python/CustomScanInsertionPoint.py
from burp import IBurpExtender
from burp import IScannerInsertionPointProvider
from burp import IScannerInsertionPoint
from burp import IParameter
from exceptions_fix import FixBurpExceptions


class BurpExtender(IBurpExtender, IScannerInsertionPointProvider):
    
    #
    # implement IBurpExtender
    #
    def	registerExtenderCallbacks(self, callbacks):
        
        self._extensionName = "C2 Custom Insertion Points"
        # todo: set the parameter that you are interested in
        # probably can build a UI to set some options/parameter names   
        self._parameterName  = "TODO"

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName(self._extensionName)
        
        # register ourselves as a scanner insertion point provider
        callbacks.registerScannerInsertionPointProvider(self)
        
        # print out for extension loaded
        print(self._extensionName + " Loaded")
        return
        
    # 
    # implement IScannerInsertionPointProvider
    #
    def getInsertionPoints(self, baseRequestResponse):
        
        # retrieve the data parameter and 
        # check whether request contains interesting parameter name
        # baseRequestResponse is the request that we are scanning 

        parameter = self._helpers.getRequestParameter(baseRequestResponse.getRequest(), self._parameterName)
        
        if (parameter is None):
            return None
        
        else:
            # if the parameter is present, add a single custom insertion point for it
            # print("Executing Insertion Point")
            # print("Parameter Name: " + parameter.getName())
            # print("Encoded Parameter Value: " + parameter.getValue())

            insertionPoints = []

            insertionPoints.append(InsertionPoint(self._helpers,
                                baseRequestResponse.getRequest(), 
                                parameter.getName(), 
                                parameter.getValue()))

            return insertionPoints
        
# 
# class implementing IScannerInsertionPoint
#
class InsertionPoint(IScannerInsertionPoint):

    def __init__(self, helpers, baseRequest, parameterName, parameterValue):
        self._helpers = helpers
        self._baseRequest = baseRequest
        self._parameterName = parameterName
        self._baseValue = parameterValue
        return

    def getInsertionPointName(self):
        return "Base64-wrapped input"

    def getBaseValue(self):
        return self._baseValue

    def buildRequest(self, payload):
        # build the raw data using the specified payload
        # print("---Build Request---")

        # todo: Dodgy encoding 11 + Base64- and URL-encode the data
        encodedPayload = TODO(payload)
        
        # todo: update the request with the new parameter value 
        # PARAM_BODY - Used to indicate a parameter within the message body.
        # PARAM_COOKIE - Used to indicate an HTTP cookie.
        # PARAM_JSON -  Used to indicate an item of data within a JSON structure.

        newRequest = self._helpers.updateParameter(self._baseRequest, 
            self._helpers.buildParameter(self._parameterName, encodedPayload, IParameter.PARAM_BODY))

        # print("New Request: " + newRequest)

        return newRequest

    def getPayloadOffsets(self, payload):
        # since the payload is being inserted into a serialized data structure, there aren't any offsets 
        # into the request where the payload literally appears
        return None

    def getInsertionPointType(self):
        return INS_EXTENSION_PROVIDED

FixBurpExceptions()

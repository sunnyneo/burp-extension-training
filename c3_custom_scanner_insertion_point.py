# References
# https://github.com/PortSwigger/example-custom-scan-insertion-points/
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
    def registerExtenderCallbacks(self, callbacks):
        
        self._extensionName = "C3 Custom Insertion Points"

        # todo: set the parameter that you are interested in
        # probably can build a UI to set some options/parameter names   
        self._keyParameter  = "TODO"

        # todo: set delimiter between parameter and value "=" or what
        self._delimiter = "TODO"

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
        
        # retrieve the parameter
        parameter = self._helpers.getRequestParameter(baseRequestResponse.getRequest(), self._keyParameter)
        parameterValue = parameter.getValue()
        insertionPoints = []

        if (parameter is None):
            return None
        
        else:
            # if the parameter is present, add a single custom insertion point for it
            # keyParameter is the parameter we extracted the encoded value from
            # todo: parse encoded parameter and add insertionpoint based on parameters found

            print("Executing Insertion Point")

            baseValue = self._helpers.bytesToString(TODO)

            for eachParam in baseValue.split(self._delimiter):
                eachParamName, eachParamValue = eachParam.split('=')

                insertionPoints.append(InsertionPoint(self._helpers,
                                                baseRequestResponse.getRequest(),
                                                self._keyParameter,   
                                                baseValue,
                                                eachParamName,
                                                eachParamValue,
                                                self._delimiter))

            return insertionPoints
        
# 
# class implementing IScannerInsertionPoint
#
class InsertionPoint(IScannerInsertionPoint):

    # todo: read the constructor
    def __init__(self, helpers, baseRequest,
            keyParameter,
            baseValue, 
            parameterName, 
            parameterValue,
            delimiter):

        self._helpers = helpers
        self._baseRequest = baseRequest
        self._keyParameter = keyParameter
        self._baseValue = baseValue
        self._delimiter = delimiter

        # len(parameterName) + 1 to include "=" 
        start = baseValue.find(parameterName) + len(parameterName) + 1
        end = baseValue.find(self._delimiter, start)
        
        if (end == -1):
            end = len(baseValue)

        print("start: " + str(start))
        print("end :" + str(end))
        
        self._insertionPointPrefix = baseValue[:start]
        self._insertionPointSuffix = baseValue[end:]
        return
        
    # 
    # implement IScannerInsertionPoint
    #
    def getInsertionPointName(self):
        return "Base64-wrapped input"

    def getBaseValue(self):
        return self._baseValue

    def buildRequest(self, payload):
        # build the raw data using the specified payload
        print("---Build Request---")

        insertValue = self._insertionPointPrefix + self._helpers.bytesToString(payload) + self._insertionPointSuffix;

        # todo: Base64- and URL-encode the data
        encodedInsertValue = TODO
        
        print("Insert Value: " + insertValue.encode('utf8'))
        # update the request with the new parameter value
        # update the request with the new parameter value 
        # PARAM_BODY - Used to indicate a parameter within the message body.
        # PARAM_COOKIE - Used to indicate an HTTP cookie.
        # PARAM_JSON -  Used to indicate an item of data within a JSON structure.
        return self._helpers.updateParameter(self._baseRequest, 
            self._helpers.buildParameter(self._keyParameter, encodedInsertValue, IParameter.PARAM_BODY))
        
    def getPayloadOffsets(self, payload):
        # since the payload is being inserted into a serialized data structure, there aren't any offsets 
        # into the request where the payload literally appears
        return None

    def getInsertionPointType(self):
        return INS_EXTENSION_PROVIDED

FixBurpExceptions()

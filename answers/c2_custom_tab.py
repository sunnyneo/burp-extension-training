# References
# https://github.com/PortSwigger/example-custom-editor-tab/
# https://github.com/PortSwigger/example-custom-editor-tab/blob/master/python/CustomEditorTab.py 
# https://github.com/securityMB/burp-exceptions

from burp import IBurpExtender              
from burp import IMessageEditorTab          
from burp import IMessageEditorTabFactory    
from burp import IParameter
from exceptions_fix import FixBurpExceptions
import datetime 

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):     
    
    #
    # Implement IBurpExtender Methods
    #
    def registerExtenderCallbacks(self, callbacks):

        self._extensionName = "C2 Custom Tab"

        # set the parameter that you are interested in
        # probably can build a UI to set some options/parameter names 
        self._parameterName = "input"

        # save helper functions to use in other methods in class
        # keep a reference to our callbacks object
        # obtain an extension helpers object
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName(self._extensionName)

        # register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(self)

        # print out for extension loaded
        print(self._extensionName + " Loaded")
        return

    def createNewInstance(self, controller, editable):
        # create a new instance of our custom editor tab
        return CustomTab(self, controller, editable)

# 
# class implementing IMessageEditorTab
#
class CustomTab(IMessageEditorTab):

    def __init__(self, extender, controller, editable):

        self._extender = extender
        self._editable = editable

        # create an instance of Burp's text editor, to display our processed data
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)
      
        # get helpers class for current class
        self._helpers = extender._helpers
        self._currentMessage = ""

        # get parameterName defined in BurpExtender
        self._parameterName = extender._parameterName

    #
    # implement IMessageEditorTab
    #
    def getTabCaption(self):
        # returns the name of the custom tab
        return "Decoded Tab"

    def getUiComponent(self):
        # burp uses this to retrieve component
        # for the content of the custom tab  
        return self._txtInput.getComponent()
        
    def isEnabled(self, content, isRequest):
        # check whether custom tab should be enabled based on..
        # whether it's a request and is the parameter name in the request?
        # probably can build ui to set request/response, parameter name
        paramFound = False 
        if isRequest == True:
            requestInfo = self._extender._helpers.analyzeRequest(content)
            parameters = requestInfo.getParameters()
            for param in parameters:
                if self._parameterName == param.getName():
                    paramFound = True
                    break;

        return isRequest and paramFound

        
    def setMessage(self, content, isRequest):
        # set the content in the custom tab
        # if no content, just display nothing
        if (content is None):
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)

        else:
            # todo decode
            # content to be processed and displayed using setText()
            # set whether the content can be modified
            # dodgy encoding 11 + base64
            parameter = self._helpers.getRequestParameter(content, self._parameterName)
            parameterValue = parameter.getValue()
            urlValue = self._helpers.urlDecode(parameterValue[2:len(parameterValue)])
            b64Value = self._helpers.base64Decode(urlValue)

            self._txtInput.setText(b64Value)
            self._txtInput.setEditable(self._editable)

        # remember the displayed content
        self._currentMessage = content


    def getMessage(self):
           # determine whether the user modified the deserialized data
           if self._txtInput.isTextModified():

               # todo
               # get the text in textbox
               # add 11 for dodgy encoding
               text = self._txtInput.getText()  

               parameterValue = self._helpers.bytesToString(text)
               b64Value = self._helpers.base64Encode(parameterValue)
               urlValue = self._helpers.urlEncode("11" + b64Value)
               
               # update the request with the new parameter value
               # IParameter buildParameter(PARAMETER NAME,
               #         PARAMETER VALUE,
               #         IParameter.PARAM_BODY)
               updatedRequest = self._helpers.updateParameter(
                    self._currentMessage, 
                    self._helpers.buildParameter(self._parameterName, 
                        urlValue, 
                        IParameter.PARAM_BODY)
                )
               return updatedRequest

           else:
               return self._currentMessage
       
    def isModified(self):
        return self._txtInput.isTextModified()
       
    def getSelectedData(self):
        return self._txtInput.getSelectedText()

FixBurpExceptions()

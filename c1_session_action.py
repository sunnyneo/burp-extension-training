#Code taken from https://www.twelvesec.com/2017/05/05/authorization-token-manipulation/ and modified by Sunny Neo

from exceptions_fix import FixBurpExceptions
import json
import datetime
from java.io import PrintWriter
from burp import IBurpExtender, IBurpExtenderCallbacks, ISessionHandlingAction

class BurpExtender(IBurpExtender, ISessionHandlingAction):
    #
    # Define Extension Name
    #
    NAME = "Custom Authorization Header Handler"
     
    #
    # Implement IBurpExtender Methods
    #
    def registerExtenderCallbacks(self, callbacks):
        # Save helper functions to use in other methods in class
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        #Set Extension name
        callbacks.setExtensionName(self.NAME) 
        
        #Tell Burp this plugin uses Session Handling Action
        self._callbacks.registerSessionHandlingAction(self) 

        #Loaded print out
        print("Custom Authorization Header Handler")
        print('starting at time :{:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now()))
        print("-----------------------------------------------------------------\n\n")
        return
    
    #Set action name in session handling
    def getActionName(self):
        return self.NAME
     
    #The main function to operate on the request
    def performAction(self, currentRequest, macroItems):

        #extract current request values 
        request_info = self._helpers.analyzeRequest(currentRequest)
        
        #Get response body for the macro issued request
        macro_response_info = self._helpers.analyzeResponse(macroItems[0].getResponse())

        macro_msg = macroItems[0].getResponse()
        resp_body = macro_msg[macro_response_info.getBodyOffset():]
        macro_body_string = self._helpers.bytesToString(resp_body)
        
        #Parse JSON and retrieve token in response body
        login_resp = json.loads(macro_body_string)

        print('Macro Response Body: %s',login_resp)

        #Get token
        token = login_resp["new_token"]
        
        #Retrieve headers in current request and 
        #reconstruct it with token value
        req_headers = request_info.getHeaders()
        req_body = currentRequest.getRequest()[request_info.getBodyOffset():]
          
        for eachHeader in req_headers:
            if 'secret-token' in eachHeader:
                 req_headers.remove(eachHeader)
                 break
       
        req_headers.add('secret-token: ' + token)        

        print('Header Checked at time :  {:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now()))        
        print("-----------------------------------------------------------------"        )
        print("Adding new header - secret-token: " + token)                
        print("-----------------------------------------------------------------")                
        print("Geting authorized..done\n\n")                
        
        # Build request with bypass headers        
        message = self._helpers.buildHttpMessage(req_headers, req_body)        
        # Update Request with New Header        
        currentRequest.setRequest(message)
        return

FixBurpExceptions()

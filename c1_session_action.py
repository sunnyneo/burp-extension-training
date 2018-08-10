# References
# https://github.com/PortSwigger/example-custom-session-tokens/
# https://github.com/PortSwigger/example-custom-session-tokens/blob/master/python/SessionTokens.py
# https://www.twelvesec.com/2017/05/05/authorization-token-manipulation/ 
# https://github.com/securityMB/burp-exceptions

from exceptions_fix import FixBurpExceptions
import json
import datetime
from burp import IBurpExtender
from burp import IBurpExtenderCallbacks
from burp import ISessionHandlingAction

class BurpExtender(IBurpExtender, ISessionHandlingAction):
    
    #
    # Define Extension Name
    #
    NAME = "Custom Authorization Header Handler"
     
    #
    # Implement IBurpExtender Methods
    #
    def registerExtenderCallbacks(self, callbacks):
        # save helper functions to use in other methods in class
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        # set Extension name
        callbacks.setExtensionName(self.NAME) 
        
        # tell Burp this extension uses Session Handling Action
        self._callbacks.registerSessionHandlingAction(self) 

        # print out for extension loaded
        print("Custom Authorization Header Handler Loaded")
        return
    
    # set action name in session handling
    def getActionName(self):
        return self.NAME
     
    # main function to operate on the request
    def performAction(self, currentRequest, macroItems):

        # extract current request values 
        request_info = self._helpers.analyzeRequest(currentRequest)
        
        # get response body for the macro issued request
        macro_response_info = self._helpers.analyzeResponse(macroItems[0].getResponse())

        macro_msg = macroItems[0].getResponse()
        resp_body = macro_msg[macro_response_info.getBodyOffset():]
        macro_body_string = self._helpers.bytesToString(resp_body)
        
        # parse JSON and retrieve token in response body
        login_resp = json.loads(macro_body_string)

        print('Macro Response Body: %s',login_resp)

        # get token
        token = login_resp["new_token"]
        
        # retrieve headers in current request and 
        # reconstruct it with token value
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
        print("Getting authorized..done\n\n")                
        
        # build request with bypass headers        
        message = self._helpers.buildHttpMessage(req_headers, req_body)    
            
        # update Request with New Header        
        currentRequest.setRequest(message)
        return

FixBurpExceptions()

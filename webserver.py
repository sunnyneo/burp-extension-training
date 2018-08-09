#!/usr/bin/python
from flask import Flask
from flask import request
from flask import jsonify
from threading import Lock
import uuid
import base64
from urllib.parse import unquote
import json

app = Flask(__name__)
tokens = []
tokens_lock = Lock()

@app.route("/")
def hello():
    return '''
<html>
    
        <head>
            <title>Test Page</title>
        </head> 

        <body>
            <h1>Hello World</h1>
        </body> 
</html>
    '''

#custom header and token reset every 5 requests
#Error message for request without valid token
@app.route("/1/")
def challenge1():
    requestCounter = 0
    inputToken = request.headers.get('secret-token')
    if inputToken is None or not inputToken in tokens:
        print(tokens)
        return generateResponse("Invalid Token. Go to /token/")

    else:
        requestCounter += 1
        if requestCounter == 5:
            print("Resetting Tokens")
            resetToken() 
        return generateResponse("Request successfully received.")

#value is required to be base64 and url encoded
@app.route("/2/",methods = ['GET','POST'])
def challenge2():
    #GET Request
    #Stub Function just to show input is put into JSON 
    #and base64 & URL encoded 
    if request.method == 'GET':
        return '''<html>
            <script>
                function submit() {

                    var input = document.getElementById("userid").value;
                    if (isNaN(input) || input > 10) {
                        document.getElementById("response").innerText = "Only User ID 1- 10. Try again.";
                    }
                    else {
                        var data = btoa(input);
                        console.log(data);
                        var xhttp = new XMLHttpRequest();
                        xhttp.onreadystatechange = function() {
                            if (this.readyState == 4 && this.status == 200) {
                              document.getElementById("response").innerText =
                              this.responseText;
                            }
                        };
                        xhttp.open("POST", "/2/", true);
                        xhttp.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
                        xhttp.send("input=11" + encodeURIComponent(data) + "&browser=" + navigator.product);
                    }

                }
            </script>
            <title>Challenge 2</title>
           <div id="body">
                <div id="response">
                </div>
                <div id="userinput">
                    UserID: <input type="text" id="userid"><br>
                    <button type="button" onclick="submit()">Submit</button>
                </div>
            </div>
        </html>'''
    
    #POST Request
    #Get data, parse it to get each parameter
    #Check whether data is URL Encoded
    elif request.method == 'POST':
       
        getBody = request.get_data().decode('utf-8')
        parameters = getBody.split('&')

        try: 
            for eachParam in parameters:
                if 'input' in eachParam:
                    getInput = eachParam.split('=')[1]
                    break

            if getInput is None:
               raise ValueError("Empty Input!")
            
            else:
                urldInput = unquote(getInput[2:len(getInput)])
                b64dInput = base64.b64decode(urldInput).decode('utf-8')
                recvData = {'data:' : b64dInput}

                # print("urlInput: " + urldInput)
                # print("base64Input: " + b64dInput)
                print("recvData: " + str(recvData))

                return generateResponse("Request successfully received.", recvData)
            
        #Can't parse the data
        except Exception as e:
            print(e)
            return generateResponse("Fail to process input")   
    

#Parameters in base64 and url encoded string
@app.route("/3/",methods = ['GET','POST'])
def challenge3():
    #GET Request
    #Stub Function just to show input is put into JSON 
    #and base64 & URL encoded 
    if request.method == 'GET':
        return '''<html>
            <script>
                function encodeInput(userid) {
                    var allInput = "userid=" + userid + "!!!location=" + window.location.href + "!!!browser=" + navigator.product;
                    var encodedInput = btoa(allInput);
                    return encodedInput;
                }
                function submit() {
                    var userid = document.getElementById("userid").value;

                    if (isNaN(userid) || userid > 10) {
                        document.getElementById("response").innerText = "Only User ID 1- 10. Try again.";
                    }
                    else {
                        var data = encodeInput(userid);
                        console.log(data);
                        var xhttp = new XMLHttpRequest();
                        xhttp.onreadystatechange = function() {
                            if (this.readyState == 4 && this.status == 200) {
                              document.getElementById("response").innerText =
                              this.responseText;
                            }
                        };
                        xhttp.open("POST", "/3/", true);
                        xhttp.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
                        xhttp.send("input=" + encodeURIComponent(data));
                    }      
                }
            </script>
            <title>Challenge 3</title>
           <div id="body">
                <div id="response">
                </div>
                <div id="userinput">
                    UserID: <input type="text" id="userid"><br>
                    <button type="button" onclick="submit()">Submit</button>
                </div>
            </div>
        </html>'''
    
    #POST Request
    #Get data, parse it to get each parameter
    #Check whether data is URL Encoded
    elif request.method == 'POST':
       
        getBody = request.get_data().decode('utf-8')
        parameters = getBody.split('&')

        try: 
            for eachParam in parameters:
                if 'input' in eachParam:
                    getInput = eachParam.split('=')[1]
                    break

            if getInput is None:
               raise ValueError("Empty Input!")
            
            else:
                urlInput = unquote(getInput)
                b64Input = base64.b64decode(urlInput).decode('utf-8')
                
                print("getInput: " + getInput)
                print("urlInput: " + urlInput)
                print("base64Input: " + b64Input)

                reconstructInput = {}

                innerParameters = b64Input.split('!!!')
                for innerParam in innerParameters:
                    key,value = innerParam.split('=', 1)
                    reconstructInput.update({key : value})

                print(str(reconstructInput))

                return generateResponse("Request successfully received.", reconstructInput)
            
        #Can't parse the data
        except Exception as e:
            print(e)
            return generateResponse("Fail to process input")   

@app.route("/4/<string:randomPath>",methods = ['GET'])
def challenge4(randomPath):

    if 'start' in request.url:
        response = '<html>\n'
        for i in range(1,100):
            eachiFrame = "<iframe src=\"http://127.0.0.1:5000/4/" + "a"*i 
            eachiFrame = eachiFrame + "\"></iframe>\n"
            response = response + eachiFrame 
        
        response = response + '</html>'

        return response

    else:   
        length = len(request.url)
        response = generateResponse("Request successfully received.")
        if length % 3 == 0 or length % 4 == 0:
            response.headers.set('Secret', 'you-are-not-supposed-to-see-this')
        
        return response 
    

@app.errorhandler(404)
def default_error(e):
    return '''<html>
        <title> 404 :( </title>

        <h1>Wrong Page :( </h1>
    </html>
    '''
@app.route("/token/")
def generateToken():
    global tokens
    newToken = str(uuid.uuid4())
    if len(tokens) == 10:
        print("clearing tokens")
        resetToken()
    else:
        addToken(newToken)

    return generateResponse("Request successfully received", 
                {"new_token" : newToken}
            )

def generateResponse(msg, content=None):
        data = { 'statusmsg': msg}
        if content != None: 
            data.update(content)

        '''
        response = app.response_class(
                    response=json.dumps(data),
                    status=200,
                    mimetype='/application/json'
        )
        '''
        return jsonify(**data) 

#critical section
def resetToken():
    tokens_lock.acquire()
    for i in tokens:
        tokens.remove(i)
    tokens_lock.release()

def addToken(newToken):
    tokens_lock.acquire()
    tokens.append(newToken)
    tokens_lock.release()

if __name__ == '__main__':
    app.run(port=5000,debug=True)


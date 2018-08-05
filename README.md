# burp-extension-training

## Requirements
Python >=3.6 <br>
Flask <br>
Burp <br>
Jython 2.7.1 Standalone (http://search.maven.org/remotecontent?filepath=org/python/jython-standalone/2.7.1/jython-standalone-2.7.1.jar)

## To Run
```git clone https://github.com/sunnyneo/burp-extension-training.git```
### Server-Side
```
pip install flask
export FLASK_APP=webserver.py
flask run
```
### Client-Side
```java -jar -Xms2G burpsuite_pro_v1.7.36.jar```

#### Configure Burp with Jython
```
Burp -> Extender -> Options

Jython Standalone 2.7.1
```

## Challenge 1
http://127.0.0.1:5000/1/

### Objective
Develop a session action extension used in a session handling rule to automatically update the request with the custom header value obtained from http://127.0.0.1:5000/token/. The generated token will be cleared after every 5 successful requests or 10 tokens generated. 

Get "statusmsg: Request successfully received" for all requests sent to the server.  

```
curl -v http://127.0.0.1:5000/1/
curl -v http://127.0.0.1:5000/token/
curl -v http://127.0.0.1:5000/1/ -H 'secret-token: 070dc567-4ab8-4a62-a212-c845c6dfdae2'
```
## Challenge 2
http://127.0.0.1:5000/2/

### Objective
Develop a custom tab that will decode the encoded value in the HTTP request and allow live editing, and upon detecting any modification in the textbox, the extension will automatically encode  the modified values and update the request.

Get "statusmsg: Request successfully received" along with your tampered value displayed.

## Challenge 3
http://127.0.0.1:5000/3/

### Objective
Develop an active scanner extension that will decode the encoded value in the request, parse the parameters in decoded value and insert active scan payload into each of the parameters then encode the the entire field before sending it to the server

## Challenge 4 
http://127.0.0.1:5000/4/start 

### Objective
Develop a passive scanner extension to flag out all the URLs with "secret" header in the response so that all the affected URLs can be exported from Burp to a report writing tool 

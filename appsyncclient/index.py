import sys, os, base64, datetime, hashlib, hmac
import requests
import json
import boto3
from urllib.parse import urlparse
import paho.mqtt.client as mqtt
import ssl
import time

regionDefault = os.environ.get("region","us-east-1")
appsyncUrlDefault = os.environ.get("appsync_url","")


class AppSyncClient():
    def __init__(self,*args,**kargs):
        pass

    def execute(self,**kargs):
        region = kargs.get("region") if kargs.get("region") else regionDefault
        url = kargs.get("url") if kargs.get("url") else appsyncUrlDefault
        data = kargs.get("data")
        callback = kargs.get("callback")
        method = kargs.get("method","POST")
        headers = self.getHeaders(url,method,region,data)

        response = self.sendRequest(url,method,data,headers)

        if callback != None:
            (clientId,wsUrl,topic) = self.getSubscriptionDetails(response)
            self.subscribe(clientId,wsUrl,topic,callback)

        return response

    def sendRequest(self,url,method,data,headers):
        response = requests.post(url,data=data,headers=headers)
        return response.json()

    def sign(self,key, msg):
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    def getSignatureKey(self,key, date_stamp, regionName, serviceName):
        kDate = self.sign(('AWS4' + key).encode('utf-8'), date_stamp)
        kRegion = self.sign(kDate, regionName)
        kService = self.sign(kRegion, serviceName)
        kSigning = self.sign(kService, 'aws4_request')
        return kSigning

    def subscribe(self,clientId,wsUrl,topic,callback):
        # The callback for when the client receives a CONNACK response from the server.
        def on_connect(client, userdata, flags, rc):
            print("Connected with result code " + str(rc))

            # Subscribing in on_connect() means that if we lose the connection and
            # reconnect then subscriptions will be renewed.
            client.subscribe(topic)

        # parse the websockets presigned url
        urlparts = urlparse(wsUrl)

        headers = {
            "Host": "{0:s}".format(urlparts.netloc),
        }

        client = mqtt.Client(client_id=clientId, transport="websockets")
        client.on_connect = on_connect
        client.on_message = callback

        client.ws_set_options(path="{}?{}".format(urlparts.path, urlparts.query), headers=headers)
        client.tls_set(cert_reqs=ssl.CERT_NONE)
        client.tls_insecure_set(True)


        print("trying to connect now....")
        client.connect(urlparts.netloc, 443)

        client.loop_start()

    def getSubscriptionDetails(self,response):

        connections = response.get('extensions',{}).get('subscription',{}).get('mqttConnections',[])

        if len(connections) > 0:
            client = connections[0]
            client_id = client.get("client")
            ws_url = client.get("url")
            topic = client.get("topics",[None])[0]
            return (client_id,ws_url,topic)

        return (None,None,None)



    def getHeaders(self,url,method,region,data):
        service = 'appsync'
        creds = boto3.Session().get_credentials()
        access_key = creds.access_key
        secret_key = creds.secret_key
        if access_key is None or secret_key is None:
            logger.error("No credentials available")
            sys.exit()

        t = datetime.datetime.utcnow()
        amz_date = t.strftime('%Y%m%dT%H%M%SZ')
        date_stamp = t.strftime('%Y%m%d')

        urldetails = urlparse(url)
        canonical_uri = urldetails.path

        canonical_querystring = urldetails.query

        host = urldetails.netloc

        content_type = 'application/x-amz-json-1.0'

        canonical_headers = 'content-type:' + content_type + '\n' + 'host:' + host + '\n' + 'x-amz-date:' + amz_date + '\n'

        signed_headers = 'content-type;host;x-amz-date'

        payload_hash = hashlib.sha256(data.encode('utf-8')).hexdigest()
        canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash

        algorithm = 'AWS4-HMAC-SHA256'
        credential_scope = date_stamp + '/' + region + '/' + service + '/' + 'aws4_request'
        string_to_sign = algorithm + '\n' +  amz_date + '\n' +  credential_scope + '\n' +  hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
        signing_key = self.getSignatureKey(secret_key, date_stamp, region, service)
        signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()
        authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' +  'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature
        headers = {'Content-Type':content_type,
                   'X-Amz-Date':amz_date,
                   'Authorization':authorization_header}

        return headers

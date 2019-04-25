import sys, os, base64, datetime, hashlib, hmac
import requests
import json
import boto3
from urllib.parse import urlparse
import paho.mqtt.client as mqtt
import ssl
import time

import logging

from .awssigner import AwsSigner

API_KEY = "API_KEY"
AWS_IAM = "AWS_IAM"

logger = logging.getLogger("appsync-client")

class AppSyncClient():
    def __init__(self,*args,**kargs):
        self.region = kargs.get("region")
        self.url = kargs.get("url")
        self.method = kargs.get("method","POST")
        self.authenticationType = kargs.get("authenticationType",AWS_IAM)
        self.apiId = kargs.get("apiId")
        self.apiKey = kargs.get("apiKey")

        if (self.apiId == None and self.apiKey == None) or self.region == None:
            logger.error("region, (apiId or apiKey) should be available")
            raise Exception("configuration error")

        if self.apiId != None and self.url == None:
            self.url = self.getUrl(self.apiId,self.region)
            if self.url == None:
                logger.error("appsync url unavailable")
                raise Exception("configuration error")

            logger.info("Retrieved appsync url : "+str(self.url))

    def execute(self,data,callback=None):

        if ( data == None ):
            logger.error("data is required")
            raise Exception("configuration error, data is required")

        region = self.region
        url = self.url
        method = self.method
        authenticationType = self.authenticationType
        apiId = self.apiId
        apiKey = self.apiKey

        if authenticationType == API_KEY:
            logger.info("Connecting with API_KEY")
            headers = self.getHeaders(region,apiId,apiKey)
        if authenticationType == AWS_IAM:
            logger.info("Connecting with IAM")
            headers = AwsSigner().getSignedHeaders(url,method,region,data)

        response = self.sendRequest(url,method,data,headers)

        if callback != None:
            (clientId,wsUrl,topic) = self.getSubscriptionDetails(response)
            self.subscribe(clientId,wsUrl,topic,callback)

        return response

    def getUrl(self,apiId,region):
        appsyncbotoclient = boto3.client("appsync",region_name = region)
        response = appsyncbotoclient.get_graphql_api(apiId=apiId)
        return response.get("graphqlApi",{}).get("uris",{}).get("GRAPHQL",None)

    def sendRequest(self,url,method,data,headers):
        logger.info("Sending request")
        logger.debug("data  : "+str(data))
        logger.debug("headers  : "+str(headers))
        response = requests.post(url,data=data,headers=headers)
        logger.debug("response  : "+str(response.json()))
        return response.json()

    def getApiKey(self,region,apiId):
        appsyncbotoclient = boto3.client("appsync",region_name = region)
        response = appsyncbotoclient.list_api_keys(apiId=apiId)
        apiKey = None
        for keyItem in response.get("apiKeys",[]):
            if int(keyItem.get("expires")) > int(time.time()):
                apiKey = keyItem.get("id")

        if(apiKey == None):
            apiKey = appsyncbotoclient.create_api_key(apiId=apiId).get("apiKey",{}).get("id",None)
        return apiKey

    def subscribe(self,clientId,wsUrl,topic,callback):
        # The callback for when the client receives a CONNACK response from the server.
        def on_connect(client, userdata, flags, rc):
            logger.info("Connected to mqtt with result code  : "+str(rc))

            # Subscribing in on_connect() means that if we lose the connection and
            # reconnect then subscriptions will be renewed.
            client.subscribe(topic)

        # parse the websockets presigned url
        print(wsUrl)
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
        logger.warn("Using insecure SSL handshake...")
        logger.info("Connecting to "+str(wsUrl))

        client.connect(urlparts.netloc, 443)

        client.loop_start()
        logger.info("Started listener...")

    def getSubscriptionDetails(self,response):

        connections = response.get('extensions',{}).get('subscription',{}).get('mqttConnections',[])

        if len(connections) > 0:
            client = connections[0]
            client_id = client.get("client")
            ws_url = client.get("url")
            topic = client.get("topics",[None])[0]
            return (client_id,ws_url,topic)

        return (None,None,None)

    def getHeaders(self,region,apiId,apiKey):
        if(apiKey == None):
            apiKey = self.getApiKey(region,apiId)
            logger.info("Retrieved appsync apiKey : OK")
        return {
            'Content-Type': 'application/json',
            'X-Api-Key': apiKey
        }

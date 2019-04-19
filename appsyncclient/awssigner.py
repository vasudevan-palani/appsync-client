import sys, os, base64, datetime, hashlib, hmac
import requests
import json
import boto3
from urllib.parse import urlparse
import paho.mqtt.client as mqtt
import ssl
import time

import logging

logger = logging.getLogger("appsync-client")

class AwsSigner():
    def __init__(self):
        pass

    def sign(self,key, msg):
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    def getSignatureKey(self,key, date_stamp, regionName, serviceName):
        kDate = self.sign(('AWS4' + key).encode('utf-8'), date_stamp)
        kRegion = self.sign(kDate, regionName)
        kService = self.sign(kRegion, serviceName)
        kSigning = self.sign(kService, 'aws4_request')
        return kSigning

    def getSignedHeaders(self,url,method,region,data):
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

        logger.info("Signed Headers : "+str(headers))

        return headers

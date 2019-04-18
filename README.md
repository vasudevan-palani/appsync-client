# appsync-client

## Usage

```python

def callback(client, userdata, msg):
  #use the msg
  pass

appsyncClient = AppSyncClient()
query = json.dumps({"query": "mutation {\n  updateSecret(id:\"1234\",secretString:\"sdfsdf\") {\n    id\n    secretString\n  }\n}\n"})
response = appsyncClient.execute(region="us-east-2",url="https://..../graphql",method="POST",data=query,callback=callback)
```

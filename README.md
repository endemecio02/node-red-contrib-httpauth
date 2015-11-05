# node-red-contrib-httpauth
Node-RED node for HTTP Basic/Digest Auth

This Node-RED module performs Basic and Digest authentication.
It is to be used in conjunction with an http input node.

![flow.png](images/flow.png)

## Config ##

![flow.png](images/config.png)

There are three type of configuration:

 1. File: the user credentials are stored in a file. (mutliple credentials)
 2. Shared: credentials shared which multiple nodes. (one credential)
 3. Not Shared: each node has it's own credentials. (one credential)

With all three types of configurations you must specify the following:

 - Auth Type: what authentication type will be used: Basic, Digest
 - Realm: what realm will be used with this node
 - Hashed: are the passwords in the Password field or in the credentials file hashed.
     This field is only relavent if Auth Type is Digest. It has no effect on Basic.

### File Configuration ###

![file.png](images/file.png)

With File configuration you specify 

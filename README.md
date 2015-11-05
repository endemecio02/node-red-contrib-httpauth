# node-red-contrib-httpauth
Node-RED node for HTTP Basic/Digest Auth

This Node-RED module performs Basic and Digest authentication.
It is to be used in conjunction with an http input node.

![flow.png](images/flow.png)

# Config #

<img src="images/config.png" style="max-width: 40%;" />

There are three levels of configuration:
1. File: the user credentials are stored in a file. (mutliple credentials)
2. Shared: credentials shared which multiple nodes. (one credential)
3. Not Shared: each node has it's own credentials. (one credential)



var md5 = require("md5");

var sessions = {};

function basicAuth(authStr, node, msg) {
	var values = new Buffer(authStr, "base64").toString().split(":");
	var username = values[0];
	var password = values[1];
	var user = node.httpauthconf.getUser(node.httpauthconf.realm, username);

	if (user && password == user.password) {
		node.send(msg);
	} else {
		unAuth(node, msg);
	}
}

function digestAuth(authStr, node, msg) {
	var values = authStr.split(", ");
	var auth = {method: msg.req.route.method.toUpperCase()};

	for (var index = 0; index < values.length; index++) {
		var value = values[index].trim();
		var prop = value.match(/^\w+\b/)[0].toLowerCase();
		auth[prop] = value.substring(prop.length + 1);
		auth[prop] = auth[prop].search('"') == 0 ? auth[prop].substring(1, auth[prop].length - 1) : auth[prop];
	}

	var user = node.httpauthconf.getUser(auth.realm, auth.username);
	var session = sessions[auth.nonce];

	if (user && session && auth.opaque == session.opaque) {
		var ha1 = node.httpauthconf.src == "file" ? user.password : md5(auth.username + ":" + auth.realm + ":" + user.password);
		ha1 = auth.algorithm == "MD5-sess" ? md5(ha1 + ":" + auth.nonce + ":" + auth.cnonce) : ha1;

		var ha2 = md5(auth.method + ":" + auth.uri);

		var response = md5(ha1 + ":" + auth.nonce + ":" + auth.nc + ":" + auth.cnonce + ":" + auth.qop + ":" + ha2);

		if (auth.response == response) {
			node.send(msg);
		} else {
			unAuth(node, msg);
		}
	} else {
		unAuth(node, msg);
	}
}

function digestStale(auth, node, msg) {
}

function unAuth(node, msg) {
var count = 0;
	switch (node.httpauthconf.authType) {
		case "Digest":
			var date = new Date();
			var random = Math.random();
			var realm = node.httpauthconf.realm;
			var nonce = new Buffer(date.getTime() + ":" + random).toString("base64");
			var opaque = new Buffer(String(random)).toString("base64");
			var qop = "auth";
			var algorithm = "MD5-sess";

			sessions[nonce] = {
				timestamp: date.getTime(),
				expires: date.getTime() + 30000,
				stale: false,
				random: random,
				realm: realm,
				opaque: opaque,
				qop: qop,
				algorithm: algorithm
			};

			msg.res.set("WWW-Authenticate", 'Digest realm="' + realm + '", nonce="' + nonce + '", opaque="' + opaque + '", qop="' + qop + '", algorithm="' + algorithm + '"');
			break;
		case "Basic": default: msg.res.set("WWW-Authenticate", 'Basic realm="' + realm + '"');
	}

	msg.res.set("Content-Type", "text/plain");
	msg.res.status(401).send("401 Unauthorized");
}

module.exports = function(RED) {
	"use strict";

	function HttpAuthNode(config) {
		RED.nodes.createNode(this, config);

		var src = "inline";
		var authType = config.authType;
		var realm = config.realm.trim();
		var realmL = realm.toLowerCase();
		var username = config.username.trim();
		var usernameL = username.toLowerCase();
		var password = config.password;
		var getUser = function(_realm, _username) {
			if (_realm.trim().toLowerCase() == realmL && _username.trim().toLowerCase() == usernameL) {
				return {
					realm: realm,
					username: username,
					password: password
				};
			}
			return null;
		};

		var cred = RED.nodes.getNode(config.cred);
		if (cred) {
			src = "cred";
			authType = cred.authType;
			realm = cred.realm.trim();
			realmL = realm.toLowerCase();
			username = cred.username.trim();
			usernameL = username.toLowerCase();
			password = cred.password;
		}

		var file = RED.nodes.getNode(config.file);
		if (file) {
			src = "file";
			authType = file.authType;
			realm = file.realm.trim();
			realmL = realm.toLowerCase();
			getUser = file.getUser;
		}

		this.httpauthconf = {};
		this.httpauthconf.src = src;
		this.httpauthconf.authType = authType;
		this.httpauthconf.realm = realm;
		this.httpauthconf.getUser = getUser;

		var node = this;

		this.on('input', function (msg) {
			var header = msg.req.get("Authorization");
			var authType = header ? header.match(/^\w+\b/)[0] : null;

			if (header && authType == node.httpauthconf.authType) {
				var authStr = header.substring(authType.length).trim();

				switch (authType) {
					case "Basic": basicAuth(authStr, node, msg); break;
					case "Digest": digestAuth(authStr, node, msg); break;
					default: unAuth(node, msg);
				}
			} else {
				unAuth(node, msg);
			}
		});

		this.on("close", function() {
			// Called when the node is shutdown - eg on redeploy.
			// Allows ports to be closed, connections dropped etc.
			// eg: node.client.disconnect();
		});
	}

	RED.nodes.registerType("node-red-contrib-httpauth", HttpAuthNode);
};
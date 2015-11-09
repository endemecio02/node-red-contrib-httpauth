var crypto = require("crypto");

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
	var method = msg.req.route.method;

	// Bluemix workaround
	if (!method && msg.req.route.methods) {
		for (var _method in msg.req.route.methods) {
			if (!method && msg.req.route.methods[_method]) {
				method = _method;
			}
		}
	}

	var auth = {method: method.toUpperCase()};

	for (var index = 0; index < values.length; index++) {
		var value = values[index].trim();
		var prop = value.match(/^\w+\b/)[0].toLowerCase();
		auth[prop] = value.substring(prop.length + 1);
		auth[prop] = auth[prop].search('"') == 0 ? auth[prop].substring(1, auth[prop].length - 1) : auth[prop];
	}

	var user = node.httpauthconf.getUser(auth.realm, auth.username);
	var session = sessions[auth.nonce + auth.opaque];

	if (user && session) {
		var ha1 = null;

		if (user.hashed) {
			ha1 = user.password;
		} else {
			var hash = crypto.createHash("md5");
			hash.update(auth.username + ":" + auth.realm + ":" + user.password, "utf8");
			ha1 = hash.digest("hex");
		}

		if (auth.algorithm == "MD5-sess") {
			var hash = crypto.createHash("md5");
			hash.update(ha1 + ":" + auth.nonce + ":" + auth.cnonce, "utf8");
			ha1 = hash.digest("hex");
		}

		var hash = crypto.createHash("md5");
		hash.update(auth.method + ":" + auth.uri, "utf8");
		var ha2 = hash.digest("hex");

		hash = crypto.createHash("md5");
		hash.update(ha1 + ":" + auth.nonce + ":" + auth.nc + ":" + auth.cnonce + ":" + auth.qop + ":" + ha2, "utf8");
		var response = hash.digest("hex");

		if (auth.response == response) {
			var timestamp = (new Date()).getTime();

			if (session.expires > timestamp) {
				session.expires = timestamp;
				node.send(msg);
			} else {
				delete sessions[auth.nonce + auth.opaque];
				unAuth(node, msg, true);
			}
		} else {
			unAuth(node, msg);
		}
	} else {
		unAuth(node, msg);
	}
}

function digestSession(realm) {
	var date = new Date();
	var timestamp = date.getTime();
	var expires = timestamp + 10000; // 10 seconds from now
	var random = Math.random(timestamp);
	var nonce = new Buffer(timestamp + ":" + random).toString("base64");
	var opaque = new Buffer(String(timestamp + random)).toString("base64");
	var qop = "auth";
	var algorithm = "MD5-sess";

	return {
		timestamp: timestamp,
		expires: expires,
		random: random,
		realm: realm,
		nonce: nonce,
		opaque: opaque,
		qop: qop,
		algorithm: algorithm
	};
}

function unAuth(node, msg, stale) {
	var res = msg.res._res || msg.res; // Resolves deprecates warning messages.

	switch (node.httpauthconf.authType) {
		case "Digest":
			var session = digestSession(node.httpauthconf.realm);
			sessions[session.nonce + session.opaque] = session;

			res.set("WWW-Authenticate", 
				'Digest realm="' + session.realm + '"'
				+ ', nonce="' + session.nonce + '"'
				+ ', opaque="' + session.opaque + '"'
				+ ', qop="' + session.qop + '"'
				+ ', algorithm="' + session.algorithm + '"'
				+ (stale ? ', stale="true"' : '')
			);
			break;
		case "Basic": default: res.set("WWW-Authenticate", 'Basic realm="' + node.httpauthconf.realm + '"');
	}

	res.type("text/plain");
	res.status(401).send("401 Unauthorized");
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
		var hashed = config.hashed;
		var getUser = function(_realm, _username) {
			if (_realm.trim().toLowerCase() == realmL && _username.trim().toLowerCase() == usernameL) {
				return {
					realm: realm,
					username: username,
					password: password,
					hashed: hashed
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
			hashed = cred.hashed;
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
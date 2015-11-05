var fs = require("fs");

module.exports = function(RED) {
	"use strict";

	function HttpAuthFileNode(config) {
		RED.nodes.createNode(this, config);

		var authType = config.authType;
		var realm = config.realm.trim();
		var realmL = realm.toLowerCase();
		var filePath = config.filePath.trim();
		var hashed = config.hashed;
		var users = {};

		var stats = fs.statSync(filePath);
		if (stats.isFile()) {
			var data = fs.readFileSync(filePath, "utf8");
			var lines = data.trim().split("\n");

			for (var index = 0; index < lines.length; index++) {
				var values = lines[index].split(":");
				var _username = values[0].trim();
				var _usernameL = _username.toLowerCase();
				var _realm = values[1].trim();
				var _realmL = _realm.toLowerCase();
				var _password = values[2];

				if (_realmL == realmL) {
					users[_usernameL] = {
						realm: _realm,
						username: _username,
						password: _password,
						hashed: hashed
					};
				}
			}
		}

		this.authType = config.authType;
		this.realm = config.realm;
		this.getUser = function(_realm, _username) {
			var _realmL = _realm.trim().toLowerCase();
			var _usernameL = _username.trim().toLowerCase();
			if (_realmL == realmL && users[_usernameL]) {
				return {
					realm: users[_usernameL].realm,
					username: users[_usernameL].username,
					password: users[_usernameL].password,
					hashed: users[_usernameL].hashed
				};
			}
			return null;
		};
	}

	RED.nodes.registerType("node-red-contrib-httpauthfile", HttpAuthFileNode);
};
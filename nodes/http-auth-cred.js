module.exports = function(RED) {
	"use strict";

	function HttpAuthCredNode(config) {
		RED.nodes.createNode(this, config);

		this.authType = config.authType;
		this.realm = config.realm;
		this.username = config.username;
		this.password = config.password;
		this.hashed = config.hashed;
	}

	RED.nodes.registerType("node-red-contrib-httpauthcred", HttpAuthCredNode);
};
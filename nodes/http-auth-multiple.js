var fs = require("fs");

module.exports = function(RED) {
    "use strict";

    function HttpAuthMultipleNode(config) {
        RED.nodes.createNode(this, config);

        var authType = config.authType;
        var realm = config.realm.trim();
		var realmL = realm.toLowerCase();
		var hashed = config.hashed;
        var users = {};
        for (var key in config.auths) {

            config.auths[key].forEach(function(value, index) {

                var _username = value.user.trim();
                var _usernameL = _username.toLowerCase();
                var _realm = key;
                var _realmL = _realm.toLowerCase();
                var _password = value.password;

                if (_realmL == realmL) {
                    users[_usernameL] = {
                        realm: _realm,
                        username: _username,
                        password: _password,
                        hashed: hashed
                    };
                }
            });
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

    RED.nodes.registerType("node-red-contrib-httpauthmultiple", HttpAuthMultipleNode);
};
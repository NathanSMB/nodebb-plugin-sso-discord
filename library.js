"use strict";
var User = module.parent.require('./user'),
	Groups = module.parent.require('./groups'),
	meta = module.parent.require('./meta'),
	db = module.parent.require('../src/database'),
	socketAdmin = module.parent.require('./socket.io/admin'),
	settings = module.parent.require('./settings'),
	helpers = module.parent.require('./routes/helpers'),
	passport = module.parent.require('passport'),
	fs = module.parent.require('fs'),
	path = module.parent.require('path'),
	nconf = module.parent.require('nconf'),
	winston = module.parent.require('winston'),
	async = module.parent.require('async');

var OAuth = {};
var authenticationController = module.parent.require('./controllers/authentication');

var discordSettings = new settings('discordSSO', '1.0.0', {
	appDetails : {
		clientID: "",
		secret: ""
	}
}, function() {});

socketAdmin.settings.syncDiscordSettings = function(){
	discordSettings.sync();
}

var constants = {
		type: 'oauth2',
		name: 'discord',
		scope: 'identify,email',
		oauth2: {
			authorizationURL: 'https://discordapp.com/api/oauth2/authorize',
			tokenURL: 'https://discordapp.com/api/oauth2/token',
			clientID: nconf.get('oauth:id'),
			clientSecret: nconf.get('oauth:secret')
		},
		userRoute: 'https://discordapp.com/api/users/@me'
	},
	configOk = false,
		passportOAuth,
	opts;

OAuth.init = function(params, callback){
	function render(req, res) {
		res.render('admin/plugins/sso-discord', {});
	}
	params.router.get('/admin/plugins/sso-discord', params.middleware.admin.buildHeader, render);
	params.router.get('/api/admin/plugins/sso-discord', render);

	constants.oauth2.clientID = discordSettings.get('appDetails.clientID');
	constants.oauth2.clientSecret = discordSettings.get('appDetails.secret');

	params.router.get('/auth/discord/callback', passport.authenticate('discord',  { failureRedirect: '/verifydiscord' }), function(req, res){
		res.redirect('/');
	});

	params.router.get('/verifydiscord', params.middleware.buildHeader, function(req,res){
		res.render('verifydiscord', {});
	});
	params.router.get('/api/verifydiscord', function(req,res){
		res.render('verifydiscord', {});
	});


	callback();
}

OAuth.setWidgetAreas = function(areas, callback){
	areas = areas.concat([
		{
			'name': 'Verify Discord Header',
			'template': 'verifydiscord.tpl',
			'location': 'header'
		},
		{
			'name': 'Verify Discord Footer',
			'template': 'verifydiscord.tpl',
			'location': 'footer'
		},
		{
			'name': 'Verify Discord Sidebar',
			'template': 'verifydiscord.tpl',
			'location': 'sidebar'
		},
		{
			'name': 'Verify Discord Content',
			'template': 'verifydiscord.tpl',
			'location': 'content'
		}
	]);
	cb(null, areas);
}

OAuth.addMenuItem = function(custom_header, callback) {
	custom_header.authentication.push({
		'route': '/plugins/sso-discord',
		'icon': 'fa-check-square discord-sso-icon',
		'name': 'Discord'
	});

	callback(null, custom_header);
};

OAuth.getStrategy = function(strategies, callback) {
	if (constants.oauth2.clientID && constants.oauth2.clientSecret) {
		configOk = true;
	} else {
		winston.error('[sso-discord] Cliend ID and Client Secret required (library.js:36)');
	}
	if (configOk) {
		passportOAuth = require('passport-oauth')['OAuth2Strategy'];

		opts = constants.oauth2;
		opts.callbackURL = nconf.get('url') + '/auth/' + constants.name + '/callback';

		passportOAuth.Strategy.prototype.userProfile = function(accessToken, done) {

			this._oauth2.useAuthorizationHeaderforGET(true);

			this._oauth2.get(constants.userRoute, accessToken, function(err, body, res) {
				if (err) { return done(new Error('failed to fetch user profile', err)); }

				try {
					var json = JSON.parse(body);
					OAuth.parseUserReturn(json, function(err, profile) {
						if (err) return done(err);
						profile.provider = constants.name;

						done(null, profile);
					});
				} catch(e) {
					done(e);
				}
			});
		};

		opts.passReqToCallback = true;

		passport.use(constants.name, new passportOAuth(opts, function(req, token, secret, profile, done) {
			// This is where the payload object is created.
			OAuth.login({
				oAuthid: profile.id,
				handle: profile.displayName,
				email: profile.emails[0].value,
				isAdmin: profile.isAdmin,
				verified: profile.verified
			}, function(err, user) {
				if (err) {
					return done(err);
				}
				if(user !== null){
					authenticationController.onSuccessfulLogin(req, user.uid);
				}
				done(null, user);
			});
		}));

		strategies.push({
			name: constants.name,
			url: '/auth/' + constants.name,
			callbackURL: '/auth/' + constants.name + '/callback',
			icon: 'fa-check-square discord-sso-icon',
			scope: (constants.scope || '').split(',')
		});

		callback(null, strategies);
	} else {
		callback(null);
	}
};

OAuth.parseUserReturn = function(data, callback) {
	// Alter this section to include whatever data you would like
	// NodeBB *requires* the following: id, displayName, emails.
	// Everything else is optional.

	// Do you want to automatically make somebody an admin? Then set profile.isAdmin to true.

	// Find out what is available by uncommenting this line:
	// console.log(data);
	// Discord User Documentation:  https://discordapp.com/developers/docs/resources/user

	var profile = {
		id: data.id,
		displayName: data.username,
		emails: [
			{
				value: data.email
			}
		],
		verified: data.verified
	};

	callback(null, profile);
}

OAuth.login = function(payload, callback) {
	OAuth.getUidByOAuthid(payload.oAuthid, function(err, uid) {
		if(err) {
			return callback(err);
		}

		if (uid !== null) {
			// Existing User
			// This is the best place to modify existing users.

			callback(null, {
				uid: uid
			});
		} else {
			// New User
			var success = function(uid) {
				// This is the best place to modify information for new users as a uid is gaurenteed to exist.

				// Save provider-specific information to the user
				User.setUserField(uid, constants.name + 'Id', payload.oAuthid);
				db.setObjectField(constants.name + 'Id:uid', payload.oAuthid, uid);

				if (payload.isAdmin) {
					Groups.join('administrators', uid, function(err) {
						callback(null, {
							uid: uid
						});
					});
				} else {
					callback(null, {
						uid: uid
					});
				}
			};

			User.getUidByEmail(payload.email, function(err, uid) {
				if(err) {
					return callback(err);
				}
				if(payload.verified){
					if (!uid) {
						User.create({
							username: payload.handle,
							email: payload.email
						}, function(err, uid) {
							if(err) {
								return callback(err);
							}

							success(uid);
						});
					} else {
						success(uid); // Existing account -- merge
					}
				} else {
					callback(null, null)
				}
			});
		}
	});
};

OAuth.getUidByOAuthid = function(oAuthid, callback) {
	db.getObjectField(constants.name + 'Id:uid', oAuthid, function(err, uid) {
		if (err) {
			return callback(err);
		}
		callback(null, uid);
	});
};

OAuth.deleteUserData = function(data, callback) {
	async.waterfall([
		async.apply(User.getUserField, data.uid, constants.name + 'Id'),
		function(oAuthIdToDelete, next) {
			db.deleteObjectField(constants.name + 'Id:uid', oAuthIdToDelete, next);
		}
	], function(err) {
		if (err) {
			winston.error('[sso-discord] Could not remove OAuthId data for uid ' + data.uid + '. Error: ' + err);
			return callback(err);
		}
		callback(null, data);
	});
};

OAuth.whitelistFields = function(params, callback) {
	params.whitelist.push(constants.name + 'Id');
    callback(null, params);
};

module.exports = OAuth;

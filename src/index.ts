import crypto from 'crypto';
import express from 'express';
import * as ldapts from 'ldapts';
import winston from 'winston';

require('source-map-support').install();
require('toml-require').install();

const config = require('../config.toml') as ServerConfig;

const log = winston.createLogger({
	level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
	format: winston.format.combine(
		winston.format.timestamp(),
		winston.format.printf(info => `[${info.timestamp}] ${info.level}: ${info.message}`),
	),
	transports: [
		new winston.transports.Console(),
	],
});

const DEFUALT_PORT = 8081;

interface ServerConfig {
	port?: number;
	signingKey: string;
	allowGuests?: boolean;
	ldap: ldapts.ClientOptions & {
		bindDN: string;
		bindPW: string;
		userDN: string;
		userSearchFilter: string;
		groupDN?: string;
		groupName?: string;
		memberOfAttribute: string;
	};
}

interface AuthResponse {
	status: 'auth' | 'guest' | 'badpass' | 'outgroup' | 'banned';
	token?: string;
	ingroup?: string;
}

interface DrawpileAuthPayload {
	username: string;
	flags?: string[];
	iat: number; // issued at, seconds since epoch
	uid?: number | string;
	group?: string;
	nonce: string; // random 64-bit hex string
}

interface LDAPUser {
	dn: string;
	objectClass: string[];
	entryUUID: string;
	[key: string]: string | string[] | Buffer | Buffer[];
}

const ldapClient = new ldapts.Client(config.ldap);

const app = express();
app.use(express.json());

function createDrawpileAuthToken(payload: DrawpileAuthPayload, avatar?: string | Buffer) {
	const payloadJSON = JSON.stringify(payload);
	const signingKey = `-----BEGIN PRIVATE KEY-----
${config.signingKey}
-----END PRIVATE KEY-----`;
	const signature = crypto.sign(null, Buffer.from(payloadJSON, 'utf8'), signingKey).toString('base64');

	// version.payload.avatar?.signature
	const components = [
		avatar ? '2': '1',
		Buffer.from(payloadJSON).toString('base64'),
		signature
	];
	if (avatar) components.splice(2, 0, typeof avatar === 'string' ? avatar : avatar.toString('base64'));
	return components.join('.');
}

async function findUser(username: string): Promise<LDAPUser | null> {
	await ldapClient.bind(config.ldap.bindDN, config.ldap.bindPW);

	try {
		const searchFilter = config.ldap.userSearchFilter.replace('%u', username);
		const searchResults = await ldapClient.search(config.ldap.userDN, {
			filter: searchFilter,
		});

		return searchResults.searchEntries[0] as LDAPUser;
	} catch (err) {
		if (err.code === 0x20) { // no such object
			return null;
		}

		throw err;
	} finally {
		await ldapClient.unbind();
	}
}

async function loginUser(username: string, password: string): Promise<LDAPUser | null> {
	const user = await findUser(username);
	if (!user) return null;

	try {
		await ldapClient.bind(user.dn as string, password);
	} finally {
		await ldapClient.unbind();
	}

	return user;
}

app.get('/', async (req, res) => {
	log.info('Request received from ' + req.ip);

	if (!req.body.username) return res.status(400).send('Bad request');

	const authResponse: AuthResponse = {
		status: 'auth',
		ingroup: config.ldap.groupName,
	};

	if (!req.body.password) { // auth server request
		if (!config.allowGuests) {
			return res.json(authResponse);
		}

		const user = await findUser(req.body.username);
		if (user) {
			return res.json(authResponse); // auth required, username taken
		}

		authResponse.status = 'guest';
		return res.json(authResponse);
	}

	// since password is set, this is a login request

	let user: LDAPUser | null = null;

	try {
		user = await loginUser(req.body.username, req.body.password);
	} catch (err) {
		if (err.code === 0x31) { // invalid credentials
			log.info(`Incorrect credentials for user ${req.body.username}`);
			authResponse.status = 'badpass';
			return res.json(authResponse);
		}

		log.error(err);
		return res.status(500).send('Internal server error');
	}

	if (!user) {
		log.info(`Username ${req.body.username} not found in LDAP`);
		authResponse.status = 'badpass';
		return res.json(authResponse);
	}

	log.info(`Username ${req.body.username} successfully authenticated`);

	const authPayload: DrawpileAuthPayload = {
		username: req.body.username,
		iat: Date.now(),
		uid: user.entryUUID,
		nonce: crypto.randomBytes(8).toString('hex'),
	};

	authResponse.token = createDrawpileAuthToken(authPayload);
	return res.json(authResponse);
});

app.listen(config.port || DEFUALT_PORT);
log.info('Listening on http://127.0.0.1:' + (config.port || DEFUALT_PORT));

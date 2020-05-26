import crypto from 'crypto';
import express from 'express';
import * as ldapts from 'ldapts';
import winston from 'winston';

require('source-map-support').install();
require('toml-require').install();

interface ServerConfig {
	port?: number;
	signingKey: string;
	allowGuests?: boolean;
	ldap: ldapts.ClientOptions & {
		bindDN: string;
		bindPW: string;
		userDN: string;
		userSearchFilter: string;
		groupDN: string;
		memberOfAttribute: string;
		flagGroups: {
			[flag: string]: string;
		}
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

const config = require('../config.toml') as ServerConfig;
const DEFUALT_PORT = 8081;
const signingKey = crypto.createPrivateKey({
	key: Buffer.from(config.signingKey, 'base64'),
	format: 'der',
	type: 'pkcs8',
});

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


const ldapClient = new ldapts.Client(config.ldap);

const app = express();
app.use(express.json());

const btoa = (data: string) => Buffer.from(data, 'utf8').toString('base64');

function createDrawpileAuthToken(payload: DrawpileAuthPayload, avatar?: string | Buffer) {
	const payloadJSON = JSON.stringify(payload);

	// version.payload.avatar?.signature
	const components = [
		avatar ? '2': '1',
		btoa(payloadJSON),
	];

	const signature = crypto.sign(null, Buffer.from(components.join('.'), 'utf8'), signingKey).toString('base64');

	if (avatar) components.push(typeof avatar === 'string' ? avatar : avatar.toString('base64'));
	components.push(signature);

	return components.join('.');
}

async function findUser(username: string, group?: string): Promise<LDAPUser | null> {
	await ldapClient.bind(config.ldap.bindDN, config.ldap.bindPW);

	try {
		let searchFilter = config.ldap.userSearchFilter.replace('%u', username);
		if (group) {
			const groupDN = `cn=${group},${config.ldap.groupDN}`;
			searchFilter = `(&${config.ldap.userSearchFilter.replace('%u', username)}(${config.ldap.memberOfAttribute}=${groupDN}))`;
		}

		const searchResults = await ldapClient.search(config.ldap.userDN, {
			filter: searchFilter,
		});

		log.debug(JSON.stringify(searchResults, undefined, 2));

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

async function isUserInGroup(username: string, group: string): Promise<boolean> {
	const user = await findUser(username, group);
	if (user) return true;
	return false;
}

app.use((req, res, next) => {
	log.info('Request received from ' + req.ip);
	log.debug('Request method: ' + req.method);
	log.debug('Request URI: ' + req.url);
	log.debug('Request body: ' + JSON.stringify(req.body));

	next();
});

app.post('/', async (req, res) => {
	if (!req.body.username) return res.status(400).send('Bad request');

	const authResponse: AuthResponse = {
		status: 'auth',
		ingroup: req.body.group,
	};

	if (!req.body.password) { // server request
		log.info(`Checking if username ${req.body.username} is available for guest access`);

		if (!config.allowGuests) {
			log.info(`Guest login disabled`);
			return res.json(authResponse);
		}

		const user = await findUser(req.body.username, req.body.group);
		if (user) {
			log.info(`Username ${req.body.username} is taken by a registered user`);
			return res.json(authResponse); // auth required, username taken
		}

		log.info(`Username ${req.body.username} is available`);
		authResponse.status = 'guest';
		return res.json(authResponse);
	}

	// since password is set, this is a login request

	// missing nonce, invalid request
	if (!req.body.nonce) return res.status(400).send('Bad request');

	log.info(`Attempting to authenticate user ${req.body.username}`);

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
		log.info(`Username ${req.body.username} not found${req.body.group ? `, or not a member of group ${req.body.group}` : ''}`);
		authResponse.status = 'badpass';
		return res.json(authResponse);
	}

	log.info(`Username ${req.body.username} successfully authenticated`);

	const flags: string[] = [];

	await ldapClient.bind(config.ldap.bindDN, config.ldap.bindPW);
	for (const flag in config.ldap.flagGroups) {
		const group = config.ldap.flagGroups[flag];
		log.info(`Checking if ${req.body.username} is a member of ${group}`);
		
		if (await isUserInGroup(req.body.username, group)) {
			log.info(`${req.body.username} is a member of ${group}; granting flag ${flag}`);
			flags.push(flag);
		} else {
			log.info(`${req.body.username} is a NOT member of ${group}`);
		}
	}
	await ldapClient.unbind();

	const authPayload: DrawpileAuthPayload = {
		username: req.body.username,
		iat: Date.now(),
		uid: user.entryUUID,
		flags,
		group: req.body.group,
		nonce: req.body.nonce,
	};
	log.debug('Auth payload: ' + JSON.stringify(authPayload));

	authResponse.token = createDrawpileAuthToken(authPayload);
	log.debug('Auth response: ' + JSON.stringify(authResponse));
	return res.json(authResponse);
});

log.debug('Starting with config:');
log.debug(JSON.stringify(config, undefined, 2));
app.listen(config.port || DEFUALT_PORT);
log.info('Listening on http://127.0.0.1:' + (config.port || DEFUALT_PORT));

import crypto from 'crypto';
import express from 'express';
import * as ldapts from 'ldapts';
import winston from 'winston';
import { CONFIG } from './config';

require('source-map-support').install();

const packageInfo = require('../package.json'); // eslint-disable-line

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

const log = winston.createLogger({
	level: process.env.LOG_LEVEL ?? (process.env.NODE_ENV === 'production' ? 'info' : 'debug'),
	format: winston.format.combine(
		winston.format.timestamp(),
		winston.format.printf(info => `[${info.timestamp}] ${info.level}: ${info.message}`),
	),
	transports: [
		new winston.transports.Console(),
	],
});

log.info(`Starting ${packageInfo.name} v${packageInfo.version}...`);

log.silly('Starting with config:');
log.silly(CONFIG.toString());

if (!CONFIG.get('signingKey')) {
	log.error('No signing key provided!');
	process.exit(1);
}

const signingKey = crypto.createPrivateKey({
	key: Buffer.from(CONFIG.get('signingKey'), 'base64'),
	format: 'der',
	type: 'pkcs8',
});

const ldapClient = new ldapts.Client({
	url: CONFIG.get('ldap.url'),
});

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
	await ldapClient.bind(CONFIG.get('ldap.bindDN'), CONFIG.get('ldap.bindPW'));

	try {
		let searchFilter = CONFIG.get('ldap.userSearchFilter').replace(/%u/, username);
		if (group) {
			const groupDN = `cn=${group},${CONFIG.get('ldap.groupDN')}`;
			searchFilter = `(&${CONFIG.get('ldap.userSearchFilter').replace(/%u/, username)}(${CONFIG.get('ldap.memberOfAttribute')}=${groupDN}))`;
		}

		const searchResults = await ldapClient.search(CONFIG.get('ldap.userDN'), {
			filter: searchFilter,
		});

		log.silly(JSON.stringify(searchResults, undefined, 2));

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

app.use((req, _, next) => {
	log.http('Request received from ' + req.ip);
	log.silly('Request method: ' + req.method);
	log.silly('Request URI: ' + req.url);
	log.silly('Request body: ' + JSON.stringify(req.body));

	next();
});

app.post(CONFIG.get('path'), async (req, res) => {
	if (!req.body.username) return res.status(400).send('Bad request');

	const authResponse: AuthResponse = {
		status: 'auth',
		ingroup: req.body.group,
	};

	if (!req.body.password) { // server request
		log.info(`Checking if username ${req.body.username} is available for guest access`);

		if (!CONFIG.get('allowGuests')) {
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

	await ldapClient.bind(CONFIG.get('ldap.bindDN'), CONFIG.get('ldap.bindPW'));
	for (const flag in CONFIG.get('ldap.flagGroups')) {
		const group = CONFIG.get('ldap.flagGroups')[flag];
		log.info(`Checking if ${req.body.username} is a member of ${group}`);
		
		if (await isUserInGroup(req.body.username, group)) {
			log.info(`${req.body.username} is a member of ${group}; granting flag ${flag}`);
			flags.push(flag);
		} else {
			log.info(`${req.body.username} is a NOT member of ${group}`);
		}
	}
	await ldapClient.unbind();

	let username = req.body.username;

	if (CONFIG.has('ldap.displayNameAttribute')) {
		username = user[CONFIG.get('ldap.displayNameAttribute')] ?? username;
	}

	const authPayload: DrawpileAuthPayload = {
		username,
		iat: Date.now(),
		uid: user.entryUUID,
		flags,
		group: req.body.group,
		nonce: req.body.nonce,
	};
	log.debug('Auth payload: ' + JSON.stringify(authPayload));

	authResponse.token = createDrawpileAuthToken(authPayload);
	log.silly('Auth response: ' + JSON.stringify(authResponse));
	return res.json(authResponse);
});

app.listen(CONFIG.get('port'));
log.info(`Listening on http://127.0.0.1:${CONFIG.get('port')}${CONFIG.get('path')}`);

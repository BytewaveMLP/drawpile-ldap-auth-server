import crypto from 'crypto';
import express from 'express';
import * as ldapts from 'ldapts';
import winston from 'winston';

require('source-map-support').install();
require('toml-require').install();

const packageInfo = require('../package.json'); // eslint-disable-line

interface ServerConfig {
	signingKey?: string;
	port?: number;
	path?: string;
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

const configFile = require('../config.toml') as ServerConfig;

log.info(`Starting drawpile-ldap-auth-server v${packageInfo.version}...`);

const DEFAULT_PORT = 8081;
const DEFAULT_ROUTE = '/';

function strToBool(str: string): boolean {
	return ['yes', '1', 'y', 'true', 't'].includes(str);
}

const CONFIG: ServerConfig = {
	signingKey: process.env.DRAWPILE_AUTH_TOKEN_SIGNING_KEY ?? configFile.signingKey,
	port: process.env.PORT ? parseInt(process.env.PORT) : (configFile.port ?? DEFAULT_PORT),
	path: process.env.ROUTE ?? configFile.path ?? DEFAULT_ROUTE,
	allowGuests: process.env.allowGuests ? strToBool(process.env.allowGuests) : (configFile.allowGuests ?? false),
	ldap: {
		url: process.env.LDAP_URL ?? configFile.ldap.url,
		bindDN: process.env.LDAP_BIND_DN ?? configFile.ldap.bindDN,
		bindPW: process.env.LDAP_BIND_PASS ?? configFile.ldap.bindPW,
		userDN: process.env.LDAP_USER_DN ?? configFile.ldap.userDN,
		userSearchFilter: process.env.LDAP_USER_FILTER ?? configFile.ldap.userSearchFilter,
		groupDN: process.env.LDAP_GROUP_DN ?? configFile.ldap.groupDN,
		memberOfAttribute: process.env.LDAP_MEMBER_OF_ATTR ?? configFile.ldap.memberOfAttribute,
		flagGroups: configFile.ldap.flagGroups // no easy way to get this out of the environment
	},
};

log.silly('Starting with config:');
log.silly(JSON.stringify(CONFIG, undefined, 2));

if (!CONFIG.signingKey) {
	log.error('No signing key provided!');
	process.exit(1);
}

const signingKey = crypto.createPrivateKey({
	key: Buffer.from(CONFIG.signingKey, 'base64'),
	format: 'der',
	type: 'pkcs8',
});

const ldapClient = new ldapts.Client(CONFIG.ldap);

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
	await ldapClient.bind(CONFIG.ldap.bindDN, CONFIG.ldap.bindPW);

	try {
		let searchFilter = CONFIG.ldap.userSearchFilter.replace('%u', username);
		if (group) {
			const groupDN = `cn=${group},${CONFIG.ldap.groupDN}`;
			searchFilter = `(&${CONFIG.ldap.userSearchFilter.replace(/%u/, username)}(${CONFIG.ldap.memberOfAttribute}=${groupDN}))`;
		}

		const searchResults = await ldapClient.search(CONFIG.ldap.userDN, {
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

// eslint-disable-next-line @typescript-eslint/no-non-null-assertion
app.post(CONFIG.path!, async (req, res) => {
	if (!req.body.username) return res.status(400).send('Bad request');

	const authResponse: AuthResponse = {
		status: 'auth',
		ingroup: req.body.group,
	};

	if (!req.body.password) { // server request
		log.info(`Checking if username ${req.body.username} is available for guest access`);

		if (!CONFIG.allowGuests) {
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

	await ldapClient.bind(CONFIG.ldap.bindDN, CONFIG.ldap.bindPW);
	for (const flag in CONFIG.ldap.flagGroups) {
		const group = CONFIG.ldap.flagGroups[flag];
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
	log.silly('Auth response: ' + JSON.stringify(authResponse));
	return res.json(authResponse);
});

app.listen(CONFIG.port);
log.info(`Listening on http://127.0.0.1:${CONFIG.port}${CONFIG.path || '/'}`);

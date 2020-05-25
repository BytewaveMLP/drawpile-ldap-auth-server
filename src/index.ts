import express from "express";
import * as ldapts from 'ldapts';
require('source-map-support').install();
require('toml-require').install();
const config = require('../config.toml') as ServerConfig;

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

const ldapClient = new ldapts.Client(config.ldap);

const app = express();
app.use(express.json());

app.get('/', async (req, res) => {
	if (!req.body.username) return res.status(400).send('Bad request');

	const authResponse: AuthResponse = {
		status: 'auth',
		ingroup: config.ldap.groupName,
	};

	if (!req.body.password && !config.allowGuests) { // attempted guest auth but no password presented
		authResponse.status = 'auth';
		return res.json(authResponse);
	}

	await ldapClient.bind(config.ldap.bindDN, config.ldap.bindPW);

	let searchResults: ldapts.SearchResult;

	try {
		const searchFilter = config.ldap.userSearchFilter.replace('%u', req.body.username);
		searchResults = await ldapClient.search(config.ldap.userDN, {
			filter: searchFilter,
		});

		return res.json(searchResults.searchEntries);
	} catch (err) {
		if (err.code === 0x20) {
			if (config.allowGuests) {
				authResponse.status = 'guest';
			}
			return res.send(authResponse);
		}

		return res.status(500).send(err);
	} finally {
		await ldapClient.unbind();
	}
});

app.listen(config.port || DEFUALT_PORT);
console.log('Listening on http://127.0.0.1:' + (config.port || DEFUALT_PORT));

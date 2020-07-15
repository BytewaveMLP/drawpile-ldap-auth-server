import toml from 'toml';
import convict from 'convict';

convict.addParser({ extension: 'toml', parse: toml.parse });

const DEFAULT_PORT = 8081;
const DEFAULT_ROUTE = '/';

const config = convict({
	signingKey: {
		doc: 'Private key used to sign Drawpile auth tokens',
		format: String,
		default: undefined as unknown as string,
		env: 'DRAWPILE_AUTH_TOKEN_SIGNING_KEY',
		arg: 'drawpile-auth-token-signing-key',
		sensitive: true,
	},
	port: {
		doc: 'Port the auth server should listen on',
		format: 'port',
		default: DEFAULT_PORT,
		env: 'PORT',
		arg: 'port',
	},
	path: {
		doc: 'Route to serve requests on; useful you run this behind a reverse proxy like nginx',
		format: '*',
		default: DEFAULT_ROUTE,
		env: 'ROUTE',
		arg: 'route',
	},
	allowGuests: {
		doc: 'Should guests be allowed to authenticate with the server?',
		format: Boolean,
		default: false,
		env: 'ALLOW_GUESTS',
		arg: 'allow-guests',
	},
	ldap: {
		url: {
			doc: 'URL to connect to LDAP server',
			format: String,
			default: undefined as unknown as string,
			env: 'LDAP_URL',
			arg: 'ldap-url',
		},
		bindDN: {
			doc: 'DN of the LDAP user to bind to when looking up user info',
			format: String,
			default: undefined as unknown as string,
			env: 'LDAP_BIND_DN',
			arg: 'ldap-bind-dn',
		},
		bindPW: {
			doc: 'Password of the LDAP user to bind to when looking up user info',
			format: String,
			default: undefined as unknown as string,
			env: 'LDAP_BIND_PASS',
			arg: 'ldap-bind-pass',
			sensitive: true,
		},
		userDN: {
			doc: 'DN where LDAP users are stored',
			format: String,
			default: undefined as unknown as string,
			env: 'LDAP_USER_DN',
			arg: 'ldap-user-dn',
		},
		userSearchFilter: {
			doc: 'Search filter to locate LDAP users; %u is substituted with the provided login username',
			format: '*',
			default: '(uid=%u)',
			env: 'LDAP_USER_FILTER',
			arg: 'ldap-user-filter',
		},
		groupDN: {
			doc: 'DN where LDAP groups are stored',
			format: String,
			default: undefined as unknown as string,
			env: 'LDAP_GROUP_DN',
			arg: 'ldap-group-dn',
		},
		memberOfAttribute: {
			doc: 'memberOf attribute used by your LDAP server',
			format: '*',
			default: 'memberOf',
			env: 'LDAP_MEMBER_OF_ATTR',
			arg: 'ldap-member-of-attr',
		},
		displayNameAttribute: {
			doc: 'LDAP attribute used to store the display name to use for users',
			format: '*',
			default: undefined as string | undefined,
			env: 'LDAP_DISPLAY_NAME_ATTR',
			arg: 'ldap-display-name-attr',
		},
		imageAttribute: {
			doc: 'LDAP attribute used to store profile images for users',
			format: '*',
			default: undefined as string | undefined,
			env: 'LDAP_IMAGE_ATTR',
			arg: 'ldap-image-attr',
		},
		flagGroups: {
			doc: 'Mapping of Drawpile flags to LDAP group names',
			format: '*',
			default: {} as Record<string, string>,
		},
	},
});

try {
	config.loadFile('config.toml');
} catch (err) {} // eslint-disable-line no-empty

config.validate({ allowed: 'strict' });

export const CONFIG = config;
export default CONFIG;

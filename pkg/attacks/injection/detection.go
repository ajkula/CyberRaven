package injection

import (
	"strings"
	"time"

	"github.com/ajkula/cyberraven/pkg/utils"
)

// detectInjection - fonction unifiée de détection
func (it *InjectionTester) detectInjection(injectionType string, baseline, response *utils.HTTPResponse, payload string) bool {
	responseBody := strings.ToLower(response.BodyPreview)

	// Patterns de détection par type
	patterns := map[string][]string{
		"sql": {
			"sql syntax", "mysql_fetch", "ora-", "postgresql", "sqlite",
			"syntax error", "unclosed quotation", "quoted string not properly terminated",
			"microsoft ole db", "microsoft jet database", "odbc drivers error",
			"invalid column name", "table doesn't exist", "unknown column",
			"you have an error in your sql syntax", "warning: mysql_",
			"function.mysql", "mysql result", "mysqlclient version",
			"postgresql query failed", "supplied argument is not a valid postgresql",
			"ora-00933", "ora-00921", "ora-00936", "ora-01756",
			"microsoft access driver", "jdb-odbc",
		},
		"nosql": {
			"mongodb", "mongoose", "couchdb", "redis",
			"$where", "$regex", "$ne", "$gt", "$lt",
			"bson", "objectid", "aggregation",
		},
		"json": {
			"json parse error", "invalid json", "syntax error",
			"unexpected token", "malformed json",
		},
		"path": {
			"root:x:", "[boot loader]", "windows registry",
			"etc/passwd", "windows\\system32", "/etc/",
			"program files", "documents and settings",
		},
	}

	// Vérification des patterns
	if typePatterns, exists := patterns[injectionType]; exists {
		for _, pattern := range typePatterns {
			if strings.Contains(responseBody, pattern) {
				return true
			}
		}
	}

	// Vérifications spécifiques par type
	switch injectionType {
	case "sql":
		if baseline != nil {
			// Time-based blind SQL injection
			if response.Duration > baseline.Duration*3 && response.Duration > 5*time.Second {
				if strings.Contains(strings.ToLower(payload), "sleep") ||
					strings.Contains(strings.ToLower(payload), "waitfor") ||
					strings.Contains(strings.ToLower(payload), "benchmark") {
					return true
				}
			}

			// Boolean-based blind SQL injection
			if len(response.BodyPreview) != len(baseline.BodyPreview) {
				sizeDiff := abs(len(response.BodyPreview) - len(baseline.BodyPreview))
				if sizeDiff > 100 {
					return true
				}
			}

			// Status code changes
			if response.StatusCode != baseline.StatusCode && response.StatusCode == 500 {
				return true
			}
		}

	case "nosql":
		// Erreur 500 avec message d'erreur
		if response.StatusCode == 500 && strings.Contains(responseBody, "error") {
			return true
		}

	default:
		// Pour json et path, les patterns suffisent
	}

	return false
}

// detectDatabaseType attempts to identify the database type from error messages
func (it *InjectionTester) detectDatabaseType(responseBody string) string {
	responseBody = strings.ToLower(responseBody)

	dbTypes := map[string][]string{
		"MySQL":      {"mysql", "mysql_"},
		"PostgreSQL": {"postgresql", "postgres", "pgsql"},
		"Oracle":     {"oracle", "ora-"},
		"SQLite":     {"sqlite"},
		"MongoDB":    {"mongodb", "mongoose"},
		"Redis":      {"redis"},
	}

	for dbType, indicators := range dbTypes {
		for _, indicator := range indicators {
			if strings.Contains(responseBody, indicator) {
				return dbType
			}
		}
	}

	return "Unknown"
}

/**
 * write_tdengine.c - Plugin Collectd pour TDengine
 * Version: 2.13 - Fix auto-création tables avec clause USING
 *
 * V2.13 Fix:
 * - FIX CRITIQUE: Ajout clause USING <stable> TAGS(?, ?) dans les prepared statements
 *   Sans cette clause, taos_stmt_set_tbname_tags() ne peut pas auto-créer les tables
 *   si la STABLE n'existe pas encore (création asynchrone)
 * - Résout l'erreur -2147473917 en boucle (stale statement)
 *
 * V2.4 Improvements over V2.3:
 * - MAX_COLUMNS augmenté de 4 à 8 (support plus de métriques multi-colonnes)
 *   Permet par exemple : interface avec rx/tx + errors/drops = 4 colonnes
 *
 * V2.3 Features (conservées):
 * - CREATE TABLE asynchrone (thread dédié, zéro blocking)
 * - Queue thread-safe + cache optimiste
 * - Élimine la latence de ~5ms par nouvelle table
 *
 * V2.2 Features (conservées):
 * - Retry mechanism avec data_point_t binaires (plus de perte de données !)
 * - Exponential backoff pour les retries (configurable)
 * - Flush du retry buffer avant shutdown (récupération maximale)
 * - Statistiques détaillées (total_retried, total_retry_failed)
 * - FIX: Invalidation du stmt_cache lors de la reconnexion TDengine
 *
 * V2.1 Features (conservées):
 * - Support 1-8 colonnes - généralisation du binding
 * - Cache statement par (stable, num_cols)
 * - Performance: 4-5x throughput (50K → 200-250K metrics/s)
 *
 * V2.0 Features (conservées):
 * - Thread-safe circular buffer avec batching
 * - Prepared statements avec cache LRU
 * - SQL Injection prevention avec échappement
 * - Lock-free reads optimisées pour haute performance
 */

#include "collectd.h"
#include "plugin.h"
#include "utils/common/common.h"
#include "daemon/utils_llist.h"

#include <taos.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>  /* V2.11: Pour gettimeofday() */
#include <stdint.h>
#include <ctype.h>

#define PLUGIN_NAME "write_tdengine"
#define DEFAULT_DB "collectd_metrics"
#define BATCH_SIZE 5000
#define BATCH_TIMEOUT_MS 50
#define MAX_BUFFER_SIZE 100000
#define MAX_TABLE_CACHE 10000
#define TABLE_NAME_MAX 512
#define ESCAPED_STRING_MAX 256
#define SQL_CHUNK_SIZE 768

/* Codes d'erreur TDengine pour statements invalides
 * Ces codes indiquent que le statement doit être recréé après reconnexion */
#define TAOS_ERR_STMT_INVALID_1  -2147481327
#define TAOS_ERR_STMT_INVALID_2  -2147482327
#define TAOS_ERR_STMT_INVALID_3  -2147473917
#define TAOS_ERR_STMT_RANGE_LOW  -2147490000
#define TAOS_ERR_STMT_RANGE_HIGH -2147470000

/* Structure optimisée pour stocker les données brutes dans le buffer
 * V2.4: Support 1-8 colonnes avec TAGS (doublé de 4 à 8)
 * Taille: ~480 bytes (permet métriques multi-colonnes complexes)
 */
#define MAX_COLUMNS 8
typedef struct {
    char table_name[128];       /* Nom de la table de destination */
    char stable_name[64];       /* Nom de la super-table */
    char hostname[64];          /* Tag: hostname */
    char plugin_instance[128];  /* Tag: plugin_instance */
    uint64_t timestamp;         /* Timestamp en millisecondes (precision='ms') */

    int64_t values[MAX_COLUMNS]; /* Valeurs des colonnes (max 8) */
    uint8_t num_values;         /* Nombre de colonnes utilisées (1-8) */
    char padding[7];            /* Alignement pour performance */
} data_point_t;

/* Structure pour un lot de données à réessayer (V2.2 - Binary retry) */
typedef struct {
  data_point_t *points;      /* Array de data points binaires */
  size_t count;              /* Nombre de points dans le batch */
  size_t capacity;           /* Capacité allouée (pour resize) */
  int attempts_made;         /* Nombre de tentatives de retry */
  cdtime_t initial_timestamp; /* Timestamp du premier échec */
  cdtime_t last_retry;       /* Timestamp de la dernière tentative */
} retry_batch_t;

/* Cache simple des tables créées pour éviter les CREATE TABLE répétées */
typedef struct {
    char table_names[MAX_TABLE_CACHE][TABLE_NAME_MAX];
    volatile uint32_t count;
    pthread_rwlock_t lock;
} table_cache_t;

/* Cache entry pour un prepared statement
 * Chaque statement est associé à une table spécifique et réutilisé
 */
#define MAX_STMT_CACHE 1000

typedef struct {
    char stable_name[64];       /* Nom de la super-table pour ce statement */
    TAOS_STMT *stmt;            /* Handle du prepared statement */
    uint64_t last_used;         /* Timestamp pour LRU eviction */
    uint8_t num_columns;        /* Nombre de colonnes (1-4) */
    bool is_active;             /* true si l'entry est utilisée */
} stmt_cache_entry_t;

/* Cache global des prepared statements avec gestion LRU */
typedef struct {
    stmt_cache_entry_t entries[MAX_STMT_CACHE];
    size_t count;
    pthread_rwlock_t lock;      /* Read-write lock pour accès concurrent */
} stmt_cache_t;

/* Configuration d'un niveau de rétention (équivalent RRA) */
typedef struct retention_config {
    int duration_seconds;       /* Durée de rétention totale */
    int resolution_seconds;     /* Résolution (step/pdp_per_row) */
    char database[128];         /* Nom de la database pour ce niveau */
    bool is_raw;                /* true si c'est la base brute (pas d'agrégation) */
    struct retention_config *next;
} retention_config_t;

/* Structure pour une règle de mapping configurable */
typedef struct mapping_rule {
    char *plugin;
    char *type;
    char *stable;
    struct mapping_rule *next;
} mapping_rule_t;

/* Configuration et état global thread-safe */
typedef struct {
    /* Connexion */
    TAOS *conn;

    /* Configuration de connexion */
    char *host;
    int port;
    char *user;
    char *password;
    char *database;

    /* Timing de reconnexion */
    cdtime_t last_connect_attempt;
    cdtime_t reconnect_interval;
    volatile uint64_t reconnect_attempts;

    /* Circular buffer ring */
    data_point_t *buffer_array;
    size_t buffer_capacity;
    volatile size_t write_idx;
    volatile size_t read_idx;

    /* Synchronisation */
    pthread_mutex_t write_lock;
    pthread_mutex_t read_lock;
    pthread_mutex_t buffer_cond_lock;  /* Mutex dédié pour buffer_cond */
    pthread_cond_t buffer_cond;
    pthread_mutex_t conn_lock;  /* Protège la connexion */

    pthread_t flush_thread;
    volatile bool running;

    /* Statistiques atomiques */
    volatile uint64_t total_written;
    volatile uint64_t total_errors;
    volatile uint64_t total_dropped;
    volatile uint64_t batch_flushes;
    volatile uint64_t reconnections;
    volatile uint64_t total_retried;      /* Batches réessayés avec succès */
    volatile uint64_t total_retry_failed; /* Batches échoués après tous les retry */

    /* Cache des tables */
    table_cache_t table_cache;

    /* Cache des super-tables créées (pour éviter CREATE STABLE répétés) */
    table_cache_t stable_cache;

    /* Cache des prepared statements (optimisation V2.0) */
    stmt_cache_t stmt_cache;

    /* Liste chaînée des configurations de rétention */
    retention_config_t *retentions;

    /* Liste chaînée des règles de mapping */
    mapping_rule_t *mappings;

    /* Configuration de la logique de réessai */
    bool enable_retry;
    int retry_attempts;
    int retry_delay_ms;
    size_t max_retry_buffer_size_bytes;

    /* Tampon pour les lots à réessayer */
    llist_t *retry_buffer;
    size_t current_retry_buffer_size;
    pthread_mutex_t retry_buffer_lock;

    /* V2.3: Thread asynchrone pour CREATE TABLE */
    pthread_t create_table_thread;
    llist_t *create_table_queue;      /* Queue des super-tables à créer */
    pthread_mutex_t create_table_lock;
    pthread_cond_t create_table_cond;
    volatile uint64_t total_tables_created_async; /* Statistique */

    /* V2.11: Métriques internes du plugin (self-monitoring) */
    bool internal_metrics_enabled;
    int internal_metrics_interval;     /* Intervalle d'écriture en secondes (défaut: 60) */
    int internal_metrics_retention_days;  /* Rétention en jours (défaut: 30) */
    volatile uint64_t total_latency_us;     /* Latence cumulée en microsecondes */
    volatile uint64_t latency_samples;       /* Nombre d'échantillons de latence */
    volatile uint64_t stables_created_success;   /* STABLEs créées avec succès */
    volatile uint64_t stables_created_failed;    /* Échecs de création STABLE */
    volatile uint64_t streams_created_success;   /* Streams créés avec succès */
    volatile uint64_t streams_created_failed;    /* Échecs de création stream */
    volatile uint64_t stmt_cache_hits;           /* Hits dans le cache de statements */
    volatile uint64_t stmt_cache_misses;         /* Miss (recréation de statement) */

} config_t;

static config_t *g_config = NULL;

/* Forward declarations for tdengine connection functions */
static int tdengine_connect(config_t *conf);
static int tdengine_ensure_connected(config_t *conf);
static int create_aggregation_streams_for_stable(config_t *conf, const char *stable_name);

static const mapping_rule_t* find_mapping_rule(const char *plugin, const char *type) {
    for (mapping_rule_t *rule = g_config->mappings; rule != NULL; rule = rule->next) {
        if (strcmp(rule->plugin, plugin) != 0) {
            continue;
        }
        // Check for wildcard or exact match on type
        if (strcmp(rule->type, "*") == 0 || strcmp(rule->type, type) == 0) {
            return rule;
        }
    }
    return NULL;
}

/**
 * Échappe les caractères SQL dangereux dans une chaîne
 * Remplace les caractères spéciaux par des underscores
 * Performance: O(n), pas d'allocation mémoire
 */
static void sql_escape_identifier(char *dest, size_t dest_size,
                                   const char *src) {
    size_t i = 0;
    for (; src[0] && i < dest_size - 1; src++) {
        /* Autorise seulement alphanumériques et underscore */
        if (isalnum((unsigned char)src[0]) || src[0] == '_') {
            dest[i++] = src[0];
        } else {
            /* Remplace les caractères spéciaux par underscore */
            if (i < dest_size - 1) {
                dest[i++] = '_';
            }
        }
    }
    dest[i] = '\0';
}

/**
 * Construit le nom de la table avec échappement SQL
 * Inclut plugin_instance ET type_instance pour différencier les CAKE TINs, HTB classes, etc.
 * Optimisé: allocation stack, pas de malloc
 */
static void build_table_name(char *dest, size_t size,
                             const char *stable,
                             const char *plugin_instance,
                             const char *type_instance,
                             const char *host) {
    char escaped_plugin_inst[ESCAPED_STRING_MAX];
    char escaped_type_inst[ESCAPED_STRING_MAX];
    char escaped_host[ESCAPED_STRING_MAX];

    /* Échappe les valeurs dangereuses */
    sql_escape_identifier(escaped_plugin_inst, sizeof(escaped_plugin_inst),
                         (plugin_instance && plugin_instance[0]) ? plugin_instance : "");
    sql_escape_identifier(escaped_type_inst, sizeof(escaped_type_inst),
                         (type_instance && type_instance[0]) ? type_instance : "");
    sql_escape_identifier(escaped_host, sizeof(escaped_host), host);

    /* Construit le nom: stable_plugin_instance_type_instance
     * Exemples:
     * - tc_bytes_eth1_14_tin0_cake_4_0 (netlink: plugin_instance + type_instance)
     * - cpu_percent_idle (cpu: type_instance seul)
     * - interface_octets_eth0 (interface: plugin_instance seul)
     */
    if (escaped_plugin_inst[0] && escaped_type_inst[0]) {
        /* Cas complet: stable + plugin_instance + type_instance
         * Exemple: tc_bytes_eth1_14_tin0_cake_4_0 */
        int ret = snprintf(dest, size, "%s_%s_%s", stable, escaped_plugin_inst, escaped_type_inst);
        if (ret < 0 || ret >= (int)size) {
            /* Fallback: stable + plugin_instance seulement */
            snprintf(dest, size, "%s_%s", stable, escaped_plugin_inst);
        }
    } else if (escaped_plugin_inst[0]) {
        /* Seulement plugin_instance disponible
         * Exemple: interface_octets_eth0 */
        snprintf(dest, size, "%s_%s", stable, escaped_plugin_inst);
    } else if (escaped_type_inst[0]) {
        /* Seulement type_instance disponible (CPU, Memory, etc.)
         * Exemple: cpu_percent_idle, memory_used */
        snprintf(dest, size, "%s_%s", stable, escaped_type_inst);
    } else {
        /* Fallback: utiliser le host */
        snprintf(dest, size, "%s_%s", stable, escaped_host);
    }
}

/**
 * V2.1: Cache des tables individuelles pour éviter CREATE TABLE répétées
 * V2.6: OBSOLÈTE - Plus utilisé depuis taos_stmt_set_tbname_tags()
 * Conservé pour compatibilité de structure mais jamais appelé
 */
__attribute__((unused))
static bool table_cache_exists(config_t *conf, const char *table_name) {
    pthread_rwlock_rdlock(&conf->table_cache.lock);
    for (uint32_t i = 0; i < conf->table_cache.count; i++) {
        if (strcmp(conf->table_cache.table_names[i], table_name) == 0) {
            pthread_rwlock_unlock(&conf->table_cache.lock);
            return true;
        }
    }
    pthread_rwlock_unlock(&conf->table_cache.lock);
    return false;
}

__attribute__((unused))
static void table_cache_add(config_t *conf, const char *table_name) {
    pthread_rwlock_wrlock(&conf->table_cache.lock);
    if (conf->table_cache.count < MAX_TABLE_CACHE) {
        sstrncpy(conf->table_cache.table_names[conf->table_cache.count],
                table_name, TABLE_NAME_MAX);
        conf->table_cache.count++;
    }
    pthread_rwlock_unlock(&conf->table_cache.lock);
}

/**
 * Vérifie si une super-table existe dans le cache
 */
static bool stable_cache_exists(config_t *conf, const char *stable_name) {
    pthread_rwlock_rdlock(&conf->stable_cache.lock);
    for (uint32_t i = 0; i < conf->stable_cache.count; i++) {
        if (strcmp(conf->stable_cache.table_names[i], stable_name) == 0) {
            pthread_rwlock_unlock(&conf->stable_cache.lock);
            return true;
        }
    }
    pthread_rwlock_unlock(&conf->stable_cache.lock);
    return false;
}

/**
 * Ajoute une super-table au cache
 */
static void stable_cache_add(config_t *conf, const char *stable_name) {
    pthread_rwlock_wrlock(&conf->stable_cache.lock);
    if (conf->stable_cache.count < MAX_TABLE_CACHE) {
        sstrncpy(conf->stable_cache.table_names[conf->stable_cache.count],
                stable_name, TABLE_NAME_MAX);
        conf->stable_cache.count++;
    }
    pthread_rwlock_unlock(&conf->stable_cache.lock);
}

/**
 * V2.11: Écrit les métriques internes du plugin vers TDengine
 * Cette fonction collecte et envoie les métriques de santé du plugin
 * Return: 0 si OK, -1 si erreur
 */
/* Forward declaration */
static TAOS_STMT* get_or_create_stmt(config_t *conf, const char *stable_name, uint8_t num_columns);

/* V2.11: Structure pour une métrique interne */
typedef struct {
    const char *name;
    const char *type;
    double value;
} internal_metric_t;

/**
 * V2.11: Écrit les métriques internes du plugin (self-monitoring)
 * Utilise des prepared statements pour cohérence avec le reste du plugin
 */
static int write_internal_metrics(config_t *conf) {
    static _Bool stable_created = 0;

    if (!conf || !conf->internal_metrics_enabled || !conf->running) {
        return 0;
    }

    /* Vérifie la connexion */
    if (tdengine_ensure_connected(conf) != 0) {
        return -1;
    }

    /* Crée la STABLE une seule fois */
    if (!stable_created) {
        pthread_mutex_lock(&conf->conn_lock);
        if (!conf->conn) {
            pthread_mutex_unlock(&conf->conn_lock);
            return -1;
        }

        const char *create_sql =
            "CREATE STABLE IF NOT EXISTS write_tdengine_metrics ("
            "ts TIMESTAMP, `value` DOUBLE"
            ") TAGS ("
            "hostname NCHAR(64), metric_name NCHAR(128), metric_type NCHAR(16)"
            ")";

        TAOS_RES *res = taos_query(conf->conn, create_sql);
        int err = res ? taos_errno(res) : -1;
        if (err != 0) {
            WARNING(PLUGIN_NAME ": Failed to create internal metrics STABLE: %s",
                    res ? taos_errstr(res) : "no result");
            if (res) taos_free_result(res);
            pthread_mutex_unlock(&conf->conn_lock);
            return -1;
        }
        taos_free_result(res);
        pthread_mutex_unlock(&conf->conn_lock);
        stable_created = 1;
        INFO(PLUGIN_NAME ": Created internal metrics STABLE");
    }

    /* Récupère le hostname */
    char hostname[DATA_MAX_NAME_LEN];
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        sstrncpy(hostname, "localhost", sizeof(hostname));
    }
    hostname[DATA_MAX_NAME_LEN - 1] = '\0';

    /* Calcule les métriques */
    size_t buffer_usage;
    pthread_mutex_lock(&conf->write_lock);
    if (conf->write_idx >= conf->read_idx) {
        buffer_usage = conf->write_idx - conf->read_idx;
    } else {
        buffer_usage = conf->buffer_capacity - conf->read_idx + conf->write_idx;
    }
    pthread_mutex_unlock(&conf->write_lock);

    double latency_ms = 0.0;
    uint64_t samples = __sync_fetch_and_add(&conf->latency_samples, 0);
    if (samples > 0) {
        uint64_t total_us = __sync_fetch_and_add(&conf->total_latency_us, 0);
        latency_ms = (double)total_us / (double)samples / 1000.0;
    }

    pthread_mutex_lock(&conf->retry_buffer_lock);
    size_t retry_buffer_size = conf->current_retry_buffer_size;
    pthread_mutex_unlock(&conf->retry_buffer_lock);

    int conn_status = 0;
    pthread_mutex_lock(&conf->conn_lock);
    conn_status = (conf->conn != NULL) ? 1 : 0;
    pthread_mutex_unlock(&conf->conn_lock);

    /* Tableau des 13 métriques */
    internal_metric_t metrics[] = {
        {"points_written", "counter", (double)__sync_fetch_and_add(&conf->total_written, 0)},
        {"points_dropped", "counter", (double)__sync_fetch_and_add(&conf->total_dropped, 0)},
        {"batch_flushes", "counter", (double)__sync_fetch_and_add(&conf->batch_flushes, 0)},
        {"reconnections", "counter", (double)__sync_fetch_and_add(&conf->reconnections, 0)},
        {"retries", "counter", (double)__sync_fetch_and_add(&conf->total_retried, 0)},
        {"retry_failed", "counter", (double)__sync_fetch_and_add(&conf->total_retry_failed, 0)},
        {"stables_created", "counter", (double)__sync_fetch_and_add(&conf->stables_created_success, 0)},
        {"stmt_cache_hits", "counter", (double)__sync_fetch_and_add(&conf->stmt_cache_hits, 0)},
        {"stmt_cache_misses", "counter", (double)__sync_fetch_and_add(&conf->stmt_cache_misses, 0)},
        {"buffer_usage", "gauge", (double)buffer_usage},
        {"retry_buffer_size", "gauge", (double)retry_buffer_size},
        {"latency_ms", "gauge", latency_ms},
        {"conn_status", "gauge", (double)conn_status}
    };

    int num_metrics = sizeof(metrics) / sizeof(metrics[0]);
    int64_t now = (int64_t)CDTIME_T_TO_MS(cdtime());  /* Timestamp en millisecondes */

    /* Crée UN SEUL statement pour toutes les métriques (optimisation) */
    pthread_mutex_lock(&conf->conn_lock);
    if (!conf->conn) {
        pthread_mutex_unlock(&conf->conn_lock);
        return -1;
    }
    TAOS_STMT *stmt = taos_stmt_init(conf->conn);
    pthread_mutex_unlock(&conf->conn_lock);

    if (!stmt) {
        WARNING(PLUGIN_NAME ": Failed to create statement for internal metrics");
        return -1;
    }

    /* Prépare le SQL UNE SEULE FOIS */
    const char *sql = "INSERT INTO ? USING write_tdengine_metrics TAGS(?, ?, ?) VALUES(?, ?)";
    int ret = taos_stmt_prepare(stmt, sql, 0);
    if (ret != 0) {
        WARNING(PLUGIN_NAME ": taos_stmt_prepare failed: %s", taos_stmt_errstr(stmt));
        taos_stmt_close(stmt);
        return -1;
    }

    int32_t hostname_len = (int32_t)strlen(hostname);
    int written = 0;

    /* Boucle sur les métriques - réutilise le même statement */
    for (int i = 0; i < num_metrics; i++) {
        /* Génère le nom de la child table */
        char child_table[256];
        snprintf(child_table, sizeof(child_table), "write_tdengine_metrics_%s_%s",
                 hostname, metrics[i].name);

        /* Prépare les 3 TAGS : hostname, metric_name, metric_type */
        TAOS_MULTI_BIND tags[3];
        memset(tags, 0, sizeof(tags));

        tags[0].buffer_type = TSDB_DATA_TYPE_NCHAR;
        tags[0].buffer = (void *)hostname;
        tags[0].buffer_length = hostname_len;
        tags[0].length = &hostname_len;
        tags[0].is_null = NULL;
        tags[0].num = 1;

        int32_t metric_name_len = (int32_t)strlen(metrics[i].name);
        tags[1].buffer_type = TSDB_DATA_TYPE_NCHAR;
        tags[1].buffer = (void *)metrics[i].name;
        tags[1].buffer_length = metric_name_len;
        tags[1].length = &metric_name_len;
        tags[1].is_null = NULL;
        tags[1].num = 1;

        int32_t metric_type_len = (int32_t)strlen(metrics[i].type);
        tags[2].buffer_type = TSDB_DATA_TYPE_NCHAR;
        tags[2].buffer = (void *)metrics[i].type;
        tags[2].buffer_length = metric_type_len;
        tags[2].length = &metric_type_len;
        tags[2].is_null = NULL;
        tags[2].num = 1;

        /* Set table name avec auto-création via TAGS */
        ret = taos_stmt_set_tbname_tags(stmt, child_table, tags);
        if (ret != 0) {
            WARNING(PLUGIN_NAME ": taos_stmt_set_tbname_tags failed for %s: %s",
                    child_table, taos_stmt_errstr(stmt));
            continue;
        }

        /* Prépare les bindings : timestamp + value */
        TAOS_MULTI_BIND binds[2];
        memset(binds, 0, sizeof(binds));

        binds[0].buffer_type = TSDB_DATA_TYPE_TIMESTAMP;
        binds[0].buffer = &now;
        binds[0].buffer_length = sizeof(int64_t);
        binds[0].length = NULL;
        binds[0].is_null = NULL;
        binds[0].num = 1;

        binds[1].buffer_type = TSDB_DATA_TYPE_DOUBLE;
        binds[1].buffer = &metrics[i].value;
        binds[1].buffer_length = sizeof(double);
        binds[1].length = NULL;
        binds[1].is_null = NULL;
        binds[1].num = 1;

        ret = taos_stmt_bind_param_batch(stmt, binds);
        if (ret != 0) {
            WARNING(PLUGIN_NAME ": taos_stmt_bind_param_batch failed for %s: %s",
                    metrics[i].name, taos_stmt_errstr(stmt));
            continue;
        }

        ret = taos_stmt_add_batch(stmt);
        if (ret != 0) {
            WARNING(PLUGIN_NAME ": taos_stmt_add_batch failed for %s: %s",
                    metrics[i].name, taos_stmt_errstr(stmt));
            continue;
        }

        written++;
    }

    /* Execute UNE SEULE FOIS pour tout le batch */
    if (written > 0) {
        ret = taos_stmt_execute(stmt);
        if (ret != 0) {
            WARNING(PLUGIN_NAME ": taos_stmt_execute failed: %s", taos_stmt_errstr(stmt));
        } else {
            INFO(PLUGIN_NAME ": Internal metrics: wrote %d metrics (ts=%"PRId64")", written, now);
        }
    } else {
        INFO(PLUGIN_NAME ": Internal metrics: no metrics to write");
    }

    /* Ferme le statement UNE SEULE FOIS */
    taos_stmt_close(stmt);

    return 0;
}

/**
 * V2.3: Crée une super-table de manière SYNCHRONE
 * Cette fonction est utilisée par le thread asynchrone de création
 * Auto-détection du schéma basée sur le nom de la super-table
 * Return: 0 si OK, -1 si erreur
 */
static int ensure_stable_exists_sync(config_t *conf, const char *stable_name) {
    /* V2.8: Vérifie running pour shutdown rapide */
    if (!conf->running) {
        DEBUG(PLUGIN_NAME ": Skipping STABLE creation during shutdown: %s", stable_name);
        return -1;
    }

    /* Vérifie d'abord le cache pour éviter les requêtes inutiles */
    if (stable_cache_exists(conf, stable_name))
        return 0;

    /* Détermine le schéma selon le nom de la super-table
     * - interface_* : 2 colonnes (rx, tx)
     * - tc_* : 1 colonne (val)
     * - autres : 1 colonne (val)
     */
    char create_sql[512];
    int ret;

    if (strstr(stable_name, "interface_octets") != NULL ||
        strstr(stable_name, "interface_packets") != NULL ||
        strstr(stable_name, "interface_errors") != NULL ||
        strstr(stable_name, "interface_drops") != NULL) {
        /* Types interface avec rx/tx */
        ret = snprintf(create_sql, sizeof(create_sql),
                       "CREATE STABLE IF NOT EXISTS %s ("
                       "ts TIMESTAMP, rx BIGINT, tx BIGINT"
                       ") TAGS ("
                       "hostname NCHAR(64), plugin_instance NCHAR(128)"
                       ")",
                       stable_name);
    } else {
        /* Types simples (TC, etc.) avec une seule valeur */
        ret = snprintf(create_sql, sizeof(create_sql),
                       "CREATE STABLE IF NOT EXISTS %s ("
                       "ts TIMESTAMP, val BIGINT"
                       ") TAGS ("
                       "hostname NCHAR(64), plugin_instance NCHAR(128)"
                       ")",
                       stable_name);
    }

    if (ret < 0 || ret >= (int)sizeof(create_sql)) {
        ERROR(PLUGIN_NAME ": SQL buffer overflow for CREATE STABLE");
        return -1;
    }

    TAOS_RES *res = NULL;
    pthread_mutex_lock(&conf->conn_lock);
    if (conf->conn) {
        DEBUG(PLUGIN_NAME ": Creating STABLE %s", stable_name);
        res = taos_query(conf->conn, create_sql);
    }
    pthread_mutex_unlock(&conf->conn_lock);

    if (!res) {
        ERROR(PLUGIN_NAME ": Failed to create STABLE %s: no result", stable_name);
        __sync_fetch_and_add(&conf->stables_created_failed, 1);  /* V2.11: Métrique interne */
        return -1;
    }

    int err = taos_errno(res);
    if (err != 0) {
        WARNING(PLUGIN_NAME ": CREATE STABLE %s failed: %s",
                stable_name, taos_errstr(res));
        taos_free_result(res);
        __sync_fetch_and_add(&conf->stables_created_failed, 1);  /* V2.11: Métrique interne */
        return -1;
    }

    taos_free_result(res);
    stable_cache_add(conf, stable_name);
    __sync_fetch_and_add(&conf->stables_created_success, 1);  /* V2.11: Métrique interne */
    INFO(PLUGIN_NAME ": Created STABLE %s successfully", stable_name);

    /* V2.8: Vérifie running avant de créer les streams (peut prendre 5-6s) */
    if (!conf->running) {
        INFO(PLUGIN_NAME ": Skipping stream creation during shutdown for STABLE %s", stable_name);
        return 0;
    }

    /* V2.11: Ne pas créer de streams pour les métriques internes */
    if (strcmp(stable_name, "write_tdengine_metrics") == 0) {
        INFO(PLUGIN_NAME ": Skipping stream creation for internal metrics STABLE");
        return 0;
    }

    /* Crée les STREAMs d'agrégation pour cette nouvelle super-table */
    if (conf->retentions != NULL) {
        create_aggregation_streams_for_stable(conf, stable_name);
    }

    return 0;
}

/**
 * V2.3: Thread dédié pour créer les tables de manière asynchrone
 * Traite la queue create_table_queue et exécute les CREATE STABLE
 */
static void *create_table_thread_func(void *arg) {
    config_t *conf = (config_t *)arg;

    INFO(PLUGIN_NAME ": Async CREATE TABLE thread started");

    while (conf->running) {
        pthread_mutex_lock(&conf->create_table_lock);

        /* Attend qu'il y ait des tables à créer ou que le plugin s'arrête */
        while (conf->running && llist_size(conf->create_table_queue) == 0) {
            struct timespec timeout;
            clock_gettime(CLOCK_REALTIME, &timeout);
            timeout.tv_sec += 1;  /* Timeout de 1 seconde */
            pthread_cond_timedwait(&conf->create_table_cond, &conf->create_table_lock, &timeout);
        }

        /* Récupère la première table à créer */
        llentry_t *entry = llist_head(conf->create_table_queue);
        if (entry != NULL) {
            char *stable_name = (char *)entry->value;
            llist_remove(conf->create_table_queue, entry);
            pthread_mutex_unlock(&conf->create_table_lock);

            /* V2.7: Vérifie running après avoir récupéré l'item pour shutdown rapide */
            if (!conf->running) {
                DEBUG(PLUGIN_NAME ": Skipping STABLE creation during shutdown: %s", stable_name);
                sfree(stable_name);
                continue;  /* Retourne au début de la boucle while(running) */
            }

            /* Crée la table de manière synchrone (on est dans le thread dédié) */
            INFO(PLUGIN_NAME ": Async thread creating STABLE %s", stable_name);
            if (ensure_stable_exists_sync(conf, stable_name) == 0) {
                __sync_fetch_and_add(&conf->total_tables_created_async, 1);
            }

            /* Libère la mémoire */
            sfree(stable_name);
        } else {
            pthread_mutex_unlock(&conf->create_table_lock);
        }
    }

    /* Flush final de la queue avant de quitter */
    pthread_mutex_lock(&conf->create_table_lock);
    llentry_t *entry;
    while ((entry = llist_head(conf->create_table_queue)) != NULL) {
        char *stable_name = (char *)entry->value;
        llist_remove(conf->create_table_queue, entry);
        pthread_mutex_unlock(&conf->create_table_lock);

        DEBUG(PLUGIN_NAME ": Async thread (shutdown) creating STABLE %s", stable_name);
        ensure_stable_exists_sync(conf, stable_name);
        sfree(stable_name);

        pthread_mutex_lock(&conf->create_table_lock);
    }
    pthread_mutex_unlock(&conf->create_table_lock);

    INFO(PLUGIN_NAME ": Async CREATE TABLE thread stopped");
    return NULL;
}

/**
 * V2.3: Envoie une requête de création de table au thread asynchrone
 * Cache optimiste : marque immédiatement la table comme "en cours" pour éviter les doublons
 * Return: toujours 0 (non-bloquant)
 */
static int ensure_stable_exists_async(config_t *conf, const char *stable_name) {
    /* Vérifie d'abord le cache pour éviter les requêtes inutiles */
    if (stable_cache_exists(conf, stable_name))
        return 0;

    /* Ajoute à la queue du thread asynchrone SANS ajouter au cache
     * Le cache sera mis à jour par ensure_stable_exists_sync() après création réussie */
    char *stable_copy = sstrdup(stable_name);
    if (stable_copy) {
        pthread_mutex_lock(&conf->create_table_lock);

        /* Vérifie si déjà dans la queue pour éviter les doublons */
        bool already_queued = false;
        for (llentry_t *e = llist_head(conf->create_table_queue); e != NULL; e = e->next) {
            if (strcmp((char *)e->value, stable_name) == 0) {
                already_queued = true;
                break;
            }
        }

        if (!already_queued) {
            llentry_t *entry = llentry_create(stable_copy, stable_copy);
            if (entry) {
                llist_append(conf->create_table_queue, entry);
                pthread_cond_signal(&conf->create_table_cond);
                INFO(PLUGIN_NAME ": Queued STABLE %s for async creation (queue size: %d)", stable_name, llist_size(conf->create_table_queue));
            } else {
                sfree(stable_copy);
            }
        } else {
            sfree(stable_copy);
        }
        pthread_mutex_unlock(&conf->create_table_lock);
    }

    /* Return toujours 0 - non bloquant
     * Si la table n'existe pas encore, le retry mechanism s'occupera de réessayer */
    return 0;
}

/**
 * Fonction de comparaison pour qsort() - trie par table_name
 * Permet de grouper les insertions par table pour optimiser les prepared statements
 */
static int compare_table_name(const void *a, const void *b) {
    const data_point_t *dp_a = (const data_point_t *)a;
    const data_point_t *dp_b = (const data_point_t *)b;
    return strcmp(dp_a->table_name, dp_b->table_name);
}

/**
 * Invalide tous les prepared statements en cache (V2.2)
 *
 * Appelé lors d'une reconnexion à TDengine pour s'assurer que tous
 * les statements sont recréés avec la nouvelle connexion.
 *
 * IMPORTANT: Doit être appelé APRÈS avoir fermé l'ancienne connexion
 * et AVANT de réutiliser des statements.
 */
static void invalidate_stmt_cache(config_t *conf) {
    if (!conf) return;

    pthread_rwlock_wrlock(&conf->stmt_cache.lock);

    size_t invalidated = 0;
    for (size_t i = 0; i < conf->stmt_cache.count; i++) {
        if (conf->stmt_cache.entries[i].is_active &&
            conf->stmt_cache.entries[i].stmt) {
            taos_stmt_close(conf->stmt_cache.entries[i].stmt);
            conf->stmt_cache.entries[i].stmt = NULL;
            conf->stmt_cache.entries[i].is_active = false;
            invalidated++;
        }
    }
    conf->stmt_cache.count = 0;

    pthread_rwlock_unlock(&conf->stmt_cache.lock);

    if (invalidated > 0) {
        INFO(PLUGIN_NAME ": Invalidated %zu cached statements due to reconnection", invalidated);
    }
}

/**
 * Récupère ou crée un prepared statement pour une super-table donnée (V3.0)
 *
 * Cache LRU avec read-write lock pour performance :
 * - Lecture parallèle sans contention (cache hit)
 * - Write lock seulement pour ajout/éviction (cache miss)
 * - Un statement par (stable_name, num_columns) - réutilisé pour toutes les tables
 *
 * @param conf Configuration globale
 * @param stable_name Nom de la super-table
 * @param num_columns Nombre de colonnes (1-4)
 * @return Handle du prepared statement, ou NULL en cas d'erreur
 */
static TAOS_STMT* get_or_create_stmt(config_t *conf, const char *stable_name, uint8_t num_columns) {
    /* Phase 1: Recherche en lecture seule (accès concurrent sans contention) */
    pthread_rwlock_rdlock(&conf->stmt_cache.lock);

    for (size_t i = 0; i < conf->stmt_cache.count; i++) {
        if (!conf->stmt_cache.entries[i].is_active) {
            continue;
        }

        if (strcmp(conf->stmt_cache.entries[i].stable_name, stable_name) == 0 &&
            conf->stmt_cache.entries[i].num_columns == num_columns) {

            /* Cache hit! */
            TAOS_STMT *stmt = conf->stmt_cache.entries[i].stmt;
            conf->stmt_cache.entries[i].last_used = (uint64_t)time(NULL);
            pthread_rwlock_unlock(&conf->stmt_cache.lock);

            __sync_fetch_and_add(&conf->stmt_cache_hits, 1);  /* V2.11: Métrique interne */
            DEBUG(PLUGIN_NAME ": Statement cache HIT for stable %s (%d cols)", stable_name, num_columns);
            return stmt;
        }
    }

    pthread_rwlock_unlock(&conf->stmt_cache.lock);

    /* Phase 2: Cache miss - créer un nouveau statement (write lock) */
    pthread_rwlock_wrlock(&conf->stmt_cache.lock);

    /* Double-check: un autre thread a peut-être ajouté pendant qu'on attendait le write lock */
    for (size_t i = 0; i < conf->stmt_cache.count; i++) {
        if (!conf->stmt_cache.entries[i].is_active) {
            continue;
        }

        if (strcmp(conf->stmt_cache.entries[i].stable_name, stable_name) == 0 &&
            conf->stmt_cache.entries[i].num_columns == num_columns) {

            TAOS_STMT *stmt = conf->stmt_cache.entries[i].stmt;
            conf->stmt_cache.entries[i].last_used = (uint64_t)time(NULL);
            pthread_rwlock_unlock(&conf->stmt_cache.lock);
            return stmt;
        }
    }

    /* Créer le nouveau statement */
    __sync_fetch_and_add(&conf->stmt_cache_misses, 1);  /* V2.11: Métrique interne */
    TAOS_STMT *stmt = NULL;

    pthread_mutex_lock(&conf->conn_lock);
    if (conf->conn) {
        stmt = taos_stmt_init(conf->conn);
    }
    pthread_mutex_unlock(&conf->conn_lock);

    if (!stmt) {
        ERROR(PLUGIN_NAME ": Failed to init statement for stable %s", stable_name);
        pthread_rwlock_unlock(&conf->stmt_cache.lock);
        return NULL;
    }

    /* Construire le SQL avec clause USING pour auto-création de table
     * La clause USING <stable> TAGS(?, ?) permet à taos_stmt_set_tbname_tags()
     * de créer automatiquement la table si elle n'existe pas.
     *
     * Format: INSERT INTO ? USING <stable> TAGS(?, ?) VALUES (?, ?, ...)
     * - 2 TAGS: hostname (NCHAR), plugin_instance (NCHAR)
     * - 1 timestamp + N colonnes de valeurs */
    char sql[256];
    char placeholders[64] = "?";  /* Timestamp */

    for (uint8_t i = 0; i < num_columns; i++) {
        strcat(placeholders, ", ?");
    }

    snprintf(sql, sizeof(sql), "INSERT INTO ? USING %s TAGS(?, ?) VALUES (%s)",
             stable_name, placeholders);

    int ret = taos_stmt_prepare(stmt, sql, 0);
    if (ret != 0) {
        ERROR(PLUGIN_NAME ": Failed to prepare statement for %s (%d cols): %s",
              stable_name, num_columns, taos_stmt_errstr(stmt));
        taos_stmt_close(stmt);
        pthread_rwlock_unlock(&conf->stmt_cache.lock);
        return NULL;
    }

    /* Trouver un slot libre ou évincer la plus ancienne entrée (LRU) */
    size_t target_idx = conf->stmt_cache.count;

    if (conf->stmt_cache.count >= MAX_STMT_CACHE) {
        /* Cache plein - trouver l'entrée la moins récemment utilisée */
        uint64_t oldest_time = UINT64_MAX;

        for (size_t i = 0; i < MAX_STMT_CACHE; i++) {
            if (!conf->stmt_cache.entries[i].is_active) {
                target_idx = i;
                break;
            }

            if (conf->stmt_cache.entries[i].last_used < oldest_time) {
                oldest_time = conf->stmt_cache.entries[i].last_used;
                target_idx = i;
            }
        }

        /* Fermer le statement évincé */
        if (conf->stmt_cache.entries[target_idx].stmt) {
            DEBUG(PLUGIN_NAME ": Evicting cached statement for stable %s (LRU)",
                  conf->stmt_cache.entries[target_idx].stable_name);
            taos_stmt_close(conf->stmt_cache.entries[target_idx].stmt);
        }
    } else {
        target_idx = conf->stmt_cache.count;
        conf->stmt_cache.count++;
    }

    /* Stocker dans le cache */
    sstrncpy(conf->stmt_cache.entries[target_idx].stable_name, stable_name,
             sizeof(conf->stmt_cache.entries[target_idx].stable_name));
    conf->stmt_cache.entries[target_idx].stmt = stmt;
    conf->stmt_cache.entries[target_idx].last_used = (uint64_t)time(NULL);
    conf->stmt_cache.entries[target_idx].num_columns = num_columns;
    conf->stmt_cache.entries[target_idx].is_active = true;

    pthread_rwlock_unlock(&conf->stmt_cache.lock);

    DEBUG(PLUGIN_NAME ": Statement cache MISS - created new statement for stable %s (%d cols, SQL: %s, cache size: %zu)",
          stable_name, num_columns, sql, conf->stmt_cache.count);

    return stmt;
}

/**
 * Ajoute un data_point binaire au buffer circulaire (V2.0)
 * Thread-safe avec mutex pour le writer
 * Performance: ~microseconde pour copie de 160 bytes (vs 768 en V1)
 */
static int buffer_add_binary(config_t *conf, const data_point_t *point) {
    pthread_mutex_lock(&conf->write_lock);

    size_t next_write = (conf->write_idx + 1) % conf->buffer_capacity;

    /* Vérifie si buffer plein */
    if (next_write == conf->read_idx) {
        pthread_mutex_unlock(&conf->write_lock);
        __sync_fetch_and_add(&conf->total_dropped, 1);
        return -1;
    }

    /* Copie directement la structure binaire dans le buffer (pas de malloc) */
    memcpy(&conf->buffer_array[conf->write_idx], point, sizeof(data_point_t));

    /* Mise à jour atomique de l'index */
    __sync_synchronize();
    conf->write_idx = next_write;

    pthread_mutex_unlock(&conf->write_lock);

    /* Signal avec le mutex dédié (POSIX-compliant) */
    pthread_mutex_lock(&conf->buffer_cond_lock);
    pthread_cond_signal(&conf->buffer_cond);
    pthread_mutex_unlock(&conf->buffer_cond_lock);

    return 0;
}

/**
 * Envoie un batch de données à TDengine
 * Utilisation mémoire optimisée avec un seul malloc pour le batch entier
 */
/**
 * Flush optimisé V3.0 avec auto-création des tables via TAGS
 *
 * Améliorations V3.0 vs V2.0:
 * - Auto-création tables avec taos_stmt_set_tbname_tags() (élimine CREATE TABLE synchrone)
 * - Support 1-4 colonnes (plus seulement 1-2)
 * - Réutilisation statement par (stable, num_cols) au lieu de (table, is_dual)
 * - Réduction mémoire 42% (448 bytes vs 768 de V1.0)
 *
 * Performance attendue: 4-5x throughput (50K → 200-250K metrics/s)
 */
static int flush_batch_stmt(config_t *conf, data_point_t *batch, size_t count,
                           TAOS_MULTI_BIND *binds_pool,
                           int64_t *timestamps_pool,
                           int64_t **col_buffers_pool) {
    /* V2.11: Tracking de latence pour métriques internes */
    struct timeval start_time, end_time;
    gettimeofday(&start_time, NULL);

    if (count == 0)
        return 0;

    /* Vérifie la connexion avant d'envoyer */
    if (tdengine_ensure_connected(conf) != 0) {
        ERROR(PLUGIN_NAME ": Not connected to TDengine");
        return -1;
    }

    /* Trie le batch par table_name pour grouper les insertions */
    qsort(batch, count, sizeof(data_point_t), compare_table_name);

    size_t i = 0;
    int global_error = 0;
    size_t points_written = 0;

    /* Parcourt le batch trié et traite chaque groupe de table */
    while (i < count) {
        const char *current_table = batch[i].table_name;
        const char *stable_name = batch[i].stable_name;
        uint8_t num_cols = batch[i].num_values;

        /* Compte combien de points pour cette table */
        size_t table_count = 0;
        while (i + table_count < count &&
               strcmp(batch[i + table_count].table_name, current_table) == 0) {
            table_count++;
        }

        DEBUG(PLUGIN_NAME ": Processing %zu points for table %s (stable=%s, cols=%d)",
              table_count, current_table, stable_name, num_cols);

        /* Récupère ou crée le prepared statement pour cette super-table */
        TAOS_STMT *stmt = get_or_create_stmt(conf, stable_name, num_cols);
        if (!stmt) {
            ERROR(PLUGIN_NAME ": Failed to get statement for stable %s", stable_name);
            i += table_count;
            global_error = -1;
            continue;
        }

        /* V2.6: Auto-création de table avec TAGS (TDengine 3.x native support)
         * Utilise taos_stmt_set_tbname_tags() pour créer automatiquement la table
         * si elle n'existe pas, éliminant le CREATE TABLE synchrone */

        /* Prépare les TAGS pour l'auto-création */
        TAOS_MULTI_BIND tags[2];
        memset(tags, 0, sizeof(tags));

        /* Tag 1: hostname (NCHAR) */
        int32_t hostname_len = (int32_t)strlen(batch[i].hostname);
        tags[0].buffer_type = TSDB_DATA_TYPE_NCHAR;
        tags[0].buffer = (void *)batch[i].hostname;
        tags[0].buffer_length = hostname_len;
        tags[0].length = &hostname_len;
        tags[0].is_null = NULL;
        tags[0].num = 1;

        /* Tag 2: plugin_instance (NCHAR) */
        int32_t plugin_instance_len = (int32_t)strlen(batch[i].plugin_instance);
        tags[1].buffer_type = TSDB_DATA_TYPE_NCHAR;
        tags[1].buffer = (void *)batch[i].plugin_instance;
        tags[1].buffer_length = plugin_instance_len;
        tags[1].length = &plugin_instance_len;
        tags[1].is_null = NULL;
        tags[1].num = 1;

        /* Set table name avec auto-création via TAGS */
        int ret = taos_stmt_set_tbname_tags(stmt, current_table, tags);
        if (ret != 0) {
            /* Codes -214748xxxx = Statement invalide après reconnexion ou création STABLE
             * Solution: invalider tout le cache, vérifier la connexion et réessayer une fois */
            if (ret == TAOS_ERR_STMT_INVALID_1 ||
                ret == TAOS_ERR_STMT_INVALID_2 ||
                ret == TAOS_ERR_STMT_INVALID_3 ||
                (ret < TAOS_ERR_STMT_RANGE_HIGH && ret > TAOS_ERR_STMT_RANGE_LOW)) {
                WARNING(PLUGIN_NAME ": Detected stale statement (ret=%d) - forcing reconnection", ret);
                invalidate_stmt_cache(conf);

                /* V2.12 FIX: Force reconnexion immédiate - les statements sont invalides même si SELECT NOW() passe */
                pthread_mutex_lock(&conf->conn_lock);
                if (conf->conn) {
                    INFO(PLUGIN_NAME ": Forcing reconnection due to stale statements");
                    taos_close(conf->conn);
                    conf->conn = NULL;
                }
                pthread_mutex_unlock(&conf->conn_lock);

                /* Reconnecte immédiatement */
                /* Désactive temporairement le throttling de reconnexion pour ce cas critique */
                cdtime_t saved_last_attempt = conf->last_connect_attempt;
                conf->last_connect_attempt = 0;

                if (tdengine_ensure_connected(conf) != 0) {
                    conf->last_connect_attempt = saved_last_attempt;
                    ERROR(PLUGIN_NAME ": Failed to reconnect after stale statement");
                    return -1;
                }
                conf->last_connect_attempt = saved_last_attempt;
                __sync_fetch_and_add(&conf->reconnections, 1);
                INFO(PLUGIN_NAME ": Successfully reconnected after stale statement, retrying batch");

                /* Retourne -1 pour que le retry mechanism réessaye le batch entier */
                return -1;
            }

            ERROR(PLUGIN_NAME ": taos_stmt_set_tbname_tags failed for %s (ret=%d): %s",
                  current_table, ret, taos_stmt_errstr(stmt));
            i += table_count;
            global_error = -1;
            continue;
        }

        /* Utilise les buffers pré-alloués (pas de malloc dans le hot path) */
        TAOS_MULTI_BIND *binds = binds_pool;
        int64_t *timestamps = timestamps_pool;
        int64_t **col_buffers = col_buffers_pool;

        /* Réinitialise binds pour cette itération */
        memset(binds, 0, (1 + num_cols) * sizeof(TAOS_MULTI_BIND));

        /* Remplit les buffers depuis le batch */
        for (size_t j = 0; j < table_count; j++) {
            timestamps[j] = batch[i + j].timestamp;
            for (uint8_t c = 0; c < num_cols; c++) {
                col_buffers[c][j] = batch[i + j].values[c];
            }
        }

        /* Configure le binding pour timestamp */
        binds[0].buffer_type = TSDB_DATA_TYPE_TIMESTAMP;
        binds[0].buffer = timestamps;
        binds[0].buffer_length = sizeof(int64_t);
        binds[0].length = NULL;
        binds[0].is_null = NULL;
        binds[0].num = table_count;

        /* Configure les bindings pour toutes les colonnes de valeurs */
        for (uint8_t c = 0; c < num_cols; c++) {
            binds[1 + c].buffer_type = TSDB_DATA_TYPE_BIGINT;
            binds[1 + c].buffer = col_buffers[c];
            binds[1 + c].buffer_length = sizeof(int64_t);
            binds[1 + c].length = NULL;
            binds[1 + c].is_null = NULL;
            binds[1 + c].num = table_count;
        }

        /* Bind toutes les colonnes en un seul appel */
        ret = taos_stmt_bind_param_batch(stmt, binds);
        if (ret != 0) {
            ERROR(PLUGIN_NAME ": taos_stmt_bind_param_batch failed for %s: %s",
                  current_table, taos_stmt_errstr(stmt));
            goto cleanup_buffers;
        }

        ret = taos_stmt_add_batch(stmt);
        if (ret != 0) {
            ERROR(PLUGIN_NAME ": taos_stmt_add_batch failed for %s: %s",
                  current_table, taos_stmt_errstr(stmt));
            goto cleanup_buffers;
        }

        ret = taos_stmt_execute(stmt);
        if (ret != 0) {
            ERROR(PLUGIN_NAME ": taos_stmt_execute failed for %s: %s",
                  current_table, taos_stmt_errstr(stmt));
            global_error = -1;
        } else {
            points_written += table_count;
            DEBUG(PLUGIN_NAME ": Successfully wrote %zu points to %s (auto-created with TAGS)",
                  table_count, current_table);
        }

cleanup_buffers:
        /* Pas de free() nécessaire - buffers pré-alloués réutilisés */

        /* Passe au groupe de table suivant */
        i += table_count;
    }

    /* Mise à jour des statistiques */
    if (points_written > 0) {
        __sync_fetch_and_add(&conf->total_written, points_written);
        __sync_fetch_and_add(&conf->batch_flushes, 1);
    }

    /* V2.11: Calcul de la latence pour métriques internes */
    gettimeofday(&end_time, NULL);
    uint64_t latency_us = (end_time.tv_sec - start_time.tv_sec) * 1000000ULL +
                          (end_time.tv_usec - start_time.tv_usec);
    __sync_fetch_and_add(&conf->total_latency_us, latency_us);
    __sync_fetch_and_add(&conf->latency_samples, 1);

    if (global_error != 0 && points_written == 0) {
        return -1;  /* Échec complet */
    }

    return 0;  /* Succès total ou partiel */
}

/**
 * Thread de flush asynchrone avec timeout
 * Batche les données pour optimiser les requêtes réseau
 * Inclut la logique de réessai pour les lots échoués
 */
static void* flush_thread_func(void *arg) {
    config_t *conf = (config_t *)arg;
    data_point_t batch[BATCH_SIZE];

    /* Pré-allocation des buffers pour éviter malloc dans le hot path */
    TAOS_MULTI_BIND binds_pool[1 + MAX_COLUMNS];
    int64_t timestamps_pool[BATCH_SIZE];
    int64_t col_buffers_storage[MAX_COLUMNS][BATCH_SIZE];
    int64_t *col_buffers_pool[MAX_COLUMNS];

    /* Initialiser les pointeurs vers les buffers de colonnes */
    for (int c = 0; c < MAX_COLUMNS; c++) {
        col_buffers_pool[c] = col_buffers_storage[c];
    }

    INFO(PLUGIN_NAME ": Flush thread started");

    while (conf->running) {
        /* Attente avec le mutex dédié (POSIX-compliant) */
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += BATCH_TIMEOUT_MS * 1000000;
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000;
        }

        pthread_mutex_lock(&conf->buffer_cond_lock);
        pthread_cond_timedwait(&conf->buffer_cond, &conf->buffer_cond_lock, &ts);
        pthread_mutex_unlock(&conf->buffer_cond_lock);

        /* Lecture du buffer avec son propre lock */
        pthread_mutex_lock(&conf->read_lock);
        size_t count = 0;
        while (count < BATCH_SIZE && conf->read_idx != conf->write_idx) {
            memcpy(&batch[count], &conf->buffer_array[conf->read_idx], sizeof(data_point_t));
            conf->read_idx = (conf->read_idx + 1) % conf->buffer_capacity;
            count++;
        }
        pthread_mutex_unlock(&conf->read_lock);

        /* V2.2: Flush avec prepared statements + retry binaire */
        if (count > 0) {
            DEBUG(PLUGIN_NAME ": Flushing batch of %zu points with prepared statements", count);

            int code = flush_batch_stmt(conf, batch, count,
                                       binds_pool, timestamps_pool, col_buffers_pool);

            if (code != 0 && conf->enable_retry) {
                /* V2.2: Retry avec data_point_t binaires */
                retry_batch_t *retry = calloc(1, sizeof(retry_batch_t));
                if (retry) {
                    retry->points = malloc(count * sizeof(data_point_t));
                    if (retry->points) {
                        memcpy(retry->points, batch, count * sizeof(data_point_t));
                        retry->count = count;
                        retry->capacity = count;
                        retry->attempts_made = 1;
                        retry->initial_timestamp = cdtime();
                        retry->last_retry = cdtime();

                        pthread_mutex_lock(&conf->retry_buffer_lock);
                        size_t batch_size = count * sizeof(data_point_t);
                        if (conf->current_retry_buffer_size + batch_size <= conf->max_retry_buffer_size_bytes) {
                            llist_append(conf->retry_buffer, llentry_create(NULL, retry));
                            conf->current_retry_buffer_size += batch_size;
                            INFO(PLUGIN_NAME ": Batch queued for retry (%zu points, buffer size: %zu bytes)",
                                 count, conf->current_retry_buffer_size);
                        } else {
                            WARNING(PLUGIN_NAME ": Retry buffer full, %zu points dropped", count);
                            free(retry->points);
                            free(retry);
                            __sync_fetch_and_add(&conf->total_dropped, count);
                        }
                        pthread_mutex_unlock(&conf->retry_buffer_lock);
                    } else {
                        free(retry);
                        WARNING(PLUGIN_NAME ": Failed to allocate retry points, %zu dropped", count);
                        __sync_fetch_and_add(&conf->total_dropped, count);
                    }
                } else {
                    WARNING(PLUGIN_NAME ": Failed to allocate retry batch, %zu points dropped", count);
                    __sync_fetch_and_add(&conf->total_dropped, count);
                }
                __sync_fetch_and_add(&conf->total_errors, 1);

                /* V2.10: Si le batch principal échoue, skip retry processing
                 * Raison: Si la connexion est down, tous les retry vont aussi échouer
                 * Mieux vaut attendre le prochain BATCH_TIMEOUT_MS pour laisser le temps
                 * à la connexion de se rétablir */
                continue;
            } else if (code != 0) {
                /* Retry désactivé - drop */
                WARNING(PLUGIN_NAME ": Batch flush failed, %zu points dropped (retry disabled)",
                        count);
                __sync_fetch_and_add(&conf->total_errors, 1);
                __sync_fetch_and_add(&conf->total_dropped, count);

                /* V2.10: Idem, skip pour laisser le temps à la connexion de se rétablir */
                continue;
            }
        }

        /* V2.2: Process retry buffer avec prepared statements binaires */
        if (conf->enable_retry) {
            pthread_mutex_lock(&conf->retry_buffer_lock);
            llentry_t *entry = llist_head(conf->retry_buffer);
            while(entry) {
                retry_batch_t *item = entry->value;

                /* Protection contre attempts_made = 0 */
                if (item->attempts_made == 0) {
                    entry = entry->next;
                    continue;
                }

                cdtime_t now = cdtime();
                uint64_t delay_ms = conf->retry_delay_ms * (1 << (item->attempts_made - 1));

                if ((now - item->last_retry) < MS_TO_CDTIME_T(delay_ms)) {
                    entry = entry->next;
                    continue;
                }

                /* Tente de re-flush le batch avec prepared statements */
                DEBUG(PLUGIN_NAME ": Retrying batch with %zu points (attempt %d/%d)",
                      item->count, item->attempts_made, conf->retry_attempts);

                int code = flush_batch_stmt(conf, item->points, item->count,
                                           binds_pool, timestamps_pool, col_buffers_pool);
                if (code == 0) {
                    INFO(PLUGIN_NAME ": Successfully sent retry batch (%zu points after %d attempts)",
                         item->count, item->attempts_made);
                    __sync_fetch_and_add(&conf->total_retried, 1);
                    size_t batch_size = item->count * sizeof(data_point_t);
                    conf->current_retry_buffer_size -= batch_size;
                    free(item->points);
                    free(item);
                    llentry_t *to_remove = entry;
                    entry = entry->next;
                    llist_remove(conf->retry_buffer, to_remove);
                } else {
                    item->attempts_made++;
                    item->last_retry = now;
                    if (item->attempts_made > conf->retry_attempts) {
                        ERROR(PLUGIN_NAME ": Batch failed after %d attempts. Discarding %zu points.",
                              conf->retry_attempts, item->count);
                        __sync_fetch_and_add(&conf->total_retry_failed, 1);
                        __sync_fetch_and_add(&conf->total_dropped, item->count);
                        size_t batch_size = item->count * sizeof(data_point_t);
                        conf->current_retry_buffer_size -= batch_size;
                        free(item->points);
                        free(item);
                        llentry_t *to_remove = entry;
                        entry = entry->next;
                        llist_remove(conf->retry_buffer, to_remove);
                    } else {
                        WARNING(PLUGIN_NAME ": Retry batch failed again. Re-queued for retry (%d/%d, %zu points).",
                                item->attempts_made, conf->retry_attempts, item->count);
                        entry = entry->next;
                    }
                }
            }
            pthread_mutex_unlock(&conf->retry_buffer_lock);
        }

        /* V2.11: Écriture périodique des métriques internes */
        if (conf->internal_metrics_enabled) {
            static cdtime_t last_metrics_write = 0;
            cdtime_t now = cdtime();
            if (last_metrics_write == 0 ||
                (now - last_metrics_write) >= TIME_T_TO_CDTIME_T(conf->internal_metrics_interval)) {
                write_internal_metrics(conf);
                last_metrics_write = now;
            }
        }
    }

    /* Flush final avant shutdown (V2.0: avec prepared statements) */
    INFO(PLUGIN_NAME ": Flushing remaining data before shutdown...");
    {
        pthread_mutex_lock(&conf->read_lock);
        size_t count = 0;
        while (count < BATCH_SIZE && conf->read_idx != conf->write_idx) {
            memcpy(&batch[count], &conf->buffer_array[conf->read_idx], sizeof(data_point_t));
            conf->read_idx = (conf->read_idx + 1) % conf->buffer_capacity;
            count++;
        }
        pthread_mutex_unlock(&conf->read_lock);

        if (count > 0) {
            flush_batch_stmt(conf, batch, count,
                           binds_pool, timestamps_pool, col_buffers_pool);
        }
    }

    /* V2.2: Tente un dernier flush du retry buffer avant shutdown */
    INFO(PLUGIN_NAME ": Flushing retry buffer before shutdown...");
    pthread_mutex_lock(&conf->retry_buffer_lock);
    llentry_t *entry = llist_head(conf->retry_buffer);
    size_t retry_flushed = 0, retry_dropped = 0;
    while (entry) {
        retry_batch_t *item = entry->value;

        /* Dernière tentative de flush */
        int code = flush_batch_stmt(conf, item->points, item->count,
                                   binds_pool, timestamps_pool, col_buffers_pool);
        if (code == 0) {
            retry_flushed += item->count;
            INFO(PLUGIN_NAME ": Successfully flushed %zu retry points before shutdown", item->count);
        } else {
            retry_dropped += item->count;
            WARNING(PLUGIN_NAME ": Failed to flush %zu retry points before shutdown", item->count);
        }

        /* Libère les ressources */
        free(item->points);
        free(item);
        entry = entry->next;
    }
    llist_destroy(conf->retry_buffer);
    conf->retry_buffer = NULL;
    pthread_mutex_unlock(&conf->retry_buffer_lock);

    if (retry_flushed > 0 || retry_dropped > 0) {
        INFO(PLUGIN_NAME ": Shutdown retry stats: %zu flushed, %zu dropped",
             retry_flushed, retry_dropped);
    }

    INFO(PLUGIN_NAME ": Flush thread stopped");
    return NULL;
}

/**
 * Callback d'écriture collectd
 * Optimisée pour haute performance:
 * - Pas d'allocation dynamique (stack only)
 * - Cache des tables pour éviter CREATE TABLE répétés
 * - Vérification de sécurité SQL
 */
static int write_callback(const data_set_t *ds, const value_list_t *vl,
                         user_data_t __attribute__((unused)) *user_data) {

    if (!g_config)
        return -1;

    /* Vérification de la connexion sous le lock suivant le pattern collectd */
    pthread_mutex_lock(&g_config->conn_lock);
    bool is_connected = (g_config->conn != NULL);
    pthread_mutex_unlock(&g_config->conn_lock);

    if (!is_connected)
        return -1;

    const mapping_rule_t *rule = find_mapping_rule(vl->plugin, vl->type);
    if (!rule)
        return 0;

    /* Construit le nom de la table avec sécurité SQL
     * Inclut type_instance pour différencier les CAKE TINs (tin0, tin1, etc.) */
    char table_name[TABLE_NAME_MAX];
    build_table_name(table_name, sizeof(table_name), rule->stable,
                    vl->plugin_instance, vl->type_instance, vl->host);

    /* Convertit le timestamp collectd en millisecondes (TDengine timestamp avec precision='ms') */
    uint64_t ts = CDTIME_T_TO_MS(vl->time);

    /* V3.0: Crée un data_point binaire optimisé avec support 1-4 colonnes
     * et auto-création via TAGS (élimine CREATE TABLE synchrone) */
    data_point_t point;
    memset(&point, 0, sizeof(point));

    /* Remplit les métadonnées */
    sstrncpy(point.table_name, table_name, sizeof(point.table_name));
    sstrncpy(point.stable_name, rule->stable, sizeof(point.stable_name));
    sstrncpy(point.hostname, vl->host, sizeof(point.hostname));
    sstrncpy(point.plugin_instance,
             (vl->plugin_instance[0] ? vl->plugin_instance : ""),
             sizeof(point.plugin_instance));
    point.timestamp = ts;

    /* V3.0: Support 1-4 colonnes (généralisation) */
    if (ds->ds_num > MAX_COLUMNS) {
        WARNING(PLUGIN_NAME ": Too many columns %zu for table %s (max %d)",
                ds->ds_num, table_name, MAX_COLUMNS);
        return -1;
    }

    point.num_values = ds->ds_num;

    /* Convertit toutes les valeurs en int64_t */
    for (size_t i = 0; i < ds->ds_num; i++) {
        switch (ds->ds[i].type) {
        case DS_TYPE_GAUGE:
            point.values[i] = (int64_t)(vl->values[i].gauge * 1000000);  /* Préserve précision */
            break;
        case DS_TYPE_DERIVE:
            point.values[i] = (int64_t)vl->values[i].derive;
            break;
        case DS_TYPE_COUNTER:
            point.values[i] = (int64_t)vl->values[i].counter;
            break;
        case DS_TYPE_ABSOLUTE:
            point.values[i] = (int64_t)vl->values[i].absolute;
            break;
        default:
            WARNING(PLUGIN_NAME ": Unknown data source type %d for %s column %zu",
                    ds->ds[i].type, table_name, i);
            return -1;
        }
    }

    DEBUG(PLUGIN_NAME ": Created V3.0 point for %s: stable=%s, cols=%d, ts=%lu",
          table_name, rule->stable, point.num_values, ts);

    /* V2.6: Envoie la création de STABLE au thread asynchrone (non-bloquant)
     * La création de la table individuelle est gérée automatiquement par
     * taos_stmt_set_tbname_tags() dans flush_batch_stmt() - ZERO latence ! */
    ensure_stable_exists_async(g_config, rule->stable);

    /* V2.6: Plus besoin de CREATE TABLE synchrone !
     * taos_stmt_set_tbname_tags() crée automatiquement la table lors de l'insertion
     * Avantages:
     * - Zéro latence dans write_callback (non-bloquant)
     * - Création atomique par TDengine (thread-safe)
     * - Cache de tables devenu inutile (supprimé)
     */

    return buffer_add_binary(g_config, &point);
}

/**
 * Parse un bloc <Retention> et ajoute la configuration à la liste chaînée
 */
static int parse_retention_block(oconfig_item_t *ci, config_t *conf) {
    retention_config_t *ret = calloc(1, sizeof(retention_config_t));
    if (!ret) {
        ERROR(PLUGIN_NAME ": Failed to allocate retention config");
        return -1;
    }

    /* Valeurs par défaut */
    ret->is_raw = false;

    /* Parse les paramètres du bloc <Retention> */
    for (int i = 0; i < ci->children_num; i++) {
        oconfig_item_t *child = ci->children + i;

        if (strcasecmp("Duration", child->key) == 0) {
            char *duration_str = NULL;
            if (cf_util_get_string(child, &duration_str) == 0) {
                /* Parse "3h", "6h", "1d", "1y", etc. */
                int value;
                char unit;
                if (sscanf(duration_str, "%d%c", &value, &unit) == 2) {
                    switch (unit) {
                        case 'h': ret->duration_seconds = value * 3600; break;
                        case 'd': ret->duration_seconds = value * 86400; break;
                        case 'w': ret->duration_seconds = value * 604800; break;
                        case 'm': ret->duration_seconds = value * 2592000; break; /* 30j */
                        case 'y': ret->duration_seconds = value * 31536000; break;
                        default:
                            ERROR(PLUGIN_NAME ": Invalid duration unit '%c' in '%s'", unit, duration_str);
                            free(duration_str);
                            free(ret);
                            return -1;
                    }
                } else {
                    ERROR(PLUGIN_NAME ": Invalid duration format '%s'", duration_str);
                    free(duration_str);
                    free(ret);
                    return -1;
                }
                free(duration_str);
            }
        } else if (strcasecmp("Resolution", child->key) == 0) {
            char *resolution_str = NULL;
            if (cf_util_get_string(child, &resolution_str) == 0) {
                /* Parse "1s", "4s", "1m", "1h", "1d", etc. */
                int value;
                char unit;
                if (sscanf(resolution_str, "%d%c", &value, &unit) == 2) {
                    switch (unit) {
                        case 's': ret->resolution_seconds = value; break;
                        case 'm': ret->resolution_seconds = value * 60; break;
                        case 'h': ret->resolution_seconds = value * 3600; break;
                        case 'd': ret->resolution_seconds = value * 86400; break;
                        default:
                            ERROR(PLUGIN_NAME ": Invalid resolution unit '%c' in '%s'", unit, resolution_str);
                            free(resolution_str);
                            free(ret);
                            return -1;
                    }
                } else {
                    ERROR(PLUGIN_NAME ": Invalid resolution format '%s'", resolution_str);
                    free(resolution_str);
                    free(ret);
                    return -1;
                }
                free(resolution_str);
            }
        } else if (strcasecmp("Database", child->key) == 0) {
            char *db_name = NULL;
            if (cf_util_get_string(child, &db_name) == 0) {
                sstrncpy(ret->database, db_name, sizeof(ret->database));
                free(db_name);
            }
        } else if (strcasecmp("IsRaw", child->key) == 0) {
            cf_util_get_boolean(child, &ret->is_raw);
        }
    }

    /* Validation */
    if (ret->duration_seconds <= 0 || ret->database[0] == '\0') {
        ERROR(PLUGIN_NAME ": Retention block missing Duration or Database");
        free(ret);
        return -1;
    }

    /* Ajoute à la liste chaînée */
    ret->next = conf->retentions;
    conf->retentions = ret;

    INFO(PLUGIN_NAME ": Added retention: duration=%ds resolution=%ds database=%s raw=%d",
         ret->duration_seconds, ret->resolution_seconds, ret->database, ret->is_raw);

    return 0;
}

static int parse_mapping_block(oconfig_item_t *ci, config_t *conf) {
    mapping_rule_t *rule = calloc(1, sizeof(mapping_rule_t));
    if (!rule) {
        ERROR(PLUGIN_NAME ": Failed to allocate mapping rule");
        return -1;
    }

    for (int i = 0; i < ci->children_num; i++) {
        oconfig_item_t *child = ci->children + i;
        if (strcasecmp("Plugin", child->key) == 0) {
            cf_util_get_string(child, &rule->plugin);
        } else if (strcasecmp("Type", child->key) == 0) {
            cf_util_get_string(child, &rule->type);
        } else if (strcasecmp("Stable", child->key) == 0) {
            cf_util_get_string(child, &rule->stable);
        }
    }

    if (!rule->plugin || !rule->type || !rule->stable) {
        ERROR(PLUGIN_NAME ": Mapping block is missing Plugin, Type, or Stable");
        free(rule->plugin);
        free(rule->type);
        free(rule->stable);
        free(rule);
        return -1;
    }

    // Add to the head of the list
    rule->next = conf->mappings;
    conf->mappings = rule;

    INFO(PLUGIN_NAME ": Added mapping: Plugin=%s, Type=%s -> Stable=%s",
         rule->plugin, rule->type, rule->stable);

    return 0;
}

/**
 * Callback de configuration collectd
 * Parse les paramètres du fichier de configuration
 */
static int config_callback(oconfig_item_t *ci) {
    if (g_config) {
        ERROR(PLUGIN_NAME ": Already configured");
        return -1;
    }

    g_config = calloc(1, sizeof(config_t));
    if (!g_config)
        return -1;

    g_config->database = strdup(DEFAULT_DB);
    g_config->buffer_capacity = MAX_BUFFER_SIZE;
    g_config->enable_retry = false;
    g_config->retry_attempts = 3;
    g_config->retry_delay_ms = 1000;
    g_config->max_retry_buffer_size_bytes = 16 * 1024 * 1024;
    g_config->mappings = NULL;
    /* V2.11: Métriques internes désactivées par défaut */
    g_config->internal_metrics_enabled = false;
    g_config->internal_metrics_interval = 60;  /* 60 secondes par défaut */
    g_config->internal_metrics_retention_days = 30;  /* 30 jours par défaut */
    g_config->total_latency_us = 0;
    g_config->latency_samples = 0;
    g_config->stables_created_success = 0;
    g_config->stables_created_failed = 0;
    g_config->streams_created_success = 0;
    g_config->streams_created_failed = 0;
    g_config->stmt_cache_hits = 0;
    g_config->stmt_cache_misses = 0;

    /* Parse les options de configuration */
    for (int i = 0; i < ci->children_num; i++) {
        oconfig_item_t *child = ci->children + i;

        if (strcasecmp("Host", child->key) == 0) {
            cf_util_get_string(child, &g_config->host);
        } else if (strcasecmp("Port", child->key) == 0) {
            int port;
            if (cf_util_get_int(child, &port) == 0 && port > 0 && port < 65536) {
                g_config->port = port;
            }
        } else if (strcasecmp("User", child->key) == 0) {
            cf_util_get_string(child, &g_config->user);
        } else if (strcasecmp("Password", child->key) == 0) {
            cf_util_get_string(child, &g_config->password);
        } else if (strcasecmp("Database", child->key) == 0) {
            cf_util_get_string(child, &g_config->database);
        } else if (strcasecmp("BufferSize", child->key) == 0) {
            int size;
            if (cf_util_get_int(child, &size) == 0) {
                if (size > 0 && size <= MAX_BUFFER_SIZE) {
                    g_config->buffer_capacity = size;
                }
            }
        } else if (strcasecmp("ReconnectInterval", child->key) == 0) {
            int interval;
            if (cf_util_get_int(child, &interval) == 0 && interval > 0) {
                g_config->reconnect_interval = TIME_T_TO_CDTIME_T(interval);
            }
        } else if (strcasecmp("Retention", child->key) == 0) {
            /* Parse un bloc <Retention> */
            if (parse_retention_block(child, g_config) != 0) {
                ERROR(PLUGIN_NAME ": Failed to parse Retention block");
                /* Continue parsing other blocks */
            }
        } else if (strcasecmp("Mapping", child->key) == 0) {
            if (parse_mapping_block(child, g_config) != 0) {
                ERROR(PLUGIN_NAME ": Failed to parse Mapping block");
            }
        } else if (strcasecmp("EnableRetry", child->key) == 0) {
            cf_util_get_boolean(child, &g_config->enable_retry);
        } else if (strcasecmp("RetryAttempts", child->key) == 0) {
            int attempts;
            if (cf_util_get_int(child, &attempts) == 0 && attempts >= 0) {
                g_config->retry_attempts = attempts;
            }
        } else if (strcasecmp("RetryDelay", child->key) == 0) {
            int delay;
            if (cf_util_get_int(child, &delay) == 0 && delay > 0) {
                g_config->retry_delay_ms = delay;
            }
        } else if (strcasecmp("MaxRetryBufferSize", child->key) == 0) {
            int size_mb;
            if (cf_util_get_int(child, &size_mb) == 0 && size_mb > 0) {
                g_config->max_retry_buffer_size_bytes = (size_t)size_mb * 1024 * 1024;
            }
        } else if (strcasecmp("InternalMetrics", child->key) == 0) {
            cf_util_get_boolean(child, &g_config->internal_metrics_enabled);
        } else if (strcasecmp("InternalMetricsInterval", child->key) == 0) {
            int interval;
            if (cf_util_get_int(child, &interval) == 0 && interval > 0) {
                g_config->internal_metrics_interval = interval;
            }
        } else if (strcasecmp("InternalMetricsRetention", child->key) == 0) {
            int retention;
            if (cf_util_get_int(child, &retention) == 0 && retention > 0) {
                g_config->internal_metrics_retention_days = retention;
            }
        }
    }

    /* Allocation du buffer circulaire */
    g_config->buffer_array =
        calloc(g_config->buffer_capacity, sizeof(data_point_t));
    if (!g_config->buffer_array) {
        ERROR(PLUGIN_NAME ": Failed to allocate buffer");
        free(g_config->host);
        free(g_config->user);
        free(g_config->password);
        free(g_config->database);
        free(g_config);
        g_config = NULL;
        return -1;
    }

    /* Initialisation des locks et variables de condition */
    pthread_mutex_init(&g_config->write_lock, NULL);
    pthread_mutex_init(&g_config->read_lock, NULL);
    pthread_mutex_init(&g_config->buffer_cond_lock, NULL);
    pthread_cond_init(&g_config->buffer_cond, NULL);
    pthread_rwlock_init(&g_config->table_cache.lock, NULL);
    pthread_rwlock_init(&g_config->stable_cache.lock, NULL);
    pthread_mutex_init(&g_config->conn_lock, NULL);
    g_config->table_cache.count = 0;
    g_config->stable_cache.count = 0;

    /* Initialisation du tampon de réessai */
    g_config->retry_buffer = llist_create();
    pthread_mutex_init(&g_config->retry_buffer_lock, NULL);
    g_config->current_retry_buffer_size = 0;
    g_config->total_retried = 0;
    g_config->total_retry_failed = 0;

    /* Valeurs par défaut pour les credentials si non spécifiés */
    if (!g_config->host)
        g_config->host = strdup("localhost");
    if (g_config->port <= 0)
        g_config->port = 6030;  /* Port par défaut TDengine */
    if (!g_config->user)
        g_config->user = strdup("root");
    if (!g_config->password)
        g_config->password = strdup("taosdata");

    /* Intervalle de reconnexion par défaut: 30 secondes */
    g_config->reconnect_interval = TIME_T_TO_CDTIME_T(30);

    INFO(PLUGIN_NAME ": Configured with host=%s:%d user=%s database=%s buffer_size=%zu",
        g_config->host, g_config->port, g_config->user, g_config->database,
        g_config->buffer_capacity);

    return 0;
}

/**
 * Crée les STREAMs d'agrégation pour une super-table donnée
 * Les STREAMs créent automatiquement les super-tables cibles avec le bon schéma
 */
static int create_aggregation_streams_for_stable(config_t *conf, const char *stable_name) {
    if (!conf || !conf->conn || !stable_name) {
        return -1;
    }

    retention_config_t *prev_ret = NULL;
    retention_config_t *ret = conf->retentions;

    /* Parcourt les retentions pour créer les streams de cascade */
    while (ret != NULL) {
        /* V2.8: Vérifie running à chaque itération pour shutdown rapide */
        if (!conf->running) {
            INFO(PLUGIN_NAME ": Interrupted stream creation during shutdown (remaining streams skipped)");
            return 0;
        }

        if (ret->is_raw) {
            /* La base brute n'a pas de STREAM (c'est la source) */
            prev_ret = ret;
            ret = ret->next;
            continue;
        }

        /* Détermine la database source (précédente dans la liste ou base principale) */
        const char *source_db = prev_ret ?
            (prev_ret->is_raw ? conf->database : prev_ret->database) :
            conf->database;

        /* Les STREAMs créent automatiquement les super-tables avec le bon schéma
         * via la clause INTO, donc pas besoin de create_stable_in_database() */

        /* Nom du stream : stream_<target_db>_<stable>_<resolution> */
        char stream_name[256];
        snprintf(stream_name, sizeof(stream_name), "stream_%s_%s_%ds",
                 ret->database, stable_name, ret->resolution_seconds);

        /* Nettoie le nom du stream (remplace les points par underscores) */
        for (char *p = stream_name; *p; p++) {
            if (*p == '.') *p = '_';
        }

        /* Détecte si c'est une table à 2 colonnes (rx/tx) ou 1 colonne (val) */
        bool is_dual_column = (strstr(stable_name, "interface_octets") != NULL ||
                              strstr(stable_name, "interface_packets") != NULL ||
                              strstr(stable_name, "interface_errors") != NULL ||
                              strstr(stable_name, "interface_drops") != NULL);

        /* Construit le SQL du STREAM */
        char create_stream_sql[2048];
        int n;

        if (is_dual_column) {
            /* Pour les tables rx/tx, préserve les sous-tables (tbname) */
            n = snprintf(create_stream_sql, sizeof(create_stream_sql),
                        "CREATE STREAM IF NOT EXISTS %s "
                        "INTO %s.%s SUBTABLE(tbname) "
                        "AS SELECT "
                        "_wstart AS ts, "
                        "AVG(rx) AS rx, "
                        "AVG(tx) AS tx, "
                        "hostname, plugin_instance "
                        "FROM %s.%s "
                        "PARTITION BY tbname, hostname, plugin_instance "
                        "INTERVAL(%ds)",
                        stream_name,
                        ret->database, stable_name,
                        source_db, stable_name,
                        ret->resolution_seconds);
        } else {
            /* Pour les tables à 1 colonne, préserve les sous-tables (tbname) */
            n = snprintf(create_stream_sql, sizeof(create_stream_sql),
                        "CREATE STREAM IF NOT EXISTS %s "
                        "INTO %s.%s SUBTABLE(tbname) "
                        "AS SELECT "
                        "_wstart AS ts, "
                        "AVG(val) AS val, "
                        "hostname, plugin_instance "
                        "FROM %s.%s "
                        "PARTITION BY tbname, hostname, plugin_instance "
                        "INTERVAL(%ds)",
                        stream_name,
                        ret->database, stable_name,
                        source_db, stable_name,
                        ret->resolution_seconds);
        }

        if (n < 0 || n >= (int)sizeof(create_stream_sql)) {
            ERROR(PLUGIN_NAME ": Failed to format CREATE STREAM for %s", stream_name);
            ret = ret->next;
            continue;
        }

        INFO(PLUGIN_NAME ": Creating stream: %s", stream_name);

        pthread_mutex_lock(&conf->conn_lock);
        TAOS_RES *res = taos_query(conf->conn, create_stream_sql);
        int code = taos_errno(res);

        if (code != 0) {
            /* Si le stream existe déjà, c'est OK */
            if (code != 0x2603) {  /* TSDB_CODE_MND_STREAM_ALREADY_EXIST */
                ERROR(PLUGIN_NAME ": Failed to create stream %s: %s",
                      stream_name, taos_errstr(res));
            }
        } else {
            INFO(PLUGIN_NAME ": Created stream: %s -> %s.%s (interval=%ds)",
                 stream_name, ret->database, stable_name, ret->resolution_seconds);
        }

        taos_free_result(res);
        pthread_mutex_unlock(&conf->conn_lock);

        /* Petit délai pour éviter de saturer la queue des streams TDengine
         * (itemsInStreamQ limité à 25 par défaut) */
        struct timespec delay = {0, 250000000};  /* 250ms */
        nanosleep(&delay, NULL);

        prev_ret = ret;
        ret = ret->next;
    }

    return 0;
}

/**
 * Inverse l'ordre de la liste chaînée des retentions
 * Nécessaire car les blocs <Retention> sont ajoutés en tête (ordre LIFO)
 * mais doivent être traités dans l'ordre du fichier de conf (FIFO)
 */
static void reverse_retention_list(config_t *conf) {
    retention_config_t *prev = NULL;
    retention_config_t *current = conf->retentions;
    retention_config_t *next = NULL;

    while (current != NULL) {
        next = current->next;
        current->next = prev;
        prev = current;
        current = next;
    }

    conf->retentions = prev;
}

/**
 * Crée toutes les databases de rétention configurées
 * Applique les paramètres DURATION et KEEP de TDengine
 */
static int ensure_retention_databases(config_t *conf) {
    if (!conf || !conf->conn) {
        ERROR(PLUGIN_NAME ": Invalid config or no connection for retention databases");
        return -1;
    }

    retention_config_t *ret = conf->retentions;
    int created_count = 0;

    while (ret != NULL) {
        char create_db_sql[512];

        /* Pour la base brute, on utilise la database principale déjà créée */
        if (ret->is_raw) {
            INFO(PLUGIN_NAME ": Skipping retention database creation for raw data (using main database %s)",
                 conf->database);
            ret = ret->next;
            continue;
        }

        /* Calcule KEEP et DURATION selon contraintes TDengine :
         * 1. KEEP >= 3 * DURATION
         * 2. s3_keeplocal >= 3 * DURATION (où s3_keeplocal ~= 360d par défaut)
         * Donc DURATION doit être <= 120d
         */
        int keep_days = (ret->duration_seconds * 1.2) / 86400;  /* KEEP = durée configurée +20% */
        if (keep_days < 1) keep_days = 1;

        /* DURATION limité à 120d à cause de s3_keeplocal = 360d */
        int duration_days = keep_days / 3;  /* DURATION = KEEP / 3 */
        if (duration_days > 120) {
            duration_days = 120;  /* Limite s3_keeplocal */
            keep_days = duration_days * 3 + 10;  /* KEEP > 3 * DURATION */
        }
        if (duration_days < 1) {
            duration_days = 1;
            keep_days = 4;  /* Assure KEEP > 3 * DURATION */
        }

        /* CREATE DATABASE avec DURATION et KEEP optimisés */
        int n = snprintf(create_db_sql, sizeof(create_db_sql),
                        "CREATE DATABASE IF NOT EXISTS %s "
                        "KEEP %dd "
                        "DURATION %dd "
                        "PRECISION 'ms'",
                        ret->database,
                        keep_days,
                        duration_days);

        if (n < 0 || n >= (int)sizeof(create_db_sql)) {
            ERROR(PLUGIN_NAME ": Failed to format CREATE DATABASE for %s", ret->database);
            ret = ret->next;
            continue;
        }

        INFO(PLUGIN_NAME ": Creating retention database: %s", create_db_sql);

        pthread_mutex_lock(&conf->conn_lock);
        TAOS_RES *res = taos_query(conf->conn, create_db_sql);
        int code = taos_errno(res);

        if (code != 0) {
            ERROR(PLUGIN_NAME ": Failed to create database %s: %s",
                  ret->database, taos_errstr(res));
            taos_free_result(res);
            pthread_mutex_unlock(&conf->conn_lock);
            ret = ret->next;
            continue;
        }

        taos_free_result(res);
        pthread_mutex_unlock(&conf->conn_lock);

        created_count++;
        INFO(PLUGIN_NAME ": Created retention database: %s (keep=%dd, duration=%dd)",
             ret->database, keep_days, duration_days);

        ret = ret->next;
    }

    INFO(PLUGIN_NAME ": Ensured %d retention databases", created_count);
    return 0;
}

/**
 * Connexion à TDengine avec gestion de reconnexion
 * Utilise les credentials configurés, avec fallback sur les valeurs par défaut
 * Return: 0 si connexion OK, -1 si échouée
 */
static int tdengine_connect(config_t *conf) {
    if (!conf) return -1;

    pthread_mutex_lock(&conf->conn_lock);

    /* Ferme la connexion précédente si elle existe */
    if (conf->conn) {
        taos_close(conf->conn);
        conf->conn = NULL;
    }

    /* Tentative de connexion SANS spécifier de database pour pouvoir la créer */
    conf->conn = taos_connect(
        conf->host,
        conf->user,
        conf->password,
        NULL,  /* Pas de database pour l'instant */
        conf->port
    );

    if (!conf->conn) {
        ERROR(PLUGIN_NAME ": Failed to connect to TDengine at %s:%d (user=%s)",
              conf->host, conf->port, conf->user);
        pthread_mutex_unlock(&conf->conn_lock);
        return -1;
    }

    /* Crée la database si elle n'existe pas */
    char create_db_sql[256];
    int ret = snprintf(create_db_sql, sizeof(create_db_sql),
                       "CREATE DATABASE IF NOT EXISTS %s", conf->database);
    if (ret > 0 && ret < (int)sizeof(create_db_sql)) {
        TAOS_RES *res = taos_query(conf->conn, create_db_sql);
        if (res) {
            int err = taos_errno(res);
            if (err != 0) {
                WARNING(PLUGIN_NAME ": Failed to create database %s: %s",
                        conf->database, taos_errstr(res));
            } else {
                DEBUG(PLUGIN_NAME ": Database %s created or already exists",
                      conf->database);
            }
            taos_free_result(res);
        }
    }

    /* Sélectionne la database */
    char use_db_sql[256];
    ret = snprintf(use_db_sql, sizeof(use_db_sql), "USE %s", conf->database);
    if (ret > 0 && ret < (int)sizeof(use_db_sql)) {
        TAOS_RES *res = taos_query(conf->conn, use_db_sql);
        if (!res) {
            ERROR(PLUGIN_NAME ": Failed to select database %s", conf->database);
            taos_close(conf->conn);
            conf->conn = NULL;
            pthread_mutex_unlock(&conf->conn_lock);
            return -1;
        }

        int err = taos_errno(res);
        char err_msg[256] = "";
        if (err != 0) {
            const char *err_str = taos_errstr(res);
            if (err_str) {
                sstrncpy(err_msg, err_str, sizeof(err_msg));
            }
        }
        taos_free_result(res);

        if (err != 0) {
            ERROR(PLUGIN_NAME ": Failed to select database %s: %s",
                  conf->database, err_msg[0] ? err_msg : "unknown error");
            taos_close(conf->conn);
            conf->conn = NULL;
            pthread_mutex_unlock(&conf->conn_lock);
            return -1;
        }
    }

    pthread_mutex_unlock(&conf->conn_lock);

    INFO(PLUGIN_NAME ": Connected to TDengine at %s:%d database=%s",
         conf->host, conf->port, conf->database);

    return 0;
}

/**
 * Vérifie et reconnecte si nécessaire
 * Utilisée dans le flush_thread pour gérer les disconnexions
 */
static int tdengine_ensure_connected(config_t *conf) {
    if (!conf) return -1;

    pthread_mutex_lock(&conf->conn_lock);

    /* Vérifie si la connexion existe et fonctionne */
    if (conf->conn) {
        TAOS_RES *res = taos_query(conf->conn, "SELECT NOW()");
        if (res) {
            int err = taos_errno(res);
            taos_free_result(res);
            if (err == 0) {
                pthread_mutex_unlock(&conf->conn_lock);
                return 0;  /* Connexion OK */
            }
        }
        /* Connexion cassée, fermer */
        INFO(PLUGIN_NAME ": Connection lost, closing and invalidating cache");
        taos_close(conf->conn);
        conf->conn = NULL;

        /* V2.2: Invalide tous les cached statements car ils pointent vers l'ancienne connexion */
        invalidate_stmt_cache(conf);
    }

    pthread_mutex_unlock(&conf->conn_lock);

    /* Tentative de reconnexion */
    cdtime_t now = cdtime();
    if ((now - conf->last_connect_attempt) < conf->reconnect_interval) {
        DEBUG(PLUGIN_NAME ": Reconnect interval not expired yet");
        return -1;
    }

    conf->last_connect_attempt = now;
    __sync_fetch_and_add(&conf->reconnect_attempts, 1);

    WARNING(PLUGIN_NAME ": Reconnecting to TDengine (attempt #%lu)",
            conf->reconnect_attempts);

    if (tdengine_connect(conf) == 0) {
        __sync_fetch_and_add(&conf->reconnections, 1);
        return 0;
    }

    return -1;
}

/**
 * Callback d'initialisation collectd
 * Crée la connexion TDengine et lance le thread de flush
 */
static int init_callback(void) {
    if (!g_config) {
        ERROR(PLUGIN_NAME ": Not configured");
        return -1;
    }

    INFO(PLUGIN_NAME ": Connecting to TDengine at %s:%d",
         g_config->host, g_config->port);

    if (tdengine_connect(g_config) != 0) {
        ERROR(PLUGIN_NAME ": Failed to connect to TDengine");
        return -1;
    }

    /* Inverse l'ordre des retentions pour traitement dans l'ordre du fichier de conf */
    if (g_config->retentions != NULL) {
        reverse_retention_list(g_config);
    }

    /* Crée les databases de rétention si configurées */
    if (g_config->retentions != NULL) {
        INFO(PLUGIN_NAME ": Setting up retention databases");
        if (ensure_retention_databases(g_config) != 0) {
            WARNING(PLUGIN_NAME ": Failed to setup some retention databases");
            /* Continue anyway - non-fatal */
        }
    }

    /* V2.0: Initialise le cache de prepared statements */
    memset(&g_config->stmt_cache, 0, sizeof(stmt_cache_t));
    if (pthread_rwlock_init(&g_config->stmt_cache.lock, NULL) != 0) {
        ERROR(PLUGIN_NAME ": Failed to initialize statement cache lock");
        taos_close(g_config->conn);
        g_config->conn = NULL;
        return -1;
    }
    g_config->stmt_cache.count = 0;
    INFO(PLUGIN_NAME ": Prepared statement cache initialized (max %d entries)", MAX_STMT_CACHE);

    /* Lance le thread de flush asynchrone */
    g_config->running = true;
    if (pthread_create(&g_config->flush_thread, NULL, flush_thread_func,
                      g_config) != 0) {
        ERROR(PLUGIN_NAME ": Failed to create flush thread");
        taos_close(g_config->conn);
        g_config->conn = NULL;
        g_config->running = false;
        return -1;
    }

    /* V2.3: Lance le thread de création de tables asynchrone */
    g_config->create_table_queue = llist_create();
    if (!g_config->create_table_queue) {
        ERROR(PLUGIN_NAME ": Failed to create table queue");
        g_config->running = false;
        pthread_join(g_config->flush_thread, NULL);
        taos_close(g_config->conn);
        g_config->conn = NULL;
        return -1;
    }

    if (pthread_mutex_init(&g_config->create_table_lock, NULL) != 0) {
        ERROR(PLUGIN_NAME ": Failed to initialize create table lock");
        llist_destroy(g_config->create_table_queue);
        g_config->running = false;
        pthread_join(g_config->flush_thread, NULL);
        taos_close(g_config->conn);
        g_config->conn = NULL;
        return -1;
    }

    if (pthread_cond_init(&g_config->create_table_cond, NULL) != 0) {
        ERROR(PLUGIN_NAME ": Failed to initialize create table condition");
        pthread_mutex_destroy(&g_config->create_table_lock);
        llist_destroy(g_config->create_table_queue);
        g_config->running = false;
        pthread_join(g_config->flush_thread, NULL);
        taos_close(g_config->conn);
        g_config->conn = NULL;
        return -1;
    }

    if (pthread_create(&g_config->create_table_thread, NULL, create_table_thread_func,
                      g_config) != 0) {
        ERROR(PLUGIN_NAME ": Failed to create async CREATE TABLE thread");
        pthread_cond_destroy(&g_config->create_table_cond);
        pthread_mutex_destroy(&g_config->create_table_lock);
        llist_destroy(g_config->create_table_queue);
        g_config->running = false;
        pthread_join(g_config->flush_thread, NULL);
        taos_close(g_config->conn);
        g_config->conn = NULL;
        return -1;
    }

    INFO(PLUGIN_NAME ": Plugin initialized successfully (async CREATE TABLE enabled)");
    return 0;
}

/**
 * Callback de shutdown collectd
 * Flush les dernières données et nettoie les ressources
 */
static int shutdown_callback(void) {
    if (!g_config)
        return 0;

    INFO(PLUGIN_NAME ": Shutting down...");

    /* V2.8: Arrête les threads de manière douce (pas de pthread_cancel brutal)
     * Les threads font déjà un flush final propre avant return NULL */
    g_config->running = false;

    /* V2.8: Réveille TOUS les threads AVANT d'attendre leur terminaison */
    pthread_mutex_lock(&g_config->read_lock);
    pthread_cond_broadcast(&g_config->buffer_cond);
    pthread_mutex_unlock(&g_config->read_lock);

    pthread_mutex_lock(&g_config->create_table_lock);
    pthread_cond_broadcast(&g_config->create_table_cond);
    pthread_mutex_unlock(&g_config->create_table_lock);

    /* Attend que le flush_thread se termine proprement (flush final inclus) */
    INFO(PLUGIN_NAME ": Waiting for flush thread to finish gracefully...");
    int join_status = pthread_join(g_config->flush_thread, NULL);
    if (join_status != 0 && join_status != ESRCH) {
        ERROR(PLUGIN_NAME ": Stopping flush thread failed: %s", strerror(join_status));
    } else {
        INFO(PLUGIN_NAME ": Flush thread terminated gracefully");
    }

    /* V2.8: Attend que le thread de création de tables se termine */
    INFO(PLUGIN_NAME ": Waiting for create table thread to finish gracefully...");

    join_status = pthread_join(g_config->create_table_thread, NULL);
    if (join_status != 0 && join_status != ESRCH) {
        ERROR(PLUGIN_NAME ": Stopping create table thread failed: %s", strerror(join_status));
    } else {
        INFO(PLUGIN_NAME ": CREATE TABLE thread terminated");
    }

    /* Nettoie la queue restante */
    pthread_mutex_lock(&g_config->create_table_lock);
    llentry_t *ct_entry;
    while ((ct_entry = llist_head(g_config->create_table_queue)) != NULL) {
        char *stable_name = (char *)ct_entry->value;
        llist_remove(g_config->create_table_queue, ct_entry);
        sfree(stable_name);
    }
    llist_destroy(g_config->create_table_queue);
    pthread_mutex_unlock(&g_config->create_table_lock);

    pthread_cond_destroy(&g_config->create_table_cond);
    pthread_mutex_destroy(&g_config->create_table_lock);

    /* Affiche les statistiques finales */
    INFO(PLUGIN_NAME ": Statistics:");
    INFO(PLUGIN_NAME ":   Total written: %lu", g_config->total_written);
    INFO(PLUGIN_NAME ":   Total errors:  %lu", g_config->total_errors);
    INFO(PLUGIN_NAME ":   Total retried: %lu", g_config->total_retried);
    INFO(PLUGIN_NAME ":   Total retry failed: %lu", g_config->total_retry_failed);
    INFO(PLUGIN_NAME ":   Total dropped: %lu (buffer full or malloc failed)", g_config->total_dropped);
    INFO(PLUGIN_NAME ":   Batch flushes: %lu", g_config->batch_flushes);
    INFO(PLUGIN_NAME ":   Total reconnections: %lu", g_config->reconnections);
    INFO(PLUGIN_NAME ":   Total tables created async: %lu", g_config->total_tables_created_async);

    /* V2.0: Ferme tous les prepared statements du cache */
    pthread_rwlock_wrlock(&g_config->stmt_cache.lock);
    size_t stmt_closed = 0;
    for (size_t i = 0; i < g_config->stmt_cache.count; i++) {
        if (g_config->stmt_cache.entries[i].is_active &&
            g_config->stmt_cache.entries[i].stmt) {
            taos_stmt_close(g_config->stmt_cache.entries[i].stmt);
            g_config->stmt_cache.entries[i].stmt = NULL;
            g_config->stmt_cache.entries[i].is_active = false;
            stmt_closed++;
        }
    }
    pthread_rwlock_unlock(&g_config->stmt_cache.lock);
    INFO(PLUGIN_NAME ": Closed %zu prepared statements from cache", stmt_closed);

    /* Ferme la connexion TDengine sous le lock suivant le pattern collectd */
    pthread_mutex_lock(&g_config->conn_lock);
    if (g_config->conn) {
        taos_close(g_config->conn);
        g_config->conn = NULL;
    }
    pthread_mutex_unlock(&g_config->conn_lock);

    /* Nettoie les locks */
    pthread_mutex_destroy(&g_config->write_lock);
    pthread_mutex_destroy(&g_config->read_lock);
    pthread_mutex_destroy(&g_config->buffer_cond_lock);
    pthread_cond_destroy(&g_config->buffer_cond);
    pthread_rwlock_destroy(&g_config->table_cache.lock);
    pthread_rwlock_destroy(&g_config->stable_cache.lock);
    pthread_rwlock_destroy(&g_config->stmt_cache.lock);  /* V2.0: stmt cache lock */
    pthread_mutex_destroy(&g_config->conn_lock);
    pthread_mutex_destroy(&g_config->retry_buffer_lock);

    /* Libère la mémoire */
    free(g_config->buffer_array);
    free(g_config->host);
    free(g_config->user);
    free(g_config->password);
    free(g_config->database);

    /* Libère le tampon de réessai (V2.2 - binary retry) */
    llentry_t *entry = llist_head(g_config->retry_buffer);
    while(entry) {
        retry_batch_t *item = entry->value;
        free(item->points);
        free(item);
        entry = entry->next;
    }
    llist_destroy(g_config->retry_buffer);

    /* Libère la liste chaînée des mappings */
    mapping_rule_t *rule = g_config->mappings;
    while (rule != NULL) {
        mapping_rule_t *next = rule->next;
        free(rule->plugin);
        free(rule->type);
        free(rule->stable);
        free(rule);
        rule = next;
    }

    /* Libère la liste chaînée des retentions */
    retention_config_t *ret = g_config->retentions;
    while (ret != NULL) {
        retention_config_t *next = ret->next;
        free(ret);
        ret = next;
    }

    free(g_config);
    g_config = NULL;

    INFO(PLUGIN_NAME ": Shutdown complete");
    return 0;
}

void module_register(void) {
    plugin_register_complex_config(PLUGIN_NAME, config_callback);
    plugin_register_init(PLUGIN_NAME, init_callback);
    plugin_register_write(PLUGIN_NAME, write_callback, NULL);
    plugin_register_shutdown(PLUGIN_NAME, shutdown_callback);
}

/**
 * Author: YuutaW <YuutaW@YMC.MOE>
 *
 * CFLAGS=-std=c99 -I/usr/local/include/ -D_POSIX_C_SOURCE=200809L
 * LDFLAGS=-ljson-c -lcurl
 *
 * License: GPLv2
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <sysexits.h>
#include <curl/curl.h>
#include <stdlib.h>
#include <json-c/json_object.h>
#include <json-c/json_tokener.h>
#include <json-c/json.h>
#include <assert.h>

enum source_type {
    jar,
    client,
    extract_jar,
    log4j,
    asset,
    asset_index,
    fabric
};

struct source {
    struct source *next;
    char *id;
    char *hash;
    char *url;
    enum source_type type;
};

static struct source *source_fist = NULL;

static char *out_pkgbuild = "PKGBUILD.gen";
static FILE *pkgbuild = NULL;
static char *out_launcher = "launcher.gen";
static FILE *launcher = NULL;
static char *out_fabric_launcher = "launcher.fabric.gen";
static char *version = NULL;
static CURL *curl = NULL;
static json_object *json = NULL;
static json_tokener *tok = NULL;
static char *all_version_manifest_url = "https://launchermeta.mojang.com/mc/game/version_manifest_v2.json";
static char *version_manifest_url = NULL;
static char *all_fabric_manifest_url = "https://meta.fabricmc.net/v2/versions/loader";
static char *fabric_manifest_url = NULL;
static char *assets_url = NULL;

static void cleanup(void) {
    if (pkgbuild) fclose(pkgbuild);
    if (launcher) fclose(launcher);
    if (curl) {
        curl_easy_cleanup(curl);
        curl_global_cleanup();
    }
    if (tok) json_tokener_free(tok);
    if (json) {
        json_object_put(json);
        json = NULL;
    }
    struct source *s = source_fist;
    while (s) {
        struct source *s1 = s->next;
        free(s->hash);
        free(s->id);
        free(s->url);
        free(s);
        s = s1;
    }
    if (version) free(version);
}

static char get(const char *url, const char fail_not_found) {
    /* The url may belong to the json. Use it first. */
    curl_easy_setopt(curl, CURLOPT_URL, url);
    if (json) {
        json_object_put(json);
        json = NULL;
    }
    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_WRITE_ERROR) {
        cleanup();
        exit(1);
    }
    if (res) {
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (!fail_not_found && (http_code == 400 || http_code == 404)) return 1;
        cleanup();
        errx(res, "Cannot GET %s: %s",
             url,
             curl_easy_strerror(res));
    }
    /* No worries for IDE condition warning: it will be set in the callback function. */
    if (!json) {
        cleanup();
        errx(1, "Cannot parse response JSON: "
                "The stream ends without a full JSON.");
    }
    return 0;
}

static FILE *try_fopen(const char *path) {
    FILE *f = fopen(path, "w+");
    if (!f) {
        cleanup();
        err(errno, "Cannot open %s", path);
    }
    return f;
}

static size_t write_data(void *buffer, size_t size, size_t nmemb, void *userp) {
    json = json_tokener_parse_ex(tok,
                                 buffer,
                                 (int) (size * nmemb));
    enum json_tokener_error e;
    if (!json && (e = json_tokener_get_error(tok)) != json_tokener_continue) {
        /* Not sure if it is safe to call curl_easy_cleanup() within the callback.
         * Thus, delegate exit to the caller.
         * We will lose the return code here. */
        fprintf(stderr, "Cannot parse response JSON: %s",
                json_tokener_error_desc(e));
        /* Not necessary, but just to satisfy me. */
        json_tokener_reset(tok);
        return 0;
    }
    return size * nmemb;
}

static void src(const char *hash, const char *url, const enum source_type type) {
    char *id = strrchr(url, '/');
    if (!id) {
        cleanup();
        errx(1, "URL %s is not valid.", url);
    }
    /* Remove leading / */
    id++;
    struct source *s = malloc(sizeof(struct source));
    if (!s) {
        cleanup();
        err(errno, "Cannot allocate memory. Requested %lu bytes.",
            sizeof(struct source));
    }
    s->next = source_fist;
    s->id = calloc(strlen(id) + 1, sizeof(char));
    if (!s->id) {
        free(s);
        cleanup();
        err(errno, "Cannot allocate memory");
    }
    strcpy(s->id, id);
    s->hash = calloc(strlen(hash) + 1, sizeof(char));
    if (!s->hash) {
        free(s->id);
        free(s);
        cleanup();
        err(errno, "Cannot allocate memory");
    }
    strcpy(s->hash, hash);
    s->url = calloc(strlen(url) + 1, sizeof(char));
    if (!s->url) {
        free(s->id);
        free(s->hash);
        free(s);
        cleanup();
        err(errno, "Cannot allocate memory");
    }
    strcpy(s->url, url);

    s->type = type;

    source_fist = s;
}

static void append(FILE *stream, const char *key, const char *value) {
    fprintf(stream, "%s=\"$%s %s\"\n",
            key,
            key,
            value);
}

static void arg(const char jvm, const char *value) {
    if (strchr(value, ' ')) {
        fprintf(stderr, "Warn: Refusing argument with space: %s\n", value);
        return;
    }
    append(launcher, jvm ? (jvm == 2 ? "JVM_ARGS_X86" : "JVM_ARGS") : "MC_ARGS", value);
}

static void set(FILE *stream, const char *key, const char *value) {
    fprintf(stream, "%s=\"%s\"\n",
            key,
            value);
}

static void parse_artifact(json_object *artifact, const enum source_type type) {
    json_object *obj;
    if (!json_object_object_get_ex(artifact, "sha1", &obj)) {
        cleanup();
        errx(1, "Invalid version.json: library doesn't have sha1.");
    }
    const char *sha1 = json_object_get_string(obj);
    if (!json_object_object_get_ex(artifact, "url", &obj)) {
        cleanup();
        errx(1, "Invalid version.json: library doesn't have url.");
    }
    const char *url = json_object_get_string(obj);
    src(sha1, url, type);
}

static char check_rules(json_object *rules) {
    char allow = 0;
    unsigned int rules_len = json_object_array_length(rules);
    for (unsigned int j = 0; j < rules_len; j++) {
        const json_object *rule = json_object_array_get_idx(rules, j);
        json_object *obj2;
        if (json_object_object_get_ex(rule, "os", &obj2)) {
            json_object *obj3;
            if (json_object_object_get_ex(obj2, "name", &obj3)) {
                /* Definitely not Unix, bro? */
                continue;
            }
            if (json_object_object_get_ex(obj2, "arch", &obj3) &&
                !strcmp("x86", json_object_get_string(obj3))) {
                allow = 2;
                break;
            }
            continue;
        }
        if (!json_object_object_get_ex(rule, "action", &obj2)) {
            cleanup();
            errx(1, "Rule doesn't have an action.");
        }
        /* Although the value seems to be always allow,
         * a double check seems satisfying. */
        if (!strcmp("allow", json_object_get_string(obj2))) {
            allow = 1;
            break;
        }
    }
    return allow;
}

static const char *fetch_version_manifest(void) {
    get(all_version_manifest_url, 1);
    json_object *obj;
    if (!version) {
        if (!json_object_object_get_ex(json, "latest", &obj)) {
            cleanup();
            errx(1, "Invalid version_manifest_v2.json: No latest object.");
        }
        if (!json_object_object_get_ex(obj, "release", &obj)) {
            cleanup();
            errx(1, "Invalid version_manifest_v2.json: No release object.");
        }
        const char *ver = json_object_get_string(obj);
        unsigned int len = strlen(ver);
        version = calloc(len + 1, sizeof(char));
        if (!version) {
            cleanup();
            err(errno, "Cannot allocate memory");
        }
        memcpy(version, ver, len + 1);
    }
    if (!json_object_object_get_ex(json, "versions", &obj)) {
        cleanup();
        errx(1, "Invalid version_manifest_v2.json: No versions[] object.");
    }
    unsigned int len = json_object_array_length(obj);
    for (unsigned int i = 0; i < len; i++) {
        const json_object *item = json_object_array_get_idx(obj, i);
        json_object *obj1;
        if (!json_object_object_get_ex(item, "id", &obj1)) {
            cleanup();
            errx(1, "Version doesn't have an id object.");
        }
        if (strcmp(version, json_object_get_string(obj1)) != 0) continue;
        if (!json_object_object_get_ex(item, "url", &obj1)) {
            cleanup();
            errx(1, "Invalid version_manifest_v2.json: no URL.");
        }
        return json_object_get_string(obj1);
    }
    cleanup();
    errx(1, "Version %s is not found.", version);
}

static const char *fetch_fabric_manifest(void) {
    get(all_fabric_manifest_url, 1);
    unsigned int len = json_object_array_length(json);
    for (unsigned int i = 0; i < len; i++) {
        const json_object *item = json_object_array_get_idx(json, i);
        json_object *obj1;
        if (!json_object_object_get_ex(item, "stable", &obj1)) {
            cleanup();
            errx(1, "Invalid fabric version json: no stable.");
        }
        if (!json_object_get_boolean(obj1)) continue;
        if (!json_object_object_get_ex(item, "version", &obj1)) {
            cleanup();
            errx(1, "Fabric loader doesn't have the version object.");
        }
        return json_object_get_string(obj1);
    }
    cleanup();
    errx(1, "No stable Fabric versions found.");
}

static void parse_arguments(struct json_object *obj) {
    json_object *args;
    if (!json_object_object_get_ex(obj, "game", &args)) {
        cleanup();
        errx(1, "Invalid version.json: No game[] object.");
    }
    unsigned int args_len = json_object_array_length(args);
    for (unsigned int i = 0; i < args_len; i++) {
        json_object *item = json_object_array_get_idx(args, i);
        if (json_object_is_type(item, json_type_string)) {
            arg(0, json_object_get_string(item));
            continue;
        }
        if (!json_object_is_type(item, json_type_object)) {
            cleanup();
            errx(1, "Unknown Argument type: it must be a string or object.");
        }
        /* Currently, we don't support --demo, --width and --height. */
        json_object *val;
        if (!json_object_object_get_ex(item, "value", &val)) {
            cleanup();
            errx(1, "Argument doesn't have a value object.");
        }
        if (json_object_is_type(val, json_type_string)) {
            fprintf(stderr, "Skipped unsupported game argument: %s\n",
                    json_object_get_string(val));
        } else if (json_object_is_type(val, json_type_array)) {
            fprintf(stderr, "Skipped unsupported game argument: ");
            unsigned int len = json_object_array_length(val);
            for (unsigned int j = 0; j < len; j++) {
                fprintf(stderr, "%s ",
                        json_object_get_string(
                                json_object_array_get_idx(val, j)
                        ));
            }
            fprintf(stderr, "\n");
        }
    }
    if (!json_object_object_get_ex(obj, "jvm", &args)) {
        cleanup();
        errx(1, "Invalid version.json: No jvm[] object.");
    }
    args_len = json_object_array_length(args);
    for (unsigned int i = 0; i < args_len; i++) {
        json_object *item = json_object_array_get_idx(args, i);
        if (json_object_is_type(item, json_type_string)) {
            arg(1, json_object_get_string(item));
            continue;
        }
        if (!json_object_is_type(item, json_type_object)) {
            cleanup();
            errx(1, "Unknown JVM Argument type: it must be a string or object.");
        }
        json_object *value;
        unsigned int value_len = 1;
        if (!json_object_object_get_ex(item, "value", &value)) {
            cleanup();
            errx(1, "JVM Argument doesn't have a value object.");
        }
        if (json_object_is_type(value, json_type_array)) {
            value_len = json_object_array_length(value);
        }
        json_object *rules;
        if (json_object_object_get_ex(item, "rules", &rules)) {
            const char rule = check_rules(rules);
            if (!rule) continue;
            if (rule == 2) {
                if (json_object_is_type(value, json_type_string)) {
                    arg(2, json_object_get_string(value));
                } else {
                    for (unsigned int j = 0; j < value_len; j++) {
                        arg(2,
                               json_object_get_string(
                                       json_object_array_get_idx(value, j)
                               ));
                    }
                }
            } else {
                if (json_object_is_type(value, json_type_string)) {
                    arg(1, json_object_get_string(value));
                } else {
                    for (unsigned int j = 0; j < value_len; j++) {
                        arg(1,
                               json_object_get_string(
                                       json_object_array_get_idx(value, j)
                               ));
                    }
                }
            }
        }
    }
}

static char *parse_maven(const char *name, const char *maven_repo) {
    /* Download from Maven instead */
    unsigned short seg = 0;
    char *name_cpy = calloc(strlen(name) + 1, sizeof(char));
    if (!name_cpy) {
        cleanup();
        err(errno, "Cannot allocate memory");
    }
    memcpy(name_cpy, name, strlen(name) + 1);
    const unsigned int repo_len = strlen(maven_repo);
    unsigned int artifact_len = 0;
    const unsigned int len = repo_len + 1 /* / */ +
                             2 * strlen(name) + 1 /* / before jar name */ + 4 /* .jar */ + 1;
    char *url_jar = calloc(len, sizeof(char));
    if (!url_jar) {
        cleanup();
        err(errno, "Cannot allocate memory");
    }
    unsigned int url_jar_len = 0;
    unsigned int artifact_start = 0;
    memcpy(url_jar, maven_repo, repo_len);
    url_jar_len += repo_len;
    url_jar[url_jar_len ++] = '/';
    /* Highly inefficient code. */
    for (char *p = strtok(name_cpy, ":"); p != NULL; p = strtok(NULL, ":")) {
        switch (seg ++) {
            case 0: {
                unsigned int z = 0;
                char c;
                while ((c = p[z ++]) != '\0') {
                    if (c == '.') url_jar[url_jar_len ++] = '/';
                    else url_jar[url_jar_len ++] = c;
                }
                url_jar[url_jar_len ++] = '/';
                break;
            }
            case 1:
                artifact_len = strlen(p);
                artifact_start = url_jar_len;
                memcpy(&url_jar[url_jar_len], p, artifact_len);
                url_jar_len += artifact_len;
                url_jar[url_jar_len ++] = '/';
                break;
            case 2: {
                unsigned int version_len = strlen(p);
                memcpy(&url_jar[url_jar_len], p, version_len);
                url_jar_len += version_len;
                url_jar[url_jar_len ++] = '/';
                memcpy(&url_jar[url_jar_len], &url_jar[artifact_start], artifact_len);
                url_jar_len += artifact_len;
                url_jar[url_jar_len ++] = '-';
                memcpy(&url_jar[url_jar_len], p, version_len);
                url_jar_len += version_len;
                memcpy(&url_jar[url_jar_len], ".jar\0", 5);
                url_jar_len += 5;
                break;
            }
            default:
                free(url_jar);
                free(name_cpy);
                errx(1, "Illegal maven name: %s", name);
        }
    }
    free(name_cpy);
    return url_jar;
}

static void fetch_version(const char *url, const char is_fabric) {
    /* URL is no longer valid. */
    if (get(url, is_fabric ? 0 : 1)) {
        fprintf(stderr, "Warn: No Fabric available for this version.\n");
        return;
    }
    json_object *obj;
    if (!json_object_object_get_ex(json, "mainClass", &obj)) {
        cleanup();
        errx(1, "Invalid version.json: No mainClass object.");
    }
    set(launcher, "MAIN_CLASS", json_object_get_string(obj));
    if (!is_fabric) {
        if (!json_object_object_get_ex(json, "id", &obj)) {
            cleanup();
            errx(1, "Invalid version.json: No id object.");
        }
        set(launcher, "ID", json_object_get_string(obj));
        set(pkgbuild, "_MC_ID", json_object_get_string(obj));
    }
    if (json_object_object_get_ex(json, "javaVersion", &obj)) {
        if (!json_object_object_get_ex(obj, "majorVersion", &obj)) {
            cleanup();
            errx(1, "Invalid version.json: No majorVersion object.");
        }
        fprintf(pkgbuild, "_JAVA_VERSION=%d\n",
                json_object_get_int(obj));
    }
    if (!json_object_object_get_ex(json, "libraries", &obj)) {
        cleanup();
        errx(1, "Invalid version.json: No libraries[] object.");
    }
    unsigned int libs_len = json_object_array_length(obj);
    for (unsigned int i = 0; i < libs_len; i++) {
        const json_object *item = json_object_array_get_idx(obj, i);
        json_object *obj1;
        if (json_object_object_get_ex(item, "rules", &obj1)) {
            if (!check_rules(obj1)) continue;
        }
        if (!json_object_object_get_ex(item, "downloads", &obj1)) {
            json_object *maven;
            if (!json_object_object_get_ex(item, "name", &obj1) ||
                !json_object_object_get_ex(item, "url", &maven)) {
                cleanup();
                errx(1, "Library doesn't have downloads object.");
            }
            const char *name = json_object_get_string(obj1);
            const char *maven_repo = json_object_get_string(maven);
            char *maven_url = parse_maven(name, maven_repo);
            src("SKIP", maven_url, is_fabric ? fabric : jar);
            free(maven_url);
            continue;
        }
        json_object *artifact;
        json_object *natives;
        json_object *classifiers;
        /* Prefer natives in case they both exist.
         * It seems that if they both exist, there must be a standalone artifact before it.
         */
        if (json_object_object_get_ex(item, "natives", &natives) &&
            json_object_object_get_ex(obj1, "classifiers", &classifiers)) {
            if (!json_object_object_get_ex(natives, "linux", &obj1))
                continue;
            if (!json_object_object_get_ex(classifiers,
                                           json_object_get_string(obj1),
                                           &obj1))
                continue;
            parse_artifact(obj1, extract_jar);
        } else if (json_object_object_get_ex(obj1, "artifact", &artifact)) {
            parse_artifact(artifact,
                           json_object_object_get_ex(item, "extract", &obj1) ? extract_jar
                                                                             : jar);
        } else {
            cleanup();
            errx(1, "Library doesn't have an artifact or natives and classifiers object.");
        }
    }

    if (!is_fabric) {
        if (!json_object_object_get_ex(json, "downloads", &obj)) {
            cleanup();
            errx(1, "Invalid version.json: No downloads object.");
        }
        if (!json_object_object_get_ex(obj, "client", &obj)) {
            cleanup();
            errx(1, "Invalid version.json: No client object.");
        }
        parse_artifact(obj, client);

        if (!json_object_object_get_ex(json, "assetIndex", &obj)) {
            cleanup();
            errx(1, "Invalid version.json: No assetIndex object.");
        }
        json_object *obj1;
        if (!json_object_object_get_ex(obj, "url", &obj1)) {
            cleanup();
            errx(1, "Invalid version.json: assetIndex does not have the url object.");
        }
        assets_url = (char *) json_object_get_string(obj1);
        if (!json_object_object_get_ex(obj, "sha1", &obj1)) {
            cleanup();
            errx(1, "Invalid version.json: assetIndex does not have the sha1 object.");
        }
        src(json_object_get_string(obj1), assets_url, asset_index);
        if (!json_object_object_get_ex(obj, "id", &obj1)) {
            cleanup();
            errx(1, "Invalid version.json: assetIndex does not have the id object.");
        }
        set(pkgbuild, "_ASSET_ID", json_object_get_string(obj1));
        set(launcher, "ASSET_ID", json_object_get_string(obj1));
        set(launcher, "assets_index_name", json_object_get_string(obj1));
    }

    if (json_object_object_get_ex(json, "arguments", &obj)) {
        parse_arguments(obj);
    } else if (json_object_object_get_ex(json, "minecraftArguments", &obj)) {
        arg(0, json_object_get_string(obj));
    } else {
        cleanup();
        errx(1, "Invalid version.json: No arguments or minecraftArguments object.");
    }
    if (json_object_object_get_ex(json, "logging", &obj)) {
        if (json_object_object_get_ex(obj, "client", &obj)) {
            json_object *file;
            json_object *a;
            if (!json_object_object_get_ex(obj, "file", &file)) {
                cleanup();
                errx(1, "Logging doesn't have the file object.");
            }
            if (!json_object_object_get_ex(obj, "argument", &a)) {
                cleanup();
                errx(1, "Logging doesn't have the argument object.");
            }
            json_object *id;
            if (!json_object_object_get_ex(file, "id", &id)) {
                cleanup();
                errx(1, "Logging file doesn't have the id object.");
            }
            set(pkgbuild, "_LOG4J_FILE", json_object_get_string(id));
            set(launcher, "LOG4J_FILE", json_object_get_string(id));
            parse_artifact(file, log4j);
            /* Hope Mojang won't change this. */
            if (strcmp("-Dlog4j.configurationFile=${path}",
                       json_object_get_string(a)) != 0) {
                fprintf(stderr,
                        "Unsupported Log4J Configuration: %s",
                        (char *) json_object_get_string(a));
            } else {
                arg(1, "-Dlog4j.configurationFile=LOG4J_XML_PATH");
            }
        }
    }
}

static void fetch_assets(void) {
    get(assets_url, 1);
    json_object *obj;
    if (!json_object_object_get_ex(json, "objects", &obj)) {
        cleanup();
        errx(1, "Invalid assets JSON: no objects object.");
    }
    char url[85];
    json_object_object_foreach(obj, key, val) {
        json_object *hash;
        if (!json_object_object_get_ex(val, "hash", &hash)) {
            cleanup();
            errx(1, "Invalid assets JSON: no hash object.");
        }
        const char *hash_str = json_object_get_string(hash);
        if (strlen(hash_str) != 40) {
            cleanup();
            errx(1, "Invalid length of hash.");
        }
        sprintf(url, "https://resources.download.minecraft.net/%c%c/%s",
                hash_str[0],
                hash_str[1],
                hash_str);
        src(hash_str, url, asset);
    }
}

static void out(const char *tag, enum source_type type) {
    char tag_fin[64];
    sprintf(tag_fin, "_MC_%s=\"", tag);
    struct source *s = source_fist;
    fprintf(pkgbuild, "%s", tag_fin);
    while (s) {
        if (s->type == type) fprintf(pkgbuild, "%s\n", s->id);
        s = s->next;
    }
    fprintf(pkgbuild, "\"\n");

    sprintf(tag_fin, "_MC_%s_SHA1=\"", tag);
    s = source_fist;
    fprintf(pkgbuild, "%s", tag_fin);
    while (s) {
        if (s->type == type) fprintf(pkgbuild, "%s\n", s->hash);
        s = s->next;
    }
    fprintf(pkgbuild, "\"\n");

    sprintf(tag_fin, "_MC_%s_URL=\"", tag);
    s = source_fist;
    fprintf(pkgbuild, "%s", tag_fin);
    while (s) {
        if (s->type == type) fprintf(pkgbuild, "%s\n", s->url);
        s = s->next;
    }
    fprintf(pkgbuild, "\"\n");
}

int main(int argc, char **argv) {
    int opt;
    while ((opt = getopt(argc, argv, "o:O:v:m:M:f:F:g:")) != -1) {
        switch (opt) {
            case 'o':
                out_pkgbuild = optarg;
                break;
            case 'O':
                out_launcher = optarg;
                break;
            case 'v': {
                unsigned int len = strlen(optarg);
                version = calloc(len + 1, sizeof(char));
                if (!version) {
                    cleanup();
                    err(errno, "Cannot allocate memory");
                }
                memcpy(version, optarg, len + 1);
                break;
            }
            case 'm':
                version_manifest_url = optarg;
                break;
            case 'M':
                all_version_manifest_url = optarg;
                break;
            case 'f':
                fabric_manifest_url = optarg;
                break;
            case 'F':
                all_fabric_manifest_url = optarg;
                break;
            case 'g':
                out_fabric_launcher = optarg;
                break;
            default:
                errx(EX_USAGE, "-o %s -O %s -v %s -g %s",
                     out_pkgbuild,
                     out_launcher,
                     version,
                     out_fabric_launcher);
        }
    }
    pkgbuild = try_fopen(out_pkgbuild);
    launcher = try_fopen(out_launcher);
    CURLcode res = curl_global_init(CURL_GLOBAL_SSL);
    if (res) {
        cleanup();
        errx(res, "Cannot initialize libcurl global: %s",
             curl_easy_strerror(res));
    }
    if (!(curl = curl_easy_init())) {
        curl_global_cleanup();
        cleanup();
        errx(1, "Cannot initialize libcurl.");
    }
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
    tok = json_tokener_new();
    if (!tok) {
        cleanup();
        errx(1, "Cannot initialize JSON tok.");
    }
    fetch_version(version_manifest_url == NULL ? fetch_version_manifest() : version_manifest_url, 0);
    if (assets_url) fetch_assets();
    out("CLIENT", client);
    out("JAR", jar);
    out("EXTRACT_JAR", extract_jar);
    out("ASSET", asset);
    out("LOG4J", log4j);
    out("ASSET_INDEX", asset_index);
    fclose(launcher);

    launcher = try_fopen(out_fabric_launcher);
    char fabric_built_url[256];
    if (!fabric_manifest_url) {
        const char *ver = fetch_fabric_manifest();
        set(pkgbuild, "_FABRIC", ver);
        set(launcher, "FABRIC", ver);
        sprintf(fabric_built_url,
                "https://meta.fabricmc.net/v2/versions/loader/%s/%s/profile/json",
                version,
                ver);
        fabric_manifest_url = fabric_built_url;
    }
    fetch_version(fabric_manifest_url, 1);
    out("FABRIC_JAR", fabric);

    cleanup();
    return 0;
}

#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <strings.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/limits.h>

#define ALL_TABLES -1

#define RED "\033[0;31m"
#define YELLOW "\033[0;33m"
#define RESET "\033[0;0m"

#define BYTE_S 1L
#define KBYTE_S 1024L
#define MBYTE_S ((uint64_t) (KBYTE_S * KBYTE_S))

# define NT_LEN 1

bool _verbose_flag;

typedef struct query_s {
    char *stmt, *specifiers;
    bool is_parameterized;
    size_t specifiers_len;
} quert_t;

typedef quert_t *Query;

static Query parse_stmt(const char *restrict stmt) {
    const size_t prepare_stmt_len = strnlen(stmt, KBYTE_S * 2);
    char prepare_stmt[(KBYTE_S * 2) + NT_LEN], result[(KBYTE_S * 2) + NT_LEN] = "", specifiers[63 + NT_LEN] = "";

    strncpy(prepare_stmt, stmt, prepare_stmt_len);

    for (unsigned int i = 0, j = 0, k = 0; i < prepare_stmt_len; i++, j++) {
        if (prepare_stmt[i] == '%') {
            result[j] = '?';
            specifiers[k] = prepare_stmt[i + 1];
            i++;
            k++;
        } else
            result[j] = prepare_stmt[i];
    }

    Query query = (Query) malloc(sizeof(quert_t));

    if (!query)
        exit(EXIT_FAILURE);

    query->stmt = (char*) calloc(2048, sizeof(char));

    if (!query->stmt)
        exit(EXIT_FAILURE);
    strncpy(query->stmt, result, KBYTE_S * 2);
    query->specifiers = (char*) calloc(64, sizeof(char));

    if (!query->specifiers)
        exit(EXIT_FAILURE);

    if (specifiers[0] != '\0') {
        query->is_parameterized = true;
        query->specifiers_len = strnlen(specifiers, 63);
        strncpy(query->specifiers, specifiers, 63);
        return query;
    }
    query->is_parameterized = false;
    query->specifiers_len = 0;

    return query;
}

static void destroy_query(Query query) {
    free(query->stmt);
    query->stmt = NULL;

    free(query->specifiers);
    query->specifiers = NULL;

    free(query);
    query = NULL;
    return;
}

static void print_headers(const int rows, sqlite3_stmt *sql_byte_code) {
    sqlite3_step(sql_byte_code);
    printf("| %s |", sqlite3_column_name(sql_byte_code, 0));

    for (int i = 1; i < rows; i++)
        printf(" %s |", sqlite3_column_name(sql_byte_code, i));
    printf("\n");
}

static void print_rows(const int rows, sqlite3_stmt *sql_byte_code) {
    int result;
    const char *row_value;

    do {
        row_value = (char*) sqlite3_column_text(sql_byte_code, 0);

        printf("| %s |", row_value ? row_value: "NULL");

        for (int i = 1; i < rows; i++) {
            row_value = (char*) sqlite3_column_text(sql_byte_code, i);

            printf(" %s |", row_value ? row_value: "NULL");
        }
        printf("\n");
        result = sqlite3_step(sql_byte_code);

    } while(result == SQLITE_ROW);
}

static int sqlite_exec(const char *restrict stmt, ...) {
    sqlite3 *db;
    sqlite3_stmt *sql_byte_code;
    int result_code = sqlite3_open("test.sqlite3", &db);

    if (result_code != SQLITE_OK) {
        fprintf(stderr, RED "Database Error: Cannot open database: %s\n" RESET, sqlite3_errmsg(db));
        exit(EXIT_FAILURE);
    }
    const Query restrict query = parse_stmt(stmt);
    result_code = sqlite3_prepare_v2(db, query->stmt, KBYTE_S * 2, &sql_byte_code, NULL);

    if (result_code != SQLITE_OK) {
        if (_verbose_flag)
            fprintf(stderr, YELLOW "SQL error: %s\n" RESET, sqlite3_errmsg(db));
        sqlite3_finalize(sql_byte_code);
        sqlite3_close(db);
        return -1;
    }

    if (query->is_parameterized) {
        char c;
        va_list args;
        struct stat file;
        char *string;

        va_start(args, stmt);

        for (unsigned short i = 0; i < query->specifiers_len; i++) {
            c = query->specifiers[i];

            switch (c) {
            case 'd':
                sqlite3_bind_int(sql_byte_code, i + 1, va_arg(args, int));
                continue;
            case 's':
                string = va_arg(args, char*);

                sqlite3_bind_text(sql_byte_code, i + 1, string, strnlen(string, PATH_MAX), SQLITE_STATIC);
                continue;
            case 'f':
                sqlite3_bind_double(sql_byte_code, i + 1, va_arg(args, double));
                continue;
            case 'b':
                string = va_arg(args, char*);

                stat(string, &file);
                sqlite3_bind_blob(sql_byte_code, i + 1, string, file.st_size, SQLITE_STATIC);
                continue;
            }
        }
        va_end(args);
    }

    if (strncasecmp("SELECT", query->stmt, 6) == 0) {
        const int rows = sqlite3_column_count(sql_byte_code);

        print_headers(rows, sql_byte_code);
        print_rows(rows, sql_byte_code);
    } else {
        sqlite3_step(sql_byte_code);

        if (_verbose_flag)
            printf("Rows affected: %d\n", sqlite3_changes(db));
    }
    destroy_query(query);
    sqlite3_finalize(sql_byte_code);
    sqlite3_close(db);

    return 0;
}


static void sqlite_load_exec(const char *restrict filepath) {
    sqlite3 *db;
    char buf[KBYTE_S], sql_buf[MBYTE_S] = {0};
    char *err_msg;
    FILE *fixture = fopen(filepath, "r");

    if (!fixture) {
        fprintf(stderr, RED "%s\n" RESET, strerror(errno));
        return;
    }

    while (fgets(buf, KBYTE_S, fixture))
        strncat(sql_buf, buf, KBYTE_S);
    int result_code = sqlite3_open("test.sqlite3", &db);

    if (result_code != SQLITE_OK) {
        fprintf(stderr, RED "Database Error: Cannot open database: %s\n" RESET, sqlite3_errmsg(db));
        return;
    }
    result_code = sqlite3_exec(db, sql_buf, NULL, NULL, &err_msg);

    if (result_code != SQLITE_OK) {
        fprintf(stderr, RED "SQL error: %s\n" RESET, err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return;
    }
    sqlite3_close(db);

    return;
}

static void sqlite_dumpdb(void) {
    sqlite3 *d_db, *s_db;
    sqlite3_backup *backup;
    int result_code = sqlite3_open("test.sqlite3", &s_db);

    if (result_code != SQLITE_OK) {
        fprintf(stderr, RED "Database Error: Cannot open source database: %s\n" RESET, sqlite3_errmsg(s_db));
        return;
    }
    result_code = sqlite3_open("copy.sqlite3", &d_db);

    if (result_code != SQLITE_OK) {
        fprintf(stderr, RED "Database Error: Cannot open destination database : %s\n" RESET, sqlite3_errmsg(d_db));
        return;
    }
    backup = sqlite3_backup_init(d_db, "main", s_db, "main");

    if (!backup) {
        fprintf(stderr, RED "Database Error: Cannot initalize database copy: %s\n" RESET, sqlite3_errmsg(d_db));
        return;
    }
    result_code = sqlite3_backup_step(backup, ALL_TABLES);

    while (result_code == SQLITE_OK)
        result_code = sqlite3_backup_step(backup, ALL_TABLES);

    if (result_code != SQLITE_DONE) {
        fprintf(stderr, RED "Database Error: Cannot copy database: %s\n" RESET, sqlite3_errmsg(s_db));
        return;
    }
    sqlite3_backup_finish(backup);
    sqlite3_close(s_db);

    return;
}

static void sqlite_dumptable(const char *restrict table) {
    sqlite3 *db;
    sqlite3_stmt *stmt_table, *stmt_data;
    char sql_stmt[4096] = {0};
    char *data;
    int col_cnt, result_code = sqlite3_open("test.sqlite3", &db);

    if (result_code != SQLITE_OK) {
        fprintf(stderr, RED "Database Error: Cannot open database: %s\n" RESET, sqlite3_errmsg(db));
        return;
    }
    snprintf(sql_stmt, KBYTE_S, "SELECT sql, COUNT() FROM sqlite_master WHERE type = 'table' AND name = '%s'", table);
    result_code = sqlite3_prepare_v2(db, sql_stmt, -1, &stmt_table, NULL);

    if (result_code != SQLITE_OK) {
        fprintf(stderr, RED "SQL error: %s\n" RESET, sqlite3_errmsg(db));
        return;
    }
    result_code = sqlite3_step(stmt_table);

    if (sqlite3_column_int(stmt_table, 1) == 0) {
        fprintf(stderr, RED "SQL error: table '%s' does not exist\n" RESET, table);
        return;
    }
    printf("PRAGMA foreign_keys=off;\nBEGIN TRANSACTION;\nDROP TABLE IF EXISTS %s;\n", table);
    data = (char*) sqlite3_column_text(stmt_table, 0);

    if (!data) {
        fprintf(stderr, RED "Database Error: Cannot open database: %s\n" RESET, sqlite3_errmsg(db));
        return;
    }

    printf("%s;\n", data);
    snprintf(sql_stmt, KBYTE_S, "SELECT * FROM %s;", table);
    result_code = sqlite3_prepare_v2(db, sql_stmt, -1, &stmt_data, NULL);

    if (result_code != SQLITE_OK) {
        fprintf(stderr, RED "SQL error: %s\n" RESET, sqlite3_errmsg(db));
        return;
    }
    result_code = sqlite3_step(stmt_data);

    while (result_code == SQLITE_ROW) {
        snprintf(sql_stmt, KBYTE_S, "INSERT INTO \"%s\" VALUES (", table);
        col_cnt = sqlite3_column_count(stmt_data);

        for (int index = 0; index < col_cnt; index++) {
            if (index)
                strcat(sql_stmt, ",");
            data = (char*) sqlite3_column_text(stmt_data, index);

            if (data) {
                if (sqlite3_column_type(stmt_data, index) == SQLITE_TEXT) {
                    strcat(sql_stmt, "'");
                    strcat(sql_stmt, data);
                    strcat(sql_stmt, "'");
                } else
                    strcat(sql_stmt, data);
            } else
                strcat(sql_stmt, "NULL");
        }
        printf("%s);\n", sql_stmt);
        result_code = sqlite3_step(stmt_data);
    }
    result_code = sqlite3_step(stmt_table);

    if (stmt_table)
        sqlite3_finalize(stmt_table);
    result_code = sqlite3_prepare_v2(db, "SELECT sql FROM sqlite_master WHERE type = 'trigger';", -1, &stmt_table, NULL);

    if (result_code != SQLITE_OK) {
        fprintf(stderr, RED "SQL error: %s\n" RESET, sqlite3_errmsg(db));
        return;
    }
    result_code = sqlite3_step(stmt_table);

    while (result_code == SQLITE_ROW) {
        data = (char*) sqlite3_column_text(stmt_table, 0);

        if (!data) {
            fprintf(stderr, RED "Database Error: Cannot open database: %s\n" RESET, sqlite3_errmsg(db));
            return;
        }

        printf("%s;\n", data);
        result_code = sqlite3_step(stmt_table);
    }
    puts("COMMIT;");

    return;
}

static char *sqlite_get_version(void) {
    return "Sqlite3 Version " SQLITE_VERSION;
}

int main(const int argc, char **const argv) {
    _verbose_flag = true;

    puts(sqlite_get_version());
    sqlite_dumpdb();
    sqlite_dumptable("sample");
    sqlite_load_exec("test_fixture.sql");
    sqlite_exec("SELECT * FROM sample;");
	return EXIT_SUCCESS;
}

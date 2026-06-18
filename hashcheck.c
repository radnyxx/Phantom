/*
 * hashcheck.c — Fast local hash verification against bundled IOC list.
 * Python C extension for the Phantom security toolkit.
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_HASH_LEN 64
#define MAX_LINE_LEN 128
#define INITIAL_CAPACITY 64

typedef struct {
    char **hashes;
    size_t count;
    size_t capacity;
} IOCDatabase;

static IOCDatabase db = {NULL, 0, 0};

static void db_free(void) {
    if (db.hashes) {
        for (size_t i = 0; i < db.count; i++) {
            free(db.hashes[i]);
        }
        free(db.hashes);
        db.hashes = NULL;
        db.count = 0;
        db.capacity = 0;
    }
}

static int db_add(const char *hash) {
    if (db.count >= db.capacity) {
        size_t new_cap = db.capacity == 0 ? INITIAL_CAPACITY : db.capacity * 2;
        char **new_hashes = realloc(db.hashes, new_cap * sizeof(char *));
        if (!new_hashes) return -1;
        db.hashes = new_hashes;
        db.capacity = new_cap;
    }
    db.hashes[db.count] = strdup(hash);
    if (!db.hashes[db.count]) return -1;
    db.count++;
    return 0;
}

static void strtolower(char *s) {
    for (; *s; s++) {
        if (*s >= 'A' && *s <= 'Z') *s += 32;
    }
}

static int is_valid_hash(const char *s) {
    size_t len = strlen(s);
    if (len != 32 && len != 40 && len != 64) return 0;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            return 0;
    }
    return 1;
}

static PyObject *hashcheck_load(PyObject *self, PyObject *args) {
    const char *filepath;
    if (!PyArg_ParseTuple(args, "s", &filepath)) return NULL;

    db_free();

    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        PyErr_SetString(PyExc_IOError, "Cannot open IOC file");
        return NULL;
    }

    char line[MAX_LINE_LEN];
    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\0') continue;

        p[strcspn(p, "\n\r")] = '\0';
        strtolower(p);

        if (is_valid_hash(p) && db_add(p) != 0) {
            fclose(fp);
            db_free();
            PyErr_SetString(PyExc_MemoryError, "Failed to allocate IOC database");
            return NULL;
        }
    }
    fclose(fp);

    return PyLong_FromSize_t(db.count);
}

static int hash_matches(const char *query) {
    char normalized[MAX_HASH_LEN + 1];
    strncpy(normalized, query, MAX_HASH_LEN);
    normalized[MAX_HASH_LEN] = '\0';
    strtolower(normalized);

    for (size_t i = 0; i < db.count; i++) {
        if (strcmp(normalized, db.hashes[i]) == 0)
            return 1;
    }
    return 0;
}

static PyObject *hashcheck_check(PyObject *self, PyObject *args) {
    const char *hash;
    if (!PyArg_ParseTuple(args, "s", &hash)) return NULL;

    if (!is_valid_hash(hash)) {
        PyErr_SetString(PyExc_ValueError, "Invalid hash format (expected MD5, SHA1, or SHA256)");
        return NULL;
    }

    if (db.count == 0) {
        PyErr_SetString(PyExc_RuntimeError, "IOC database not loaded — call load() first");
        return NULL;
    }

    return PyBool_FromLong(hash_matches(hash));
}

static PyObject *hashcheck_count(PyObject *self, PyObject *args) {
    return PyLong_FromSize_t(db.count);
}

static PyMethodDef HashcheckMethods[] = {
    {"load",  hashcheck_load,  METH_VARARGS, "Load IOC hashes from a file."},
    {"check", hashcheck_check, METH_VARARGS, "Check a hash against loaded IOCs."},
    {"count", hashcheck_count, METH_NOARGS,  "Return number of loaded IOC hashes."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef hashcheckmodule = {
    PyModuleDef_HEAD_INIT,
    "hashcheck",
    "Fast local hash verification against IOC lists.",
    -1,
    HashcheckMethods
};

PyMODINIT_FUNC PyInit_hashcheck(void) {
    return PyModule_Create(&hashcheckmodule);
}

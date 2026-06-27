/*
 * pontus.h — C-ABI surface over pontus-core (D-001).
 *
 * The GUI links the `pontus_ffi` shared library and includes this header.
 * All read views are returned as JSON strings (UTF-8, NUL-terminated).
 *
 * Ownership:
 *   - Every char* returned here is allocated by Rust; free it with
 *     pontus_string_free(), never with free().
 *   - The handle from pontus_open() must be released with pontus_close().
 *   - A NULL return means the call failed.
 *   - All functions are NULL-safe.
 */
#ifndef PONTUS_H
#define PONTUS_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque store handle. */
typedef struct PontusHandle PontusHandle;

/* Open (creating if absent) a store at db_path. NULL on failure. */
PontusHandle *pontus_open(const char *db_path);

/* Close a handle from pontus_open(). */
void pontus_close(PontusHandle *handle);

/* Library version string. Caller frees with pontus_string_free(). */
char *pontus_version(void);

/* JSON array of all assets. Caller frees with pontus_string_free(). */
char *pontus_assets_json(PontusHandle *handle);

/* JSON array of the most recent `limit` scans. Caller frees. */
char *pontus_scans_json(PontusHandle *handle, long long limit);

/* JSON array of one asset's observation history (newest first). Caller frees. */
char *pontus_asset_history_json(PontusHandle *handle, long long asset_id);

/* JSON array of per-host changes between two scans. Caller frees. */
char *pontus_diff_json(PontusHandle *handle, long long from_scan, long long to_scan);

/* JSON array of topology edges for a scan: [{"from":"..","to":".."}, ..]. Caller frees. */
char *pontus_topology_json(PontusHandle *handle, long long scan_id);

/* JSON array of hosts ranked by exploitation-weighted risk for a scan (worst
 * first), each with its vulnerabilities worst first. Caller frees. */
char *pontus_risk_json(PontusHandle *handle, long long scan_id);

/* JSON array of one scan's host observations (identity, IP, state). Caller frees. */
char *pontus_observations_json(PontusHandle *handle, long long scan_id);

/* Designate a scan as the baseline to diff against. Returns true on success. */
bool pontus_set_baseline(PontusHandle *handle, long long scan_id);

/* The designated baseline scan id, or -1 if none is set. */
long long pontus_baseline(PontusHandle *handle);

/* Free a string returned by this library. */
void pontus_string_free(char *s);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PONTUS_H */

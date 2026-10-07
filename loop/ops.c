/*
 * The maintenance operations that mutate a live Pipeline handle
 * between iterations: master rotation (--rekey-every) and blob
 * reopen (--blob-cycle-every).
 */

#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>
#include <string.h>

#include "loop.h"

/* Byte length of each fresh master drawn for a rotation. Matches the
 * size Init auto-generates for both the parallax and the wrapper
 * master. */
#define REKEY_MASTER_SIZE 32

/* Master rotation. Rotates the parallax + wrapper masters on every
 * active Pipeline under the write lock and retains the refreshed
 * blob for subsequent blob reopens. Masters are drawn fresh from the
 * OS CSPRNG on every rotation regardless of --seed (master rotation
 * is pipeline keying, not plaintext content); a disabled layer passes
 * no bytes, which Rekey ignores. The eight inner seeds and the MAC
 * key are untouched by design — Rekey targets only the two
 * outer-layer master secrets. */
static int rekey_pipes(struct worker *w, int64_t iter)
{
    struct run_state *r = w->run;
    uint8_t perm[REKEY_MASTER_SIZE];
    uint8_t wrap[REKEY_MASTER_SIZE];
    const uint8_t *perm_p = NULL;
    const uint8_t *wrap_p = NULL;
    size_t perm_len = 0;
    size_t wrap_len = 0;

    if (r->cfg.parallax) {
        if (fill_random(perm, sizeof(perm)) != 0) {
            worker_fail(w, "g%d iter %lld: csprng: parallax master", w->id, (long long)iter);
            return -1;
        }
        perm_p = perm;
        perm_len = sizeof(perm);
    }
    if (r->cfg.wrapper) {
        if (fill_random(wrap, sizeof(wrap)) != 0) {
            worker_fail(w, "g%d iter %lld: csprng: wrapper master", w->id, (long long)iter);
            return -1;
        }
        wrap_p = wrap;
        wrap_len = sizeof(wrap);
    }

    int rc = 0;
    pthread_rwlock_wrlock(&r->pipe_lock);
    if (r->stream_pipe != NULL) {
        uint8_t *blob = NULL;
        size_t blob_len = 0;
        itb_status st = itb_pipeline_rekey(r->stream_pipe, perm_p, perm_len,
                                           wrap_p, wrap_len, &blob, &blob_len);
        if (st != ITB_STATUS_OK) {
            worker_fail(w, "g%d iter %lld: Rekey(%s): status %d: %s",
                        w->id, (long long)iter, r->stream_profile, (int)st, itb_last_error());
            rc = -1;
            goto done;
        }
        itb_bytes_free(r->stream_blob);
        r->stream_blob = blob;
        r->stream_blob_len = blob_len;
    }
    if (r->msg_pipe != NULL) {
        uint8_t *blob = NULL;
        size_t blob_len = 0;
        itb_status st = itb_pipeline_rekey(r->msg_pipe, perm_p, perm_len,
                                           wrap_p, wrap_len, &blob, &blob_len);
        if (st != ITB_STATUS_OK) {
            worker_fail(w, "g%d iter %lld: Rekey(%s): status %d: %s",
                        w->id, (long long)iter, r->msg_profile, (int)st, itb_last_error());
            rc = -1;
            goto done;
        }
        itb_bytes_free(r->msg_blob);
        r->msg_blob = blob;
        r->msg_blob_len = blob_len;
    }
    {
        long long n = (long long)atomic_fetch_add(&r->rekeys, 1) + 1;
        log_line("rekey: g%d iter %lld rotated parallax + wrapper masters (rekey #%lld)",
                 w->id, (long long)iter, n);
    }
done:
    pthread_rwlock_unlock(&r->pipe_lock);
    return rc;
}

/* Blob reopen. Reopens every active Pipeline from its retained blob
 * under the write lock: a fresh handle is loaded from the blob, the
 * running handle is freed, and the fresh one is swapped in, so every
 * later iteration round-trips through seeds and masters that survived
 * a blob crossing. The input is the blob Init or the latest Rekey
 * handed out, not a fresh Save: that is what a receiver holds, and
 * reopening from it proves the handed-out bytes rather than the live
 * state. The blob carries the Pipeline's full shape, so no override
 * reaches the reopen. On a Load failure the running handle stays and
 * the failure aborts the run. */
static int blob_cycle_pipes(struct worker *w, int64_t iter)
{
    struct run_state *r = w->run;
    int rc = 0;
    pthread_rwlock_wrlock(&r->pipe_lock);
    if (r->stream_pipe != NULL) {
        itb_pipeline *fresh = NULL;
        itb_status st = itb_pipeline_load(r->stream_blob, r->stream_blob_len,
                                          NULL, 0, NULL, 0, &fresh);
        if (st != ITB_STATUS_OK) {
            worker_fail(w, "g%d iter %lld: Load(%s): status %d: %s",
                        w->id, (long long)iter, r->stream_profile, (int)st, itb_last_error());
            rc = -1;
            goto done;
        }
        itb_pipeline_free(r->stream_pipe);
        r->stream_pipe = fresh;
    }
    if (r->msg_pipe != NULL) {
        itb_pipeline *fresh = NULL;
        itb_status st = itb_pipeline_load(r->msg_blob, r->msg_blob_len,
                                          NULL, 0, NULL, 0, &fresh);
        if (st != ITB_STATUS_OK) {
            worker_fail(w, "g%d iter %lld: Load(%s): status %d: %s",
                        w->id, (long long)iter, r->msg_profile, (int)st, itb_last_error());
            rc = -1;
            goto done;
        }
        itb_pipeline_free(r->msg_pipe);
        r->msg_pipe = fresh;
    }
    {
        long long n = (long long)atomic_fetch_add(&r->blob_cycles, 1) + 1;
        log_line("blob-cycle: g%d iter %lld reopened from session blob (cycle #%lld)",
                 w->id, (long long)iter, n);
    }
done:
    pthread_rwlock_unlock(&r->pipe_lock);
    return rc;
}

/* Handle mutation. Runs the periodic Pipeline-mutating operations
 * after a completed iteration: master rotation (--rekey-every) and
 * blob reopen (--blob-cycle-every). Both intervals count per-worker
 * iterations; the warmup iteration (iter 0) never triggers because
 * the worker loop calls this for iter >= 1 only. Rekey rewrites the
 * outer-layer keying of a live handle and a blob reopen replaces the
 * handle outright; each takes the write lock, so in-flight cipher
 * calls on other workers drain before anything changes and no
 * encrypt is separated from its decrypt by either. Returns 0, or -1
 * after recording the worker error. */
int worker_maintenance(struct worker *w, int64_t iter)
{
    const struct config *cfg = &w->run->cfg;
    if (cfg->rekey_every > 0 && iter % cfg->rekey_every == 0) {
        if (rekey_pipes(w, iter) != 0) {
            return -1;
        }
    }
    if (cfg->blob_cycle_every > 0 && iter % cfg->blob_cycle_every == 0) {
        if (blob_cycle_pipes(w, iter) != 0) {
            return -1;
        }
    }
    return 0;
}

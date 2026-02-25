#include "structures.h"

/* Function prototypes for functions from scorer.c */
int compute_score(EntityStats *e);
int compute_ip_score(IPStats *ip);

/* Evaluate user for alerts */
static void evaluate_user(SharedState *state, EntityStats *user)
{
    if (!user)
        return;

    int score = compute_score(user);
    user->current_score = score;

    /* Always print user stats */
    printf("[USER %d] score=%d, failed=%d, resources=%d, ips=%d, last_alert=%d\n",
           user->user_id, score, user->failed_attempts,
           user->resource_count, user->ip_count, user->last_alert_score);

    /* Check if thresholds are exceeded */
    int threshold_met = 0;
    if (user->failed_attempts >= THRESH_FAILED_IP)
    {
        printf("  └─ FAILED threshold met: %d >= %d\n", user->failed_attempts, THRESH_FAILED_IP);
        threshold_met = 1;
    }
    if (user->resource_count >= THRESH_RESOURCES)
    {
        printf("  └─ RESOURCE threshold met: %d >= %d\n", user->resource_count, THRESH_RESOURCES);
        threshold_met = 1;
    }
    if (user->ip_count >= THRESH_IPS)
    {
        printf("  └─ IP threshold met: %d >= %d\n", user->ip_count, THRESH_IPS);
        threshold_met = 1;
    }

    if (threshold_met)
    {
        int severity = severity_from_score(score);
        printf("  └─ Threshold met! severity=%d, score=%d, last_alert=%d\n",
               severity, score, user->last_alert_score);

        /* Alert if severity is at least SUSPICIOUS and score changed */
        if (severity >= 1 && score != user->last_alert_score)
        {
            printf("  └─ 🔔 TRIGGERING ALERT for user %d!\n", user->user_id);

            AlertItem item = {
                .user_id = user->user_id,
                .score = score,
                .severity = severity,
                .timestamp = time(NULL)};

            if (user->ip_count > 0 && user->ip_refs != NULL)
            {
                strncpy(item.ip_address, user->ip_refs[0].ip, 39);
            }
            else
            {
                strncpy(item.ip_address, "0.0.0.0", 39);
            }
            item.ip_address[39] = '\0';

            push_alert(state, item);
            user->last_alert_score = score;
            user->last_alert_time = time(NULL);
            state->total_alerts_generated++;
        }
        else if (severity >= 1 && score == user->last_alert_score)
        {
            printf("  └─ ⏸️  Alert suppressed (same score as last alert)\n");
        }
        else if (severity < 1)
        {
            printf("  └─ ⏸️  Severity too low: %d (need >=1)\n", severity);
        }
    }
}

/* Evaluate IP for alerts */
void evaluate_ip(SharedState *state, IPStats *ip)
{
    if (!ip)
        return;

    if (ip->failed_attempts >= THRESH_FAILED_IP)
    {
        int score = compute_ip_score(ip);
        int severity = severity_from_score(score);

        printf("[IP %s] failed=%d, score=%d, severity=%d, last_alert=%d\n",
               ip->ip_address, ip->failed_attempts, score, severity, ip->last_alert_score);

        if (severity >= 1 && score != ip->last_alert_score)
        {
            printf("  └─ 🔔 TRIGGERING IP ALERT for %s!\n", ip->ip_address);

            AlertItem item = {
                .user_id = -1,
                .score = score,
                .severity = severity,
                .timestamp = time(NULL)};
            strncpy(item.ip_address, ip->ip_address, 39);
            item.ip_address[39] = '\0';

            push_alert(state, item);
            ip->last_alert_score = score;
            ip->last_alert_time = time(NULL);
            state->total_alerts_generated++;
        }
    }
}

/* Analyzer thread */
void *analyzer_thread(void *arg)
{
    SharedState *state = (SharedState *)arg;
    time_t last_full_eval = 0;

    while (1)
    {
        pthread_mutex_lock(&state->lock);

        /* Wait for new logs or shutdown */
        while (state->head == NULL && !state->ingestion_done)
        {
            pthread_cond_wait(&state->cond_new_log, &state->lock);
        }

        if (state->ingestion_done && state->head == NULL)
        {
            state->analyzer_done = 1;
            pthread_cond_signal(&state->cond_alert);
            pthread_mutex_unlock(&state->lock);
            break;
        }

        /* Get current time */
        time_t now = time(NULL);

        /* Expire old logs */
        expire_old_logs(state, now);

        /* Evaluate every 2 seconds */
        if (now - last_full_eval >= 2)
        {
            printf("\n[DEBUG] 🔍 Running evaluation at %ld\n", now);

            /* Evaluate all users */
            int user_count = 0;
            for (int i = 0; i < HASH_SIZE; i++)
            {
                EntityStats *user = state->user_map[i];
                while (user)
                {
                    evaluate_user(state, user);
                    user = user->next;
                    user_count++;
                }
            }

            if (user_count > 0)
            {
                printf("[DEBUG] 📊 Evaluated %d users\n", user_count);
            }

            /* Evaluate all IPs */
            pthread_mutex_lock(&state->ip_lock);
            int ip_count = 0;
            for (int i = 0; i < HASH_SIZE; i++)
            {
                IPStats *ip = state->ip_map[i];
                while (ip)
                {
                    evaluate_ip(state, ip);
                    ip = ip->next;
                    ip_count++;
                }
            }
            pthread_mutex_unlock(&state->ip_lock);

            if (ip_count > 0)
            {
                printf("[DEBUG] 📊 Evaluated %d IPs\n", ip_count);
            }
            printf("[DEBUG] ✅ Evaluation complete\n\n");

            last_full_eval = now;
        }

        pthread_mutex_unlock(&state->lock);

        /* Don't spin too fast */
        usleep(500000); /* 500ms */
    }

    return NULL;
}
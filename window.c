#include "structures.h"

/* Add log to statistics (O(1) with ref counting) */
void add_log_to_stats(SharedState *state, LogEntry *entry)
{
    /* Update user stats */
    EntityStats *user = get_or_create_user(state, entry->user_id);

    /* Track failed logins */
    if (strcmp(entry->status_code, "FAILED") == 0 &&
        strcmp(entry->event_type, "LOGIN") == 0)
    {
        user->failed_attempts++;
    }

    /* Track resources with ref counting */
    if (strcmp(entry->resource_id, "-") != 0)
    {
        int found = 0;
        for (int i = 0; i < user->resource_count; i++)
        {
            if (strcmp(user->resources[i].name, entry->resource_id) == 0)
            {
                user->resources[i].ref_count++;
                found = 1;
                break;
            }
        }
        if (!found)
        {
            if (user->resource_count >= user->resource_cap)
            {
                user->resource_cap *= 2;
                user->resources = (ResourceRef *)realloc(user->resources,
                                                         sizeof(ResourceRef) * user->resource_cap);
            }
            strncpy(user->resources[user->resource_count].name, entry->resource_id, 31);
            user->resources[user->resource_count].ref_count = 1;
            user->resource_count++;
        }
    }

    /* Track IPs with ref counting */
    int ip_found = 0;
    for (int i = 0; i < user->ip_count; i++)
    {
        if (strcmp(user->ip_refs[i].ip, entry->ip_address) == 0)
        {
            user->ip_refs[i].ref_count++;
            ip_found = 1;
            break;
        }
    }
    if (!ip_found)
    {
        if (user->ip_count >= user->ip_cap)
        {
            user->ip_cap *= 2;
            user->ip_refs = (IPRef *)realloc(user->ip_refs,
                                             sizeof(IPRef) * user->ip_cap);
        }
        strncpy(user->ip_refs[user->ip_count].ip, entry->ip_address, 39);
        user->ip_refs[user->ip_count].ref_count = 1;
        user->ip_count++;
    }

    /* Update IP stats for failed logins */
    if (strcmp(entry->event_type, "LOGIN") == 0 &&
        strcmp(entry->status_code, "FAILED") == 0)
    {
        pthread_mutex_lock(&state->ip_lock);
        IPStats *ip_stat = get_or_create_ip(state, entry->ip_address);
        ip_stat->failed_attempts++;
        ip_stat->window_start = entry->timestamp;
        pthread_mutex_unlock(&state->ip_lock);
    }
}

/* Remove log from statistics (O(1) with ref counting) */
void remove_log_from_stats(SharedState *state, LogEntry *entry)
{
    EntityStats *user = get_or_create_user(state, entry->user_id);

    /* Update failed logins */
    if (strcmp(entry->status_code, "FAILED") == 0 &&
        strcmp(entry->event_type, "LOGIN") == 0)
    {
        if (user->failed_attempts > 0)
            user->failed_attempts--;
    }

    /* Update resources with ref counting */
    if (strcmp(entry->resource_id, "-") != 0)
    {
        for (int i = 0; i < user->resource_count; i++)
        {
            if (strcmp(user->resources[i].name, entry->resource_id) == 0)
            {
                user->resources[i].ref_count--;
                if (user->resources[i].ref_count == 0)
                {
                    /* Remove by shifting */
                    memmove(&user->resources[i], &user->resources[i + 1],
                            (user->resource_count - i - 1) * sizeof(ResourceRef));
                    user->resource_count--;
                }
                break;
            }
        }
    }

    /* Update IPs with ref counting */
    for (int i = 0; i < user->ip_count; i++)
    {
        if (strcmp(user->ip_refs[i].ip, entry->ip_address) == 0)
        {
            user->ip_refs[i].ref_count--;
            if (user->ip_refs[i].ref_count == 0)
            {
                memmove(&user->ip_refs[i], &user->ip_refs[i + 1],
                        (user->ip_count - i - 1) * sizeof(IPRef));
                user->ip_count--;
            }
            break;
        }
    }

    /* Update IP stats */
    if (strcmp(entry->event_type, "LOGIN") == 0 &&
        strcmp(entry->status_code, "FAILED") == 0)
    {
        pthread_mutex_lock(&state->ip_lock);
        unsigned int idx = hash_ip(entry->ip_address);
        IPStats *ip_stat = state->ip_map[idx];
        while (ip_stat)
        {
            if (strcmp(ip_stat->ip_address, entry->ip_address) == 0)
            {
                if (ip_stat->failed_attempts > 0)
                    ip_stat->failed_attempts--;
                break;
            }
            ip_stat = ip_stat->next;
        }
        pthread_mutex_unlock(&state->ip_lock);
    }
}

/* Expire old logs (O(1) per expiry) */
void expire_old_logs(SharedState *state, time_t now)
{
    while (state->tail && (now - state->tail->timestamp) > WINDOW_SECONDS)
    {
        LogEntry *old = state->tail;

        /* Remove from stats */
        remove_log_from_stats(state, old);

        /* Unlink from list */
        state->tail = old->prev;
        if (state->tail)
        {
            state->tail->next = NULL;
        }
        else
        {
            state->head = NULL;
        }

        state->log_count--;
        free(old);
    }
}
#include "structures.h"

/* Murmur-style hash for integers */
unsigned int hash_user(int user_id)
{
    unsigned int h = (unsigned int)user_id;
    h = (h ^ (h >> 16)) * 0x85ebca6b;
    h = (h ^ (h >> 13)) * 0xc2b2ae35;
    h = h ^ (h >> 16);
    return h % HASH_SIZE;
}

/* DJB2 hash for IP strings */
unsigned int hash_ip(const char *ip)
{
    unsigned int hash = 5381;
    int c;
    while ((c = *ip++))
    {
        hash = ((hash << 5) + hash) + c;
    }
    return hash % HASH_SIZE;
}

/* Get or create user stats */
EntityStats *get_or_create_user(SharedState *state, int user_id)
{
    unsigned int idx = hash_user(user_id);
    EntityStats *e = state->user_map[idx];

    /* Look for existing */
    while (e)
    {
        if (e->user_id == user_id)
            return e;
        e = e->next;
    }

    /* Create new */
    e = (EntityStats *)calloc(1, sizeof(EntityStats));
    if (!e)
    {
        perror("calloc EntityStats");
        exit(1);
    }

    e->user_id = user_id;
    e->resource_cap = 8;
    e->resources = (ResourceRef *)malloc(sizeof(ResourceRef) * e->resource_cap);
    e->ip_cap = 4;
    e->ip_refs = (IPRef *)malloc(sizeof(IPRef) * e->ip_cap);

    if (!e->resources || !e->ip_refs)
    {
        perror("malloc resources/ips");
        exit(1);
    }

    /* Insert at head */
    e->next = state->user_map[idx];
    state->user_map[idx] = e;

    return e;
}

/* Get or create IP stats */
IPStats *get_or_create_ip(SharedState *state, const char *ip)
{
    unsigned int idx = hash_ip(ip);
    IPStats *ip_stat = state->ip_map[idx];

    /* Look for existing */
    while (ip_stat)
    {
        if (strcmp(ip_stat->ip_address, ip) == 0)
            return ip_stat;
        ip_stat = ip_stat->next;
    }

    /* Create new */
    ip_stat = (IPStats *)calloc(1, sizeof(IPStats));
    if (!ip_stat)
    {
        perror("calloc IPStats");
        exit(1);
    }

    strncpy(ip_stat->ip_address, ip, 39);
    ip_stat->ip_address[39] = '\0';
    ip_stat->window_start = time(NULL);

    /* Insert at head */
    ip_stat->next = state->ip_map[idx];
    state->ip_map[idx] = ip_stat;

    return ip_stat;
}

/* Remove user if no activity */
void remove_user_if_empty(SharedState *state, int user_id)
{
    EntityStats *e = get_or_create_user(state, user_id);
    if (e->failed_attempts == 0 && e->resource_count == 0 && e->ip_count == 0)
    {
        unsigned int idx = hash_user(user_id);
        EntityStats *prev = NULL;
        EntityStats *cur = state->user_map[idx];

        while (cur)
        {
            if (cur == e)
            {
                if (prev)
                    prev->next = cur->next;
                else
                    state->user_map[idx] = cur->next;

                free(e->resources);
                free(e->ip_refs);
                free(e);
                return;
            }
            prev = cur;
            cur = cur->next;
        }
    }
}

/* Remove IP if no activity */
void remove_ip_if_empty(SharedState *state, const char *ip)
{
    unsigned int idx = hash_ip(ip);
    IPStats *prev = NULL;
    IPStats *cur = state->ip_map[idx];

    while (cur)
    {
        if (strcmp(cur->ip_address, ip) == 0)
        {
            if (cur->failed_attempts == 0)
            {
                if (prev)
                    prev->next = cur->next;
                else
                    state->ip_map[idx] = cur->next;
                free(cur);
            }
            return;
        }
        prev = cur;
        cur = cur->next;
    }
}

/* Free all resources */
void free_all_resources(SharedState *state)
{
    /* Free user map */
    for (int i = 0; i < HASH_SIZE; i++)
    {
        EntityStats *e = state->user_map[i];
        while (e)
        {
            EntityStats *tmp = e;
            e = e->next;
            free(tmp->resources);
            free(tmp->ip_refs);
            free(tmp);
        }
    }

    /* Free IP map */
    for (int i = 0; i < HASH_SIZE; i++)
    {
        IPStats *ip = state->ip_map[i];
        while (ip)
        {
            IPStats *tmp = ip;
            ip = ip->next;
            free(tmp);
        }
    }

    /* Free log entries */
    LogEntry *cur = state->head;
    while (cur)
    {
        LogEntry *tmp = cur;
        cur = cur->next;
        free(tmp);
    }
}
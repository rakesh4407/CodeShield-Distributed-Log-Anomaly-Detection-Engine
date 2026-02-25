#include "structures.h"

LogEntry *parse_log_line(const char *line)
{
    LogEntry *entry = (LogEntry *)calloc(1, sizeof(LogEntry));
    if (!entry)
    {
        perror("calloc LogEntry");
        exit(1);
    }

    long ts;
    /* format: timestamp, user_id, ip, event_type, resource_id, status_code */
    int n = sscanf(line, " %ld , %d , %39[^,] , %15[^,] , %31[^,] , %15[^\n]",
                   &ts, &entry->user_id, entry->ip_address,
                   entry->event_type, entry->resource_id, entry->status_code);
    if (n < 6)
    {
        free(entry);
        return NULL;
    }
    entry->timestamp = (time_t)ts;

    /* trim leading spaces from parsed strings */
    {
        char *fields[] = {entry->ip_address, entry->event_type,
                          entry->resource_id, entry->status_code};
        for (int i = 0; i < 4; i++)
        {
            char *p = fields[i];
            while (*p == ' ')
            {
                memmove(p, p + 1, strlen(p));
            }
            /* trim trailing spaces/newlines */
            size_t len = strlen(p);
            while (len > 0 && (p[len - 1] == ' ' || p[len - 1] == '\n' || p[len - 1] == '\r'))
                p[--len] = '\0';
        }
    }

    return entry;
}

void *ingestion_thread(void *arg)
{
    SharedState *state = (SharedState *)arg;

    /* Try to open the log file */
    FILE *fp = fopen("sample_logs.txt", "r");
    if (!fp)
    {
        /* If file doesn't exist, create a simple test file */
        printf("sample_logs.txt not found. Creating test data...\n");
        fp = fopen("sample_logs.txt", "w");
        if (!fp)
        {
            perror("fopen");
            exit(1);
        }

        /* Generate some test logs */
        time_t base = time(NULL) - 600; /* 10 minutes ago */
        for (int i = 0; i < 100; i++)
        {
            fprintf(fp, "%ld, %d, 192.168.1.%d, %s, %s, %s\n",
                    (long)(base + i * 2),
                    (i % 5) + 100, /* users 100-104 */
                    (i % 10) + 1,
                    (i % 3 == 0) ? "LOGIN" : (i % 3 == 1) ? "FILE_ACCESS"
                                                          : "API_CALL",
                    (i % 2 == 0) ? "res_1" : "res_2",
                    (i % 4 == 0) ? "FAILED" : "SUCCESS");
        }
        fclose(fp);

        /* Reopen for reading */
        fp = fopen("sample_logs.txt", "r");
        if (!fp)
        {
            perror("fopen");
            exit(1);
        }
    }

    char line[256];
    while (fgets(line, sizeof(line), fp))
    {
        if (line[0] == '\n' || line[0] == '#')
            continue;

        LogEntry *entry = parse_log_line(line);
        if (!entry)
            continue;

        pthread_mutex_lock(&state->lock);

        /* Insert at head (newest) */
        entry->next = state->head;
        entry->prev = NULL;
        if (state->head)
            state->head->prev = entry;
        state->head = entry;
        if (!state->tail)
            state->tail = entry;
        state->log_count++;
        state->total_logs_processed++;

        pthread_cond_signal(&state->cond_new_log);
        pthread_mutex_unlock(&state->lock);

        /* Small delay to simulate real-time */
        usleep(10000); /* 10 ms */
    }

    fclose(fp);

    pthread_mutex_lock(&state->lock);
    state->ingestion_done = 1;
    pthread_cond_signal(&state->cond_new_log);
    pthread_mutex_unlock(&state->lock);

    printf("\nIngestion complete. %d logs loaded.\n", state->total_logs_processed);
    return NULL;
}
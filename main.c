#include "structures.h"

void print_dashboard(SharedState *state)
{
    printf("\n\033[1;36m"); /* Cyan bold */
    printf("┌─────────────────────────────────────────────┐\n");
    printf("│         FINAL ANALYSIS DASHBOARD            │\n");
    printf("├─────────────────────────────────────────────┤\n");
    printf("│ Total logs processed: %-21d │\n", state->total_logs_processed);
    printf("│ Alerts generated:     %-21d │\n", state->total_alerts_generated);
    printf("│ Active entities:       ");

    int active_users = 0, active_ips = 0;
    for (int i = 0; i < HASH_SIZE; i++)
    {
        EntityStats *u = state->user_map[i];
        while (u)
        {
            if (u->current_score > 0)
                active_users++;
            u = u->next;
        }
        IPStats *ip = state->ip_map[i];
        while (ip)
        {
            if (ip->failed_attempts > 0)
                active_ips++;
            ip = ip->next;
        }
    }
    printf("%-21d │\n", active_users + active_ips);
    printf("├─────────────────────────────────────────────┤\n");
    printf("│         TOP SUSPICIOUS ENTITIES             │\n");
    printf("├─────────────────────────────────────────────┤\n");

    /* Collect top 5 users by score */
    typedef struct
    {
        int user_id;
        int score;
        int severity;
    } ScoreEntry;

    ScoreEntry top_users[5] = {0};

    for (int i = 0; i < HASH_SIZE; i++)
    {
        EntityStats *u = state->user_map[i];
        while (u)
        {
            int score = u->current_score;
            if (score > 0)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (score > top_users[j].score)
                    {
                        /* Shift down */
                        for (int k = 4; k > j; k--)
                        {
                            top_users[k] = top_users[k - 1];
                        }
                        top_users[j].user_id = u->user_id;
                        top_users[j].score = score;
                        top_users[j].severity = severity_from_score(score);
                        break;
                    }
                }
            }
            u = u->next;
        }
    }

    for (int i = 0; i < 5 && top_users[i].score > 0; i++)
    {
        const char *color = top_users[i].severity >= 3 ? "\033[1;31m" : top_users[i].severity >= 2 ? "\033[31m"
                                                                    : top_users[i].severity >= 1   ? "\033[33m"
                                                                                                   : "\033[0m";
        printf("│ %sUser %-6d Score: %-4d [%-12s\033[1;36m │\n",
               color, top_users[i].user_id, top_users[i].score,
               severity_str(top_users[i].severity));
    }

    printf("└─────────────────────────────────────────────┘\033[0m\n\n");
}

int main(void)
{
    /* Clear screen */
    printf("\033[2J\033[H");

    printf("\033[1;35m"); /* Magenta bold */
    printf("╔════════════════════════════════════════════════╗\n");
    printf("║         CODESHIELD ANOMALY DETECTION          ║\n");
    printf("║            Hackathon Edition v2.0              ║\n");
    printf("╚════════════════════════════════════════════════╝\033[0m\n\n");

    /* Initialize shared state */
    SharedState *state = (SharedState *)calloc(1, sizeof(SharedState));
    if (!state)
    {
        perror("calloc SharedState");
        return 1;
    }

    pthread_mutex_init(&state->lock, NULL);
    pthread_mutex_init(&state->ip_lock, NULL);
    pthread_cond_init(&state->cond_new_log, NULL);
    pthread_cond_init(&state->cond_alert, NULL);

    /* Clear alert log */
    FILE *fp = fopen("alert_log.txt", "w");
    if (fp)
        fclose(fp);

    /* Create threads */
    pthread_t t_ingest, t_analyze, t_alert;

    printf("Starting threads...\n");

    if (pthread_create(&t_ingest, NULL, ingestion_thread, state) != 0)
    {
        perror("pthread_create ingestion");
        return 1;
    }

    if (pthread_create(&t_analyze, NULL, analyzer_thread, state) != 0)
    {
        perror("pthread_create analyzer");
        return 1;
    }

    if (pthread_create(&t_alert, NULL, alert_thread, state) != 0)
    {
        perror("pthread_create alert");
        return 1;
    }

    /* Progress indicator */
    int last_count = 0;
    while (!state->ingestion_done || state->head != NULL)
    {
        sleep(1);
        if (state->log_count > last_count)
        {
            printf("\rProcessing logs: %d", state->log_count);
            fflush(stdout);
            last_count = state->log_count;
        }
    }

    printf("\n\nIngestion complete. Waiting for analysis to finish...\n");

    /* Wait for threads */
    pthread_join(t_ingest, NULL);
    pthread_join(t_analyze, NULL);
    pthread_join(t_alert, NULL);

    /* Print final dashboard */
    print_dashboard(state);

    /* Cleanup */
    free_all_resources(state);
    pthread_mutex_destroy(&state->lock);
    pthread_mutex_destroy(&state->ip_lock);
    pthread_cond_destroy(&state->cond_new_log);
    pthread_cond_destroy(&state->cond_alert);
    free(state);

    printf("\n✅ All resources freed. Clean exit.\n");
    printf("📝 Check alert_log.txt for critical alerts.\n\n");

    return 0;
}
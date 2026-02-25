#include "structures.h"

void push_alert(SharedState *state, AlertItem item)
{
    pthread_mutex_lock(&state->lock);

    if (state->aq_count < ALERT_QUEUE_CAP)
    {
        state->alert_queue[state->aq_tail] = item;
        state->aq_tail = (state->aq_tail + 1) % ALERT_QUEUE_CAP;
        state->aq_count++;
        pthread_cond_signal(&state->cond_alert);
    }
    else
    {
        fprintf(stderr, "[WARN] Alert queue full, dropping alert\n");
    }

    pthread_mutex_unlock(&state->lock);
}

static void print_colored_alert(const AlertItem *a)
{
    /* Color codes for terminal */
    const char *colors[] = {"\033[0m", "\033[33m", "\033[31m", "\033[1;31m"};
    const char *reset = "\033[0m";

    printf("\n%s", colors[a->severity]);
    printf("╔════════════════════════════════════════════╗\n");
    printf("║                 ALERT                      ║\n");
    printf("╠════════════════════════════════════════════╣\n");
    if (a->user_id != -1)
    {
        printf("║ User:     %-30d ║\n", a->user_id);
    }
    printf("║ IP:       %-30s ║\n", a->ip_address);
    printf("║ Score:    %-30d ║\n", a->score);
    printf("║ Severity: %-30s ║\n", severity_str(a->severity));
    printf("╚════════════════════════════════════════════╝%s\n\n", reset);
}

static void write_alert_to_file(const AlertItem *a)
{
    FILE *fp = fopen("alert_log.txt", "a");
    if (!fp)
    {
        perror("fopen alert_log.txt");
        return;
    }

    time_t t = a->timestamp;
    struct tm *tm_info = localtime(&t);
    char timebuf[26];
    strftime(timebuf, 26, "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(fp, "[%s] ", timebuf);
    if (a->user_id != -1)
    {
        fprintf(fp, "User: %d | ", a->user_id);
    }
    fprintf(fp, "IP: %s | Score: %d | Severity: %s\n",
            a->ip_address, a->score, severity_str(a->severity));

    fclose(fp);
}

void *alert_thread(void *arg)
{
    SharedState *state = (SharedState *)arg;

    while (1)
    {
        pthread_mutex_lock(&state->lock);

        /* Wait for alerts or shutdown */
        while (state->aq_count == 0 && !state->analyzer_done)
        {
            pthread_cond_wait(&state->cond_alert, &state->lock);
        }

        /* Process all queued alerts */
        while (state->aq_count > 0)
        {
            AlertItem a = state->alert_queue[state->aq_head];
            state->aq_head = (state->aq_head + 1) % ALERT_QUEUE_CAP;
            state->aq_count--;

            pthread_mutex_unlock(&state->lock);

            /* Print to console (always) */
            print_colored_alert(&a);

            /* Write critical alerts to file */
            if (a.severity >= 3)
            {
                write_alert_to_file(&a);
            }

            pthread_mutex_lock(&state->lock);
        }

        if (state->analyzer_done && state->aq_count == 0)
        {
            pthread_mutex_unlock(&state->lock);
            break;
        }

        pthread_mutex_unlock(&state->lock);
    }

    return NULL;
}
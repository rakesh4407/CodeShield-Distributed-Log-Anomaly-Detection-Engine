#ifndef STRUCTURES_H
#define STRUCTURES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

/* ─── Constants ─── */
#define WINDOW_SECONDS 300
#define HASH_SIZE 2048 /* Larger for better distribution */
#define ALERT_QUEUE_CAP 1024

/* Thresholds from problem statement */
#define THRESH_FAILED_IP 5
#define THRESH_RESOURCES 10
#define THRESH_IPS 3

/* ─── Log Entry (doubly-linked list) ─── */
typedef struct LogEntry
{
    time_t timestamp;
    int user_id;
    char ip_address[40];
    char event_type[16];
    char resource_id[32];
    char status_code[16];
    struct LogEntry *prev;
    struct LogEntry *next;
} LogEntry;

/* ─── Resource reference counting ─── */
typedef struct
{
    char name[32];
    int ref_count;
} ResourceRef;

/* ─── IP reference counting ─── */
typedef struct
{
    char ip[40];
    int ref_count;
} IPRef;

/* ─── Per-user statistics ─── */
typedef struct EntityStats
{
    int user_id;
    int failed_attempts;

    /* Resource tracking with ref counting */
    ResourceRef *resources;
    int resource_count;
    int resource_cap;

    /* IP tracking with ref counting */
    IPRef *ip_refs;
    int ip_count;
    int ip_cap;

    /* Score tracking */
    int current_score;
    int last_alert_score;
    time_t last_alert_time;

    struct EntityStats *next; /* For hash chaining */
} EntityStats;

/* ─── Per-IP statistics ─── */
typedef struct IPStats
{
    char ip_address[40];
    int failed_attempts;
    time_t window_start;
    int last_alert_score;
    time_t last_alert_time;
    struct IPStats *next;
} IPStats;

/* ─── Alert item ─── */
typedef struct
{
    int user_id;
    char ip_address[40];
    int score;
    int severity; /* 0=normal 1=suspicious 2=high 3=critical */
    time_t timestamp;
} AlertItem;

/* ─── Central shared state ─── */
typedef struct
{
    /* Log storage */
    LogEntry *head;
    LogEntry *tail;
    int log_count;

    /* Hash maps */
    EntityStats *user_map[HASH_SIZE];
    IPStats *ip_map[HASH_SIZE];

    /* Alert queue */
    AlertItem alert_queue[ALERT_QUEUE_CAP];
    int aq_head;
    int aq_tail;
    int aq_count;

    /* Synchronization */
    pthread_mutex_t lock;
    pthread_mutex_t ip_lock;
    pthread_cond_t cond_new_log;
    pthread_cond_t cond_alert;

    /* Control flags */
    int ingestion_done;
    int analyzer_done;

    /* Performance metrics */
    int total_logs_processed;
    int total_alerts_generated;
    double avg_processing_time;
} SharedState;

/* ─── Severity helpers ─── */
static inline int severity_from_score(int s)
{
    if (s >= 31)
        return 3; /* Critical */
    if (s >= 21)
        return 2; /* High Risk */
    if (s >= 11)
        return 1; /* Suspicious */
    return 0;     /* Normal */
}

static inline const char *severity_str(int sev)
{
    switch (sev)
    {
    case 3:
        return "CRITICAL THREAT";
    case 2:
        return "HIGH RISK";
    case 1:
        return "SUSPICIOUS";
    default:
        return "NORMAL";
    }
}

/* ================================================== */
/*             FUNCTION PROTOTYPES                    */
/* ================================================== */

/* hashmap.c */
unsigned int hash_user(int user_id);
unsigned int hash_ip(const char *ip);
EntityStats *get_or_create_user(SharedState *state, int user_id);
IPStats *get_or_create_ip(SharedState *state, const char *ip);
void remove_user_if_empty(SharedState *state, int user_id);
void remove_ip_if_empty(SharedState *state, const char *ip);
void free_all_resources(SharedState *state);

/* scorer.c */
int compute_score(EntityStats *e); /* ADD THIS - needed by analyzer.c */
int compute_ip_score(IPStats *ip);
int compute_user_score(EntityStats *e); /* For compatibility */
void evaluate_entity(SharedState *state, EntityStats *e, const char *ip);
void evaluate_ip(SharedState *state, IPStats *ip);

/* alert.c */
void push_alert(SharedState *state, AlertItem item);
void *alert_thread(void *arg);

/* ingestion.c */
LogEntry *parse_log_line(const char *line);
void *ingestion_thread(void *arg);

/* window.c */
void add_log_to_stats(SharedState *state, LogEntry *entry);
void remove_log_from_stats(SharedState *state, LogEntry *entry);
void expire_old_logs(SharedState *state, time_t now);

/* analyzer.c */
void *analyzer_thread(void *arg);

/* main.c */
void print_dashboard(SharedState *state);

#endif /* STRUCTURES_H */
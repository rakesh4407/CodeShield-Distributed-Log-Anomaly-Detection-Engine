#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/*
 * Generates sample_logs.txt with 1200+ log entries including:
 *  - Normal users doing normal things
 *  - Brute force attacker (many failed logins from one IP)
 *  - Resource crawler (accessing tons of unique resources)
 *  - IP hopper (same user, many different IPs)
 *  - Combined attacker (all patterns at once)
 */

int main(void)
{
    FILE *fp = fopen("sample_logs.txt", "w");
    if (!fp)
    {
        perror("fopen");
        return 1;
    }

    srand((unsigned)time(NULL));
    time_t base = 1708069200; /* some epoch base */
    int entry_count = 0;
    time_t t = base;

    fprintf(fp, "# CodeShield sample log data — auto-generated\n");

    /* ── Normal traffic (600 entries, users 1-20) ── */
    const char *normal_ips[] = {
        "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5",
        "10.0.0.6", "10.0.0.7", "10.0.0.8", "10.0.0.9", "10.0.0.10"};

    for (int i = 0; i < 600; i++)
    {
        int user = (rand() % 20) + 1;
        const char *ip = normal_ips[user % 10];
        const char *events[] = {"LOGIN", "FILE_ACCESS", "API_CALL", "TRANSACTION"};
        const char *ev = events[rand() % 4];
        char resource[32];
        snprintf(resource, sizeof(resource), "res_%d", (rand() % 20) + 1);
        const char *status = (rand() % 20 == 0) ? "FAILED" : "SUCCESS";

        fprintf(fp, "%ld, %d, %s, %s, %s, %s\n", (long)t, user, ip, ev, resource, status);
        t += (rand() % 3) + 1;
        entry_count++;
    }

    /* ── Brute force attacker: user 101, same IP, many failed logins ── */
    for (int i = 0; i < 80; i++)
    {
        fprintf(fp, "%ld, 101, 192.168.1.20, LOGIN, -, FAILED\n", (long)t);
        t += 2;
        entry_count++;
    }

    /* ── Resource crawler: user 102, accesses 80 unique resources ── */
    for (int i = 0; i < 80; i++)
    {
        char res[32];
        snprintf(res, sizeof(res), "secret_doc_%d", i + 1);
        fprintf(fp, "%ld, 102, 172.16.0.55, FILE_ACCESS, %s, SUCCESS\n", (long)t, res);
        t += 2;
        entry_count++;
    }

    /* ── IP hopper: user 103, uses 60 different IPs ── */
    for (int i = 0; i < 60; i++)
    {
        char ip[40];
        snprintf(ip, sizeof(ip), "45.33.%d.%d", (i / 10) + 1, (i % 254) + 1);
        fprintf(fp, "%ld, 103, %s, LOGIN, -, FAILED\n", (long)t, ip);
        t += 3;
        entry_count++;
    }

    /* ── Combined attacker: user 104, does everything ── */
    for (int i = 0; i < 100; i++)
    {
        char ip[40];
        snprintf(ip, sizeof(ip), "99.%d.%d.%d", (i % 5) + 1, (i % 10) + 1, (i % 254) + 1);
        char res[32];
        snprintf(res, sizeof(res), "vault_%d", i + 1);
        const char *status = (i % 2 == 0) ? "FAILED" : "SUCCESS";
        const char *ev = (i % 3 == 0) ? "LOGIN" : "FILE_ACCESS";
        fprintf(fp, "%ld, 104, %s, %s, %s, %s\n", (long)t, ip, ev, res, status);
        t += 2;
        entry_count++;
    }

    /* ── More normal traffic to fill up ── */
    for (int i = 0; i < 280; i++)
    {
        int user = (rand() % 20) + 1;
        const char *ip = normal_ips[user % 10];
        fprintf(fp, "%ld, %d, %s, API_CALL, res_%d, SUCCESS\n",
                (long)t, user, ip, (rand() % 5) + 1);
        t += (rand() % 4) + 1;
        entry_count++;
    }

    fclose(fp);
    printf("Generated %d log entries in sample_logs.txt\n", entry_count);
    printf("Time span: %ld seconds (~%.1f minutes)\n",
           (long)(t - base), (double)(t - base) / 60.0);
    return 0;
}
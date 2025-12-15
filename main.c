#ifdef _WIN32
#include <windows.h>
#include <process.h>

#define THREAD_RET DWORD
#define THREAD_PARAM LPVOID
#define WINAPI_ATTR WINAPI

typedef HANDLE thread_t;
typedef HANDLE mutex_t;
typedef HANDLE sem_t;

#define MUTEX_INIT(m)   m = CreateMutex(NULL, FALSE, NULL)
#define MUTEX_LOCK(m)   WaitForSingleObject(m, INFINITE)
#define MUTEX_UNLOCK(m) ReleaseMutex(m)
#define MUTEX_DESTROY(m) CloseHandle(m)

#define SEM_INIT(s, v)  s = CreateSemaphore(NULL, v, LONG_MAX, NULL)
#define SEM_WAIT(s)     WaitForSingleObject(s, INFINITE)
#define SEM_POST(s)     ReleaseSemaphore(s, 1, NULL)
#define SEM_DESTROY(s)  CloseHandle(s)

#define THREAD_CREATE(t, func, arg) \
    do { *(t) = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)func, arg, 0, NULL); } while(0)

#define THREAD_JOIN(t) \
    do { WaitForSingleObject(t, INFINITE); CloseHandle(t); } while(0)

#else
#include <pthread.h>
#include <unistd.h>
#include <semaphore.h>

#define THREAD_RET void*
#define THREAD_PARAM void*
#define WINAPI_ATTR

typedef pthread_t thread_t;
typedef pthread_mutex_t mutex_t;
typedef sem_t sem_t;

#define MUTEX_INIT(m)   pthread_mutex_init(&(m), NULL)
#define MUTEX_LOCK(m)   pthread_mutex_lock(&(m))
#define MUTEX_UNLOCK(m) pthread_mutex_unlock(&(m))
#define MUTEX_DESTROY(m) pthread_mutex_destroy(&(m))

#define SEM_INIT(s, v)  sem_init(&(s), 0, v)
#define SEM_WAIT(s)     sem_wait(&(s))
#define SEM_POST(s)     sem_post(&(s))
#define SEM_DESTROY(s)  sem_destroy(&(s))

#define THREAD_CREATE(t, func, arg) pthread_create(t, NULL, func, arg)
#define THREAD_JOIN(t)  pthread_join(t, NULL)

#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#define MAX_THREADS 6
#define MIN_THREADS 1
#define PASS_LEN 4
#define CHARSET_LEN 52

char *INPUT_FILE = "users.txt";

#ifdef _WIN32
ssize_t getline(char **lineptr, size_t *n, FILE *stream) {
    if (!lineptr || !n || !stream) return -1;
    if (!*lineptr) { *n = 128; *lineptr = malloc(*n); if (!*lineptr) return -1; }
    size_t pos = 0;
    int c;
    while ((c = fgetc(stream)) != EOF) {
        if (pos + 1 >= *n) {
            size_t new_n = *n * 2;
            char *new_ptr = realloc(*lineptr, new_n);
            if (!new_ptr) return -1;
            *lineptr = new_ptr;
            *n = new_n;
        }
        (*lineptr)[pos++] = c;
        if (c == '\n') break;
    }
    if (pos == 0) return -1;
    (*lineptr)[pos] = '\0';
    return pos;
}
#endif

/* MD5 constants */
static const uint32_t r[] = {
    7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5,9,14,20, 5,9,14,20, 5,9,14,20, 5,9,14,20,
    4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
};

static const uint32_t k[] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static const char charset[] =
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

typedef struct {
    char *username;
    char *hash;
} user_t;

typedef struct {
    user_t *users;
    size_t user_count;
    size_t *next_index;
    mutex_t index_mutex;
    char (*results)[PASS_LEN + 1];
    FILE *output;
    sem_t *sems;
} pool_arg_t;


int parse_int_arg(int argc, char *argv[], int position, int *out_value);
int parse_string_arg(int argc, char *argv[], int position, const char **out_str);

user_t *read_users_file(const char *filename, size_t *out_count);
void free_users(user_t *users, size_t count);

void md5(const uint8_t *initial_msg, size_t initial_len, uint8_t digest[16]);
static uint32_t left_rotate(uint32_t x, uint32_t c);
void md5_hex(const char *input, char output[33]);
int crack_md5_len4(const char *target_hash, char result[5]);

THREAD_RET WINAPI_ATTR crack_user_thread(THREAD_PARAM arg);

int main(const int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <output_file> <threads>\n", argv[0]);
        return -1;
    }

    const char *output_file;
    int threads_qty;

    if (parse_string_arg(argc, argv, 1, &output_file) != 0)
        return -1;

    if (parse_int_arg(argc, argv, 2, &threads_qty) != 0)
        return -1;

    if (threads_qty < MIN_THREADS || threads_qty > MAX_THREADS) {
        fprintf(stderr, "Threads quantity must be between %d and %d\n", MIN_THREADS, MAX_THREADS);
        return -1;
    }

    printf("Output file: %s\n", output_file);
    printf("Running %d threads\n", threads_qty);

    size_t user_count;
    user_t *users = read_users_file("users.txt", &user_count);
    if (!users) return -1;

    if (user_count > 50) {
        fprintf(stderr, "Error: maximum 50 users allowed\n");
        free_users(users, user_count);
        return -1;
    }

    FILE *out = fopen(output_file, "w");
    if (!out) {
        perror("fopen output");
        free_users(users, user_count);
        return -1;
    }

    char (*results)[PASS_LEN + 1] = malloc(user_count * sizeof(*results));
    if (!results) {
        perror("malloc results");
        fclose(out);
        free_users(users, user_count);
        return -1;
    }

    sem_t *sems = malloc(user_count * sizeof(sem_t));
    if (!sems) {
        perror("malloc sems");
        free(results);
        fclose(out);
        free_users(users, user_count);
        return -1;
    }

    for (size_t i = 0; i < user_count; i++)
        SEM_INIT(sems[i], 0);

    size_t next_index = 0;
    pool_arg_t pool = {
        .users = users,
        .user_count = user_count,
        .next_index = &next_index,
        .results = results,
        .output = out,
        .sems = sems
    };
    MUTEX_INIT(pool.index_mutex);

    thread_t threads[threads_qty];
    for (int i = 0; i < threads_qty; i++)
        THREAD_CREATE(&threads[i], crack_user_thread, &pool);

    SEM_POST(sems[0]);

    for (int i = 0; i < threads_qty; i++)
        THREAD_JOIN(threads[i]);

    MUTEX_DESTROY(pool.index_mutex);
    for (size_t i = 0; i < user_count; i++)
        SEM_DESTROY(sems[i]);

    free(sems);
    free(results);
    fclose(out);
    free_users(users, user_count);

    return 0;
}


int parse_int_arg(const int argc, char *argv[], const int position, int *out_value) {
    if (position >= argc) {
        fprintf(stderr, "Missing integer argument\n");
        return -1;
    }

    char *endptr;
    errno = 0;
    const long value = strtol(argv[position], &endptr, 10);

    if (endptr == argv[position]) {
        fprintf(stderr, "Argument is not a number\n");
        return -1;
    }

    if (*endptr != '\0') {
        fprintf(stderr, "Floating point or invalid format not allowed\n");
        return -1;
    }

    if (errno == ERANGE || value > INT_MAX || value < INT_MIN) {
        fprintf(stderr, "Integer out of range\n");
        return -1;
    }

    *out_value = (int)value;

    return 0;
}

int parse_string_arg(const int argc, char *argv[], const int position, const char **out_str) {
    if (position >= argc) {
        fprintf(stderr, "Missing output file name\n");
        return -1;
    }

    if (argv[position][0] == '\0') {
        fprintf(stderr, "Empty file name not allowed\n");
        return -1;
    }

    *out_str = argv[position];
    return 0;
}


user_t *read_users_file(const char *filename, size_t *out_count) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("fopen");
        return NULL;
    }

    user_t *users = NULL;
    size_t count = 0;

    char *line = NULL;
    size_t len = 0;

    while (getline(&line, &len, file) != -1) {
        line[strcspn(line, "\n")] = '\0';

        char *sep = strstr(line, "::");
        if (!sep) {
            fprintf(stderr, "Invalid format for user.\n");
            continue;
        }

        *sep = '\0';
        const char *username = line;
        const char *hash = sep + 2;

        const user_t user = {
            .username = strdup(username),
            .hash = strdup(hash)
        };

        if (!user.username || !user.hash) {
            perror("strdup");
            free(user.username);
            free(user.hash);
            goto cleanup;
        }

        user_t *tmp = realloc(users, (count + 1) * sizeof(user_t));
        if (!tmp) {
            perror("realloc");
            free(user.username);
            free(user.hash);
            goto cleanup;
        }

        users = tmp;
        users[count++] = user;
    }

    *out_count = count;
    free(line);
    fclose(file);
    return users;

    cleanup:
        if (users) {
            for (size_t i = 0; i < count; i++) {
                free(users[i].username);
                free(users[i].hash);
            }
            free(users);
        }

    free(line);
    fclose(file);
    return NULL;
}

void free_users(user_t *users, const size_t count) {
    if (!users) return;

    for (size_t i = 0; i < count; i++) {
        free(users[i].username);
        free(users[i].hash);
    }
    free(users);
}


static uint32_t left_rotate(const uint32_t x, const uint32_t c) {
    return (x << c) | (x >> (32 - c));
}


void md5(const uint8_t *initial_msg, const size_t initial_len, uint8_t digest[16]) {
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xefcdab89;
    uint32_t h2 = 0x98badcfe;
    uint32_t h3 = 0x10325476;

    size_t new_len = initial_len + 1;
    while (new_len % 64 != 56)
        new_len++;

    uint8_t *msg = calloc(new_len + 8, 1);
    memcpy(msg, initial_msg, initial_len);
    msg[initial_len] = 0x80;

    const uint64_t bits_len = initial_len * 8;
    memcpy(msg + new_len, &bits_len, 8);

    for (size_t offset = 0; offset < new_len; offset += 64) {

        const uint32_t *w = (uint32_t *)(msg + offset);

        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;

        for (uint32_t i = 0; i < 64; i++) {
            uint32_t f, g;

            if (i < 16) {
                f = (b & c) | (~b & d);
                g = i;
            } else if (i < 32) {
                f = (d & b) | (~d & c);
                g = (5 * i + 1) % 16;
            } else if (i < 48) {
                f = b ^ c ^ d;
                g = (3 * i + 5) % 16;
            } else {
                f = c ^ (b | ~d);
                g = (7 * i) % 16;
            }

            const uint32_t temp = d;
            d = c;
            c = b;
            b = b + left_rotate(a + f + k[i] + w[g], r[i]);
            a = temp;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
    }

    free(msg);

    memcpy(digest, &h0, 4);
    memcpy(digest + 4, &h1, 4);
    memcpy(digest + 8, &h2, 4);
    memcpy(digest + 12, &h3, 4);
}

void md5_hex(const char *input, char output[33]) {
    uint8_t digest[16];
    md5((const uint8_t *)input, strlen(input), digest);

    for (int i = 0; i < 16; i++)
        sprintf(output + i * 2, "%02x", digest[i]);

    output[32] = '\0';
}

int crack_md5_len4(const char *target_hash, char result[5]) {
    char candidate[PASS_LEN+1];
    char hash[33];

    for (int len = 1; len < PASS_LEN+1; len++) {

        int idx[PASS_LEN] = {0};

        while (1) {
            for (int i = 0; i < len; i++)
                candidate[i] = charset[idx[i]];
            candidate[len] = '\0';

            md5_hex(candidate, hash);

            if (strcmp(hash, target_hash) == 0) {
                strcpy(result, candidate);
                return 1;
            }

            int pos = len - 1;
            while (pos >= 0) {
                idx[pos]++;
                if (idx[pos] < CHARSET_LEN)
                    break;
                idx[pos] = 0;
                pos--;
            }

            if (pos < 0)
                break;
        }
    }
    return 0;
}

THREAD_RET WINAPI_ATTR crack_user_thread(THREAD_PARAM arg) {
    pool_arg_t *p = arg;

    while (1) {
        MUTEX_LOCK(p->index_mutex);
        if (*p->next_index >= p->user_count) {
            MUTEX_UNLOCK(p->index_mutex);
            break;
        }
        size_t i = (*p->next_index)++;
        MUTEX_UNLOCK(p->index_mutex);

        char password[PASS_LEN + 1];
        printf("Cracking user: %s...\n", p->users[i].username);

        if (!crack_md5_len4(p->users[i].hash, password)) {
            SEM_WAIT(p->sems[i - 1]);
            SEM_POST(p->sems[i]);
            continue;
        }

        strcpy(p->results[i], password);

        if (i > 0)
            SEM_WAIT(p->sems[i - 1]);

        fprintf(p->output, "%s %s\n",
                p->users[i].username,
                p->results[i]);

        SEM_POST(p->sems[i]);
    }

    return 0;
}

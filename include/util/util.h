#ifdef NODEBUG
#define okay(msg, ...) \
    do                 \
    {                  \
    } while (0)
#define warn(msg, ...) \
    do                 \
    {                  \
    } while (0)
#define fail(msg, ...) \
    do                 \
    {                  \
    } while (0)
#define info(msg, ...) \
    do                 \
    {                  \
    } while (0)
#define printf(msg, ...) \
    do                   \
    {                    \
    } while (0)
#define fprintf(msg, ...) \
    do                    \
    {                     \
    } while (0)
#else
#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define warn(msg, ...) fprintf(stderr, "[!] " msg "\n", ##__VA_ARGS__)
#define fail(msg, ...) fprintf(stderr, "[-] " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[*] " msg "\n", ##__VA_ARGS__)
#endif

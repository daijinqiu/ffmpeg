// Copyright (c) 2004-2013 Sergey Lyubka <valenok@gmail.com>
// Copyright (c) 2013 Cesanta Software Limited
// All rights reserved
//
// This library is dual-licensed: you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation. For the terms of this
// license, see <http://www.gnu.org/licenses/>.
//
// You are free to use this library under the terms of the GNU General
// Public License, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// Alternatively, you can license this library under a commercial
// license, as set out in <http://cesanta.com/products.html>.

// To compile a command-line utility, do
// cc -W -Wall sldr.c -DSLDR_CLI -o sldr

#ifndef _WIN32
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <stddef.h>

#ifdef _WIN32
#pragma comment(lib,"ws2_32")
#pragma comment(lib,"advapi32")
#include <winsock.h>
#include <ws2tcpip.h>
typedef int socklen_t;
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
#else
#define  closesocket(x)  close(x)
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <unistd.h>

#include <sys/time.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

#include "sldr.h"

#define MAX_HOST_NAME_LEN   1025
#define MAX_DNS_PACKET_LEN  2048
#define MAX_CACHE_ENTRIES   10000

// Linked list interface
struct ll { struct ll *prev, *next; };
#define LINKED_LIST_INIT(N)  ((N)->next = (N)->prev = (N))
#define LINKED_LIST_ENTRY(P,T,N)  ((T *)((char *)(P) - offsetof(T, N)))
#define LINKED_LIST_IS_EMPTY(N)  ((N)->next == (N))
#define LINKED_LIST_FOREACH(H,N,T) \
for (N = (H)->next, T = (N)->next; N != (H); N = (T), T = (N)->next)
#define LINKED_LIST_ADD_TO_FRONT(H,N) do { ((H)->next)->prev = (N); \
(N)->next = ((H)->next);  (N)->prev = (H); (H)->next = (N); } while (0)
#define LINKED_LIST_ADD_TO_TAIL(H,N) do { ((H)->prev)->next = (N); \
(N)->prev = ((H)->prev); (N)->next = (H); (H)->prev = (N); } while (0)
#define LINKED_LIST_REMOVE(N) do { ((N)->next)->prev = ((N)->prev); \
((N)->prev)->next = ((N)->next); LINKED_LIST_INIT(N); } while (0)

#ifdef ENABLE_DBG
#define DBG(x) do { printf("%-20s ", __func__); printf x; putchar('\n'); \
fflush(stdout); } while(0)
#else
#define DBG(x)
#endif

// User query. Holds mapping from application-level ID to sldr transaction id,
// and user defined callback function.
// TODO(lsm): alloc exactly what is needed instead of MAX_HOST_NAME_LEN
struct query {
    struct ll link;
    time_t expire;                  // Time when this query expire
    uint16_t tid;                   // UDP sldr transaction ID
    uint16_t query_type;
    char name[MAX_HOST_NAME_LEN];
    void *ctx;                        // Application context
    sldr_callback_t callback;         // User callback routine
    uint8_t addr[MAX_HOST_NAME_LEN];  // Host address
    size_t addrlen;                   // Address length
};

struct sldr {
    int sock;                       // UDP socket used for queries
#ifdef _WIN32
    struct sockaddr_in sa;        // sldr server socket address
#else
    struct sockaddr sa;           // sldr server socket address
#endif
    uint16_t tid;                   // Latest tid used
    
    struct ll active;               // Active queries, MRU order
    struct ll cached;               // Cached queries
    int num_cached;                 // Number of cached queries
};

struct dns_header {
    uint16_t transaction_id;
    uint16_t flags;
    uint16_t num_questions;
    uint16_t num_answers;
    uint16_t num_authority_prs;
    uint16_t num_other_prs;
    uint8_t  data[1];
};

int sldr_get_fd(struct sldr *sldr) {
    return sldr->sock;
}

static void fetch(const uint8_t *pkt, const uint8_t *s, int pktsiz,
                  char *dst, int dstlen) {
    const uint8_t *e = pkt + pktsiz;
    int j, i = 0, n = 0;
    
    while (*s != 0 && s < e) {
        if (n > 0)
            dst[i++] = '.';
        
        if (i >= dstlen)
            break;
        
        if ((n = *s++) == 0xc0) {
            s = pkt + *s;  /* New offset */
            n = 0;
        } else {
            for (j = 0; j < n && i < dstlen; j++)
                dst[i++] = *s++;
        }
    }
    
    dst[i] = '\0';
}

static int casecmp(register const char *s1, register const char *s2) {
    for (; *s1 != '\0' && *s2 != '\0'; s1++, s2++)
        if (tolower(*s1) != tolower(*s2))
            break;
    
    return * (unsigned char *) s1 - * (unsigned char *) s2;
}

static int set_non_blocking_mode(int fd) {
#ifdef  _WIN32
    unsigned long on = 1;
    return (ioctlsocket(fd, FIONBIO, &on));
#else
    int  flags;
    flags = fcntl(fd, F_GETFL, 0);
    return (fcntl(fd, F_SETFL, flags | O_NONBLOCK));
#endif
}

// Find what sldr server to use. Return 0 if OK, -1 if error
static int get_ip_address_of_sldr_server(struct sldr *sldr) {
    int  ret = 0;
    
#ifdef _WIN32
    int  i;
    LONG  err;
    HKEY  hKey, hSub;
    char  subkey[512], dhcpns[512], ns[512], value[128], *key =
    "SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces";
    
    if ((err = RegOpenKey(HKEY_LOCAL_MACHINE,
                          key, &hKey)) != ERROR_SUCCESS) {
        fprintf(stderr, "cannot open reg key %s: %d\n", key, err);
        ret--;
    } else {
        for (ret--, i = 0; RegEnumKey(hKey, i, subkey,
                                      sizeof(subkey)) == ERROR_SUCCESS; i++) {
            DWORD type, len = sizeof(value);
            if (RegOpenKey(hKey, subkey, &hSub) == ERROR_SUCCESS &&
                (RegQueryValueEx(hSub, "NameServer", 0,
                                 &type, value, &len) == ERROR_SUCCESS ||
                 RegQueryValueEx(hSub, "DhcpNameServer", 0,
                                 &type, value, &len) == ERROR_SUCCESS)) {
                     sldr->sa.sin_addr.s_addr = inet_addr(value);
                     ret++;
                     RegCloseKey(hSub);
                     break;
                 }
        }
        RegCloseKey(hKey);
    }
    
    if(ret==0)
    {
        sldr->sa.sin_family  = AF_INET;
        sldr->sa.sin_port  = htons(53);
    }
#else
    FILE  *fp;
    char  line[512];
    int  a, b, c, d;
    
    if ((fp = fopen("/etc/resolv.conf", "r")) == NULL) {
        //    ret--;
        int isFoundDNSServer = 0;
        
#ifdef __APPLE__
        res_state res = malloc(sizeof(struct __res_state));
        int result = res_ninit(res);
        if (result == 0) {
            union res_9_sockaddr_union *addr_union = malloc(res->nscount * sizeof(union res_9_sockaddr_union));
            res_getservers(res, addr_union, res->nscount);
            
            for (int i = 0; i < res->nscount; i++) {
                if (addr_union[i].sin.sin_family == AF_INET) {
                    struct sockaddr_in* p_addr_in = (struct sockaddr_in*)(&sldr->sa);
                    p_addr_in->sin_addr = addr_union[i].sin.sin_addr;
                    p_addr_in->sin_family = AF_INET;
                    p_addr_in->sin_port = htons(53);
                    
                    char ipv4[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(addr_union[i].sin.sin_addr), ipv4, INET_ADDRSTRLEN);
                    printf("\nDNS Server IPV4: %s\n", ipv4);
                    
                    isFoundDNSServer = 1;
                    break;
                }else if (addr_union[i].sin6.sin6_family == AF_INET6) {
                    struct sockaddr_in6* p_addr_in6 = (struct sockaddr_in6*)(&sldr->sa);
                    p_addr_in6->sin6_addr = addr_union[i].sin6.sin6_addr;
                    p_addr_in6->sin6_family = AF_INET6;
                    p_addr_in6->sin6_port = htons(53);
                    
                    char ipv6[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &(addr_union[i].sin6.sin6_addr), ipv6, INET6_ADDRSTRLEN);
                    printf("\nDNS Server IPV6: %s\n", ipv6);
                    
                    isFoundDNSServer = 1;
                    break;
                } else {
                    printf("\nUndefined Family\n");
                }
            }
        }
        
        res_nclose(res);
        free(res);
#endif
        
        if (isFoundDNSServer) {
            ret = 0;
        }else{
            ret--;
        }
    } else {
        /* Try to figure out what sldr server to use */
        for (ret--; fgets(line, sizeof(line), fp) != NULL; ) {
            if (sscanf(line, "nameserver %d.%d.%d.%d", &a, &b, &c, &d) == 4) {
                struct sockaddr_in* p_addr_in = (struct sockaddr_in*)(&sldr->sa);
                p_addr_in->sin_addr.s_addr = htonl(a << 24 | b << 16 | c << 8 | d);
                p_addr_in->sin_family = AF_INET;
                p_addr_in->sin_port = htons(53);
                ret++;
                break;
            }
        }
        (void) fclose(fp);
    }
#endif // _WIN32
    
    return ret;
}

struct sldr *sldr_create_with_ipv4_dns_server(int a, int b, int c, int d)
{
    struct sldr *sldr;
    int    rcvbufsiz = 128 * 1024;
    
#ifdef _WIN32
    { WSADATA data; WSAStartup(MAKEWORD(2,2), &data); }
#endif /* _WIN32 */
    
    /* FIXME resource leak here */
    if ((sldr = (struct sldr *) calloc(1, sizeof(*sldr))) == NULL)
        return (NULL);
    else if ((sldr->sock = socket(PF_INET, SOCK_DGRAM, 17)) == -1)
        return (NULL);
    else if (set_non_blocking_mode(sldr->sock) != 0)
        return (NULL);
    
#ifdef _WIN32
    sldr->sa.sin_addr.s_addr = htonl(a << 24 | b << 16 | c << 8 | d);
    
    sldr->sa.sin_family  = AF_INET;
    sldr->sa.sin_port  = htons(53);
#else
    struct sockaddr_in* p_addr_in = (struct sockaddr_in*)(&sldr->sa);
    p_addr_in->sin_addr.s_addr = htonl(a << 24 | b << 16 | c << 8 | d);
    p_addr_in->sin_family = AF_INET;
    p_addr_in->sin_port = htons(53);
#endif
    
    /* Increase socket's receive buffer */
    (void) setsockopt(sldr->sock, SOL_SOCKET, SO_RCVBUF,
                      (char *) &rcvbufsiz, sizeof(rcvbufsiz));
    
    LINKED_LIST_INIT(&sldr->active);
    LINKED_LIST_INIT(&sldr->cached);
    
    return sldr;
}

struct sldr *sldr_create_with_ipv6_dns_server(int a, int b, int c, int d,
                                              int e, int f, int g, int h,
                                              int i, int j, int k, int l,
                                              int m, int n, int o, int p)
{
    struct sldr *sldr;
    int    rcvbufsiz = 128 * 1024;
    
#ifdef _WIN32
    { WSADATA data; WSAStartup(MAKEWORD(2,2), &data); }
#endif /* _WIN32 */
    
    /* FIXME resource leak here */
    if ((sldr = (struct sldr *) calloc(1, sizeof(*sldr))) == NULL)
        return (NULL);
    else if ((sldr->sock = socket(PF_INET, SOCK_DGRAM, 17)) == -1)
        return (NULL);
    else if (set_non_blocking_mode(sldr->sock) != 0)
        return (NULL);
    
    struct sockaddr_in6* p_addr_in6 = (struct sockaddr_in6*)(&sldr->sa);
#ifdef __APPLE__
    p_addr_in6->sin6_addr.__u6_addr.__u6_addr8[0] = a;
    p_addr_in6->sin6_addr.__u6_addr.__u6_addr8[1] = b;
    p_addr_in6->sin6_addr.__u6_addr.__u6_addr8[2] = c;
    p_addr_in6->sin6_addr.__u6_addr.__u6_addr8[3] = d;
    p_addr_in6->sin6_addr.__u6_addr.__u6_addr8[4] = e;
    p_addr_in6->sin6_addr.__u6_addr.__u6_addr8[5] = f;
    p_addr_in6->sin6_addr.__u6_addr.__u6_addr8[6] = g;
    p_addr_in6->sin6_addr.__u6_addr.__u6_addr8[7] = h;
    p_addr_in6->sin6_addr.__u6_addr.__u6_addr8[8] = i;
    p_addr_in6->sin6_addr.__u6_addr.__u6_addr8[9] = j;
    p_addr_in6->sin6_addr.__u6_addr.__u6_addr8[10] = k;
    p_addr_in6->sin6_addr.__u6_addr.__u6_addr8[11] = l;
    p_addr_in6->sin6_addr.__u6_addr.__u6_addr8[12] = m;
    p_addr_in6->sin6_addr.__u6_addr.__u6_addr8[13] = n;
    p_addr_in6->sin6_addr.__u6_addr.__u6_addr8[14] = o;
    p_addr_in6->sin6_addr.__u6_addr.__u6_addr8[15] = p;
#else
    p_addr_in6->sin6_addr.in6_u.u6_addr8[0] = a;
    p_addr_in6->sin6_addr.in6_u.u6_addr8[1] = b;
    p_addr_in6->sin6_addr.in6_u.u6_addr8[2] = c;
    p_addr_in6->sin6_addr.in6_u.u6_addr8[3] = d;
    p_addr_in6->sin6_addr.in6_u.u6_addr8[4] = e;
    p_addr_in6->sin6_addr.in6_u.u6_addr8[5] = f;
    p_addr_in6->sin6_addr.in6_u.u6_addr8[6] = g;
    p_addr_in6->sin6_addr.in6_u.u6_addr8[7] = h;
    p_addr_in6->sin6_addr.in6_u.u6_addr8[8] = i;
    p_addr_in6->sin6_addr.in6_u.u6_addr8[9] = j;
    p_addr_in6->sin6_addr.in6_u.u6_addr8[10] = k;
    p_addr_in6->sin6_addr.in6_u.u6_addr8[11] = l;
    p_addr_in6->sin6_addr.in6_u.u6_addr8[12] = m;
    p_addr_in6->sin6_addr.in6_u.u6_addr8[13] = n;
    p_addr_in6->sin6_addr.in6_u.u6_addr8[14] = o;
    p_addr_in6->sin6_addr.in6_u.u6_addr8[15] = p;
#endif
    p_addr_in6->sin6_family = AF_INET6;
    p_addr_in6->sin6_port = htons(53);
    
    /* Increase socket's receive buffer */
    (void) setsockopt(sldr->sock, SOL_SOCKET, SO_RCVBUF,
                      (char *) &rcvbufsiz, sizeof(rcvbufsiz));
    
    LINKED_LIST_INIT(&sldr->active);
    LINKED_LIST_INIT(&sldr->cached);
    
    return sldr;
}

struct sldr *sldr_create(void) {
    struct sldr *sldr;
    int    rcvbufsiz = 128 * 1024;
    
#ifdef _WIN32
    { WSADATA data; WSAStartup(MAKEWORD(2,2), &data); }
#endif /* _WIN32 */
    
    /* FIXME resource leak here */
    if ((sldr = (struct sldr *) calloc(1, sizeof(*sldr))) == NULL)
        return (NULL);
    else if ((sldr->sock = socket(PF_INET, SOCK_DGRAM, 17)) == -1)
        return (NULL);
    else if (set_non_blocking_mode(sldr->sock) != 0)
        return (NULL);
    else if (get_ip_address_of_sldr_server(sldr) != 0)
        return (NULL);
    
    /* Increase socket's receive buffer */
    (void) setsockopt(sldr->sock, SOL_SOCKET, SO_RCVBUF,
                      (char *) &rcvbufsiz, sizeof(rcvbufsiz));
    
    LINKED_LIST_INIT(&sldr->active);
    LINKED_LIST_INIT(&sldr->cached);
    
    return sldr;
}

static void destroy_query(struct query *query) {
    LINKED_LIST_REMOVE(&query->link);
    free(query);
}

// Find host in host cache. Add it if not found.
static struct query *find_cached_query(struct sldr *sldr,
                                       enum dns_query_type query_type,
                                       const char *name) {
    struct ll *lp, *tmp;
    struct query *query;
    
    LINKED_LIST_FOREACH(&sldr->cached, lp, tmp) {
        query = LINKED_LIST_ENTRY(lp, struct query, link);
        
        if (query->query_type == query_type && casecmp(name, query->name) == 0) {
            // Keep sorted by LRU: move to the head
            LINKED_LIST_REMOVE(&query->link);
            LINKED_LIST_ADD_TO_FRONT(&sldr->cached, &query->link);
            return query;
        }
    }
    
    return NULL;
}

static struct query *find_active_query(struct sldr *sldr, uint16_t tid) {
    struct ll *lp, *tmp;
    struct query *query;
    
    LINKED_LIST_FOREACH(&sldr->active, lp, tmp) {
        query = LINKED_LIST_ENTRY(lp, struct query, link);
        if (tid == query->tid) return query;
    }
    
    return NULL;
}

void sldr_cancel(struct sldr *sldr, const void *context) {
    struct ll *lp, *tmp;
    struct query *query;
    
    LINKED_LIST_FOREACH(&sldr->active, lp, tmp) {
        query = LINKED_LIST_ENTRY(lp, struct query, link);
        if (query->ctx == context) {
            destroy_query(query);
            break;
        }
    }
}

static void call_user(struct sldr *sldr, struct query *query,
                      enum sldr_error error) {
    struct sldr_cb_data  cbd;
    
    cbd.context = query->ctx;
    cbd.query_type  = (enum dns_query_type) query->query_type;
    cbd.error = error;
    cbd.name = query->name;
    cbd.addr = query->addr;
    cbd.addr_len = query->addrlen;
    
    query->callback(&cbd);
    
    // Move query to cache
    LINKED_LIST_REMOVE(&query->link);
    LINKED_LIST_ADD_TO_FRONT(&sldr->cached, &query->link);
    sldr->num_cached++;
    if (sldr->num_cached >= MAX_CACHE_ENTRIES) {
        query = LINKED_LIST_ENTRY(sldr->cached.prev, struct query, link);
        destroy_query(query);
        sldr->num_cached--;
    }
}

static void parse_udp(struct sldr *sldr, const unsigned char *pkt, int len) {
    struct dns_header *header = (struct dns_header *) pkt;
    const unsigned char *p, *e, *s;
    struct query *q;
    uint32_t ttl;
    uint16_t type;
    char name[MAX_HOST_NAME_LEN];
    int found, stop, dlen, nlen;
    
    // We sent 1 query. We want to see more that 1 answer.
    header = (struct dns_header *) pkt;
    if (ntohs(header->num_questions) != 1) return;
    
    // Return if we did not send that query
    if ((q = find_active_query(sldr, header->transaction_id)) == NULL) return;
    
    // Received 0 answers
    if (header->num_answers == 0) {
        q->addrlen = 0;
        call_user(sldr, q, SLDR_DOES_NOT_EXIST);
        return;
    }
    
    // Skip host name
    for (e = pkt + len, nlen = 0, s = p = &header->data[0];
         p < e && *p != '\0'; p++) nlen++;
    
#define SLDR_NTOHS(p)  (((p)[0] << 8) | (p)[1])
    
    // We sent query class 1, query type 1
    if (&p[5] > e || SLDR_NTOHS(p + 1) != q->query_type) return;
    
    // Go to the first answer section
    p += 5;
    
    /* Loop through the answers, we want A type answer */
    for (found = stop = 0; !stop && &p[12] < e; ) {
        
        // Skip possible name in CNAME answer
        if (*p != 0xc0) {
            while (*p && &p[12] < e)
                p++;
            p--;
        }
        
        type = htons(((uint16_t *)p)[1]);
        
        if (type == 5) {
            // CNAME answer. shift to the next section
            dlen = htons(((uint16_t *) p)[5]);
            p += 12 + dlen;
        } else if (type == q->query_type) {
            found = stop = 1;
        } else {
            stop = 1;
        }
    }
    
    if (found && &p[12] < e) {
        dlen = htons(((uint16_t *) p)[5]);
        p += 12;
        
        if (p + dlen <= e) {
            // Add to the cache
            (void) memcpy(&ttl, p - 6, sizeof(ttl));
            q->expire = time(NULL) + (time_t) ntohl(ttl);
            
            // Call user
            if (q->query_type == DNS_MX_RECORD) {
                fetch((uint8_t *) header, p + 2,
                      len, name, sizeof(name) - 1);
                p = (const unsigned char *) name;
                dlen = strlen(name);
            }
            q->addrlen = dlen;
            if (q->addrlen > sizeof(q->addr))
                q->addrlen = sizeof(q->addr);
            (void) memcpy(q->addr, p, q->addrlen);
            call_user(sldr, q, SLDR_OK);
        }
    }
}

static int is_socket_ready(struct sldr *sldr, int milliseconds) {
    struct timeval tv;
    fd_set read_set;
    
    FD_ZERO(&read_set);
    FD_SET(sldr->sock, &read_set);
    
    tv.tv_sec = milliseconds / 1000;
    tv.tv_usec = (milliseconds % 1000) * 1000;
    
    return select(sldr->sock + 1, &read_set, NULL, NULL, &tv);
}

int sldr_poll(struct sldr *sldr, int milliseconds) {
    struct ll *lp, *tmp;
    struct query *query;
    struct sockaddr_in sa;
    socklen_t len = sizeof(sa);
    int n, num_packets = 0;
    unsigned char pkt[MAX_DNS_PACKET_LEN];
    time_t now = time(NULL);
    
    if (is_socket_ready(sldr, milliseconds) <= 0) return 0;
    
    // Check our socket for new stuff
    while ((n = recvfrom(sldr->sock, pkt, sizeof(pkt), 0,
                         (struct sockaddr *) &sa, &len)) > 0 &&
           n > (int) sizeof(struct dns_header)) {
        parse_udp(sldr, pkt, n);
        num_packets++;
    }
    
    // Cleanup expired active queries
    LINKED_LIST_FOREACH(&sldr->active, lp, tmp) {
        query = LINKED_LIST_ENTRY(lp, struct query, link);
        
        if (query->expire < now) {
            query->addrlen = 0;
            call_user(sldr, query, SLDR_TIMEOUT);
            destroy_query(query);
        }
    }
    
    // Cleanup cached queries
    LINKED_LIST_FOREACH(&sldr->cached, lp, tmp) {
        query = LINKED_LIST_ENTRY(lp, struct query, link);
        if (query->expire < now) {
            destroy_query(query);
            sldr->num_cached--;
        }
    }
    
    return num_packets;
}

void sldr_destroy(struct sldr **sldr) {
    struct ll *lp, *tmp;
    struct query *query;
    
    if (sldr == NULL || *sldr == NULL) return;
    
    if ((*sldr)->sock != -1) closesocket((*sldr)->sock);
    
    LINKED_LIST_FOREACH(&(*sldr)->active, lp, tmp) {
        query = LINKED_LIST_ENTRY(lp, struct query, link);
        destroy_query(query);
    }
    
    LINKED_LIST_FOREACH(&(*sldr)->cached, lp, tmp) {
        query = LINKED_LIST_ENTRY(lp, struct query, link);
        destroy_query(query);
        (*sldr)->num_cached--;
    }
    
    free(*sldr);
    *sldr = NULL;
}

int sldr_queue(struct sldr *sldr, void *ctx, const char *name,
                enum dns_query_type query_type, sldr_callback_t callback) {
    struct query *query;
    struct dns_header *header;
    int i, n, name_len;
    char pkt[MAX_DNS_PACKET_LEN], *p;
    const char *s;
    time_t now = time(NULL);
    struct sldr_cb_data cbd;
    
    // XXX Search the cache first
    if ((query = find_cached_query(sldr, query_type, name)) != NULL) {
        query->ctx = ctx;
        call_user(sldr, query, SLDR_OK);
        if (query->expire < now) {
            destroy_query(query);
            sldr->num_cached--;
        }
        return 1;
    }
    
    // Allocate new query
    if ((query = (struct query *) calloc(1, sizeof(*query))) == NULL) {
        (void) memset(&cbd, 0, sizeof(cbd));
        cbd.error = SLDR_ERROR;
        callback(&cbd);
        return -1;
    }
    
    // Init query structure
    query->ctx = ctx;
    query->query_type = (uint16_t) query_type;
    query->tid = ++sldr->tid;
    query->callback = callback;
    query->expire = now + DNS_QUERY_TIMEOUT;
    for (p = query->name; *name &&
         p < query->name + sizeof(query->name) - 1; name++, p++)
        *p = tolower(*name);
    *p = '\0';
    name = query->name;
    
    // Prepare sldr packet header
    header = (struct dns_header *) pkt;
    memset(header, 0, sizeof(*header));
    header->transaction_id = query->tid;
    header->flags = htons(0x100);       // Haha. guess what it is
    header->num_questions = htons(1);   // Just one query
    
    // Encode sldr name
    name_len = strlen(name);
    p = (char *) &header->data;  // For encoding host name into packet
    
    do {
        if ((s = strchr(name, '.')) == NULL)
            s = name + name_len;
        
        n = s - name;             // Chunk length
        *p++ = n;                 // Copy length
        for (i = 0; i < n; i++)   // Copy chunk
            *p++ = name[i];
        
        if (*s == '.')
            n++;
        
        name += n;
        name_len -= n;
        
    } while (*s != '\0');
    
    *p++ = 0;      // Mark end of host name
    *p++ = 0;      // Well, lets put this byte as well
    *p++ = (uint8_t) query_type;
    
    *p++ = 0;
    *p++ = 1;      // Class: inet, 0x0001
    
    assert(p < pkt + sizeof(pkt));
    n = p - pkt;      // Total packet length
    
    if (sendto(sldr->sock, pkt, n, 0,
               (struct sockaddr *) &sldr->sa, sizeof(sldr->sa)) != n) {
        memset(&cbd, 0, sizeof(cbd));
        cbd.error = SLDR_ERROR;
        callback(&cbd);
//        destroy_query(query);
        free(query);
        return -1;
    }
    
    LINKED_LIST_ADD_TO_TAIL(&sldr->active, &query->link);
    
    return 0;
}

#endif
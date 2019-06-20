/*
 * TCP protocol
 * Copyright (c) 2002 Fabrice Bellard
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include "avformat.h"
#include "libavutil/avassert.h"
#include "libavutil/parseutils.h"
#include "libavutil/opt.h"
#include "libavutil/time.h"

#include "internal.h"
#include "network.h"
#include "os_support.h"
#include "url.h"
#if HAVE_POLL_H
#include <poll.h>
#endif

#if HAVE_PTHREADS
#include <pthread.h>
#endif

////////////////////////////////////////////////-hook-///////////////////////////////////////////////
#include "libavutil/avhook.h"
////////////////////////////////////////////////-hook-///////////////////////////////////////////////

////////////////////////////////////////////////-slk-///////////////////////////////////////////////
#ifndef _WIN32
#include <resolv.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "libavutil/mongoose.h"
#endif
////////////////////////////////////////////////-slk-///////////////////////////////////////////////

////////////////////////////////////////////////-slk-///////////////////////////////////////////////
#ifndef _WIN32
typedef struct slk_resolve_answer {
    int rtype;
    void* data;
    int data_len;
    
    struct slk_resolve_answer* next;
};

typedef struct slk_resolve_result {
    int err; //-1:Unknown Error -2:Interrupt -3:Timeout
    struct slk_resolve_answer *root;
};
#endif
////////////////////////////////////////////////-slk-///////////////////////////////////////////////

typedef struct TCPContext {
    const AVClass *class;
    int fd;
    int listen;
    int open_timeout;
    int rw_timeout;
    int listen_timeout;
    int recv_buffer_size;
    int send_buffer_size;
    
    int64_t avhook_intptr;
    
    int enable_private_getaddrinfo;
    int addrinfo_one_by_one;
    int addrinfo_timeout;
    
    int enable_slk_dns_resolver;
    int use_slk_dns_tcp_resolve_packet;
    int slk_dns_resolver_timeout;
    char* slk_dns_server;
    
    AVHook *avhook;
} TCPContext;

#define OFFSET(x) offsetof(TCPContext, x)
#define D AV_OPT_FLAG_DECODING_PARAM
#define E AV_OPT_FLAG_ENCODING_PARAM
static const AVOption options[] = {
    { "listen",          "Listen for incoming connections",  OFFSET(listen),         AV_OPT_TYPE_INT, { .i64 = 0 },     0,       2,       .flags = D|E },
    { "timeout",     "set timeout (in microseconds) of socket I/O operations", OFFSET(rw_timeout),     AV_OPT_TYPE_INT, { .i64 = -1 },         -1, INT_MAX, .flags = D|E },
    { "listen_timeout",  "Connection awaiting timeout (in milliseconds)",      OFFSET(listen_timeout), AV_OPT_TYPE_INT, { .i64 = -1 },         -1, INT_MAX, .flags = D|E },
    { "send_buffer_size", "Socket send buffer size (in bytes)",                OFFSET(send_buffer_size), AV_OPT_TYPE_INT, { .i64 = -1 },         -1, INT_MAX, .flags = D|E },
    { "recv_buffer_size", "Socket receive buffer size (in bytes)",             OFFSET(recv_buffer_size), AV_OPT_TYPE_INT, { .i64 = -1 },         -1, INT_MAX, .flags = D|E },
    { "avhook",   "AVHook",                              OFFSET(avhook_intptr),   AV_OPT_TYPE_INT64, { .i64 = 0 }, INT64_MIN, INT64_MAX, .flags = D },
    { "enable_private_getaddrinfo",  "enable private getaddrinfo",                 OFFSET(enable_private_getaddrinfo), AV_OPT_TYPE_INT, { .i64 = 0 },         0, 1, .flags = D|E },
    { "addrinfo_one_by_one",  "parse addrinfo one by one in getaddrinfo()",    OFFSET(addrinfo_one_by_one), AV_OPT_TYPE_INT, { .i64 = 0 },         0, 1, .flags = D|E },
    { "addrinfo_timeout", "set timeout (in microseconds) for getaddrinfo()",   OFFSET(addrinfo_timeout), AV_OPT_TYPE_INT, { .i64 = -1 },       -1, INT_MAX, .flags = D|E },
    { "enable_slk_dns_resolver",  "enable slk dns resolver",                 OFFSET(enable_slk_dns_resolver), AV_OPT_TYPE_INT, { .i64 = 0 },         0, 1, .flags = D|E },
    { "use_slk_dns_tcp_resolve_packet",  "use tcp resolve packet for slk dns resolver",                 OFFSET(use_slk_dns_tcp_resolve_packet), AV_OPT_TYPE_INT, { .i64 = 0 },         0, 1, .flags = D|E },
    { "slk_dns_resolver_timeout", "set timeout (in microseconds) for slk dns resolver",   OFFSET(slk_dns_resolver_timeout), AV_OPT_TYPE_INT, { .i64 = -1 },       -1, INT_MAX, .flags = D|E },
    { "slk_dns_server", "set slk dns server", OFFSET(slk_dns_server), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, .flags = D|E },

    { NULL }
};

static const AVClass tcp_class = {
    .class_name = "tcp",
    .item_name  = av_default_item_name,
    .option     = options,
    .version    = LIBAVUTIL_VERSION_INT,
};

int private_tcp_getaddrinfo_nonblock(const char *hostname, const char *servname,
                                 const struct addrinfo *hints, struct addrinfo **res,
                                 int64_t timeout,
                                 const AVIOInterruptCB *int_cb, int one_by_one);

////////////////////////////////////////////////-slk-///////////////////////////////////////////////
#ifndef _WIN32
int slk_getaddrinfo_nonblock(const char *hostname, const int port,
                              const struct addrinfo *hints, struct addrinfo **res,
                              int64_t timeout,
                              const struct AVIOInterruptCB *int_cb, char* dns_server, int use_tcp_resolve_packet);

void resolve_cb(struct mg_dns_message *msg, void *data, enum mg_resolve_err e);
#endif
////////////////////////////////////////////////-slk-///////////////////////////////////////////////


#if HAVE_PTHREADS

typedef struct TCPAddrinfoRequest
{
    AVBufferRef *buffer;
    
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    
    AVIOInterruptCB interrupt_callback;
    
    char            *hostname;
    char            *servname;
    struct addrinfo  hints;
    struct addrinfo *res;
    
    volatile int     finished;
    int              last_error;
} TCPAddrinfoRequest;

static void tcp_getaddrinfo_request_free(TCPAddrinfoRequest *req)
{
    av_assert0(req);
    if (req->res) {
        freeaddrinfo(req->res);
        req->res = NULL;
    }
    
    av_freep(&req->servname);
    av_freep(&req->hostname);
    pthread_cond_destroy(&req->cond);
    pthread_mutex_destroy(&req->mutex);
    av_freep(&req);
}

static void tcp_getaddrinfo_request_free_buffer(void *opaque, uint8_t *data)
{
    av_assert0(opaque);
    TCPAddrinfoRequest *req = (TCPAddrinfoRequest *)opaque;
    tcp_getaddrinfo_request_free(req);
}

static int tcp_getaddrinfo_request_create(TCPAddrinfoRequest **request,
                                          const char *hostname,
                                          const char *servname,
                                          const struct addrinfo *hints,
                                          const AVIOInterruptCB *int_cb)
{
    TCPAddrinfoRequest *req = (TCPAddrinfoRequest *) av_mallocz(sizeof(TCPAddrinfoRequest));
    if (!req)
        return ENOMEM;
    
    if (pthread_mutex_init(&req->mutex, NULL)) {
        av_freep(&req);
        return ENOMEM;
    }
    
    if (pthread_cond_init(&req->cond, NULL)) {
        pthread_mutex_destroy(&req->mutex);
        av_freep(&req);
        return ENOMEM;
    }
    
    if (int_cb)
        req->interrupt_callback = *int_cb;
    
    if (hostname) {
        req->hostname = av_strdup(hostname);
        if (!req->hostname)
            goto fail;
    }
    
    if (servname) {
        req->servname = av_strdup(servname);
        if (!req->hostname)
            goto fail;
    }
    
    if (hints) {
        req->hints.ai_family   = hints->ai_family;
        req->hints.ai_socktype = hints->ai_socktype;
        req->hints.ai_protocol = hints->ai_protocol;
        req->hints.ai_flags    = hints->ai_flags;
    }
    
    req->buffer = av_buffer_create(NULL, 0, tcp_getaddrinfo_request_free_buffer, req, 0);
    if (!req->buffer)
        goto fail;
    
    *request = req;
    return 0;
fail:
    tcp_getaddrinfo_request_free(req);
    return ENOMEM;
}

static void *tcp_getaddrinfo_worker(void *arg)
{
    TCPAddrinfoRequest *req = arg;
    
    getaddrinfo(req->hostname, req->servname, &req->hints, &req->res);
    pthread_mutex_lock(&req->mutex);
    req->finished = 1;
    pthread_cond_signal(&req->cond);
    pthread_mutex_unlock(&req->mutex);
    av_buffer_unref(&req->buffer);
    return NULL;
}

static void *tcp_getaddrinfo_one_by_one_worker(void *arg)
{
    struct addrinfo *temp_addrinfo = NULL;
    struct addrinfo *cur = NULL;
    int ret = EAI_FAIL;
    int i = 0;
    int option_length = 0;
    
    TCPAddrinfoRequest *req = (TCPAddrinfoRequest *)arg;
    
    int family_option[2] = {AF_INET, AF_INET6};
    
    option_length = sizeof(family_option) / sizeof(family_option[0]);
    
    for (; i < option_length; ++i) {
        struct addrinfo *hint = &req->hints;
        hint->ai_family = family_option[i];
        ret = getaddrinfo(req->hostname, req->servname, hint, &temp_addrinfo);
        if (ret) {
            req->last_error = ret;
            continue;
        }
        pthread_mutex_lock(&req->mutex);
        if (!req->res) {
            req->res = temp_addrinfo;
        } else {
            cur = req->res;
            while (cur->ai_next)
                cur = cur->ai_next;
            cur->ai_next = temp_addrinfo;
        }
        pthread_mutex_unlock(&req->mutex);
    }
    pthread_mutex_lock(&req->mutex);
    req->finished = 1;
    pthread_cond_signal(&req->cond);
    pthread_mutex_unlock(&req->mutex);
    av_buffer_unref(&req->buffer);
    return NULL;
}

int private_tcp_getaddrinfo_nonblock(const char *hostname, const char *servname,
                                 const struct addrinfo *hints, struct addrinfo **res,
                                 int64_t timeout,
                                 const AVIOInterruptCB *int_cb, int one_by_one)
{
    int     ret;
    int64_t start;
    int64_t now;
    AVBufferRef        *req_ref = NULL;
    TCPAddrinfoRequest *req     = NULL;
    pthread_t work_thread;
    
    if (hostname && !hostname[0])
        hostname = NULL;
    
    if (timeout <= 0)
        return getaddrinfo(hostname, servname, hints, res);
    
    ret = tcp_getaddrinfo_request_create(&req, hostname, servname, hints, int_cb);
    if (ret)
        goto fail;
    
    req_ref = av_buffer_ref(req->buffer);
    if (req_ref == NULL) {
        ret = ENOMEM;
        goto fail;
    }
    
    /* FIXME: using a thread pool would be better. */
    if (one_by_one)
        ret = pthread_create(&work_thread, NULL, tcp_getaddrinfo_one_by_one_worker, req);
    else
        ret = pthread_create(&work_thread, NULL, tcp_getaddrinfo_worker, req);
    
    if (ret) {
        goto fail;
    }
    
    pthread_detach(work_thread);
    
    start = av_gettime();
    now   = start;
    
    pthread_mutex_lock(&req->mutex);
    while (1) {
        int64_t wait_time = now + 100000;
        struct timespec tv = { .tv_sec  =  wait_time / 1000000,
            .tv_nsec = (wait_time % 1000000) * 1000 };
        
        if (req->finished || (start + timeout < now)) {
            if (req->res) {
                ret = 0;
                *res = req->res;
                req->res = NULL;
            } else {
                ret = req->last_error ? req->last_error : AVERROR_EXIT;
            }
            break;
        }
#if defined(__ANDROID__) && defined(HAVE_PTHREAD_COND_TIMEDWAIT_MONOTONIC)
        ret = pthread_cond_timedwait_monotonic_np(&req->cond, &req->mutex, &tv);
#else
        ret = pthread_cond_timedwait(&req->cond, &req->mutex, &tv);
#endif
        if (ret != 0 && ret != ETIMEDOUT) {
            av_log(NULL, AV_LOG_ERROR, "pthread_cond_timedwait failed: %d\n", ret);
            ret = AVERROR_EXIT;
            break;
        }
        
        if (ff_check_interrupt(&req->interrupt_callback)) {
            ret = AVERROR_EXIT;
            break;
        }
        
        now = av_gettime();
    }
    pthread_mutex_unlock(&req->mutex);
fail:
    av_buffer_unref(&req_ref);
    return ret;
}

#else
int private_tcp_getaddrinfo_nonblock(const char *hostname, const char *servname,
                                 const struct addrinfo *hints, struct addrinfo **res,
                                 int64_t timeout,
                                 const AVIOInterruptCB *int_cb)
{
    return getaddrinfo(hostname, servname, hints, res);
}
#endif

////////////////////////////////////////////////-slk-///////////////////////////////////////////////
#ifndef _WIN32
void resolve_cb(struct mg_dns_message *msg, void *data, enum mg_resolve_err e)
{
    struct slk_resolve_result* result = (struct slk_resolve_result*)data;
    
    struct in_addr ipv4_in_addr;
    struct in6_addr ipv6_in_addr;
    struct slk_resolve_answer* root_answer = NULL;
    struct slk_resolve_answer* now_answer = NULL;
    struct slk_resolve_answer* next_answer = NULL;
    
    if (result == NULL) return;
    if (result->err == MG_RESOLVE_OK) return;
    
    if (e==MG_RESOLVE_OK)
    {
        if (msg != NULL) {
            for (int i = 0; i < msg->num_answers; i++) {
                if (msg->answers[i].rtype == MG_DNS_A_RECORD) {
                    if (mg_dns_parse_record_data(msg, &msg->answers[i], &ipv4_in_addr, 4)==0) {
                        next_answer = (struct slk_resolve_answer*)malloc(sizeof(struct slk_resolve_answer));
                        next_answer->rtype = MG_DNS_A_RECORD;
                        next_answer->data_len = 4;
                        next_answer->data = (char*)malloc(4);
                        memcpy(next_answer->data, &ipv4_in_addr, 4);
                        next_answer->next = NULL;
                        
                        if (now_answer == NULL) {
                            now_answer = next_answer;
                        }else{
                            now_answer->next = next_answer;
                            now_answer = now_answer->next;
                        }
                        
                        if (root_answer==NULL) {
                            root_answer = now_answer;
                        }
                    }
                }else if (msg->answers[i].rtype == MG_DNS_AAAA_RECORD) {
                    if (mg_dns_parse_record_data(msg, &msg->answers[i], &ipv6_in_addr, 16)==0) {
                        next_answer = (struct slk_resolve_answer*)malloc(sizeof(struct slk_resolve_answer));
                        next_answer->rtype = MG_DNS_AAAA_RECORD;
                        next_answer->data_len = 16;
                        next_answer->data = (char*)malloc(16);
                        memcpy(next_answer->data, &ipv6_in_addr, 16);
                        next_answer->next = NULL;
                        
                        if (now_answer == NULL) {
                            now_answer = next_answer;
                        }else{
                            now_answer->next = next_answer;
                            now_answer = now_answer->next;
                        }
                        
                        if (root_answer==NULL) {
                            root_answer = now_answer;
                        }
                    }
                }
            }
            
            if (root_answer!=NULL) {
                result->err = MG_RESOLVE_OK;
                result->root = root_answer;
            }
        }
    }else if(e==MG_RESOLVE_NO_ANSWERS) {
        result->err = MG_RESOLVE_NO_ANSWERS;
        return;
    }else if (e==MG_RESOLVE_EXCEEDED_RETRY_COUNT) {
        result->err = MG_RESOLVE_EXCEEDED_RETRY_COUNT;
        return;
    }else if (e==MG_RESOLVE_TIMEOUT) {
        result->err = MG_RESOLVE_TIMEOUT;
        return;
    }
}

//AVERROR_DNS_RESOLVER_INVALID : Cannot Schedule DNS Lookup
int slk_getaddrinfo_nonblock(const char *hostname, const int port,
                             const struct addrinfo *hints, struct addrinfo **res,
                             int64_t timeout,
                             const struct AVIOInterruptCB *int_cb, char* dns_server, int use_tcp_resolve_packet)
{
    struct mg_mgr m_mg_mgr;
//    struct mg_connection *dns_conn = NULL;
    struct mg_resolve_async_opts o;
    
    struct slk_resolve_result userData;
    
    struct slk_resolve_answer *this_answer = NULL;
    struct slk_resolve_answer *free_answer = NULL;
    
    struct addrinfo* root_addrinfo = NULL;
    struct addrinfo* now_addrinfo = NULL;
    struct addrinfo* next_addrinfo = NULL;
    
    struct sockaddr_in* p_sockaddr_in = NULL;
    struct sockaddr_in6* p_sockaddr_in6 = NULL;
    
    int64_t start = av_gettime();
    int64_t now;
    now = start;
    
    userData.err = -1;
    userData.root = NULL;
    
    memset(&m_mg_mgr, 0, sizeof(m_mg_mgr));
    mg_mgr_init(&m_mg_mgr, NULL);
    
    if (use_tcp_resolve_packet) {
        //        dns_conn = NULL;
        memset(&o, 0, sizeof(o));
        //        o.dns_conn = &dns_conn;
        o.nameserver = dns_server;
        
        userData.err = -1;
        userData.root = NULL;
        
        if (slk_mg_resolve_async_opt(&m_mg_mgr, hostname, MG_DNS_A_RECORD, resolve_cb, (void*)&userData, o, use_tcp_resolve_packet) != 0) {
            mg_mgr_free(&m_mg_mgr);
            return AVERROR_DNS_RESOLVER_INVALID;
        }
        
        while (1) {
            //is interrupt
            if (ff_check_interrupt(int_cb)) {
                userData.err = -2;
                break;
            }
            
            //is timeout
            now = av_gettime();
            if (start + timeout <= now) {
                userData.err = -3;
                break;
            }
            
            mg_mgr_poll(&m_mg_mgr, 500);
            
            if (userData.err==MG_RESOLVE_OK) {
                break;
            }
        }
    }else{
        while (1) {
            //is interrupt
            if (ff_check_interrupt(int_cb)) {
                userData.err = -2;
                break;
            }
            
            //is timeout
            now = av_gettime();
            if (start + timeout <= now) {
                userData.err = -3;
                break;
            }
            
            //        dns_conn = NULL;
            memset(&o, 0, sizeof(o));
            //        o.dns_conn = &dns_conn;
            o.nameserver = dns_server;
            
            userData.err = -1;
            userData.root = NULL;
            
            if (slk_mg_resolve_async_opt(&m_mg_mgr, hostname, MG_DNS_A_RECORD, resolve_cb, (void*)&userData, o, use_tcp_resolve_packet) != 0) {
                mg_mgr_free(&m_mg_mgr);
                return AVERROR_DNS_RESOLVER_INVALID;
            }
            
            mg_mgr_poll(&m_mg_mgr, 200);
            
            if (userData.err==MG_RESOLVE_OK) {
                break;
            }
        }
    }

    mg_mgr_free(&m_mg_mgr);
    
    if (userData.err==MG_RESOLVE_OK) {
        
        this_answer = userData.root;
        while (this_answer!=NULL) {
            next_addrinfo = (struct addrinfo*)malloc(sizeof(struct addrinfo));
            memset(next_addrinfo, 0, sizeof(struct addrinfo));
            next_addrinfo->ai_family = hints->ai_family;
            next_addrinfo->ai_socktype = hints->ai_socktype;
            next_addrinfo->ai_protocol = hints->ai_protocol;
            next_addrinfo->ai_flags = hints->ai_flags;
            next_addrinfo->ai_canonname = NULL;
            next_addrinfo->ai_addr = NULL;
            next_addrinfo->ai_next = NULL;
            
            if (this_answer->rtype==MG_DNS_A_RECORD) {
                p_sockaddr_in = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
                memset(p_sockaddr_in, 0, sizeof(struct sockaddr_in));
                memcpy(&p_sockaddr_in->sin_addr, this_answer->data, this_answer->data_len);
                p_sockaddr_in->sin_port = htons(port);
                p_sockaddr_in->sin_family = AF_INET;
#ifdef __APPLE__
                p_sockaddr_in->sin_len = sizeof(p_sockaddr_in);
#endif
                next_addrinfo->ai_addrlen = 16;
                next_addrinfo->ai_family = AF_INET;
                
                next_addrinfo->ai_addr = (struct sockaddr*)p_sockaddr_in;
            }else if (this_answer->rtype==MG_DNS_AAAA_RECORD) {
                p_sockaddr_in6 = (struct sockaddr_in6*)malloc(sizeof(struct sockaddr_in6));
                memset(p_sockaddr_in6, 0, sizeof(struct sockaddr_in6));
                memcpy(&p_sockaddr_in6->sin6_addr, this_answer->data, this_answer->data_len);
                p_sockaddr_in6->sin6_port = htons(port);
                p_sockaddr_in6->sin6_family = AF_INET6;
#ifdef __APPLE__
                p_sockaddr_in6->sin6_len = sizeof(p_sockaddr_in6);
#endif
                next_addrinfo->ai_addrlen = 28;
                next_addrinfo->ai_family = AF_INET6;
            }
            
            free_answer = this_answer;
            this_answer = this_answer->next;
            if (free_answer) {
                if (free_answer->data) {
                    free(free_answer->data);
                    free_answer->data = NULL;
                }
                free(free_answer);
                free_answer = NULL;
            }
            
            if (now_addrinfo == NULL) {
                now_addrinfo = next_addrinfo;
            }else{
                now_addrinfo->ai_next = next_addrinfo;
                now_addrinfo = next_addrinfo->ai_next;
            }
            
            if (root_addrinfo==NULL) {
                root_addrinfo = now_addrinfo;
            }
        }
        
        if (root_addrinfo!=NULL) {
            *res = root_addrinfo;
        }
        
        return 0;
    }else{
        if (userData.err==-2) {
            return AVERROR_EXIT;
        }else if (userData.err==-3) {
            return ETIMEDOUT;
        }else {
            return AVERROR_UNKNOWN;
        }
    }
}

#endif
////////////////////////////////////////////////-slk-///////////////////////////////////////////////

/* return non zero if error */
static int tcp_open(URLContext *h, const char *uri, int flags)
{
    int a; int b; int c; int d;
    int isDirectGetAddrInfo = 0;
    char ipv6_buf[100];
    struct in6_addr sin6_addr;

    AVHookEventTcpIOInfo hookEventTcpIOInfo;
    
    struct addrinfo hints = { 0 }, *ai, *cur_ai;
    int port, fd = -1;
    TCPContext *s = h->priv_data;
    const char *p;
    char buf[256];
    int ret;
    char hostname[1024],proto[1024],path[1024];
    char portstr[10];
    s->open_timeout = 5000000;

    s->avhook = (AVHook*)(intptr_t)s->avhook_intptr;
    
    av_url_split(proto, sizeof(proto), NULL, 0, hostname, sizeof(hostname),
        &port, path, sizeof(path), uri);
    if (strcmp(proto, "tcp"))
        return AVERROR(EINVAL);
    if (port <= 0 || port >= 65536) {
        av_log(h, AV_LOG_ERROR, "Port missing in uri\n");
        return AVERROR(EINVAL);
    }
    p = strchr(uri, '?');
    if (p) {
        if (av_find_info_tag(buf, sizeof(buf), "listen", p)) {
            char *endptr = NULL;
            s->listen = strtol(buf, &endptr, 10);
            /* assume if no digits were found it is a request to enable it */
            if (buf == endptr)
                s->listen = 1;
        }
        if (av_find_info_tag(buf, sizeof(buf), "timeout", p)) {
            s->rw_timeout = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "listen_timeout", p)) {
            s->listen_timeout = strtol(buf, NULL, 10);
        }
    }
    if (s->rw_timeout >= 0) {
        s->open_timeout =
        h->rw_timeout   = s->rw_timeout;
    }
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof(portstr), "%d", port);
    if (s->listen)
        hints.ai_flags |= AI_PASSIVE;
    
    if (strcmp(hostname, "localhost")==0) {
        isDirectGetAddrInfo = 1;
    }else{
        memset(ipv6_buf,0,100);
        if (sscanf(hostname, "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
            if (a>=0 && a<=256 && b>=0 && b<=256 && c>=0 && c<=256 && d>=0 && d<=256) {
                isDirectGetAddrInfo = 1;
            }
        }else if(sscanf(hostname, "[%99[^]]]", ipv6_buf) == 1 &&
                 inet_pton(AF_INET6, ipv6_buf, &sin6_addr)) {
            isDirectGetAddrInfo = 1;
        }
    }
#ifndef _WIN32
    if(s->enable_slk_dns_resolver && s->slk_dns_server!=NULL && !isDirectGetAddrInfo)
    {
        av_log(h, AV_LOG_INFO, "slk dns resolver enabled, call slk_getaddrinfo_nonblock function.\n");
        if (s->use_slk_dns_tcp_resolve_packet) {
            av_log(h, AV_LOG_INFO, "using tcp resolve packet for slk dns resolver.\n");
        }else{
            av_log(h, AV_LOG_INFO, "using udp resolve packet for slk dns resolver.\n");
        }
        ret = slk_getaddrinfo_nonblock(hostname, port, &hints, &ai, s->slk_dns_resolver_timeout, &h->interrupt_callback, s->slk_dns_server, s->use_slk_dns_tcp_resolve_packet);
    }else{
#endif
        if (s->enable_private_getaddrinfo) {
#if HAVE_PTHREADS
            av_log(h, AV_LOG_INFO, "have pthreads support, call private_tcp_getaddrinfo_nonblock function.\n");
            ret = private_tcp_getaddrinfo_nonblock(hostname, portstr, &hints, &ai, s->addrinfo_timeout, &h->interrupt_callback, s->addrinfo_one_by_one);
#else
            if (s->addrinfo_timeout > 0)
                av_log(h, AV_LOG_WARNING, "Ignore addrinfo_timeout without pthreads support.\n");
            if (!hostname[0])
                ret = getaddrinfo(NULL, portstr, &hints, &ai);
            else
                ret = getaddrinfo(hostname, portstr, &hints, &ai);
#endif
        }else{
            if (s->addrinfo_timeout > 0)
                av_log(h, AV_LOG_WARNING, "Ignore addrinfo_timeout without pthreads support.\n");
            if (!hostname[0])
                ret = getaddrinfo(NULL, portstr, &hints, &ai);
            else
                ret = getaddrinfo(hostname, portstr, &hints, &ai);
        }
#ifndef _WIN32
    }
#endif

    if (ret) {
        if (ret==AVERROR_EXIT) {
            return AVERROR_EXIT;
        }

        if (ret==ENOMEM || ret==ETIMEDOUT || ret==EIO || ret==AVERROR_UNKNOWN) {
            if (ret==ENOMEM) {
                av_log(h, AV_LOG_ERROR,
                       "Failed to resolve hostname %s: %s\n",
                       hostname, "No Memory Space");
                
                snprintf(hookEventTcpIOInfo.errorInfo, 1024, "Failed to resolve hostname %s: %s", hostname, "No Memory Space");
            }
            
            if (ret==ETIMEDOUT) {
                av_log(h, AV_LOG_ERROR,
                       "Failed to resolve hostname %s: %s\n",
                       hostname, "TimeOut");
                
                snprintf(hookEventTcpIOInfo.errorInfo, 1024, "Failed to resolve hostname %s: %s", hostname, "TimeOut");
            }
            
            if (ret==EIO) {
                av_log(h, AV_LOG_ERROR,
                       "Failed to resolve hostname %s: %s\n",
                       hostname, "IO Error");
                
                snprintf(hookEventTcpIOInfo.errorInfo, 1024, "Failed to resolve hostname %s: %s", hostname, "IO Error");
            }
            
            if (ret==AVERROR_UNKNOWN) {
                av_log(h, AV_LOG_ERROR,
                       "Failed to resolve hostname %s: %s\n",
                       hostname, "Unknown Error");
                
                snprintf(hookEventTcpIOInfo.errorInfo, 1024, "Failed to resolve hostname %s: %s", hostname, "Unknown Error");
            }
        }else{
            av_log(h, AV_LOG_ERROR,
                   "Failed to resolve hostname %s: %s\n",
                   hostname, gai_strerror(ret));
            
            snprintf(hookEventTcpIOInfo.errorInfo, 1024, "Failed to resolve hostname %s: %s", hostname, gai_strerror(ret));
        }

        hookEventTcpIOInfo.error = ret;
        hookEventTcpIOInfo.family = AF_UNSPEC;
        memset(hookEventTcpIOInfo.ip, 0, INET6_ADDRSTRLEN);
        hookEventTcpIOInfo.port = port;

        if (s->avhook) {
            s->avhook->func_on_event(s->avhook->opaque, AVHOOK_EVENT_TCPIO_INFO, &hookEventTcpIOInfo);
        }
        
//        return AVERROR(ret);
        return AVERROR_DNS_RESOLVER;
    }

    cur_ai = ai;

 restart:
    
    hookEventTcpIOInfo.error = 0;
    hookEventTcpIOInfo.family = cur_ai->ai_family;
    memset(hookEventTcpIOInfo.ip, 0, INET6_ADDRSTRLEN);
    hookEventTcpIOInfo.port = port;
    memset(hookEventTcpIOInfo.errorInfo, 0, 1024);
    
#ifndef _WIN32
    if (ai->ai_family==AF_INET) {
        inet_ntop(AF_INET,&(((struct sockaddr_in *)cur_ai->ai_addr)->sin_addr), hookEventTcpIOInfo.ip, INET_ADDRSTRLEN);
    }else{
        inet_ntop(AF_INET6,&(((struct sockaddr_in6 *)cur_ai->ai_addr)->sin6_addr), hookEventTcpIOInfo.ip, INET6_ADDRSTRLEN);
    }
#endif
    
    snprintf(hookEventTcpIOInfo.errorInfo, 1024, "Success to resolve hostname %s", hostname);
    
    if (s->avhook) {
        s->avhook->func_on_event(s->avhook->opaque, AVHOOK_EVENT_TCPIO_INFO, &hookEventTcpIOInfo);
    }
    
#if HAVE_STRUCT_SOCKADDR_IN6
    // workaround for IOS9 getaddrinfo in IPv6 only network use hardcode IPv4 address can not resolve port number.
    if (cur_ai->ai_family == AF_INET6){
        struct sockaddr_in6 * sockaddr_v6 = (struct sockaddr_in6 *)cur_ai->ai_addr;
        if (!sockaddr_v6->sin6_port){
            sockaddr_v6->sin6_port = htons(port);
        }
    }
#endif

    fd = ff_socket(cur_ai->ai_family,
                   cur_ai->ai_socktype,
                   cur_ai->ai_protocol);
    if (fd < 0) {
        ret = ff_neterrno();
        goto fail;
    }

    /* Set the socket's send or receive buffer sizes, if specified.
       If unspecified or setting fails, system default is used. */
    if (s->recv_buffer_size > 0) {
        setsockopt (fd, SOL_SOCKET, SO_RCVBUF, &s->recv_buffer_size, sizeof (s->recv_buffer_size));
    }
    if (s->send_buffer_size > 0) {
        setsockopt (fd, SOL_SOCKET, SO_SNDBUF, &s->send_buffer_size, sizeof (s->send_buffer_size));
    }

    if (s->listen == 2) {
        // multi-client
        if ((ret = ff_listen(fd, cur_ai->ai_addr, cur_ai->ai_addrlen)) < 0)
            goto fail1;
    } else if (s->listen == 1) {
        // single client
        if ((ret = ff_listen_bind(fd, cur_ai->ai_addr, cur_ai->ai_addrlen,
                                  s->listen_timeout, h)) < 0)
            goto fail1;
        // Socket descriptor already closed here. Safe to overwrite to client one.
        fd = ret;
    } else {
        if ((ret = ff_listen_connect(fd, cur_ai->ai_addr, cur_ai->ai_addrlen,
                                     s->open_timeout / 1000, h, !!cur_ai->ai_next)) < 0) {

            if (ret == AVERROR_EXIT)
                goto fail1;
            else
                goto fail;
        }
    }

    h->is_streamed = 1;
    s->fd = fd;

    freeaddrinfo(ai);
    return 0;

 fail:
    if (cur_ai->ai_next) {
        /* Retry with the next sockaddr */
        cur_ai = cur_ai->ai_next;
        if (fd >= 0)
            closesocket(fd);
        ret = 0;
        goto restart;
    }
 fail1:
    if (fd >= 0)
        closesocket(fd);
    freeaddrinfo(ai);
    return ret;
}

static int tcp_accept(URLContext *s, URLContext **c)
{
    TCPContext *sc = s->priv_data;
    TCPContext *cc;
    int ret;
    av_assert0(sc->listen);
    if ((ret = ffurl_alloc(c, s->filename, s->flags, &s->interrupt_callback)) < 0)
        return ret;
    cc = (*c)->priv_data;
    ret = ff_accept(sc->fd, sc->listen_timeout, s);
    if (ret < 0)
        return ret;
    cc->fd = ret;
    return 0;
}

static int tcp_read(URLContext *h, uint8_t *buf, int size)
{
    TCPContext *s = h->priv_data;
    int ret;

    if (!(h->flags & AVIO_FLAG_NONBLOCK)) {
        ret = ff_network_wait_fd_timeout(s->fd, 0, h->rw_timeout, &h->interrupt_callback);
        if (ret)
            return ret;
    }
    ret = recv(s->fd, buf, size, 0);
    return ret < 0 ? ff_neterrno() : ret;
}

static int tcp_write(URLContext *h, const uint8_t *buf, int size)
{
    TCPContext *s = h->priv_data;
    int ret;

    if (!(h->flags & AVIO_FLAG_NONBLOCK)) {
        ret = ff_network_wait_fd_timeout(s->fd, 1, h->rw_timeout, &h->interrupt_callback);
        if (ret)
            return ret;
    }
    ret = send(s->fd, buf, size, MSG_NOSIGNAL);
    return ret < 0 ? ff_neterrno() : ret;
}

static int tcp_shutdown(URLContext *h, int flags)
{
    TCPContext *s = h->priv_data;
    int how;

    if (flags & AVIO_FLAG_WRITE && flags & AVIO_FLAG_READ) {
        how = SHUT_RDWR;
    } else if (flags & AVIO_FLAG_WRITE) {
        how = SHUT_WR;
    } else {
        how = SHUT_RD;
    }

    return shutdown(s->fd, how);
}

static int tcp_close(URLContext *h)
{
    TCPContext *s = h->priv_data;
    closesocket(s->fd);
    return 0;
}

static int tcp_get_file_handle(URLContext *h)
{
    TCPContext *s = h->priv_data;
    return s->fd;
}

static int tcp_get_window_size(URLContext *h)
{
    TCPContext *s = h->priv_data;
    int avail;
    int avail_len = sizeof(avail);

#if HAVE_WINSOCK2_H
    /* SO_RCVBUF with winsock only reports the actual TCP window size when
    auto-tuning has been disabled via setting SO_RCVBUF */
    if (s->recv_buffer_size < 0) {
        return AVERROR(ENOSYS);
    }
#endif

    if (getsockopt(s->fd, SOL_SOCKET, SO_RCVBUF, &avail, &avail_len)) {
        return ff_neterrno();
    }
    return avail;
}

const URLProtocol ff_tcp_protocol = {
    .name                = "tcp",
    .url_open            = tcp_open,
    .url_accept          = tcp_accept,
    .url_read            = tcp_read,
    .url_write           = tcp_write,
    .url_close           = tcp_close,
    .url_get_file_handle = tcp_get_file_handle,
    .url_get_short_seek  = tcp_get_window_size,
    .url_shutdown        = tcp_shutdown,
    .priv_data_size      = sizeof(TCPContext),
    .flags               = URL_PROTOCOL_FLAG_NETWORK,
    .priv_data_class     = &tcp_class,
};

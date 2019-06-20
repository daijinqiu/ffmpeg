#ifndef AVUTIL_AVHOOK_H
#define AVUTIL_AVHOOK_H

#define AVHOOK_EVENT_TCPIO_INFO  0

typedef struct AVHookEventTcpIOInfo {
    int  error;
    int  family;
    char ip[46];
    int  port;
    char errorInfo[1024];
} AVHookEventTcpIOInfo;

typedef struct AVHook {
    void *opaque;
    void (*func_on_event)(void *opaque, int event_type, void *obj);
} AVHook;

#endif /* AVUTIL_AVHOOK_H */


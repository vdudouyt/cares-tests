#pragma once
#include <ares.h>

typedef struct {
   void *handle;
   void (*ares_free_hostent)(struct hostent *host);
   int (*ares_parse_a_reply)(const unsigned char *abuf, int alen,
                                     struct hostent     **host,
                                     struct ares_addrttl *addrttls,
                                     int                 *naddrttls);
} ares_impl_t;

extern ares_impl_t impl;

void load_cares_impl(const char *path);
void unload_cares_impl();

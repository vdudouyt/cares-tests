#pragma once
#include <ares.h>

typedef struct {
   void *handle;
   void (*ares_free_hostent)(struct hostent *host);
   int (*ares_parse_a_reply)(const unsigned char *abuf, int alen,
                                     struct hostent     **host,
                                     struct ares_addrttl *addrttls,
                                     int                 *naddrttls);
   int (*ares_parse_aaaa_reply)(const unsigned char *abuf, int alen,
                                     struct hostent      **host,
                                     struct ares_addr6ttl *addrttls,
                                     int                  *naddrttls);
   void (*ares_free_data)(void *dataptr);
   int (*ares_parse_caa_reply)(const unsigned char *abuf, int alen, struct ares_caa_reply **caa_out);
} ares_impl_t;

extern ares_impl_t impl;

void load_cares_impl(const char *path);
void unload_cares_impl();

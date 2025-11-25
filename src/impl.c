#include <dlfcn.h>
#include <assert.h>
#include "impl.h"

ares_impl_t impl;

void load_cares_impl(const char *path) {
   void *handle = impl.handle = dlopen(path, RTLD_LAZY);
   assert(handle);
   dlerror();
   impl.ares_free_hostent = dlsym(handle, "ares_free_hostent");
   impl.ares_parse_a_reply = dlsym(handle, "ares_parse_a_reply");
   impl.ares_parse_aaaa_reply = dlsym(handle, "ares_parse_aaaa_reply");
   impl.ares_free_data = dlsym(handle, "ares_free_data");
   impl.ares_parse_caa_reply = dlsym(handle, "ares_parse_caa_reply");
}

void unload_cares_impl() {
   dlclose(impl.handle);
}

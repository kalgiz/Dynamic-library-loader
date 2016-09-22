#ifndef LOADER_H
#define LOADER_H

#ifdef __cplusplus
extern "C" {
#endif

struct library;

struct library *library_load(const char *name, void *(*getsym)(const char *name));
void *library_getsym(struct library *lib, const char *name);

#ifdef __cplusplus
}
#endif

#endif

#ifndef ANTIVIRUS_H
#define ANTIVIRUS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <openssl/sha.h>

/* ---- db.c ---- */
/* 'extern' = la variable SE DEFINE en db.c, aquí solo avisamos que existe */
extern char **db_hashes;
extern int db_total;
void cargar_db(const char *ruta_db);
int es_malicioso(const char *hash);

/* ---- transformacion.c ---- */
void calcular_sha256(const char *ruta, char salida[65]);

/* ---- revisarCarpeta.c ---- */
void analizar_directorio(const char *ruta);

/* ---- aislar.c ---- */
void aislar(const char *ruta_origen);

#endif
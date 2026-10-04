#include "antivirus.h"

// cargar db a la memoria

// hacemos la lista xd
char **db_hashes;
int db_total = 0;

int comparar(const void *a, const void *b) {
    return strcmp(*(const char **)a, *(const char **)b);
}

// abrimos el doc
void cargar_db(const char *ruta_db) {
    FILE *archivo_db = fopen(ruta_db, "r");
    if (!archivo_db) {
        perror("No se pudo abrir la DB (x.x)");
        exit(1);
    } 

    // resevar memoria
    char linea[128];
    while(fgets(linea, sizeof(linea), archivo_db)){
        db_total++;
    }
    rewind(archivo_db);

    // asignar memoria
    db_hashes = malloc(db_total * sizeof(char *));
    int i = 0;

    while(fgets(linea, sizeof(linea), archivo_db) && i < db_total) {
        linea[strcspn(linea, "\r\n")] = 0;  // quitar salto de línea
        if (linea[0] == '#' || linea[0] == '\0') continue;  // ignorar comentarios
        db_hashes[i++] = strdup(linea);
    }
    db_total = i;
    fclose(archivo_db);

    // ordenar para búsqueda binaria
    qsort(db_hashes, db_total, sizeof(char *), comparar);  
    
}

// funcion para la busqueda binaria
int es_malicioso(const char *hash) {
    // buscamos pero guardamos en una variable
    void *resultado = bsearch(&hash, db_hashes, db_total, sizeof(char *), comparar);
    if (resultado != NULL) {
        printf(">>> archivo malicioso encontrado <<<\n");
        return 1;
    }
    return 0;
}
#include "antivirus.h"

void aislar(const char *ruta_origen) {
    const char *aislado = "/home/AlN/esc/seguridad-informatica/AntiVirus-hash/AISLADOS";

    // se extraer solo el nombre del archivo
    const char *nombre = strrchr(ruta_origen, '/');
    nombre = nombre ? nombre + 1 : ruta_origen;

    char destino[1024];
    snprintf(destino, sizeof(destino), "%s/AA_%s", aislado, nombre);

    if (rename(ruta_origen, destino) == 0) {
        chmod(destino, 0000);
        printf("### Archivo aislado en: %s ###\n", destino);
    } else {
        perror("Error al aislar");
    }
}
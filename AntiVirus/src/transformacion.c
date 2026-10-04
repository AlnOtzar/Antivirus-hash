#include "antivirus.h"

// abrimos el archivo
void calcular_sha256(const char *ruta, char salida[65]) {
    FILE *archivo = fopen(ruta, "rb"); //rb significa modo binario
    
    if (!archivo) {
        printf("no hay archivos... \n");
        return;
    }

    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    // hare bloques de 8 kb para no saturar mi memoria
    unsigned char buffer[8192];
    size_t Bloqueleido;

    // para cada bloque leido con la mayor long de 0
    while ((Bloqueleido = fread(buffer, 1, sizeof(buffer), archivo)) > 0) {
        // printf("Creando bloque de 8Kb para procesar... \n");
        SHA256_Update(&ctx, buffer, Bloqueleido);
    }

    // resultado del bloque en hexadecimal
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &ctx);
    fclose(archivo);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(salida + i * 2, "%02x", hash[i]);
    }
    salida[64] = '\0';

}
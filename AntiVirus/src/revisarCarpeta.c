#include "antivirus.h"

// contador
int limpios = 0, detectados = 0;

void analizar_directorio(const char *ruta){

	//en base a la ruta que le de en main
    DIR *dir = opendir(ruta);
    if (!dir) {
        printf("X No se encontro la ruta X \n");
        return;
    }

    struct dirent *entrada;
    while ((entrada = readdir(dir)) != NULL){
        if(strcmp(entrada->d_name, ".") == 0 || strcmp(entrada->d_name, "..") == 0){
            continue;
        }

        char ruta_completa[1024];
        snprintf(
            ruta_completa, 
            sizeof(ruta_completa), 
            "%s/%s", 
            ruta, 
            entrada->d_name);
        
        struct stat info;
        if (stat(ruta_completa, &info) != 0) {
            continue;
        }

        if (S_ISDIR(info.st_mode)) {
            // si ss carpeta  bajar un nivel
            analizar_directorio(ruta_completa);
        } else if (S_ISREG(info.st_mode)) {
        
            char hash[65];
            calcular_sha256(ruta_completa, hash);

            // comparamos (db.c)
            if (es_malicioso(hash)) {
                printf("\n### coincidencia encontrada, posible malware ###\n");
                printf("Archivo: %s\n", ruta_completa);
                printf("SHA256:  %s\n", hash);
                printf("Tamaño:  %ld bytes\n", info.st_size);
                printf("Fecha:   %s", ctime(&info.st_mtime));

                // para hacerlo las dinamico xd
                printf("\n¿Qué deseas hacer?\n");
                printf("[1] Aislar (mover a cuarentena)\n");
                printf("[2] Ignorar\n");
                printf("> ");

                int opcion;
                scanf("%d", &opcion);
                if (opcion == 1) {
                    aislar(ruta_completa);
                }
            } else {
                // printf("Limpio: %s\n", ruta_completa);
                limpios++;
            }
        }
    } 
    printf("Resumen de %s: %d limpios, %d detectados\n", ruta, limpios, detectados);
    
    closedir(dir);

}

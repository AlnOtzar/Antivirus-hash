#include "antivirus.h"

int main(int argc, char *argv[]) {
    // db real
    const char *db_path = "/home/AlN/esc/seguridad-informatica/AntiVirus-hash/AntiVirus/resource/full_sha256.txt";

    // db preuba
    // const char *db_path = "/home/AlN/esc/seguridad-informatica/AntiVirus-hash/AntiVirus/resource/test_db.txt";
    
    const char *carpeta_a_escanear = argc > 1 ? argv[1] : "/home/AlN";

    printf("Cargando base de datos...\n");
    cargar_db(db_path);
    printf("%d hashes cargados.\n", db_total);

    printf("Iniciando escaneo de %s...\n\n", carpeta_a_escanear);
    analizar_directorio(carpeta_a_escanear);

    printf("\nEscaneo completado.\n");

    // iberar memoria
    for (int i = 0; i < db_total; i++) free(db_hashes[i]);
    free(db_hashes);

    return 0;
}

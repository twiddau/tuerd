#include <stdlib.h>
#include <nfc/nfc.h>
#include <freefare.h>
#include <gcrypt.h>
#include <unistd.h>
#include <ctype.h>
#include <stdio.h>

#define DOOR_APPLICATION_ID 0xF52100

int NFC_MAX_DEVICES = 1;

int print_buffer(FILE *f, uint8_t *b, size_t n) {
    for (int i = 0; i < n; i++) {
        if (fprintf(f, "%02X", b[i]) != 2) {
            perror("Write failed");
            return -1;
        }
    }

    return 0;
}

static int parse_key(uint8_t key[static 16], const char *data) {
    if (!data || strlen(data) != 32)
        return -1;

    for (int i = 0; i < 16; i++) {
        char buf[3];
        buf[0] = tolower(data[2 * i]);
        buf[1] = tolower(data[2 * i + 1]);
        buf[2] = 0;

        sscanf(buf, "%hhx", &key[i]);
    }

    return 0;
}

#define LOG_FILE "./prepare_log"
int log_action(char *uid, int media_id)
{
    FILE *f;

    f = fopen(LOG_FILE, "a+");
    if (!f)
    {
        perror("Opening logfile failed");
        return -1;
    }

    setbuf(f, NULL);

    if (fprintf(f, "%s", uid) != 14)
    {
        fprintf(stderr, "Writing log failed");
        return -1;
    }

    fprintf(f, " ");
    if (fprintf(f, "%d", media_id) == 0)
    {
        fprintf(stderr, "Writing log failed");
        return -1;
    }

    fprintf(f, "\n");

    if (fflush(f))
    {
        perror("Flushing logfile failed");
        return -1;
    }

    int fd = fileno(f);
    if (fd == -1)
    {
        perror("fileno() failed");
        return -1;
    }

    if (fsync(fd))
    {
        perror("fsync() failed");
        return -1;
    }

    if (fclose(f))
    {
        perror("fclose() failed");
        return -1;
    }

    return 0;
}


int main(int argc, char **argv) {
    int result;
    int _error = 0;

    nfc_device *device = NULL;
    FreefareTag *tags = NULL;
    FreefareTag tag = NULL;

    nfc_connstring devices[NFC_MAX_DEVICES];
    size_t device_count;

    nfc_context *context;

    int number_count;

    if (argc > 1) {
        number_count = atoi(argv[1]);
        printf("Starting value for Media ID: %d\n", number_count);
    } else {
        printf("No starting value for ID given.\n");
        exit(EXIT_FAILURE);
    }

    const char *picckey = getenv("PICCKEY");
    uint8_t raw_picckey[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    parse_key(raw_picckey, picckey);
    MifareDESFireKey picckey_des = mifare_desfire_3des_key_new(raw_picckey);

    const char *rokey = getenv("ROKEY");
    uint8_t raw_rokey[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    parse_key(raw_rokey, rokey);
    MifareDESFireKey rokey_des = mifare_desfire_3des_key_new(raw_rokey);

    const char *fabkey = getenv("FABKEY");
    uint8_t raw_fabkey[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    parse_key(raw_fabkey, fabkey);
    MifareDESFireKey fabkey_des = mifare_desfire_3des_key_new(raw_fabkey);

    printf("Using as new PICC key: ");
    print_buffer(stdout, raw_picckey, 16);
    printf("\n");

    nfc_init(&context);

    if (context == NULL) {
        printf("Unable to init libnfc (malloc)\n");
        exit(EXIT_FAILURE);
    }

    device_count = nfc_list_devices(context, devices, 8);
    if (device_count <= 0) {
        printf("No NFC device found.\n");
        exit(EXIT_FAILURE);
    }


    while (true) {

        device = nfc_open(context, devices[0]);
        if (!device) {
            printf("nfc_open() failed\n");
            exit(EXIT_FAILURE);
        }

        tags = freefare_get_tags(device);
        if (!tags) {
            nfc_close(device);
            printf("Error listing Mifare DESFire tags.\n");
            exit(EXIT_FAILURE);
        }

        if (!tags[0]) {
            nfc_close(device);
            sleep(1);
            continue;
        }

        if (tags[0] && tags[1]) {
            nfc_close(device);
            printf("Error: More than tag found.\n");
            exit(EXIT_FAILURE);
        }

        tag = tags[0];

        char *tag_uid = freefare_get_tag_uid(tag);
        printf("Card UID: %s\n", tag_uid);

        /****** Log keys and print JSON ******/
        if (log_action(tag_uid, number_count))
        {
            fprintf(stderr, "WAL failed, aborting.\n");
            return EXIT_FAILURE;
        }

        printf("Writing tag ...\n");


        enum freefare_tag_type type = freefare_get_tag_type(tag);
        if (type != MIFARE_DESFIRE) {
            printf("Error: RFID card is not a Mifare DESFire.\n");
            goto FREEFARE_CLOSE;
        }

        result = mifare_desfire_connect(tag);
        if (result < 0) {
            printf("Can't connect to Mifare DESFire target.\n");
            goto FREEFARE_CLOSE;
        }

        struct mifare_desfire_version_info info;
        result = mifare_desfire_get_version(tag, &info);
        if (result < 0) {
            printf("Error reading Mifare DESFire Version\n");
            goto FREEFARE_CLOSE;
        }

        if (info.software.version_major < 1) {
            printf("Found old DESFire card - cannot use this card\n");
            goto FREEFARE_CLOSE;
        }

        /****** Authenticate with master key *******/
        // Default key
        uint8_t default_master_key[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00};

        MifareDESFireKey default_master_key_des;

        default_master_key_des = mifare_desfire_des_key_new_with_version(default_master_key);

        printf("Using as master key: ");
        print_buffer(stdout, default_master_key, 16);
        printf("\n");

        /****** Select default app ******/
        /*result = mifare_desfire_select_application(tag, 0x00);

        if (result < 0) {
            freefare_perror(tag, "Error selecting PICC application");
            goto FREEFARE_CLOSE;
        }*/

        /****** Authenticate with PICC master key ******/
        result = mifare_desfire_authenticate(tag, MDAR_KEY0, default_master_key_des);
        if (result < 0) {
            freefare_perror(tag, "Error authenticating with PICC master key");

            /*printf("\n");
            result = mifare_desfire_authenticate(tag, MDAR_KEY0, picckey_des);

            if (result < 0) {
                freefare_perror(tag, "Error authenticating with new PICC master key also");
                goto FREEFARE_CLOSE;
            }*/
        }
    

        /****** Set Key Settings ******/
        uint8_t picc_settings = MDMK_SETTINGS(1, 1, 1, 1);
        result = mifare_desfire_change_key_settings(tag, picc_settings);

        if (result < 0) {
            freefare_perror(tag, "Error setting new key settings");
            goto FREEFARE_CLOSE;
        }

        /****** Set master key *******/

        result = mifare_desfire_change_key(tag, MDAR_KEY0, picckey_des, default_master_key_des);
        if (result < 0) {
            freefare_perror(tag, "Error setting PICC master key");
            goto FREEFARE_CLOSE;
        }

        /****** Authenticate with new PICC master key ******/
        result = mifare_desfire_authenticate(tag, MDAR_KEY0, picckey_des);
        if (result < 0) {
            freefare_perror(tag, "Error authenticating with new PICC master key");
            goto FREEFARE_CLOSE;
        }


        /***** Create application ******/
        MifareDESFireAID app_aid = mifare_desfire_aid_new(DOOR_APPLICATION_ID);

        uint8_t app_settings = MDAPP_SETTINGS(MDAR_KEY0, 1, 1, 1, 1);

        result = mifare_desfire_create_application(tag, app_aid, app_settings, MDAR_FREE);
        if (result < 0) {
            freefare_perror(tag, "Creating application failed");
            mifare_desfire_format_picc(tag);
            goto FREEFARE_CLOSE;
        }

        /****** Selecting application ******/
        result = mifare_desfire_select_application(tag, app_aid);
        if (result < 0) {
            freefare_perror(tag, "Selecting application failed");
            goto FREEFARE_CLOSE;
        }

        /****** Authenticating with default application master key ******/
        uint8_t default_key[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

        MifareDESFireKey default_app_master_key_des = mifare_desfire_des_key_new(default_key);
        result = mifare_desfire_authenticate(tag, MDAR_KEY0, default_app_master_key_des);
        if (result < 0) {
            freefare_perror(tag, "Authentication with default amk failed");
            goto FREEFARE_CLOSE;
        }

        /****** Set application master key *******/

        result = mifare_desfire_change_key(tag, MDAR_KEY0, fabkey_des, default_app_master_key_des);
        if (result < 0) {
            freefare_perror(tag, "Error setting application master key");
            goto FREEFARE_CLOSE;
        }

        /****** Selecting application ******/
        result = mifare_desfire_select_application(tag, app_aid);
        if (result < 0) {
            freefare_perror(tag, "Selecting application failed");
            goto FREEFARE_CLOSE;
        }

        /****** Authenticating with new application master key ******/
        result = mifare_desfire_authenticate(tag, MDAR_KEY0, fabkey_des);
        if (result < 0) {
            freefare_perror(tag, "Authentication with new amk failed");
            goto FREEFARE_CLOSE;
        }

        /****** Set application key ******/
        result = mifare_desfire_change_key(tag, MDAR_KEY1, rokey_des, NULL);

        if (result < 0) {
            freefare_perror(tag, "Error setting application key (ro)");
            goto FREEFARE_CLOSE;
        }


        /****** Create std file 0  ******/
        result = mifare_desfire_create_std_data_file(tag, 0, MDCM_MACED, MDAR(1,0,0,0), 32);
        if(result < 0) {
            freefare_perror(tag, "create std file 0 failed");
            goto FREEFARE_CLOSE;
        }

        /****** Create backup data file 3  ******/
        result = mifare_desfire_create_backup_data_file(tag, 3, MDCM_PLAIN, MDAR(MDAR_FREE,0,0,0), 32);
        if(result < 0) {
            freefare_perror(tag, "create backup data file 3 failed");
            goto FREEFARE_CLOSE;
        }

        /****** Create std file 2 ******/
        result = mifare_desfire_create_std_data_file(tag, 2, MDCM_MACED, MDAR(1,0,0,0), 192);
        if(result < 0) {
            freefare_perror(tag, "create std data file 2 failed");
            goto FREEFARE_CLOSE;
        }

        /****** Create cyclic record file 1 ******/
        result = mifare_desfire_create_cyclic_record_file(tag, 1, MDCM_PLAIN, MDAR(1,0,0,0), 8, 61);
        if(result < 0) {
            freefare_perror(tag, "create cyclic record data file 1 failed");
            goto FREEFARE_CLOSE;
        }

        /******  Create backup data file 4 ******/
        result = mifare_desfire_create_backup_data_file(tag, 4, MDCM_PLAIN, MDAR(MDAR_FREE,0,0,0), 64);
        if(result < 0) {
            freefare_perror(tag, "create backup data file 4 failed");
            goto FREEFARE_CLOSE;
        }

        /***** Write media ID ******/
        uint8_t filedata[11];
        filedata[0] = 0x04;
        for (int i = 1; i < 11; i++) {
            filedata[i] = 0x00;
        }
        
        for (int i = 0; i < 4; i++) {
           filedata[10-i] = (number_count >> (i * 8)) & 0xFF;
        }

        result = mifare_desfire_write_data(tag, 0, 0, sizeof(filedata), filedata);
        if(result < 0) {
            freefare_perror(tag, "write data to file 0 failed");
            goto FREEFARE_CLOSE;

        }

        printf("Token written with Media ID: %d\n", number_count);
        number_count = number_count + 1;
        sleep(2);

        FREEFARE_CLOSE:
        freefare_free_tag(tag);
        nfc_close(device);
        sleep(1);

    }

    CLOSE:
    freefare_free_tag(tag);
    nfc_close(device);
    exit(_error);
}
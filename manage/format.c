//
// Created by Timo Widdau on 27.10.17.
//

#include <stdlib.h>
#include <nfc/nfc.h>
#include <freefare.h>
#include <gcrypt.h>
#include <unistd.h>
#include <ctype.h>

int NFC_MAX_DEVICES = 1;
uint32_t DOOR_APPLICATION_ID = 0x2305CA;

int generate_key(uint8_t key[16]) {
    gcry_cipher_hd_t des;
    int ret = gcry_cipher_open(&des, GCRY_CIPHER_DES, GCRY_CIPHER_MODE_ECB, 0);
    if (ret) return -1;

    do {
        gcry_randomize(key, 16, GCRY_STRONG_RANDOM);
        ret = gcry_cipher_setkey(des, key, 16);
    } while(ret && gcry_err_code(ret) == GPG_ERR_WEAK_KEY);

    return 0;
}


int print_buffer(FILE *f, uint8_t *b, size_t n) {
    for(int i=0; i < n; i++) {
        if(fprintf(f, "%02X", b[i]) != 2) {
            perror("Write failed");
            return -1;
        }
    }

    return 0;
}

void json_key(const char *name, uint8_t k[16]) {
    printf("   \"%s\" : \"", name);
    print_buffer(stdout, k, 16);
    printf("\"");
}

static int parse_key(uint8_t key[static 16], const char *data) {
	if(!data || strlen(data) != 32)
		return -1;

	for(int i=0; i < 16; i++) {
		char buf[3];
		buf[0] = tolower(data[2*i]);
		buf[1] = tolower(data[2*i+1]);
		buf[2] = 0;

		sscanf(buf, "%hhx", &key[i]);
	}

	return 0;
}

#define LOG_FILE "./deploy_log"
int log_action(char *uid, uint8_t master[16], uint8_t amk[16], uint8_t door[16]) {
    FILE *f;

    f = fopen(LOG_FILE, "a+");
    if(!f) {
        perror("Opening logfile failed");
        return -1;
    }

    setbuf(f, NULL);

    if(fprintf(f, "%s", uid) != 14) {
        fprintf(stderr, "Writing log failed");
        return -1;
    }

    fprintf(f, " ");
    if(print_buffer(f, master, 16)) {
        fprintf(stderr, "Writing log failed");
        return -1;
    }

    fprintf(f, " ");
    if(print_buffer(f, amk, 16)) {
        fprintf(stderr, "Writing log failed");
        return -1;
    }

    fprintf(f, " ");
    if(print_buffer(f, door, 16)) {
        fprintf(stderr, "Writing log failed");
        return -1;
    }
    fprintf(f, "\n");

    if(fflush(f)) {
        perror("Flushing logfile failed");
        return -1;
    }

    int fd = fileno(f);
    if(fd == -1) {
        perror("fileno() failed");
        return -1;
    }

    if(fsync(fd)) {
        perror("fsync() failed");
        return -1;
    }

    if(fclose(f)) {
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
    nfc_init(&context);

    if (context == NULL) {
        printf("Unable to init libnfc (malloc)");
        exit(EXIT_FAILURE);
    }

    device_count = nfc_list_devices(context, devices, 8);
    if (device_count <= 0) {
        printf("No NFC device found.");
        exit(EXIT_FAILURE);
    }

    device = nfc_open(context, devices[0]);
    if (!device) {
        printf("nfc_open() failed");
        exit(EXIT_FAILURE);
    }

    tags = freefare_get_tags(device);
    if (!tags) {
        nfc_close(device);
        printf("Error listing Mifare DESFire tags.");
        exit(EXIT_FAILURE);
    }

    if (!tags[0]) {
        nfc_close(device);
        printf("Error: No tag found.");
        exit(EXIT_FAILURE);
    }

    if (tags[0] && tags[1]) {
        nfc_close(device);
        printf("Error: More than tag found.");
        exit(EXIT_FAILURE);
    }

    tag = tags[0];

    enum freefare_tag_type type = freefare_get_tag_type(tag);
    if (type != MIFARE_DESFIRE) {
        nfc_close(device);
        printf("Error: RFID card is not a Mifare DESFire.");
        _error = EXIT_FAILURE; goto CLOSE;
    }

    result = mifare_desfire_connect(tag);
    if (result < 0) {
        printf("Can't connect to Mifare DESFire target.");
        _error = EXIT_FAILURE; goto CLOSE;
    }

    struct mifare_desfire_version_info info;
    result = mifare_desfire_get_version(tag, &info);
    if (result < 0) {
        printf("Error reading Mifare DESFire Version");
        _error = EXIT_FAILURE;
        goto CLOSE;
    }

    if (info.software.version_major < 1) {
        printf("Found old DESFire card - cannot use this card.");
        _error = EXIT_FAILURE; goto CLOSE;
    }

    char *tag_uid = freefare_get_tag_uid(tag);
    printf("# Card UID: %s\n", tag_uid);


    /****** Authenticate with master key *******/
    // Default key
    uint8_t default_key[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t default_master_key[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    MifareDESFireKey default_master_key_des;

    if (argc > 0) {
        parse_key(default_master_key, argv[1]);
        default_master_key_des = mifare_desfire_3des_key_new(default_master_key);
    } else {
        default_master_key_des = mifare_desfire_des_key_new(default_master_key);
    }
    
    printf("Using as master key: ");
    print_buffer(stdout, default_master_key, 16);
    printf("\n");

    result = mifare_desfire_authenticate(tag, MDAR_KEY0, default_master_key_des);

    if (result < 0) {
        freefare_perror(tag, "Error authenticating with default key");
        _error = EXIT_FAILURE; goto CLOSE;
    }

	result = mifare_desfire_change_key_settings(tag, 0x0F);
	if (result < 0)
		freefare_perror(tag, "ChangeKeySettings failed");


    MifareDESFireAID app_aid = mifare_desfire_aid_new(0x2305CA);
    
	result = mifare_desfire_delete_application(tag, app_aid);
	if (result < 0)
		freefare_perror(tag, "DeleteApplication failed");
    
    uint8_t app_settings = MDAPP_SETTINGS(MDAR_KEY0, 1, 0, 1, 1);

    result = mifare_desfire_create_application(tag, app_aid, app_settings, MDAR_FREE);
    if (result < 0) {
        freefare_perror(tag, "Creating application failed");
        mifare_desfire_format_picc(tag);
        _error = EXIT_FAILURE; goto CLOSE;
    }


    result = mifare_desfire_select_application(tag, app_aid);
    if (result < 0) {
        freefare_perror(tag, "Selecting application failed");
        _error = EXIT_FAILURE; goto CLOSE;
    }

    MifareDESFireKey new_app_key_des = mifare_desfire_des_key_new(default_key);    
    result = mifare_desfire_change_key(tag, MDAR_KEY0, new_app_key_des, new_app_key_des);

    if (result < 0) {
        freefare_perror(tag, "Error setting application key 0");
        _error = EXIT_FAILURE; goto CLOSE;
    }

    result = mifare_desfire_change_key(tag, MDAR_KEY13, new_app_key_des, new_app_key_des);
    if (result < 0) {
        freefare_perror(tag, "Error setting application key 13");
        _error = EXIT_FAILURE; goto CLOSE;
    }
    

result = mifare_desfire_select_application(tag, mifare_desfire_aid_new(0x0));
if (result < 0) {
    freefare_perror(tag, "Selecting application failed #2");
     _error = EXIT_FAILURE; goto CLOSE;
}

result = mifare_desfire_authenticate(tag, MDAR_KEY0, default_master_key_des);

if (result < 0) {
    freefare_perror(tag, "Error authenticating with default key #3");
    _error = EXIT_FAILURE; goto CLOSE;
}


	result = mifare_desfire_format_picc(tag);
	if (result < 0) {
		freefare_perror(tag, "Can't format PICC.");
        _error = EXIT_FAILURE; goto CLOSE;
	}

    mifare_desfire_disconnect(tag);

CLOSE:
    freefare_free_tag(tag);
    nfc_close(device);
    exit(_error);
}
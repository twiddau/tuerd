#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include <nfc/nfc.h>
#include <freefare.h>

#include "util.h"

#include "rfid.h"

#define LOG_SECTION "rfid"
#define NFC_MAX_DEVICES 8
#define KABA_ID 0xF52100

nfc_context *nfc_ctx;
MifareDESFireAID door_aid;

static int parse_key(uint8_t key[static 16], const char *data) {
	if(!data || strlen(data) != 32)
		return -1;

	for(int i=0; i < 16; i++) {
		char buf[3];
		buf[0] = (char) tolower(data[2 * i]);
		buf[1] = (char) tolower(data[2 * i + 1]);
		buf[2] = 0;

		sscanf(buf, "%hhx", &key[i]);
	}

	return 0;
}


nfc_device *rfid_init(void) {
	nfc_init(&nfc_ctx);
	if(!nfc_ctx) {
		log("initializing libnfc failed");
		return NULL;
	}

	door_aid = mifare_desfire_aid_new(0x2305CA);

	nfc_connstring devices[NFC_MAX_DEVICES];
	size_t device_count = nfc_list_devices(nfc_ctx, devices, NFC_MAX_DEVICES);
	if(device_count <= 0) {
		log("no NFC devices found");
		return NULL;
	}

	log("found %u NFC devices:", (int) device_count);
	for(int i = 0; i < (int)device_count; i++)
		log(" - %s", devices[i]);

	int selected_device = -1;
	const char *conf_connstring = getenv("RFID_CONNSTRING");
	if(conf_connstring) {
		for(int i = 0; i < (int)device_count; i++)
			if(strstr(devices[i], conf_connstring)) {
				selected_device = i;
				break;
			}
	} else {
		log("no connection string supplied, using first device");
		selected_device = 0;
	}

	if(selected_device == -1) {
		log("could not find requested device");
		return NULL;
	}

	log("using device %s", devices[selected_device]);

	nfc_device *dev = nfc_open(nfc_ctx, devices[selected_device]);
	if(!dev) {
		log("opening NFC device failed");
		return NULL;
	}

	if(nfc_initiator_init(dev) < 0) {
		nfc_perror(dev, "configuring NFC device as initiator failed");
		return NULL;
	}

	return dev;
}

nfc_target *rfid_poll(nfc_device *dev) {
	static nfc_target target;
	int failcnt = 0;

	while(1) {
		nfc_modulation modulation = {
			.nmt = NMT_ISO14443A,
			.nbr = NBR_106
		};

		int ret = nfc_initiator_poll_target(dev, &modulation, 1, 2, 2, &target);

		// NFC_ECHIP means timeout
		if(ret > 0)
			return &target;

		if(ret != NFC_ECHIP) {
			log("nfc_initiator_poll_target() failed");

			failcnt++;
			if(failcnt >= 6) {
				log("nfc_initiator_poll_target() failed too often, aborting");
				return NULL;
			}

			sleep((unsigned int) (1 << (((failcnt > 4) ? 4 : failcnt) - 1)));
		}
	}
}

static bool rfid_authenticate(FreefareTag tag, struct rfid_key *key) {
	int ret;
	bool result = false;

	ret = mifare_desfire_connect(tag);
	if(ret < 0) {
		log("failed to connect to tag");
		return false;
	}

	ret = mifare_desfire_select_application(tag, door_aid);
	if(ret < 0) {
		log("failed to select application");
		goto out_tag;
	}

	MifareDESFireKey dfkey = mifare_desfire_3des_key_new(key->key);

	ret = mifare_desfire_authenticate(tag, 0xD, dfkey);
	if(ret < 0) {
		log("authentication failed");
		goto out_key;
	}

	if(ret == 0)
		result = true;


	bool provision_dk = true;
	
    MifareDESFireAID *aids = NULL;
    size_t aid_count;

	ret = mifare_desfire_get_application_ids(tag, &aids, &aid_count);
    for (size_t i=0; i<aid_count;i++) {
		if (mifare_desfire_aid_get_aid(aids[1]) == KABA_ID) {
			provision_dk = false;
		}
	}


	if (provision_dk) {
		MifareDESFireKey picc_key = mifare_desfire_3des_key_new(key->picc_key);

        ret = mifare_desfire_select_application(tag, 0x00);
        if(ret < 0) {
            log("select PICC application failed");
            goto out_key;
        }
		log("select picc key");

		ret = mifare_desfire_authenticate(tag, 0, picc_key);
		if(ret < 0) {
			log("authentication with PICC failed");
			goto out_key;
		}
		log("authenticaed with PICC key");
		

		MifareDESFireAID aid = mifare_desfire_aid_new(KABA_ID);

    	uint8_t app_settings = MDAPP_SETTINGS(MDAR_KEY0, 1, 0, 0, 1);
		ret = mifare_desfire_create_application(tag, aid, app_settings, 2);
		if(ret < 0) {
			log("create kaba application failed");
			goto out_app;
		}
        log("kaba: created application");

		ret = mifare_desfire_select_application(tag, aid);
		if(ret < 0) {
			log("select kaba application failed");
			goto out_app;
		}
        log("kaba: application selected");

		const char *fabkey = getenv("FABKEY");
		uint8_t raw_fabkey[16];
		parse_key(raw_fabkey, fabkey);
		MifareDESFireKey mf_fabkey = mifare_desfire_3des_key_new(raw_fabkey);

 		uint8_t default_key[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
		MifareDESFireKey default_master_key_des = mifare_desfire_des_key_new(default_key);			

		ret = mifare_desfire_authenticate(tag, MDAR_KEY0, default_master_key_des);
		if(ret < 0) {
			log("authentication with default AMK failed");
			goto out_key;
		}
		log("kaba: authenticated with default AMK key");


		ret = mifare_desfire_change_key(tag, MDAR_KEY0, mf_fabkey, default_master_key_des);
        if(ret < 0) {
			log("set key 0 in kaba app failed");
			goto out_app;
		}
        log("kaba: key 0 (fab) set");


		ret = mifare_desfire_authenticate(tag, MDAR_KEY0, mf_fabkey);
		if(ret < 0) {
			log("authentication with Fab-Key failed");
			goto out_key;
		}
		log("kaba: authenticated with Fab-Key");
			
		const char *rokey = getenv("ROKEY");
		uint8_t raw_rokey[16];
		parse_key(raw_rokey, rokey);
		MifareDESFireKey mf_rokey = mifare_desfire_3des_key_new(raw_rokey);

		ret = mifare_desfire_change_key(tag, MDAR_KEY1, mf_rokey, default_master_key_des);
		if(ret < 0) {
			log("set key 1 in kaba app failed");
			goto out_app;
		}
        log("kaba: key 1 (ro) set");
		
	
		ret = mifare_desfire_create_std_data_file(     tag,  0, MDCM_MACED, MDAR(1,0,0,0),     32);
		if(ret < 0) {
			log("create std file 0 failed");
			goto out_app;
		}
        log("kaba: created std data file 0");
		
		ret = mifare_desfire_create_backup_data_file(  tag,  3, MDCM_PLAIN, MDAR(MDAR_FREE,0,0,0),     32);
		if(ret < 0) {
			log("create backup data file 3 failed");
			goto out_app;
		}
        log("kaba: created backup data file 3");

		ret = mifare_desfire_create_std_data_file(     tag,  2, MDCM_MACED, MDAR(1,0,0,0),    192);
		if(ret < 0) {
			log("create std data file 2 failed");
			goto out_app;
		}
        log("kaba: created std data file 2");
		
		ret = mifare_desfire_create_cyclic_record_file(tag,  1, MDCM_PLAIN, MDAR(1,0,0,0), 8, 61);
		if(ret < 0) {
			log("create cyclic record data file 1 failed");
			goto out_app;
		}
        log("kaba: created cyclic record data file 1");

		ret = mifare_desfire_create_backup_data_file(  tag,  4, MDCM_PLAIN, MDAR(MDAR_FREE,0,0,0),    64);
		if(ret < 0) {
			log("create backup data file 4 failed");
			goto out_app;
		}
        log("kaba: created backup data file 4");

		char *uid = freefare_get_tag_uid(tag);

		char cid[8];
		strncpy(cid, uid + 2, 8);

		/*uint8_t data[32] = {0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
 		ret = mifare_desfire_write_data(tag, 0, 0, sizeof(data), data);
		if(ret < 0) {
			log("write data to file 0 failed");
			goto out_app;

		}*/
        log("kaba: wrote CID to file 0");
        log("kaba: done");

		out_app:
			free(aid);
	}




out_key:
	mifare_desfire_key_free(dfkey);
out_tag:
	mifare_desfire_disconnect(tag);

	return result;
}

bool rfid_authenticate_any(nfc_device *dev, key_callback_t cb) {
	FreefareTag *tags = freefare_get_tags(dev);
	if(!tags) {
		// FIXME: reset reader?
		log("error listing tags");
		return false;
	}

	for(int i = 0; tags[i]; i++) {
		FreefareTag tag = tags[i];

		if(freefare_get_tag_type(tag) != MIFARE_DESFIRE) {
			log("tag is not a desfire tag");
			continue;
		}

		char *uid = freefare_get_tag_uid(tag);
		debug("got uid %s", uid);

		struct rfid_key key;
		enum rfid_key_cb_result result = cb(uid, &key);
		switch(result) {
			case TAG_UNKNOWN:
				log("no key found in git");
				break;
			case TAG_FORBIDDEN:
				log("tag forbidden by policy");
				break;
			case TAG_ALLOWED:
				debug("tag allowed by policy");
				return rfid_authenticate(tag, &key);
			case KEY_CB_ERROR:
				log("key callback error");
				break;
			default:
				die("unknown key callback result received: %d", result);
		}

		free(uid);
	}

	debug("exhausted all available tags");

	freefare_free_tags(tags);
	return false;
}

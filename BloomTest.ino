
#include "Arduino.h"
#include <WiFi.h>


// BEGIN BF IMPL

#include "mbedtls/md.h"

typedef struct {
	uint32_t k;
	uint32_t n;
	uint32_t m;
	byte *filt;
	byte *salt;
	uint32_t saltsize;
	} bf_t;

bf_t* bf_init(uint32_t k, uint32_t m, uint32_t saltsize, byte *salt, bf_t *bf) {
	if (bf == NULL) {
		bf = (bf_t *)calloc(sizeof(bf_t), 1);
	}
	bf->k = k;
	bf->m = m;
	bf->saltsize = saltsize;
	bf->salt = salt;
	if (bf->salt == NULL && saltsize) {
		byte *slt = (byte *)calloc(saltsize,1);
		bf->salt = slt;
		for (uint32_t i=0; i<saltsize; i++) {
			slt[i] = random(256);
		}
	}
	bf->filt = (byte *)calloc(1<<(m-3),1);
	return bf;
}

bool _bf_check_set(bf_t *bf, byte *data, uint32_t datasize, bool set) {
	uint32_t kset = 0;
	uint32_t need = bf->m >> 3;
	if (bf->m & 7) {
		need++;
	}
	byte hash[32];
	byte offs=32;
	uint32_t seq = 0;
	for (uint32_t i=0 ; i < bf->k ; i++) {
		if ((offs+need) > 32) {
			mbedtls_md_context_t ctx;
			mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
			mbedtls_md_init(&ctx);
			mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 0);
			mbedtls_md_starts(&ctx);
			mbedtls_md_update(&ctx, (const unsigned char *) &seq, 4);
			mbedtls_md_update(&ctx, (const unsigned char *) data, datasize);
			if (bf->saltsize) {
				mbedtls_md_update(&ctx, (const unsigned char *) bf->salt, bf->saltsize);
			}
			mbedtls_md_update(&ctx, (const unsigned char *) &seq, 4);
			mbedtls_md_finish(&ctx, hash);
			mbedtls_md_free(&ctx);
			seq++;
			offs = 0;
		}

		uint32_t val = 0;
		uint32_t want = bf->m;
		while (want > 0) {
			byte b = hash[offs++];
			if (want >= 8) {
				val = (val << 8) + b;
				want -= 8;
			} else {
				val = (val << want) + (b >> (8-want));
				want = 0;
			}
		}

		uint32_t fo = val >> 3;
		byte fm = 1 << (val & 7);

		byte ov = bf->filt[fo];
		if ((ov & fm) == 0) {
			if (set) {
				bf->filt[fo] = ov | fm;
				kset++;
			} else {
				return false;
			}
		}
	} 

	if (set && (kset > 0)) {
		bf->n++;
		return false;
	}
	return true;
}

#define bf_check_add(bf, data, datasize) _bf_check_set(bf,data,datasize,true)
#define bf_check(bf, data, datasize) _bf_check_set(bf,data,datasize,false)

// END IMPL


#define TEST_HAVE 5000
#define TEST_LEN 4+random(200)

#define TEST_BUF 65536

#define TEST_k 16
#define TEST_m 16

#define TEST_saltsize 32

#define NO_TEST_printhex

void setup()
{
  Serial.begin(115200);

  // start wifi to get better random numbers
  const char *AP = "BFTEST";
  IPAddress apIP(1,2,3,4);
  WiFi.mode(WIFI_AP);
  WiFi.softAP(AP);
  WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
  Serial.println("AP UP");


  // summon bloomfilter
  bf_t *bf1 = bf_init(TEST_k, TEST_m, TEST_saltsize, NULL, NULL);
  Serial.println("BLOOM1: k:" + String(TEST_k) + " m:" + String(TEST_m) + " saltsize:" + String(TEST_saltsize));
  bf_t *bf2 = bf_init(TEST_k, TEST_m, TEST_saltsize, NULL, NULL);
  Serial.println("BLOOM2: k:" + String(TEST_k) + " m:" + String(TEST_m) + " saltsize:" + String(TEST_saltsize));

  // summon random buffer
  byte *rand = (byte *)malloc(TEST_BUF);
  Serial.print("RAND:" + String(TEST_BUF) + " ");
  for (int i = 0; i<TEST_BUF; i++) {
	byte v = random(256);
	rand[i] = v;
#ifdef TEST_printhex
	if (v < 16) {
		Serial.print("0");
	}
	Serial.print(String(v,HEX));
#endif
  }
  Serial.println();

  // summon random haves as size + offset inside rand buffer 
  uint32_t *haveo = (uint32_t *)calloc(TEST_HAVE,sizeof(uint32_t));
  byte     *haves = (byte     *)calloc(TEST_HAVE,sizeof(byte));
  for (int i = 0; i<TEST_HAVE; i++) {
	byte sz = TEST_LEN;
        uint32_t so = random(TEST_BUF-sz);
	haves[i] = sz;
	haveo[i] = so;
	Serial.print("have:" + String(i) + " sz:" + String(sz) + " offs:" + String(so));
	if (bf_check_add(bf1,(byte *)&rand[so],sz)) {
		Serial.print(" have");
	} else {
		Serial.print(" dont");
	}
	if (bf_check_add(bf2,(byte *)&rand[so],sz)) {
		Serial.print("have");
	} else {
		Serial.print("dont");
	}
	Serial.println("");
  }

  // check randoms (and knowns)
  int i = 0;
  uint32_t buf[64];
  uint32_t lastmil = 0;
  while (1) {
	// check haves every 64k random checks
	if (!(i & 0xffff)) {
		if (lastmil > 0) {
			Serial.println("MILLIS: " + String(millis()-lastmil));
		}
		for (int j = 0; j<TEST_HAVE; j++) {
			Serial.print("rehave:" + String(i) + ":" + String(j));
			if (bf_check(bf1,(byte *)&rand[haveo[j]],haves[j])) {
				Serial.print(" have");
			} else {
				Serial.print(" dont");
			}
			if (bf_check(bf2,(byte *)&rand[haveo[j]],haves[j])) {
				Serial.print("have");
			} else {
				Serial.print("dont");
			}
			Serial.println("");
  		}
		lastmil=millis();
	}


	byte sz = TEST_LEN;
	Serial.print("dont:" + String(i++) + " sz:" + String(sz) + " data:");
	for (int j=0; j<((sz>>2)+1); j++) {
		buf[j] = esp_random();
	}

	if (bf_check(bf1,(byte *)buf,sz)) {
		Serial.print(" have");
	} else {
		Serial.print(" dont");
	}
	if (bf_check(bf2,(byte *)buf,sz)) {
		Serial.print("have");
	} else {
		Serial.print("dont");
	}
	Serial.println("");
  }
}

void loop()
{
}


// Copyright (C) 2022, 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

#include <monocypher/monocypher-ed25519.h>

#include <mbedtls/memory_buffer_alloc.h>
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/bignum.h"
#include "mbedtls/rsa.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <tkey/assert.h>
#include <tkey/led.h>
#include <tkey/proto.h>
#include <tkey/qemu_debug.h>
#include <tkey/tk1_mem.h>
#include <tkey/touch.h>

#include "app_proto.h"

// clang-format off
static volatile uint32_t *cdi           = (volatile uint32_t *) TK1_MMIO_TK1_CDI_FIRST;
static volatile uint32_t *cpu_mon_ctrl  = (volatile uint32_t *) TK1_MMIO_TK1_CPU_MON_CTRL;
static volatile uint32_t *cpu_mon_first = (volatile uint32_t *) TK1_MMIO_TK1_CPU_MON_FIRST;
static volatile uint32_t *cpu_mon_last  = (volatile uint32_t *) TK1_MMIO_TK1_CPU_MON_LAST;
static volatile uint32_t *app_addr      = (volatile uint32_t *) TK1_MMIO_TK1_APP_ADDR;
static volatile uint32_t *app_size      = (volatile uint32_t *) TK1_MMIO_TK1_APP_SIZE;

// clang-format on

// Touch timeout in seconds
#define TOUCH_TIMEOUT 30
#define MAX_SIGN_SIZE 4096

#define KEY_SIZE 2048
#define KEY_SIZE_BYTES 256 // KEY_SIZE/8
#define EXPONENT 65537
#define RSA_PEM_FILE_SIZE 1676

const uint8_t app_name0[4] = "tk1 ";
const uint8_t app_name1[4] = "sign";
const uint32_t app_version = 0x00000003;

enum state {
	STATE_STARTED,
	STATE_LOADING,
	STATE_SIGNING,
	STATE_FAILED,
	STATE_RSA_KEY_ENCRYPTING,
	STATE_DECRYPT_KEY,
	STATE_PARSE_RSA_KEY
};

// Context for the loading of a message
struct context {
	uint8_t secret_key[64]; // Private key. Used to encrypt RSA PEM FILE
	uint8_t pubkey[32];
	uint8_t message[MAX_SIGN_SIZE];
	uint32_t left; // Bytes left to receive
	uint32_t message_size;
	uint16_t msg_idx; // Where we are currently loading a message
	uint8_t initialized;
	unsigned char key[RSA_PEM_FILE_SIZE]; // RSA key
	mbedtls_pk_context pk;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;

};

// Incoming packet from client
struct packet {
	struct frame_header hdr;      // Framing Protocol header
	uint8_t cmd[CMDLEN_MAXBYTES]; // Application level protocol
};

static enum state started_commands(enum state state, struct context *ctx,
				   struct packet pkt);
static enum state loading_commands(enum state state, struct context *ctx,
				   struct packet pkt);
static enum state signing_commands(enum state state, struct context *ctx,
				   struct packet pkt);
static int read_command(struct frame_header *hdr, uint8_t *cmd);
static void wipe_context(struct context *ctx);

static void wipe_context(struct context *ctx)
{
	crypto_wipe(ctx->message, MAX_SIGN_SIZE);
	ctx->left = 0;
	ctx->message_size = 0;
	ctx->msg_idx = 0;
}

void send_data(struct packet* pkt, const uint8_t* buf, size_t total_size, int rsp_type)
{
	int left = total_size;
	int sent = 0;
	while(left > 0)
	{
		uint8_t rsp[CMDLEN_MAXBYTES] = {0}; // Response
		int nbytes = left > CMDLEN_MAXBYTES-1 ? CMDLEN_MAXBYTES-1 : left;
		memcpy_s(rsp, CMDLEN_MAXBYTES, buf+sent, nbytes);
		sent += nbytes;
		left -= nbytes;
		appreply(pkt->hdr, rsp_type, rsp);
	}
}

int generate_seed(struct context * ctx)
{
	mbedtls_ctr_drbg_init(&ctx->ctr_drbg);
	mbedtls_entropy_init(&ctx->entropy);
	int ret = 0;
	if ((ret = mbedtls_ctr_drbg_seed(&ctx->ctr_drbg, mbedtls_entropy_func, &ctx->entropy,
									(uint8_t *)cdi,
									32)) != 0)
	{
		qemu_puts("failed mbedtls_ctr_drbg_seed: ");
		qemu_putinthex(ret);
		qemu_lf();
		mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
		mbedtls_entropy_free(&ctx->entropy);
	}
	return ret;
}

void decrypt_key(struct context * ctx)
{
	crypto_chacha20_x(ctx->key,
					  ctx->key,
                      RSA_PEM_FILE_SIZE,
                      ctx->secret_key,
                      cdi,
                      0);
}

int parse_key(struct context * ctx)
{
	ctx->initialized = 1;
	mbedtls_pk_init(&ctx->pk);
	int ret = generate_seed(ctx);
	if (ret != 0) {
		qemu_puts("generate_seed failed ");
		qemu_putinthex(ret);
		qemu_lf();
		return 1;
	}

	ret = mbedtls_pk_parse_key(&ctx->pk, ctx->key, RSA_PEM_FILE_SIZE, NULL, 0, mbedtls_ctr_drbg_random, &ctx->ctr_drbg);
	 if (ret != 0) {
		qemu_puts("mbedtls_pk_parse_key ");
		qemu_putinthex(ret);
		qemu_lf();
		return 1;
	 }

	mbedtls_rsa_context *const rsa_ctx = mbedtls_pk_rsa(ctx->pk);
    if ((ret = mbedtls_rsa_check_pubkey(rsa_ctx)) != 0) {
		qemu_puts("mbedtls_rsa_check_pubkey ");
		qemu_putinthex(ret);
		qemu_lf();
        return 1;
    }

    if ((ret = mbedtls_rsa_check_privkey(rsa_ctx)) != 0) {
		qemu_puts("mbedtls_rsa_check_privkey ");
		qemu_putinthex(ret);
		qemu_lf();
        return 1;
    }
	crypto_wipe(ctx->key, sizeof(ctx->key));

	return 0;
}

// started_commands() allows only these commands:
//
// - CMD_FW_PROBE
// - CMD_GET_NAMEVERSION
// - CMD_GET_FIRMWARE_HASH
// - CMD_GET_PUBKEY
// - CMD_SET_SIZE
//
// Anything else sent leads to state 'failed'.
//
// Arguments: the current state, the context and the incoming command.
// Returns: The new state.
static enum state started_commands(enum state state, struct context *ctx,
				   struct packet pkt)
{
	uint8_t rsp[CMDLEN_MAXBYTES] = {0}; // Response
	size_t rsp_left =
	    CMDLEN_MAXBYTES; // How many bytes left in response buf

	// Smallest possible payload length (cmd) is 1 byte.
	switch (pkt.cmd[0]) {
	case CMD_FW_PROBE:
		// Firmware probe. Allowed in this protocol state.
		// State unchanged.
		break;

	case CMD_GET_NAMEVERSION:
		qemu_puts("CMD_GET_NAMEVERSION\n");
		if (pkt.hdr.len != 1) {
			// Bad length
			state = STATE_FAILED;
			break;
		}

		memcpy_s(rsp, rsp_left, app_name0, sizeof(app_name0));
		rsp_left -= sizeof(app_name0);

		memcpy_s(&rsp[4], rsp_left, app_name1, sizeof(app_name1));
		rsp_left -= sizeof(app_name1);

		memcpy_s(&rsp[8], rsp_left, &app_version, sizeof(app_version));

		appreply(pkt.hdr, RSP_GET_NAMEVERSION, rsp);

		// state unchanged
		break;

	case CMD_GET_FIRMWARE_HASH: {
		uint32_t fw_len = 0;

		qemu_puts("APP_CMD_GET_FIRMWARE_HASH\n");
		if (pkt.hdr.len != 32) {
			rsp[0] = STATUS_BAD;
			appreply(pkt.hdr, RSP_GET_FIRMWARE_HASH, rsp);

			state = STATE_FAILED;
			break;
		}

		fw_len = pkt.cmd[1] + (pkt.cmd[2] << 8) + (pkt.cmd[3] << 16) +
			 (pkt.cmd[4] << 24);

		if (fw_len == 0 || fw_len > 8192) {
			qemu_puts("FW size must be > 0 and <= 8192\n");
			rsp[0] = STATUS_BAD;
			appreply(pkt.hdr, RSP_GET_FIRMWARE_HASH, rsp);

			state = STATE_FAILED;
			break;
		}

		rsp[0] = STATUS_OK;
		crypto_sha512(&rsp[1], (void *)TK1_ROM_BASE, fw_len);
		appreply(pkt.hdr, RSP_GET_FIRMWARE_HASH, rsp);

		// state unchanged
		break;
	}

	case CMD_GET_PUBKEY: {
		qemu_puts("CMD_GET_PUBKEY\n");
		if (pkt.hdr.len != 1) {
			// Bad length
			state = STATE_FAILED;
			break;
		}

		int ret =0;

		uint8_t Nbuf[KEY_SIZE_BYTES] = {0};
		mbedtls_rsa_context *const rsa_ctx = mbedtls_pk_rsa(ctx->pk);
		if (rsa_ctx == NULL) {
			qemu_puts("failed rsa_ctx\n");
			state = STATE_FAILED;
			break;
		}
		if((ret = mbedtls_mpi_write_binary(&rsa_ctx->private_N, Nbuf, KEY_SIZE_BYTES)) != 0){
			qemu_puts("failed mbedtls_mpi_write_binary_le: ");
			qemu_putinthex(ret);
			qemu_lf();
			break;
		}

		send_data(&pkt, Nbuf, KEY_SIZE_BYTES, RSP_GET_PUBKEY);
		// state unchanged
		break;
	}
	case CMD_SET_SIZE: {
		uint32_t local_message_size = 0;

		qemu_puts("CMD_SET_SIZE\n");
		// Bad length
		if (pkt.hdr.len != 32) {
			rsp[0] = STATUS_BAD;
			appreply(pkt.hdr, RSP_SET_SIZE, rsp);

			state = STATE_FAILED;
			break;
		}

		// cmd[1..4] contains the size.
		local_message_size = pkt.cmd[1] + (pkt.cmd[2] << 8) +
				     (pkt.cmd[3] << 16) + (pkt.cmd[4] << 24);

		if (local_message_size == 0 ||
		    local_message_size > MAX_SIGN_SIZE) {
			qemu_puts("Message size not within range!\n");
			rsp[0] = STATUS_BAD;
			appreply(pkt.hdr, RSP_SET_SIZE, rsp);

			state = STATE_FAILED;
			break;
		}

		// Set the real message size used later and reset
		// where we load the data
		ctx->message_size = local_message_size;
		ctx->left = ctx->message_size;
		ctx->msg_idx = 0;

		rsp[0] = STATUS_OK;
		appreply(pkt.hdr, RSP_SET_SIZE, rsp);
		state = STATE_LOADING;
		break;
	}
	case CMD_IS_KEY_LOADED:
	{
		rsp[0] = ctx->initialized;
		appreply(pkt.hdr, RSP_IS_KEY_LOADED, rsp);
		// state unchanged
		break;
	}

	default:
		qemu_puts("Got unknown initial command: 0x");
		qemu_puthex(pkt.cmd[0]);
		qemu_lf();

		state = STATE_FAILED;
		break;
	}

	return state;
}

// loading_commands() allows only these commands:
//
// - CMD_LOAD_DATA
//
// Anything else sent leads to state 'failed'.
//
// Arguments: the current state, the context and the incoming command.
// Returns: The new state.
static enum state loading_commands(enum state state, struct context *ctx,
				   struct packet pkt)
{
	uint8_t rsp[CMDLEN_MAXBYTES] = {0}; // Response
	int nbytes = 0;			    // Bytes to write to memory

	switch (pkt.cmd[0]) {
	case CMD_LOAD_DATA: {
		qemu_puts("CMD_LOAD_DATA\n");

		// Bad length
		if (pkt.hdr.len != CMDLEN_MAXBYTES) {
			rsp[0] = STATUS_BAD;
			appreply(pkt.hdr, RSP_LOAD_DATA, rsp);

			state = STATE_FAILED;
			break;
		}

		if (ctx->left > CMDLEN_MAXBYTES - 1) {
			nbytes = CMDLEN_MAXBYTES - 1;
		} else {
			nbytes = ctx->left;
		}

		memcpy_s(&ctx->message[ctx->msg_idx],
			 MAX_SIGN_SIZE - ctx->msg_idx, pkt.cmd + 1, nbytes);

		ctx->msg_idx += nbytes;
		ctx->left -= nbytes;

		rsp[0] = STATUS_OK;
		appreply(pkt.hdr, RSP_LOAD_DATA, rsp);

		if (ctx->left == 0) {
			state = STATE_SIGNING;
			break;
		}

		// state unchanged
		break;
	}
	case CMD_LOAD_KEY:
	// fallthrough
	case CMD_LOAD_ENC_KEY: {
		int nbytes = 0;			    // Bytes to write to memory
		qemu_puts("CMD_LOAD_KEY\n");

		// Bad length
		if (pkt.hdr.len != CMDLEN_MAXBYTES) {
			rsp[0] = STATUS_BAD;
			appreply(pkt.hdr, RSP_LOAD_DATA, rsp);

			state = STATE_FAILED;
			break;
		}

		if (ctx->left > CMDLEN_MAXBYTES - 1) {
			nbytes = CMDLEN_MAXBYTES - 1;
		} else {
			nbytes = ctx->left;
		}

		memcpy_s(&ctx->key[ctx->msg_idx],
			 RSA_PEM_FILE_SIZE - ctx->msg_idx, pkt.cmd + 1, nbytes);

		ctx->msg_idx += nbytes;
		ctx->left -= nbytes;


		rsp[0] = STATUS_OK;
		appreply(pkt.hdr, RSP_LOAD_DATA, rsp);
		if (ctx->left == 0) {
			ctx->msg_idx = 0;
			ctx->message_size = 0;
			state = pkt.cmd[0] == CMD_LOAD_ENC_KEY ? STATE_DECRYPT_KEY : STATE_RSA_KEY_ENCRYPTING;
			
		}

		// state unchanged
		break;
	}

	default:
		qemu_puts("Got unknown loading command: 0x");
		qemu_puthex(pkt.cmd[0]);
		qemu_lf();

		state = STATE_FAILED;
		break;
	}

	return state;
}

// signing_commands() allows only these commands:
//
// - CMD_GET_SIG
//
// Anything else sent leads to state 'failed'.
//
// Arguments: the current state, the context, the incoming command
// packet, and the secret key.
//
// Returns: The new state.
static enum state signing_commands(enum state state, struct context *ctx,
				   struct packet pkt)
{
	uint8_t rsp[CMDLEN_MAXBYTES] = {0};
	uint8_t signature[KEY_SIZE_BYTES] = {0};
	bool touched = true;

	switch (pkt.cmd[0]) {
	case CMD_GET_SIG:
	{

		qemu_puts("CMD_GET_SIG\n");
		if (pkt.hdr.len != 1) {
			// Bad length
			qemu_puts("Bad length\n");
			state = STATE_FAILED;
			break;
		}

#ifndef TKEY_SIGNER_APP_NO_TOUCH
		touched = touch_wait(LED_GREEN, TOUCH_TIMEOUT);
#endif
		if (!touched) {
			rsp[0] = STATUS_BAD;
			appreply(pkt.hdr, RSP_GET_SIG, rsp);

			state = STATE_STARTED;
			break;
		}

		qemu_puts("Touched, now let's sign\n");

		// All loaded, device touched, let's sign the message
		int ret = 0;
		mbedtls_md_context_t md_ctx;
		mbedtls_md_init(&md_ctx);
		const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
		if ((ret = mbedtls_md_setup(&md_ctx, md_info, 0)) != 0) {
			state = STATE_FAILED;
			qemu_puts("mbedtls_md_setup returned -0x");
			qemu_puthex(ret);
			break;
		}
		if ((ret = mbedtls_md_starts(&md_ctx)) != 0) {
			state = STATE_FAILED;
			qemu_puts("mbedtls_md_starts returned -0x");
			qemu_puthex(ret);
			break;
		}
		if ((ret = mbedtls_md_update(&md_ctx, ctx->message, ctx->message_size)) != 0) {
			state = STATE_FAILED;
			qemu_puts("mbedtls_md_update returned -0x");
			qemu_puthex(ret);
			break;
		}

		unsigned char hash[64];
		if ((ret = mbedtls_md_finish(&md_ctx, hash)) != 0) {
			state = STATE_FAILED;
			qemu_puts("mbedtls_md_finish returned -0x");
			qemu_puthex(ret);
			qemu_lf();
			break;
		}

		mbedtls_md_free(&md_ctx);
		size_t olen = 0;
		if ((ret = mbedtls_pk_sign(&ctx->pk, MBEDTLS_MD_SHA512, hash, 64,
								signature, sizeof(signature), &olen,
								mbedtls_ctr_drbg_random, &ctx->ctr_drbg)) != 0) {
			qemu_puts("failed mbedtls_pk_sign: ");
			qemu_putinthex(ret);
			qemu_lf();
			state = STATE_FAILED;
			break;
		}

		assert(olen == 256);

		qemu_puts("Sending signature!\n");
		send_data(&pkt, signature, KEY_SIZE_BYTES, RSP_GET_SIG);
		// Forget signature and most of context
		crypto_wipe(signature, sizeof(signature));
		crypto_wipe(hash, sizeof(hash));
		wipe_context(ctx);
		state = STATE_STARTED;

		break;
	 }

	default:
		qemu_puts("Got unknown signing command: 0x");
		qemu_puthex(pkt.cmd[0]);
		qemu_lf();

		state = STATE_FAILED;
		break;
	}

	return state;
}

// encrypting_commands() allows only these commands:
//
// - CMD_ENCRYPT_KEY
//
// Anything else sent leads to state 'failed'.
//
// Arguments: the current state, the context, the incoming command
// packet, and the secret key.
//
// Returns: The new state.
static enum state encrypting_commands(enum state state, struct context *ctx,
				   struct packet pkt)
{
	switch (pkt.cmd[0]) {
	 case CMD_ENCRYPT_KEY:
	 {
		qemu_puts("CMD_ENCRYPT_KEY!\n");
		unsigned char encrypted_key[RSA_PEM_FILE_SIZE] = {0};
		crypto_chacha20_x(encrypted_key,
                          ctx->key,
                          RSA_PEM_FILE_SIZE,
                          ctx->secret_key,
                          cdi,
                          0);
		send_data(&pkt, encrypted_key, RSA_PEM_FILE_SIZE, RSP_ENCRYPT_KEY);
		crypto_wipe(encrypted_key, sizeof(encrypted_key));
		state = STATE_PARSE_RSA_KEY;
		break;
	 }

	default:
		qemu_puts("Got unknown encrypting command: 0x");
		qemu_puthex(pkt.cmd[0]);
		qemu_lf();

		state = STATE_FAILED;
		break;
	}

	return state;
}

// encrypting_commands() allows only these commands:
//
// - CMD_DECRYPT_KEY
//
// Anything else sent leads to state 'failed'.
//
// Arguments: the current state, the context, the incoming command
// packet, and the secret key.
//
// Returns: The new state.
static enum state decrypt_commands(enum state state, struct context *ctx,
				   struct packet pkt)
{
	uint8_t rsp[CMDLEN_MAXBYTES] = {0};
	switch (pkt.cmd[0]) {
	 case CMD_DECRYPT_KEY:
	 {
		qemu_puts("CMD_DECRYPT_KEY!\n");
		decrypt_key(ctx);
		rsp[0] = STATUS_OK;
		appreply(pkt.hdr, RSP_DECRYPT_KEY, rsp);
		state = STATE_PARSE_RSA_KEY;
		break;
	 }

	default:
		qemu_puts("Got unknown decrypt command: 0x");
		qemu_puthex(pkt.cmd[0]);
		qemu_lf();

		state = STATE_FAILED;
		break;
	}

	return state;
}

// encrypting_commands() allows only these commands:
//
// - CMD_PARSE_KEY
//
// Anything else sent leads to state 'failed'.
//
// Arguments: the current state, the context, the incoming command
// packet, and the secret key.
//
// Returns: The new state.
static enum state parsing_commands(enum state state, struct context *ctx,
				   struct packet pkt)
{
	uint8_t rsp[CMDLEN_MAXBYTES] = {0};
	switch (pkt.cmd[0]) {
	 case CMD_PARSE_KEY:
	 {
		qemu_puts("CMD_PARSE_KEY!\n");
		uint8_t res = parse_key(ctx);
		rsp[0] = res == 0 ? STATUS_OK : STATUS_BAD;
		appreply(pkt.hdr, RSP_PARSE_KEY, rsp);
		state = res == 0 ? STATE_STARTED : STATE_FAILED;
		break;
	 }

	default:
		qemu_puts("Got unknown parsing command: 0x");
		qemu_puthex(pkt.cmd[0]);
		qemu_lf();

		state = STATE_FAILED;
		break;
	}

	return state;
}

// read_command takes a frame header and a command to fill in after
// parsing. It returns 0 on success.
static int read_command(struct frame_header *hdr, uint8_t *cmd)
{
	uint8_t in = 0;

	memset(hdr, 0, sizeof(struct frame_header));
	memset(cmd, 0, CMDLEN_MAXBYTES);

	in = readbyte();
	if (parseframe(in, hdr) == -1) {
		qemu_puts("Couldn't parse header\n");
		return -1;
	}

	// Now we know the size of the cmd frame, read it all
	if (read(cmd, CMDLEN_MAXBYTES, hdr->len) != 0) {
		qemu_puts("read: buffer overrun\n");
		return -1;
	}

	// Well-behaved apps are supposed to check for a client
	// attempting to probe for firmware. In that case destination
	// is firmware and we just reply NOK.
	if (hdr->endpoint == DST_FW) {
		appreply_nok(*hdr);
		qemu_puts("Responded NOK to message meant for fw\n");
		cmd[0] = CMD_FW_PROBE;
		return 0;
	}

	// Is it for us?
	if (hdr->endpoint != DST_SW) {
		qemu_puts("Message not meant for app. endpoint was 0x");
		qemu_puthex(hdr->endpoint);
		qemu_lf();

		return -1;
	}

	return 0;
}

int main(void)
{
	#ifndef MBEDTLS_MEMORY_BUFFER_ALLOC_C
	assert(1==2);
	#endif
	unsigned char memory_buf[15000];
	mbedtls_memory_buffer_alloc_init( memory_buf, sizeof(memory_buf) );
	struct context ctx = {0};
	enum state state = STATE_STARTED;
	struct packet pkt = {0};

	// Use Execution Monitor on RAM after app
	*cpu_mon_first = *app_addr + *app_size;
	*cpu_mon_last = TK1_RAM_BASE + TK1_RAM_SIZE;
	*cpu_mon_ctrl = 1;

	// Generate a public key from CDI
	crypto_ed25519_key_pair(ctx.secret_key, ctx.pubkey, (uint8_t *)cdi);

	led_set(LED_BLUE);

	for (;;) {
		qemu_puts("parser state: ");
		qemu_putinthex(state);
		qemu_lf();

		if (read_command(&pkt.hdr, pkt.cmd) != 0) {
			state = STATE_FAILED;
		}

		switch (state) {
		case STATE_STARTED:
			state = started_commands(state, &ctx, pkt);
			break;

		case STATE_LOADING:
			state = loading_commands(state, &ctx, pkt);
			break;

		case STATE_RSA_KEY_ENCRYPTING:
			state = encrypting_commands(state, &ctx, pkt);
			break;
		
		case STATE_DECRYPT_KEY:
			state = decrypt_commands(state, &ctx, pkt);
			break;

		case STATE_PARSE_RSA_KEY:
			state = parsing_commands(state, &ctx, pkt);
			break;

		case STATE_SIGNING:
			state = signing_commands(state, &ctx, pkt);
			break;

		case STATE_FAILED:
			// fallthrough

		default:
			qemu_puts("parser state 0x");
			qemu_puthex(state);
			qemu_lf();
			assert(1 == 2);
			break; // Not reached
		}
	}
	#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
	#if defined(MBEDTLS_MEMORY_DEBUG)
		mbedtls_memory_buffer_alloc_status();
	#endif
		mbedtls_memory_buffer_alloc_free();
	#endif  /* MBEDTLS_MEMORY_BUFFER_ALLOC_C */
}

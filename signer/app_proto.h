// Copyright (C) 2022 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

#ifndef APP_PROTO_H
#define APP_PROTO_H

#include <tkey/lib.h>
#include <tkey/proto.h>

// clang-format off
enum appcmd {
	CMD_GET_PUBKEY      = 0x01,
	RSP_GET_PUBKEY      = 0x02,
	CMD_SET_SIZE        = 0x03,
	RSP_SET_SIZE        = 0x04,
	CMD_LOAD_DATA       = 0x05,
	RSP_LOAD_DATA       = 0x06,
	CMD_GET_SIG         = 0x07,
	RSP_GET_SIG         = 0x08,
	CMD_GET_NAMEVERSION = 0x09,
	RSP_GET_NAMEVERSION = 0x0a,
	CMD_GET_FIRMWARE_HASH = 0x0b,
	RSP_GET_FIRMWARE_HASH = 0x0c,

	CMD_LOAD_KEY = 0x0d,
	CMD_ENCRYPT_KEY = 0x0e,
	RSP_ENCRYPT_KEY = 0x0f,
	CMD_LOAD_ENC_KEY = 0x10,
	CMD_IS_KEY_LOADED = 0x11,
	RSP_IS_KEY_LOADED = 0x12,

	CMD_DECRYPT_KEY = 0x13,
	RSP_DECRYPT_KEY = 0x14,
	CMD_PARSE_KEY = 0x15,
	RSP_PARSE_KEY = 0x16,

	CMD_FW_PROBE	    = 0xff,
};
// clang-format on

void appreply_nok(struct frame_header hdr);
void appreply(struct frame_header hdr, enum appcmd rspcode, void *buf);

#endif

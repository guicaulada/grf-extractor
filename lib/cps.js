// CPS (cps.dll / Fury.dll) decryption support
// Extracts the RC4 S-box from a cps.dll and provides decryption for GRF entries

var fs = require('fs')

// Load encryption key from a cps.dll file and build the RC4 S-box
function loadKey(dllPath) {
	var dll = fs.readFileSync(dllPath)

	// Search for UTF-16LE L"NUMBER" marker
	var pattern = [0x4E, 0x00, 0x55, 0x00, 0x4D, 0x00, 0x42, 0x00, 0x45, 0x00, 0x52, 0x00]
	var offset = -1

	for (var i = 0; i < dll.length - pattern.length; i++) {
		var match = true
		for (var j = 0; j < pattern.length; j++) {
			if (dll[i + j] !== pattern[j]) { match = false; break }
		}
		if (match) { offset = i; break }
	}

	if (offset === -1) {
		throw new Error('CPS: Could not find encryption key in ' + dllPath)
	}

	// Key is after L"NUMBER\0" (14 bytes) + 4 byte header
	var keyStart = offset + 14 + 4
	var key = dll.slice(keyStart, keyStart + 260)

	if (key.length < 260) {
		throw new Error('CPS: Not enough key data in ' + dllPath)
	}

	// Build S-box using the DLL's key scheduling algorithm
	var a = (key[3] << 24) | (key[2] << 16) | (key[1] << 8) | key[0]
	var sbox = new Uint8Array(256)
	for (var i = 0; i < 256; i++) {
		sbox[i] = ((a & 0xFF) ^ key[i + 4]) & 0xFF
		a = Math.imul(a, 0x2F)
	}

	return sbox
}

// RC4 decrypt a buffer in-place using the S-box
// initialI is typically the entry's real_size (decompressed size)
function decrypt(buffer, sbox, initialI) {
	var S = new Uint8Array(sbox) // working copy
	var i = initialI & 0xFF
	var j = 0

	for (var k = 0; k < buffer.length; k++) {
		i = (i + 1) & 0xFF
		j = (j + S[i]) & 0xFF
		var tmp = S[i]; S[i] = S[j]; S[j] = tmp
		buffer[k] ^= S[(S[i] + S[j]) & 0xFF]
	}

	return buffer
}

module.exports = {
	loadKey: loadKey,
	decrypt: decrypt
}

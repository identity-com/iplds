const crypto = require('@peculiar/webcrypto');

global.crypto = new crypto.Crypto();

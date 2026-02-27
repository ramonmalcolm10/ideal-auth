#!/usr/bin/env node
import { randomBytes } from 'node:crypto';

const command = process.argv[2];

switch (command) {
  case 'secret':
    console.log(`IDEAL_AUTH_SECRET=${randomBytes(32).toString('base64url')}`);
    break;
  case 'encryption-key':
    console.log(`ENCRYPTION_KEY=${randomBytes(32).toString('hex')}`);
    break;
  default:
    console.log('Usage: ideal-auth <command>\n');
    console.log('Commands:');
    console.log('  secret          Generate an IDEAL_AUTH_SECRET for your .env file');
    console.log('  encryption-key  Generate an ENCRYPTION_KEY for encrypting data at rest');
    break;
}

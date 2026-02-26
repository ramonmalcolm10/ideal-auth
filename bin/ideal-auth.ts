#!/usr/bin/env node
import { randomBytes } from 'node:crypto';

const command = process.argv[2];

switch (command) {
  case 'secret':
    console.log(`IDEAL_AUTH_SECRET=${randomBytes(32).toString('base64url')}`);
    break;
  default:
    console.log('Usage: ideal-auth <command>\n');
    console.log('Commands:');
    console.log('  secret    Generate an IDEAL_AUTH_SECRET for your .env file');
    break;
}

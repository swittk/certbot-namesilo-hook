#!/usr/bin/env node
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const dns_1 = require("dns");
const tldts = __importStar(require("tldts"));
const node_fetch_1 = __importDefault(require("node-fetch"));
const xml2js_1 = __importDefault(require("xml2js"));
const os = __importStar(require("os"));
const fs_1 = require("fs");
const readline = __importStar(require("readline"));
/*
Reference of variables for certbot hooks : https://certbot.eff.org/docs/using.html#hooks
CERTBOT_DOMAIN: The domain being authenticated
CERTBOT_VALIDATION: The validation string
CERTBOT_TOKEN: Resource name part of the HTTP-01 challenge (HTTP-01 only)
CERTBOT_REMAINING_CHALLENGES: Number of challenges remaining after the current challenge
CERTBOT_ALL_DOMAINS: A comma-separated list of all domains challenged for the current certificate
*/
/**
 * The main authHook to be called.
 */
async function authHook(nameSilo_key, certdomain, validationStr, remainingChallenges, allDomains, cache_directory) {
    await fs_1.promises.mkdir(cache_directory, { recursive: true });
    const { domain, subdomain } = tldts.parse(certdomain);
    if (!domain)
        throw 'InvalidDomain';
    console.log(`Domains to authenticate : ${allDomains}`);
    console.log(`Performing validation for domain ${certdomain}, validation string is ${validationStr}`);
    console.log(`( Remaining challenges: ${remainingChallenges} )`);
    let acmeChallengePathStr = '_acme-challenge';
    if (subdomain) {
        acmeChallengePathStr = acmeChallengePathStr + `.${subdomain}`;
    }
    const added_id = await namesilo_add_dns_record({
        key: nameSilo_key,
        domain: domain,
        type: 'TXT',
        path: acmeChallengePathStr,
        value: validationStr,
        // MUST NOT SET LOWER THAN 3600
        ttl: 3600 // Set TTL to low number because otherwise it might be cached causing the script to fail.
    });
    let record_id;
    if (!added_id) {
        console.log('did not add record, listing existing records and trying again with update');
        console.log('this could occur due to cleanup hook failing last time...');
        const records = await namesilo_list_records({ key: nameSilo_key, domain });
        const foundTXTRecord = records.find((v) => {
            return (v.host.startsWith('_acme-challenge')
                || v.type == 'TXT');
        });
        console.log('found TXT Record of', foundTXTRecord);
        if (!foundTXTRecord) {
            console.log('could not find relevant existing TXT record; crashing');
            console.log('Found records are', JSON.stringify(records));
            throw `No valid TXT record to update`;
        }
        foundTXTRecord.record_id;
        const updated_id = await namesilo_update_record({
            key: nameSilo_key,
            domain: domain,
            rrid: foundTXTRecord.record_id,
            path: acmeChallengePathStr,
            value: validationStr,
            ttl: 3600 // Set TTL to low number because otherwise it might be cached causing the script to fail.
        });
        if (!updated_id)
            throw `Failed to update record`;
        record_id = updated_id;
    }
    else {
        // Nothing
        record_id = added_id;
    }
    console.log(`Did add DNS record with record_id: ${record_id}, data of ${validationStr}`);
    // Append to record_ids file for deletion later.
    await fs_1.promises.appendFile(`${cache_directory}/record_ids`, `${record_id}\n`);
    const txtRecordURL = `${acmeChallengePathStr}.${domain}`;
    const startTime = Date.now();
    const thirty_minutes_in_ms = 30 * 60 * 1000;
    let didFindRecord = false;
    console.log(`Waiting for DNS record to be updated (started at ${new Date()})\n`);
    while (Date.now() - startTime < thirty_minutes_in_ms) {
        console.log('Checking if public record is updated yet..');
        try {
            const records = await getPublicTXTRecord(txtRecordURL);
            if (records.indexOf(validationStr) != -1) {
                console.log(`Found DNS record of ${validationStr}`);
                didFindRecord = true;
                break;
            }
            logSameLine(`Checking if public record is updated yet.. Nope (${new Date()})\n`);
        }
        catch (e) {
            if ((e === null || e === void 0 ? void 0 : e.code) == 'ENODATA') {
                console.log('No data found yet');
            }
            else {
                console.error('Error with checking of TXT record', e);
            }
        }
        let count = 0;
        let interval = setInterval(() => {
            count++;
            if (count >= loading_characters.length) {
                count = 0;
            }
            let character = loading_characters[count];
            logSameLine(`Waiting.. (recheck every 3 minutes) ${character}`);
        }, 200);
        await waitPromise(3 * 60 * 1000); // Wait 3 minutes before reloading data again
        clearInterval(interval);
    }
    if (!didFindRecord) {
        console.log('Timeout after 30 minutes, no records found');
    }
}
async function cleanupHook(nameSilo_key, certdomain, cache_directory) {
    const { domain, subdomain } = tldts.parse(certdomain);
    if (!domain)
        throw 'InvalidDomain';
    const cacheFileContent = (await fs_1.promises.readFile(`${cache_directory}/record_ids`)).toString();
    const proms = cacheFileContent.split('\n').map(async (v) => {
        const record_id = v.trim();
        if (!record_id.length)
            return;
        await namesilo_delete_record({ key: nameSilo_key, domain: domain, rrid: record_id });
        console.log(`deleted record ${record_id}`);
    });
    await Promise.all(proms);
    console.log('Cleaned up successfully');
}
async function main() {
    /** Our domain being authenticated */
    const certdomain = process.env.CERTBOT_DOMAIN;
    const validationStr = process.env.CERTBOT_VALIDATION;
    const remainingChallenges = process.env.CERTBOT_REMAINING_CHALLENGES;
    const allDomains = process.env.CERTBOT_ALL_DOMAINS;
    const nameSilo_key = process.env.NAMESILO_KEY;
    const auth_output = process.env.CERTBOT_AUTH_OUTPUT;
    if (!nameSilo_key) {
        console.error(`No NAMESILO_KEY environment variable specified. Please perform export NAMESILO_KEY=your_key before calling this function.`);
        throw new Error('!NAMESILO_KEY');
    }
    if (!certdomain) {
        console.error('No CERTBOT_DOMAIN');
        throw new Error('!CERTBOT_DOMAIN');
    }
    if (!validationStr) {
        console.error('No CERTBOT_VALIDATION');
        throw new Error('!CERTBOT_VALIDATION');
    }
    const tmpdir = os.tmpdir();
    const cache_directory = `${tmpdir}/CERTBOT_${certdomain}`;
    if (process.argv.indexOf('cleanup') != -1 || auth_output) {
        if (auth_output) {
            console.log(`Found auth_output of..`);
            console.log('\x1b[36m%s\x1b[0m', auth_output);
            console.log('\x1b[33m%s\x1b[0m', 'performing cleanup');
        }
        else {
            console.log('found cleanup argument; performing cleanup');
        }
        cleanupHook(nameSilo_key, certdomain, cache_directory);
    }
    else {
        authHook(nameSilo_key, certdomain, validationStr, remainingChallenges, allDomains, cache_directory);
    }
}
/**
 * @param params
 * @returns record_id: The unique ID of the resource record that was created. This value is necessary to perform the dnsUpdateRecord and dnsDeleteRecord functions
 */
async function namesilo_add_dns_record(params) {
    const { key, domain, type = 'TXT', path, value = '', ttl = 7207 } = params;
    // const postUrl = `https://www.namesilo.com/api/dnsAddRecord?version=1&type=xml&key=${key}&domain=${domain}&rrtype=${type}&rrhost=${path}&rrvalue=${value}&rrttl=7207`
    const postUrl = `https://www.namesilo.com/api/dnsAddRecord?version=1&type=xml&key=${key}&domain=${domain}&rrtype=${type}&rrhost=${path}&rrvalue=${value}&rrttl=${ttl}`;
    const res = await node_fetch_1.default(postUrl);
    const textres = await res.text();
    const parsed = await xml2js_1.default.parseStringPromise(textres);
    const obj = parsed;
    const reply = obj.namesilo.reply[0];
    if (reply.detail[0] != 'success') {
        if (reply.code[0] == '280') {
            // 280 is the return code if the record already exists
            // (the detail tag will say `could not add resource record to domain since it already exists (duplicate)`)
            console.log('Record with this exact details already exists so namesilo did not add any extra records');
            console.log('record_id is', reply.record_id);
            console.log('got reply', JSON.stringify(obj.namesilo.reply));
            return undefined;
        }
        else {
            console.error('Failed with code', reply.code, 'detail', reply.detail);
            throw 'Failed';
        }
    }
    return reply.record_id[0];
}
async function namesilo_list_records(params) {
    const { key, domain } = params;
    const url = `https://www.namesilo.com/api/dnsListRecords?version=1&type=xml&key=${key}&domain=${domain}`;
    const fetchres = await node_fetch_1.default(url);
    const fetchtext = await fetchres.text();
    const parsed = await xml2js_1.default.parseStringPromise(fetchtext);
    const obj = parsed;
    const reply = obj.namesilo.reply[0];
    if (reply.detail[0] != 'success') {
        console.error('Failed with code', reply.code, 'detail', reply.detail);
        throw 'Failed';
    }
    return reply.resource_record.map((v) => {
        let out = unarray_object(v);
        return out;
    });
}
/**
 * Deletes the DNS record as specified
 * Reference : https://www.namesilo.com/api-reference#dns/dns-delete-record
 * @param params
 * @returns
 */
async function namesilo_delete_record(params) {
    const { key, domain, rrid } = params;
    const url = `https://www.namesilo.com/api/dnsDeleteRecord?version=1&type=xml&key=${key}&domain=${domain}&rrid=${rrid}`;
    const res = await node_fetch_1.default(url);
    const restxt = await res.text();
    const parsed = await xml2js_1.default.parseStringPromise(restxt);
    const obj = parsed;
    if (obj.namesilo.reply[0].detail[0] != 'success') {
        throw 'Failed';
    }
    return;
}
/**
 * Namesilo update record
 * https://www.namesilo.com/api-reference#dns/dns-update-record
 * @param params
 * @returns
 */
async function namesilo_update_record(params) {
    const { key, domain, rrid, path, value = '', ttl = 7207 } = params;
    // const postUrl = `https://www.namesilo.com/api/dnsAddRecord?version=1&type=xml&key=${key}&domain=${domain}&rrtype=${type}&rrhost=${path}&rrvalue=${value}&rrttl=7207`
    const postUrl = `https://www.namesilo.com/api/dnsUpdateRecord?version=1&type=xml&key=${key}&domain=${domain}&rrid=${rrid}&rrhost=${path}&rrvalue=${value}&rrttl=${ttl}`;
    const res = await node_fetch_1.default(postUrl);
    const textres = await res.text();
    const parsed = await xml2js_1.default.parseStringPromise(textres);
    const obj = parsed;
    const reply = obj.namesilo.reply[0];
    if (reply.detail[0] != 'success') {
        if (reply.code[0] == '280') {
            // 280 is the return code if the record already exists
            // (the detail tag will say `could not add resource record to domain since it already exists (duplicate)`)
            console.log('Record with this exact details already exists so namesilo did not add any extra records');
            console.log('record_id is', reply.record_id);
            console.log('got reply', JSON.stringify(obj.namesilo.reply));
            return undefined;
        }
        else {
            console.error('Failed with code', reply.code, 'detail', reply.detail);
            console.log('got reply', JSON.stringify(obj.namesilo.reply));
            throw 'Failed';
        }
    }
    // the record_id is updated when successful according to NameSilo docs
    // `The new unique ID for the resource record that was updated. Any successful updates will result in a new record_id`
    return reply.record_id[0];
}
async function getPublicTXTRecord(address) {
    const resolver = new dns_1.promises.Resolver();
    const dnsServerList = ['ns1.dnsowl.com', 'ns2.dnsowl.com', 'ns3.dnsowl.com'];
    const dnsAddresses = await Promise.all(dnsServerList.map(async (serv) => {
        const result = await dns_1.promises.lookup(serv, 4);
        return result.address;
    }));
    console.log('dns server addresses', dnsAddresses);
    resolver.setServers(dnsAddresses);
    const res = await resolver.resolveTxt(address);
    return Array.prototype.concat.apply([], res);
}
function unarray_object(obj) {
    let outObj = {};
    for (let key in obj) {
        let item = obj[key];
        if (Array.isArray(item)) {
            outObj[key] = item[0];
        }
        else {
            outObj[key] = item;
        }
    }
    return outObj;
}
const waitPromise = (ms, rejectReceiver = {}) => {
    return new Promise((resolve, reject) => {
        setTimeout(resolve, ms);
        rejectReceiver.reject = reject;
    });
};
function logSameLine(str) {
    readline.clearLine(process.stdout, 0);
    readline.cursorTo(process.stdout, 0);
    process.stdout.write(str);
}
const loading_characters = ['⠟', '⠯', '⠷', '⠾', '⠽', '⠻'];
main();

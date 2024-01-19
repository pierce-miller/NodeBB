
const path = require("path");
const crypto = require("crypto");
const util = require("util");

const bcrypt = require("bcrypt");

import fork from './meta/debugFork';

function forkChild(message, callback) {
    // The next line calls a function in a module that has not been updated to TS yet
    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
    const child = fork(path.join(__dirname, 'password'));

    child.on('message', (msg) => {
        callback(msg.err ? new Error(msg.err) : null, msg.result);
    });
    child.on('error', (err) => {
        console.error(err.stack);
        callback(err);
    });

    child.send(message);
}

const forkChildAsync = util.promisify(forkChild);

export async function hash(rounds, password):Promise<unknown> {
    password = crypto.createHash('sha512').update(password).digest('hex');
    return await forkChildAsync({ type: 'hash', rounds: rounds, password: password });
};

export async function compare(password, hash, shaWrapped) {
    const fakeHash = await getFakeHash();

    if (shaWrapped) {
        password = crypto.createHash('sha512').update(password).digest('hex');
    }

    return await forkChildAsync({ type: 'compare', password: password, hash: hash || fakeHash });
};

let fakeHashCache;
async function getFakeHash() {
    if (fakeHashCache) {
        return fakeHashCache;
    }
    fakeHashCache = await exports.hash(12, Math.random().toString());
    return fakeHashCache;
}

// child process
process.on('message', (msg:any) => {
    if (msg.type === 'hash') {
        tryMethod(hashPassword, msg);
    } else if (msg.type === 'compare') {
        tryMethod(compare1, msg);
    }
});

async function tryMethod(method, msg) {
    try {
        const result = await method(msg);
        process.send({ result: result });
    } catch (err) {
        process.send({ err: err.message });
    } finally {
        process.disconnect();
    }
}

async function hashPassword(msg) {
    const salt = await bcrypt.genSalt(parseInt(msg.rounds, 10));
    const hash = await bcrypt.hash(msg.password, salt);
    return hash;
}

async function compare1(msg) {
    return await bcrypt.compare(String(msg.password || ''), String(msg.hash || ''));
}

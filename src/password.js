"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
exports.__esModule = true;
exports.compare = exports.hash = void 0;
var path = require("path");
var crypto = require("crypto");
var util = require("util");
var bcrypt = require("bcryptjs");
var debugFork_1 = require("./meta/debugFork");
function forkChild(message, callback) {
    // The next line calls a function in a module that has not been updated to TS yet
    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
    var child = (0, debugFork_1["default"])(path.join(__dirname, 'password'));
    child.on('message', function (msg) {
        callback(msg.err ? new Error(msg.err) : null, msg.result);
    });
    child.on('error', function (err) {
        console.error(err.stack);
        callback(err);
    });
    child.send(message);
}
var forkChildAsync = util.promisify(forkChild);
function hash(rounds, password) {
    return __awaiter(this, void 0, void 0, function () {
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    password = crypto.createHash('sha512').update(password).digest('hex');
                    return [4 /*yield*/, forkChildAsync({ type: 'hash', rounds: rounds, password: password })];
                case 1: return [2 /*return*/, _a.sent()];
            }
        });
    });
}
exports.hash = hash;
;
function compare(password, hash, shaWrapped) {
    return __awaiter(this, void 0, void 0, function () {
        var fakeHash;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, getFakeHash()];
                case 1:
                    fakeHash = _a.sent();
                    if (shaWrapped) {
                        password = crypto.createHash('sha512').update(password).digest('hex');
                    }
                    return [4 /*yield*/, forkChildAsync({ type: 'compare', password: password, hash: hash || fakeHash })];
                case 2: return [2 /*return*/, _a.sent()];
            }
        });
    });
}
exports.compare = compare;
;
var fakeHashCache;
function getFakeHash() {
    return __awaiter(this, void 0, void 0, function () {
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    if (fakeHashCache) {
                        return [2 /*return*/, fakeHashCache];
                    }
                    return [4 /*yield*/, exports.hash(12, Math.random().toString())];
                case 1:
                    fakeHashCache = _a.sent();
                    return [2 /*return*/, fakeHashCache];
            }
        });
    });
}
// child process
process.on('message', function (msg) {
    if (msg.type === 'hash') {
        tryMethod(hashPassword, msg);
    }
    else if (msg.type === 'compare') {
        tryMethod(compare1, msg);
    }
});
function tryMethod(method, msg) {
    return __awaiter(this, void 0, void 0, function () {
        var result, err_1;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    _a.trys.push([0, 2, 3, 4]);
                    return [4 /*yield*/, method(msg)];
                case 1:
                    result = _a.sent();
                    process.send({ result: result });
                    return [3 /*break*/, 4];
                case 2:
                    err_1 = _a.sent();
                    process.send({ err: err_1.message });
                    return [3 /*break*/, 4];
                case 3:
                    process.disconnect();
                    return [7 /*endfinally*/];
                case 4: return [2 /*return*/];
            }
        });
    });
}
function hashPassword(msg) {
    return __awaiter(this, void 0, void 0, function () {
        var salt, hash;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, bcrypt.genSalt(parseInt(msg.rounds, 10))];
                case 1:
                    salt = _a.sent();
                    return [4 /*yield*/, bcrypt.hash(msg.password, salt)];
                case 2:
                    hash = _a.sent();
                    return [2 /*return*/, hash];
            }
        });
    });
}
function compare1(msg) {
    return __awaiter(this, void 0, void 0, function () {
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, bcrypt.compare(String(msg.password || ''), String(msg.hash || ''))];
                case 1: return [2 /*return*/, _a.sent()];
            }
        });
    });
}

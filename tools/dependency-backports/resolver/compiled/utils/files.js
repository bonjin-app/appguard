"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.tryReadFile = tryReadFile;
exports.tryReadFileAsync = tryReadFileAsync;
const node_fs_1 = __importDefault(require("node:fs"));
function tryReadFile(file) {
    try {
        return node_fs_1.default.readFileSync(file, { encoding: 'utf-8' });
    }
    catch (error) {
        if (shouldIgnoreError(error)) {
            return null;
        }
        throw error;
    }
}
function tryReadFileAsync(file) {
    return node_fs_1.default.promises.readFile(file, { encoding: 'utf-8' }).catch((error) => {
        if (shouldIgnoreError(error)) {
            return null;
        }
        throw error;
    });
}
/**
 * We are optimistically reading files, avoiding unnecessary file lookup checks.
 * Some thrown errors are expected and should be ignored as "file not found".
 */
function shouldIgnoreError(error) {
    return 'code' in error && (error.code === 'ENOENT' || error.code === 'EISDIR');
}

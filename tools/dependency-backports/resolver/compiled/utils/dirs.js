"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.searchParentDirs = searchParentDirs;
exports.searchParentDirsAsync = searchParentDirsAsync;
const node_path_1 = __importDefault(require("node:path"));
const node_process_1 = __importDefault(require("node:process"));
function searchParentDirs(startingDir = node_process_1.default.cwd(), searchAction) {
    let currentDir = node_path_1.default.normalize(startingDir);
    let previousDir;
    do {
        const result = searchAction(currentDir, node_path_1.default.relative(currentDir, startingDir));
        if (result !== undefined) {
            return result;
        }
        previousDir = currentDir;
        currentDir = node_path_1.default.dirname(currentDir);
    } while (currentDir !== previousDir);
    return null;
}
async function searchParentDirsAsync(startingDir, searchAction) {
    let currentDir = node_path_1.default.normalize(startingDir);
    let previousDir;
    do {
        const result = await searchAction(currentDir, node_path_1.default.relative(currentDir, startingDir));
        if (result !== undefined) {
            return result;
        }
        previousDir = currentDir;
        currentDir = node_path_1.default.dirname(currentDir);
    } while (currentDir !== previousDir);
    return null;
}

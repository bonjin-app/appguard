"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.pathMatchesWorkspaceGlobs = pathMatchesWorkspaceGlobs;
exports.workspaceGlobsFromPackage = workspaceGlobsFromPackage;
exports.workspaceGlobsFromPnpm = workspaceGlobsFromPnpm;
const js_yaml_1 = require("js-yaml");
const micromatch_1 = __importDefault(require("micromatch"));
function pathMatchesWorkspaceGlobs(globs, relativePath) {
    return !relativePath || (0, micromatch_1.default)([relativePath], globs).length > 0;
}
function workspaceGlobsFromPackage(packageContent) {
    try {
        const packageData = JSON.parse(packageContent);
        if (Array.isArray(packageData?.workspaces)) {
            return packageData.workspaces;
        }
        if (Array.isArray(packageData?.workspaces?.packages)) {
            return packageData.workspaces.packages;
        }
    }
    catch (error) {
        if (error.name !== 'SyntaxError') {
            throw error;
        }
    }
    return null;
}
function workspaceGlobsFromPnpm(workspaceContent) {
    try {
        const workspaceData = workspaceContent ? (0, js_yaml_1.load)(workspaceContent) : null;
        if (Array.isArray(workspaceData?.packages)) {
            return workspaceData.packages;
        }
    }
    catch (error) {
        if (error.name !== 'YAMLException') {
            throw error;
        }
    }
    return null;
}

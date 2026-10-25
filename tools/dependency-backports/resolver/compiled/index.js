"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.resolveWorkspaceRoot = resolveWorkspaceRoot;
exports.resolveWorkspaceRootAsync = resolveWorkspaceRootAsync;
exports.getWorkspaceGlobs = getWorkspaceGlobs;
exports.getWorkspaceGlobsAsync = getWorkspaceGlobsAsync;
const node_path_1 = __importDefault(require("node:path"));
const node_process_1 = __importDefault(require("node:process"));
const dirs_1 = require("./utils/dirs");
const files_1 = require("./utils/files");
const workspaces_1 = require("./utils/workspaces");
/**
 * Resolve the root of the workspace, using bun, npm, pnpm, or yarn.
 * This will iterate the parent directories until it finds a workspace config,
 * where the starting directory is considered part of the workspace.
 *   - For bun and npm - it looks for the [`workspaces` list](https://docs.npmjs.com/cli/configuring-npm/package-json#workspaces) in `package.json`
 *   - For yarn - it looks for the [`workspaces` list or config](https://yarnpkg.com/features/workspaces) in `package.json`
 *   - For pnpm - it looks for the [`pnpm-workspace.yaml`](https://pnpm.io/workspaces) file
 */
function resolveWorkspaceRoot(startingDir = node_process_1.default.cwd(), options = {}) {
    return (0, dirs_1.searchParentDirs)(startingDir, (currentDir, relativeDir) => {
        if (options.pnpmWorkspaces !== false) {
            const workspaceContent = (0, files_1.tryReadFile)(node_path_1.default.join(currentDir, 'pnpm-workspace.yaml'));
            const workspaceGlobs = workspaceContent && (0, workspaces_1.workspaceGlobsFromPnpm)(workspaceContent);
            if (workspaceGlobs && (0, workspaces_1.pathMatchesWorkspaceGlobs)(workspaceGlobs, relativeDir)) {
                return currentDir;
            }
        }
        if (options.packageWorkspaces !== false) {
            const packageContent = (0, files_1.tryReadFile)(node_path_1.default.join(currentDir, 'package.json'));
            const packageGlobs = packageContent && (0, workspaces_1.workspaceGlobsFromPackage)(packageContent);
            if (packageGlobs && (0, workspaces_1.pathMatchesWorkspaceGlobs)(packageGlobs, relativeDir)) {
                return currentDir;
            }
        }
    });
}
/**
 * Resolve the root of the workspace, using bun, npm, pnpm, or yarn.
 * This will iterate the parent directories until it finds a workspace config,
 * where the starting directory is considered part of the workspace.
 *   - For bun and npm - it looks for the [`workspaces` list](https://docs.npmjs.com/cli/configuring-npm/package-json#workspaces) in `package.json`
 *   - For yarn - it looks for the [`workspaces` list or config](https://yarnpkg.com/features/workspaces) in `package.json`
 *   - For pnpm - it looks for the [`pnpm-workspace.yaml`](https://pnpm.io/workspaces) file
 */
function resolveWorkspaceRootAsync(startingDir = node_process_1.default.cwd(), options = {}) {
    return (0, dirs_1.searchParentDirsAsync)(startingDir, async (currentDir, relativeDir) => {
        if (options.pnpmWorkspaces !== false) {
            const workspaceContent = await (0, files_1.tryReadFileAsync)(node_path_1.default.join(currentDir, 'pnpm-workspace.yaml'));
            const workspaceGlobs = workspaceContent && (0, workspaces_1.workspaceGlobsFromPnpm)(workspaceContent);
            if (workspaceGlobs && (0, workspaces_1.pathMatchesWorkspaceGlobs)(workspaceGlobs, relativeDir)) {
                return currentDir;
            }
        }
        if (options.packageWorkspaces !== false) {
            const packageContent = await (0, files_1.tryReadFileAsync)(node_path_1.default.join(currentDir, 'package.json'));
            const packageGlobs = packageContent && (0, workspaces_1.workspaceGlobsFromPackage)(packageContent);
            if (packageGlobs && (0, workspaces_1.pathMatchesWorkspaceGlobs)(packageGlobs, relativeDir)) {
                return currentDir;
            }
        }
    });
}
/**
 * Get the configured workspace globs from the monorepo.
 *   - For bun and npm - it looks for the [`workspaces` list](https://docs.npmjs.com/cli/configuring-npm/package-json#workspaces) in `package.json`
 *   - For yarn - it looks for the [`workspaces` list or config](https://yarnpkg.com/features/workspaces) in `package.json`
 *   - For pnpm - it looks for the [`pnpm-workspace.yaml`](https://pnpm.io/workspaces) file
 * @note The provided `rootDir` must be the root of the monorepo
 */
function getWorkspaceGlobs(rootDir = node_process_1.default.cwd(), options = {}) {
    if (options.pnpmWorkspaces !== false) {
        const workspaceContent = (0, files_1.tryReadFile)(node_path_1.default.join(rootDir, 'pnpm-workspace.yaml'));
        const workspaceGlobs = workspaceContent && (0, workspaces_1.workspaceGlobsFromPnpm)(workspaceContent);
        if (workspaceGlobs) {
            return workspaceGlobs;
        }
    }
    if (options.packageWorkspaces !== false) {
        const packageContent = (0, files_1.tryReadFile)(node_path_1.default.join(rootDir, 'package.json'));
        const packageGlobs = packageContent && (0, workspaces_1.workspaceGlobsFromPackage)(packageContent);
        if (packageGlobs) {
            return packageGlobs;
        }
    }
    return null;
}
/**
 * Get the configured workspace globs from the monorepo.
 *   - For bun and npm - it looks for the [`workspaces` list](https://docs.npmjs.com/cli/configuring-npm/package-json#workspaces) in `package.json`
 *   - For yarn - it looks for the [`workspaces` list or config](https://yarnpkg.com/features/workspaces) in `package.json`
 *   - For pnpm - it looks for the [`pnpm-workspace.yaml`](https://pnpm.io/workspaces) file
 * @note The provided `rootDir` must be the root of the monorepo
 */
async function getWorkspaceGlobsAsync(rootDir = node_process_1.default.cwd(), options = {}) {
    if (options.pnpmWorkspaces !== false) {
        const workspaceContent = await (0, files_1.tryReadFileAsync)(node_path_1.default.join(rootDir, 'pnpm-workspace.yaml'));
        const workspaceGlobs = workspaceContent && (0, workspaces_1.workspaceGlobsFromPnpm)(workspaceContent);
        if (workspaceGlobs) {
            return workspaceGlobs;
        }
    }
    if (options.packageWorkspaces !== false) {
        const packageContent = await (0, files_1.tryReadFileAsync)(node_path_1.default.join(rootDir, 'package.json'));
        const packageGlobs = packageContent && (0, workspaces_1.workspaceGlobsFromPackage)(packageContent);
        if (packageGlobs) {
            return packageGlobs;
        }
    }
    return null;
}

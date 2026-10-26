'use strict';
// Supported entrypoint: the pinned Python preparation/verification driver.
// No installed Forge package or original opaque resolver bundle is loaded.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {createHash} = require('node:crypto');
const {createRequire} = require('node:module');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const [prepared, output] = process.argv.slice(2);
const recipe = JSON.parse(fs.readFileSync(path.join(__dirname, 'recipe.json')));
const source = path.join(prepared, 'source');
const producer = path.join(prepared, 'producer');
const names = ['forge.js', 'forge.min.js', 'forge.all.js', 'forge.all.min.js', 'prime.worker.js', 'prime.worker.min.js'];

function checkTree() {
  const expected = JSON.parse(fs.readFileSync(path.join(__dirname, 'tool-tree.json')));
  const actual = {files_sha256: {}, symlinks: {}};
  function visit(directory, relative = '') {
    for (const entry of fs.readdirSync(directory, {withFileTypes: true})) {
      const name = relative ? relative + '/' + entry.name : entry.name;
      const file = path.join(directory, entry.name);
      if (entry.isDirectory()) visit(file, name);
      else if (entry.isSymbolicLink()) {
        const resolved = fs.realpathSync(file);
        assert.ok(resolved.startsWith(producer + path.sep));
        assert.ok(fs.lstatSync(resolved).isFile());
        actual.symlinks[name] = {target: fs.readlinkSync(file), resolved_file_sha256: sha(fs.readFileSync(resolved))};
      } else {
        assert.ok(entry.isFile());
        actual.files_sha256[name] = sha(fs.readFileSync(file));
      }
    }
  }
  visit(producer);
  assert.deepEqual(actual.files_sha256, expected.files_sha256);
  assert.deepEqual(actual.symlinks, expected.symlinks);
}

function checkSource() {
  const found = [];
  function visit(directory, relative = '') {
    for (const entry of fs.readdirSync(directory, {withFileTypes: true})) {
      const name = relative ? relative + '/' + entry.name : entry.name;
      const file = path.join(directory, entry.name);
      assert.ok(!entry.isSymbolicLink());
      if (entry.isDirectory()) visit(file, name);
      else {
        assert.ok(entry.isFile());
        const bytes = fs.readFileSync(file);
        assert.equal(bytes.length, recipe.sources[name]?.size);
        assert.equal(sha(bytes), recipe.sources[name]?.sha256);
        found.push(name);
      }
    }
  }
  visit(source);
  assert.deepEqual(found.sort(), Object.keys(recipe.sources).sort());
}

function writeNew(name, value) {
  fs.writeFileSync(path.join(output, name), JSON.stringify(value) + '\n', {flag: 'wx', mode: 0o600});
}

async function main() {
  assert.equal(process.argv.length, 4);
  assert.equal(process.versions.node, recipe.runtime.node);
  assert.ok(!process.env.NODE_OPTIONS && !process.env.NODE_PATH);
  assert.equal(path.resolve(prepared), prepared);
  assert.equal(path.resolve(output), output);
  assert.ok(!fs.existsSync(output));
  checkSource();
  checkTree();
  const fromProducer = createRequire(path.join(producer, 'package.json'));
  function owned(from, name) {
    const resolved = from.resolve(name);
    assert.ok(resolved.startsWith(producer + path.sep));
    assert.equal(fs.realpathSync(resolved), resolved);
    return resolved;
  }
  // Resolve the same dependency ancestry used by the retained modern recipe.
  const webpackPath = owned(fromProducer, 'webpack');
  const webpack = fromProducer(webpackPath);
  const fromWebpack = createRequire(webpackPath);
  const minimizerPath = owned(fromWebpack, 'minimizer-webpack-plugin');
  const Minimizer = fromWebpack(minimizerPath);
  const fromMinimizer = createRequire(minimizerPath);
  const fromTerser = createRequire(owned(fromMinimizer, 'terser'));
  const acorn = fromTerser(owned(fromTerser, 'acorn'));
  const configs = require(path.join(source, 'webpack.config.js'));
  assert.deepEqual(configs.map(config => config.output.filename), names);
  fs.mkdirSync(output, {mode: 0o700});
  const warnings = [];
  const maps = [];

  function parseEs5(code) {
    // Retain the established syntax/literal-eval check; this runs no bundle code.
    const pending = [code];
    let strings = 0;
    while (pending.length) {
      assert.ok(++strings <= 256);
      const current = pending.pop();
      assert.ok(Buffer.byteLength(current) < 4 * 1024 * 1024);
      const nodes = [acorn.parse(current, {ecmaVersion: 5, sourceType: 'script'})];
      let visited = 0;
      while (nodes.length) {
        const node = nodes.pop();
        assert.ok(++visited <= 500000);
        if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && node.callee.name === 'eval') {
          const argument = node.arguments[0];
          if (argument?.type === 'Literal' && typeof argument.value === 'string') pending.push(argument.value);
        }
        for (const value of Object.values(node)) {
          if (Array.isArray(value)) nodes.push(...value.filter(item => item && typeof item.type === 'string'));
          else if (value && typeof value.type === 'string') nodes.push(value);
        }
      }
    }
  }

  function checkMap(map, filename) {
    const expected = recipe.maps.find(row => row.filename === filename);
    assert.ok(expected);
    assert.equal(map.version, 3);
    assert.equal(map.file, filename);
    assert.ok(map.sourceRoot === undefined || map.sourceRoot === '');
    assert.deepEqual(map.sources, expected.entries.map(entry => entry.source));
    assert.equal(map.sourcesContent.length, expected.entries.length);
    expected.entries.forEach((entry, index) => {
      assert.equal(typeof map.sourcesContent[index], 'string');
      assert.equal(sha(map.sourcesContent[index]), entry.sha256);
      if (entry.classification === 'source_inventory') {
        assert.equal(entry.sha256, recipe.sources[entry.inventory_path].sha256);
      } else {
        assert.ok(['webpack_generated', 'webpack_ignored'].includes(entry.classification));
        assert.equal(sha(fs.readFileSync(path.join(producer, 'node_modules', entry.generator_file))), entry.generator_sha256);
      }
    });
    maps.push({filename, entries: expected.entries.length, all_recorded_entries_matched: true});
  }

  for (const original of configs) {
    assert.deepEqual(original.node, {Buffer: false, process: false, crypto: false, setImmediate: false});
    const minimized = original.mode === 'production';
    // Explicit modern Webpack transforms of the unchanged official config.
    const config = {...original, context: source, target: ['web', 'es5'],
      node: {global: true, __filename: 'mock', __dirname: 'mock'},
      resolve: {fallback: {buffer: false, process: false, crypto: false}},
      output: {...original.output, path: output, globalObject: original.output.libraryTarget ? 'window' : 'self'}};
    if (minimized) {
      assert.equal(original.devtool, 'cheap-module-source-map');
      config.devtool = 'source-map';
      config.optimization = {minimizer: [new Minimizer({parallel: false, extractComments: true,
        minify: {implementation: Minimizer.terserMinify, options: {ecma: 5}}})]};
    }
    const compiler = webpack(config);
    try {
      const stats = await new Promise((resolve, reject) => compiler.run((error, value) => error ? reject(error) : resolve(value)));
      const details = stats.toJson({all: false, errors: true, warnings: true, assets: true});
      writeNew(original.output.filename + '.compiler.json', details);
      assert.equal(stats.hasErrors(), false);
      warnings.push({file: original.output.filename, count: details.warnings.length});
    } finally {
      await new Promise((resolve, reject) => compiler.close(error => error ? reject(error) : resolve()));
    }
    const code = fs.readFileSync(path.join(output, original.output.filename), 'utf8');
    parseEs5(code);
    if (minimized) {
      assert.ok(code.trimEnd().endsWith('//# sourceMappingURL=' + original.output.filename + '.map'));
      checkMap(JSON.parse(fs.readFileSync(path.join(output, original.output.filename + '.map'), 'utf8')), original.output.filename);
    }
  }
  assert.deepEqual(warnings, recipe.compiler_warnings);
  const actualNames = fs.readdirSync(output).filter(name => !name.endsWith('.compiler.json')).sort();
  assert.deepEqual(actualNames, Object.keys(recipe.outputs).sort());
  for (const [name, pin] of Object.entries(recipe.outputs)) {
    const bytes = fs.readFileSync(path.join(output, name));
    assert.equal(bytes.length, pin.size);
    assert.equal(sha(bytes), pin.sha256);
  }
  checkSource();
  checkTree();
  writeNew('compilation-receipt.json', {schema: 1, outputs: 9,
    independent_output_hashes_matched: true, es5_syntax_and_literal_eval_parsed: true,
    compiler_warnings: warnings, map_checks: maps,
    publisher_build_reproduced: false, consumer_adoption_verified: false,
    source_gate_passed: false, legal_approved: false, release_ready: false});
  console.log(JSON.stringify({verified: true, outputs: 9, publisher_build_reproduced: false, release_ready: false}));
}

main().catch(() => {
  // Keep any partial independent output for diagnosis; never replace expectations.
  console.error('forge producer verification failed');
  process.exitCode = 1;
});

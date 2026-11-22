'use strict';
/**
 * Small AST helpers shared by the ReachPrioritizer analysis engine.
 * All analysis is static: source code is parsed with @babel/parser, never executed.
 */
const parser = require('@babel/parser');

const SKIP_KEYS = new Set([
  'type', 'start', 'end', 'loc', 'range', 'extra',
  'leadingComments', 'trailingComments', 'innerComments', 'comments', 'tokens',
  'typeAnnotation', 'returnType', 'typeParameters', 'superTypeParameters',
]);

const FUNCTION_TYPES = new Set([
  'FunctionDeclaration',
  'FunctionExpression',
  'ArrowFunctionExpression',
  'ObjectMethod',
  'ClassMethod',
  'ClassPrivateMethod',
]);

const BASE_PLUGINS = [
  'asyncGenerators', 'classProperties', 'classPrivateProperties', 'classPrivateMethods',
  'dynamicImport', 'nullishCoalescingOperator', 'optionalChaining', 'objectRestSpread',
  'decorators-legacy', 'exportDefaultFrom', 'exportNamespaceFrom', 'topLevelAwait',
  'importMeta', 'logicalAssignment', 'numericSeparator', 'optionalCatchBinding',
];

function parse(source, relPath) {
  const isTs = /\.(ts|tsx|mts|cts)$/i.test(relPath);
  const plugins = [...BASE_PLUGINS];
  if (isTs) {
    plugins.push('typescript');
    if (/\.tsx$/i.test(relPath)) plugins.push('jsx');
  } else {
    plugins.push('jsx');
  }
  return parser.parse(source, {
    sourceType: 'unambiguous',
    allowReturnOutsideFunction: true,
    allowImportExportEverywhere: true,
    allowSuperOutsideMethod: true,
    allowAwaitOutsideFunction: true,
    errorRecovery: true,
    plugins,
  });
}

function children(node) {
  const out = [];
  for (const key of Object.keys(node)) {
    if (SKIP_KEYS.has(key)) continue;
    const v = node[key];
    if (Array.isArray(v)) {
      for (const item of v) if (item && typeof item.type === 'string') out.push([key, item]);
    } else if (v && typeof v.type === 'string') {
      out.push([key, v]);
    }
  }
  return out;
}

function unwrap(n) {
  while (n && (
    n.type === 'ParenthesizedExpression' || n.type === 'TSAsExpression' ||
    n.type === 'TSNonNullExpression' || n.type === 'TypeCastExpression' ||
    n.type === 'TSSatisfiesExpression' || n.type === 'TSTypeAssertion'
  )) n = n.expression;
  return n;
}

const isMember = (n) => !!n && (n.type === 'MemberExpression' || n.type === 'OptionalMemberExpression');
const isCall = (n) => !!n && (n.type === 'CallExpression' || n.type === 'OptionalCallExpression');
const isFunction = (n) => !!n && FUNCTION_TYPES.has(n.type);

function propName(member) {
  const p = member.property;
  if (!p) return null;
  if (!member.computed) {
    if (p.type === 'Identifier') return p.name;
    if (p.type === 'PrivateName') return '#' + p.id.name;
  }
  if (p.type === 'StringLiteral') return p.value;
  return null;
}

/** ['req','query','cmd'] for req.query.cmd ; null when not a static chain. */
function memberChain(n) {
  n = unwrap(n);
  if (!n) return null;
  if (n.type === 'Identifier') return [n.name];
  if (n.type === 'ThisExpression') return ['this'];
  if (n.type === 'Super') return ['super'];
  if (isMember(n)) {
    const base = memberChain(n.object);
    const p = propName(n);
    if (!base || p == null) return null;
    return [...base, p];
  }
  return null;
}

function keyName(key) {
  if (!key) return null;
  if (key.type === 'Identifier') return key.name;
  if (key.type === 'StringLiteral') return key.value;
  if (key.type === 'NumericLiteral') return String(key.value);
  if (key.type === 'PrivateName') return '#' + key.id.name;
  return null;
}

function stringValue(n) {
  n = unwrap(n);
  if (!n) return null;
  if (n.type === 'StringLiteral') return n.value;
  if (n.type === 'TemplateLiteral' && n.expressions.length === 0) {
    return n.quasis.map((q) => q.value.cooked).join('');
  }
  return null;
}

function isRequireCall(n) {
  n = unwrap(n);
  return isCall(n) && n.callee.type === 'Identifier' && n.callee.name === 'require' &&
    n.arguments.length > 0 && stringValue(n.arguments[0]) != null;
}

/** Identifiers bound by a declaration pattern. */
function patternNames(p, out = []) {
  if (!p) return out;
  switch (p.type) {
    case 'Identifier': out.push(p.name); break;
    case 'ObjectPattern':
      for (const prop of p.properties) {
        if (prop.type === 'RestElement') patternNames(prop.argument, out);
        else patternNames(prop.value, out);
      }
      break;
    case 'ArrayPattern': for (const el of p.elements) patternNames(el, out); break;
    case 'AssignmentPattern': patternNames(p.left, out); break;
    case 'RestElement': patternNames(p.argument, out); break;
    case 'TSParameterProperty': patternNames(p.parameter, out); break;
    default: break;
  }
  return out;
}

function isLiteral(n) {
  n = unwrap(n);
  if (!n) return false;
  return ['StringLiteral', 'NumericLiteral', 'BooleanLiteral', 'NullLiteral', 'RegExpLiteral', 'BigIntLiteral'].includes(n.type) ||
    (n.type === 'TemplateLiteral' && n.expressions.length === 0) ||
    (n.type === 'Identifier' && n.name === 'undefined');
}

module.exports = {
  parse, children, unwrap, isMember, isCall, isFunction, propName, memberChain,
  keyName, stringValue, isRequireCall, patternNames, isLiteral, FUNCTION_TYPES,
};

export default [
  {
    ignores: ['node_modules/', 'examples/', 'test/'],
  },
  {
    rules: {
      'no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
      'semi': ['error', 'always'],
      'quotes': ['error', 'single', { avoidEscape: true }],
      'no-trailing-spaces': 'error',
      'eol-last': ['error', 'always'],
    },
  },
];
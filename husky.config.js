let huskyConfig = {};

if (process.env.ENABLE_HUSKY_HOOKS) {
  huskyConfig = {
    hooks: {
      'pre-commit': 'lint-staged',
    },
  };
}

module.exports = huskyConfig;

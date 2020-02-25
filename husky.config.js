let huskyConfig = {};

if (process.env.ENABLE_PANTHER_GIT_HOOKS) {
  huskyConfig = {
    hooks: {
      'pre-commit': 'lint-staged',
    },
  };
}

module.exports = huskyConfig;

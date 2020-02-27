let huskyConfig = {};

if (process.env.ENABLE_PANTHER_WEB_GIT_HOOKS) {
  huskyConfig = {
    hooks: {
      'pre-commit': 'lint-staged',
    },
  };
}

module.exports = huskyConfig;

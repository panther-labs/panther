import React from 'react';

const { DialogOverlay, ...otherModules } = jest.requireActual('@reach/dialog');

const MockedDialogOverlay: React.FC = props => (
  <DialogOverlay {...props} dangerouslyBypassScrollLock />
);

module.exports = {
  ...otherModules,
  DialogOverlay: MockedDialogOverlay,
};

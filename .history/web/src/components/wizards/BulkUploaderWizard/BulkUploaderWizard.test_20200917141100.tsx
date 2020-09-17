import React from 'react';
import { Wizard } from 'Components/Wizard';
import UploadPanel from './UploadPanel';
import SuccessfulUploadPanel from './SuccessfulUploadPanel';

const BulkUploaderWizard: React.FC = () => (
  <Wizard header={false}>
    <Wizard.Step>
      <UploadPanel />
    </Wizard.Step>
    <Wizard.Step>
      <SuccessfulUploadPanel />
    </Wizard.Step>
  </Wizard>
);

export default BulkUploaderWizard;

import React from 'react';
import { DestinationFull } from 'Source/graphql/fragments/DestinationFull.generated';
import { Wizard, WizardPanelWrapper } from 'Components/Wizard';
import ConfigureDestinationScreen from './ConfigureDestinationPanel';
import DestinationTestPanel from '../common/DestinationTestPanel';

export interface WizardData {
  destination?: DestinationFull;
}

const EditDestination: React.FC = () => {
  return (
    <Wizard<WizardData> header={false}>
      <Wizard.Step>
        <WizardPanelWrapper>
          <WizardPanelWrapper.Content>
            <ConfigureDestinationScreen />
          </WizardPanelWrapper.Content>
        </WizardPanelWrapper>
      </Wizard.Step>
      <Wizard.Step>
        <WizardPanelWrapper>
          <WizardPanelWrapper.Content>
            <DestinationTestPanel />
          </WizardPanelWrapper.Content>
        </WizardPanelWrapper>
      </Wizard.Step>
    </Wizard>
  );
};

export default EditDestination;

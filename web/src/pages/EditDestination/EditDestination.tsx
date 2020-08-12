import React from 'react';
import { Wizard, WizardPanelWrapper } from 'Components/Wizard';
import ChooseDestinationScreen from './ChooseDestinationScreen';
import ConfigureDestinationScreen from './ConfigureDestinationScreen';
import SuccessScreen from './SuccessScreen';

const CreateDestination: React.FC = () => {
  return (
    <Wizard header={false}>
      <Wizard.Step>
        <WizardPanelWrapper>
          <WizardPanelWrapper.Content>
            <ChooseDestinationScreen />
          </WizardPanelWrapper.Content>
        </WizardPanelWrapper>
      </Wizard.Step>
      <Wizard.Step>
        <WizardPanelWrapper>
          <WizardPanelWrapper.Content>
            <ConfigureDestinationScreen />
          </WizardPanelWrapper.Content>
          <WizardPanelWrapper.ActionPrev />
        </WizardPanelWrapper>
      </Wizard.Step>
      <Wizard.Step>
        <WizardPanelWrapper>
          <WizardPanelWrapper.Content>
            <SuccessScreen />
          </WizardPanelWrapper.Content>
        </WizardPanelWrapper>
      </Wizard.Step>
    </Wizard>
  );
};

export default CreateDestination;

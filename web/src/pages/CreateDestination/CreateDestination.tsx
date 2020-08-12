import React from 'react';
import { Wizard, WizardPanelWrapper } from 'Components/Wizard';
import { DestinationTypeEnum } from 'Generated/schema';
import { DestinationFull } from 'Source/graphql/fragments/DestinationFull.generated';
import ChooseDestinationScreen from './ChooseDestinationScreen';
import ConfigureDestinationScreen from './ConfigureDestinationScreen';
import SuccessScreen from './SuccessScreen';

export interface WizardData {
  selectedDestinationType?: DestinationTypeEnum;
  destination?: DestinationFull;
}

const initialWizardData: WizardData = {};

const CreateDestination: React.FC = () => {
  return (
    <Wizard<WizardData> header={false} initialData={initialWizardData}>
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

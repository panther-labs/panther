import React from 'react';
import { Wizard, WizardPanelWrapper } from 'Components/Wizard';
import { DestinationTypeEnum } from 'Generated/schema';
import { DestinationFull } from 'Source/graphql/fragments/DestinationFull.generated';
import ChooseDestinationPanel from './ChooseDestinationPanel';
import ConfigureDestinationPanel from './ConfigureDestinationPanel';
import DestinationTestPanel from '../common/DestinationTestPanel';

export interface WizardData {
  selectedDestinationType?: DestinationTypeEnum;
  destination?: DestinationFull;
}

const CreateDestinationWizard: React.FC = () => {
  return (
    <Wizard<WizardData> header={false}>
      <Wizard.Step>
        <WizardPanelWrapper>
          <WizardPanelWrapper.Content>
            <ChooseDestinationPanel />
          </WizardPanelWrapper.Content>
        </WizardPanelWrapper>
      </Wizard.Step>
      <Wizard.Step>
        <WizardPanelWrapper>
          <WizardPanelWrapper.Content>
            <ConfigureDestinationPanel />
          </WizardPanelWrapper.Content>
          <WizardPanelWrapper.ActionPrev />
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

export default CreateDestinationWizard;

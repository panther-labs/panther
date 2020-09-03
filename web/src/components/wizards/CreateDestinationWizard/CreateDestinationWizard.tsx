/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import React from 'react';
import { Wizard, WizardPanel } from 'Components/Wizard';
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
        <WizardPanel>
          <ChooseDestinationPanel />
        </WizardPanel>
      </Wizard.Step>
      <Wizard.Step>
        <WizardPanel>
          <ConfigureDestinationPanel />
          <WizardPanel.ActionPrev />
        </WizardPanel>
      </Wizard.Step>
      <Wizard.Step>
        <WizardPanel>
          <DestinationTestPanel />
        </WizardPanel>
      </Wizard.Step>
    </Wizard>
  );
};

export default CreateDestinationWizard;

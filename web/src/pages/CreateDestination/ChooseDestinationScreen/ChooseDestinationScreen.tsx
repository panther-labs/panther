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
import { SimpleGrid } from 'pouncejs';
import { DESTINATIONS } from 'Source/constants';
import { DestinationTypeEnum } from 'Generated/schema';
import { useWizardContext, WizardPanelWrapper } from 'Components/Wizard';
import DestinationCard from './DestinationCard';

export type ForwardedStepContextValue = { destination: DestinationTypeEnum };

const destinationConfigs = Object.values(DESTINATIONS);

export const ChooseDestinationScreen: React.FC = () => {
  const { goToNextStep } = useWizardContext<ForwardedStepContextValue>();
  return (
    <React.Fragment>
      <WizardPanelWrapper.Heading
        title="Select an Alert Destination"
        subtitle="Add a new destination below to deliver alerts to a specific application for further triage"
      />
      <SimpleGrid columns={3} gap={5}>
        {destinationConfigs.map(destinationConfig => (
          <DestinationCard
            key={destinationConfig.title}
            logo={destinationConfig.logo}
            title={destinationConfig.title}
            onClick={() => {
              goToNextStep({ destination: destinationConfig.type });
            }}
          />
        ))}
      </SimpleGrid>
    </React.Fragment>
  );
};

export default React.memo(ChooseDestinationScreen);

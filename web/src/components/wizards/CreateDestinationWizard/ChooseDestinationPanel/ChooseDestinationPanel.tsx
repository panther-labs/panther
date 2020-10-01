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
import { Box, SimpleGrid } from 'pouncejs';
import { DESTINATIONS } from 'Source/constants';
import { EventEnum, SrcEnum, trackEvent } from 'Helpers/analytics';
import { useWizardContext, WizardPanel } from 'Components/Wizard';
import DestinationCard from './DestinationCard';
import { WizardData } from '../CreateDestinationWizard';

const destinationConfigs = Object.values(DESTINATIONS);

export const ChooseDestinationPanel: React.FC = () => {
  const { goToNextStep, setData } = useWizardContext<WizardData>();
  return (
    <Box maxWidth={700} mx="auto">
      <WizardPanel.Heading
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
              trackEvent({ event: EventEnum.PickedDestination, src: SrcEnum.Destinations, ctx: destinationConfig.type }); // prettier-ignore
              setData({ selectedDestinationType: destinationConfig.type });
              goToNextStep();
            }}
          />
        ))}
      </SimpleGrid>
    </Box>
  );
};

export default React.memo(ChooseDestinationPanel);

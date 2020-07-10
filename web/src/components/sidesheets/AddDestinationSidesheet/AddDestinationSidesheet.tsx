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

import { Box, FadeIn, SideSheet, SideSheetProps } from 'pouncejs';
import React from 'react';
import { DestinationTypeEnum } from 'Generated/schema';
import ChooseDestinationScreen from './ChooseDestinationScreen';
import ConfigureDestinationScreen from './ConfigureDestinationScreen';

export interface AddDestinationSidesheetProps extends SideSheetProps {
  destinationType: DestinationTypeEnum;
}

const AddDestinationSidesheet: React.FC<AddDestinationSidesheetProps> = ({
  destinationType,
  onClose,
  ...rest
}) => {
  const [chosenDestination, chooseDestination] = React.useState<DestinationTypeEnum>(null);

  const resetDestinationSelection = React.useCallback(() => chooseDestination(null), [
    chooseDestination,
  ]);

  return (
    <SideSheet
      aria-labelledby="destination-title"
      aria-describedby="destination-description"
      onClose={onClose}
      {...rest}
    >
      <Box width={465}>
        {chosenDestination ? (
          <FadeIn from="right">
            <ConfigureDestinationScreen
              destination={chosenDestination}
              onReset={resetDestinationSelection}
              onSuccess={onClose}
            />
          </FadeIn>
        ) : (
          <FadeIn from="bottom" offset={10}>
            <ChooseDestinationScreen chooseDestination={chooseDestination} />
          </FadeIn>
        )}
      </Box>
    </SideSheet>
  );
};

export default React.memo(AddDestinationSidesheet);

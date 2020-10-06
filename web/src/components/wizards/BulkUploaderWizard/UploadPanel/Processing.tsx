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
import { Box, Flex, Text, Button, Img } from 'pouncejs';
import animatedGears from 'Assets/gears-animated.svg';
import { WizardPanel } from 'Components/Wizard';

interface ProcessingUploaderProps {
  onAbort: () => void;
}

const ProcessingUploader: React.FC<ProcessingUploaderProps> = ({ onAbort }) => {
  return (
    <>
      <WizardPanel.Heading
        title="Bulk Upload your rules, policies & python modules"
        subtitle="If you have a collection of rules, policies, or python modules files, simply zip them together using any zip method you prefer and upload them here"
      />
      <Flex justify="center">
        <Box backgroundColor="navyblue-500" textAlign="center" p={6} minWidth={600}>
          <Text data-testid="processing-indicator" fontSize="medium">
            Your file is being processed…
          </Text>
          <Flex justify="center" mt={3}>
            <Flex
              align="center"
              justify="center"
              borderRadius="circle"
              backgroundColor="violet-500"
              width={74}
              height={74}
            >
              <Img src={animatedGears} alt="Animated gears" nativeWidth={43} nativeHeight={40} />
            </Flex>
          </Flex>
          <Box mt={4}>
            <Button onClick={onAbort} size="medium" variant="outline" variantColor="navyblue">
              Cancel
            </Button>
          </Box>
        </Box>
      </Flex>
    </>
  );
};

export default React.memo(ProcessingUploader);

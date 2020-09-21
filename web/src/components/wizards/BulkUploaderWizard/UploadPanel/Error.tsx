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
import { Box, Flex, Button, Text } from 'pouncejs';
import { WizardPanel } from 'Components/Wizard';

interface ErrorUploaderProps {
  errorMsg: string;
  onRestartUploading: () => void;
}

const ErrorUploader: React.FC<ErrorUploaderProps> = ({ errorMsg, onRestartUploading }) => {
  return (
    <>
      <WizardPanel.Heading
        title="Something went wrong!"
        subtitle="Have a look at the error below and try again. If the problem continues please contact us"
      />
      <Flex justify="center">
        <Box backgroundColor="pink-700" textAlign="center" p={6} minWidth={600}>
          <Text size="medium" fontWeight="bold">
            Could not upload your rules
          </Text>
          {errorMsg && (
            <Text fontSize="small" mt={1} fontStyle="italic">
              {errorMsg}
            </Text>
          )}
        </Box>
      </Flex>
      <Flex justify="center" mt={8} mb={4}>
        <Button onClick={onRestartUploading}>Try Again</Button>
      </Flex>
    </>
  );
};

export default React.memo(ErrorUploader);

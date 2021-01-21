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
import { SimpleGrid, Flex, Box, Text, Icon } from 'pouncejs';
import { WizardPanel, useWizardContext } from 'Components/Wizard';
import Rows from './Rows';
import { UploadDetections } from '../UploadPanel/graphql/uploadDetections.generated';

const BoxColumn: React.FC = props => <Box p={6} backgroundColor="navyblue-500" {...props} />;

const SuccessfulUpload: React.FC = () => {
  const { data } = useWizardContext<UploadDetections>();

  return (
    <WizardPanel>
      <WizardPanel.Heading
        title="Your file was successfuly processed and the following changes were made"
        subtitle="You can visit the corresponding pages to view or edit your modules, rules or policies"
      />
      <Flex justify="center" data-testid="success-indicator">
        <SimpleGrid gap={5} columns={4} mb={5}>
          <BoxColumn>
            <Flex mb={5} width={220} align="center">
              <Icon type="source-code" mr={4} />
              <Text fontWeight="bold">Python Modules</Text>
            </Flex>
            <Rows
              newItems={data?.uploadDetections?.newGlobals}
              modifiedItems={data?.uploadDetections?.modifiedGlobals}
              totalItems={data?.uploadDetections?.totalGlobals}
            />
          </BoxColumn>
          <BoxColumn>
            <Flex mb={5} width={220} align="center">
              <Icon type="rule" mr={4} />
              <Text fontWeight="bold">Rules</Text>
            </Flex>
            <Rows
              newItems={data?.uploadDetections?.newRules}
              modifiedItems={data?.uploadDetections?.modifiedRules}
              totalItems={data?.uploadDetections?.totalRules}
            />
          </BoxColumn>
          <BoxColumn>
            <Flex mb={5} width={220} align="center">
              <Icon type="policy" mr={4} />
              <Text fontWeight="bold">Policies</Text>
            </Flex>
            <Rows
              newItems={data?.uploadDetections?.newPolicies}
              modifiedItems={data?.uploadDetections?.modifiedPolicies}
              totalItems={data?.uploadDetections?.totalPolicies}
            />
          </BoxColumn>
          <BoxColumn>
            <Flex mb={5} width={220} align="center">
              <Icon type="data-models" mr={4} />
              <Text fontWeight="bold">Data Models</Text>
            </Flex>
            <Rows
              newItems={data?.uploadDetections?.newDataModels}
              modifiedItems={data?.uploadDetections?.modifiedDataModels}
              totalItems={data?.uploadDetections?.totalDataModels}
            />
          </BoxColumn>
        </SimpleGrid>
      </Flex>
      <WizardPanel.Actions>
        <WizardPanel.ActionStart>Upload another</WizardPanel.ActionStart>
      </WizardPanel.Actions>
    </WizardPanel>
  );
};

export default React.memo(SuccessfulUpload);

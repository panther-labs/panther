/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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

import React, { useState } from 'react';
import Panel from 'Components/panel';
import { Flex, Text } from 'pouncejs';
import CompanyInformationForm from 'Pages/general-settings/subcomponent/company-information-form';

interface CompanyInformationProps {
  displayName: string;
  email: string;
}

const CompanyInformation: React.FC<CompanyInformationProps> = ({ displayName, email }) => {
  const [isEditing, setEditingState] = useState<boolean>(false);

  return (
    <Panel size="large" title="Company Information">
      {isEditing ? (
        <CompanyInformationForm
          onSuccess={() => setEditingState(false)}
          displayName={displayName}
          email={email}
        />
      ) : (
        <CompanyInformationReadOnly displayName={displayName} email={email} />
      )}
    </Panel>
  );
};

const CompanyInformationReadOnly: React.FC<CompanyInformationProps> = ({ displayName, email }) => (
  <React.Fragment>
    <Flex mb={6}>
      <Text size="medium" minWidth={150} color="grey400" fontWeight="bold">
        NAME
      </Text>
      <Text size="medium" color="grey400">
        {displayName || '-'}
      </Text>
    </Flex>
    <Flex>
      <Text size="medium" minWidth={150} color="grey400" fontWeight="bold">
        EMAIL
      </Text>
      <Text size="medium" color="grey400">
        {email || '-'}
      </Text>
    </Flex>
  </React.Fragment>
);

export default CompanyInformation;

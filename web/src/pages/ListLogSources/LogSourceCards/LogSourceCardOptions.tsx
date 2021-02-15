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
import { Dropdown, DropdownButton, DropdownMenu, DropdownItem, DropdownLink } from 'pouncejs';
import { LogIntegration, S3LogIntegration, SqsLogSourceIntegration } from 'Generated/schema';
import useModal from 'Hooks/useModal';
import { MODALS } from 'Components/utils/Modal';
import urls from 'Source/urls';
import { LogIntegrationsEnum } from 'Source/constants';
import { Link as RRLink } from 'react-router-dom';
import GenericItemCard from 'Components/GenericItemCard';

interface LogSourceCardOptionsProps {
  source: LogIntegration;
}

const LogSourceCardOptions: React.FC<LogSourceCardOptionsProps> = ({ source }) => {
  const { showModal } = useModal();

  let description;
  let castedSource;
  let logSourceEditUrl;

  switch (source.integrationType) {
    case LogIntegrationsEnum.sqs:
      castedSource = source as SqsLogSourceIntegration;
      logSourceEditUrl = urls.logAnalysis.sources.edit(source.integrationId, 'sqs');
      break;
    case LogIntegrationsEnum.s3:
    default:
      castedSource = source as S3LogIntegration;
      description = `Deleting this source will not delete the associated Cloudformation stack. You will need to manually delete the stack ${castedSource.stackName} from the AWS Account ${castedSource.awsAccountId}`;
      if (castedSource.managedS3Resources?.topicARN) {
        description += `. The SNS topic created by Panther will also be kept (${castedSource.managedS3Resources.topicARN})`;
      }
      logSourceEditUrl = urls.logAnalysis.sources.edit(source.integrationId, 's3');
  }

  return (
    <Dropdown>
      <DropdownButton as={GenericItemCard.OptionsButton} />
      <DropdownMenu>
        <DropdownLink as={RRLink} to={logSourceEditUrl}>
          Edit
        </DropdownLink>
        <DropdownItem
          onSelect={() => {
            return showModal({
              modal: MODALS.DELETE_LOG_SOURCE,
              props: { source: castedSource, description },
            });
          }}
        >
          Delete
        </DropdownItem>
      </DropdownMenu>
    </Dropdown>
  );
};

export default React.memo(LogSourceCardOptions);

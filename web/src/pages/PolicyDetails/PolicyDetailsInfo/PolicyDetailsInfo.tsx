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
import { Box, Button, Icon, Flex, Card, Heading, Badge, Tooltip } from 'pouncejs';
import { PolicyDetails } from 'Generated/schema';
import urls from 'Source/urls';
import JsonViewer from 'Components/JsonViewer';
import Breadcrumbs from 'Components/Breadcrumbs';
import useModal from 'Hooks/useModal';
import { MODALS } from 'Components/utils/Modal';
import SeverityBadge from 'Components/badges/SeverityBadge';
import StatusBadge from 'Components/badges/StatusBadge';
import LinkButton from 'Components/buttons/LinkButton';

interface ResourceDetailsInfoProps {
  policy?: PolicyDetails;
}

const PolicyDetailsInfo: React.FC<ResourceDetailsInfoProps> = ({ policy }) => {
  const { showModal } = useModal();

  return (
    <React.Fragment>
      <Breadcrumbs.Actions>
        <Flex spacing={4} justify="flex-end">
          <LinkButton icon="pencil" to={urls.compliance.policies.edit(policy.id)}>
            Edit Policy
          </LinkButton>
          <Button
            variantColor="red"
            icon="trash"
            onClick={() =>
              showModal({
                modal: MODALS.DELETE_POLICY,
                props: { policy },
              })
            }
          >
            Delete Policy
          </Button>
        </Flex>
      </Breadcrumbs.Actions>

      <Card as="article" p={6}>
        <Flex as="header" align="center">
          <Heading
            fontWeight="bold"
            wordBreak="break-word"
            aria-describedby="policy-description"
            flexShrink={1}
            display="flex"
            alignItems="center"
            mr={100}
          >
            {policy.displayName || policy.id}

            <Tooltip
              content={
                <Flex spacing={3}>
                  <Flex direction="column" spacing={2}>
                    <Box id="policy-id-label">Policy ID</Box>
                    <Box id="resource-types-label">Resource Types</Box>
                  </Flex>
                  <Flex direction="column" spacing={2} fontWeight="bold">
                    <Box aria-labelledby="policy-id-label">{policy.id}</Box>
                    <Box aria-labelledby="resource-types-label">
                      {policy.resourceTypes.length > 0
                        ? policy.resourceTypes.map(resourceType => (
                            <Box key={resourceType}>{resourceType}</Box>
                          ))
                        : 'All resources'}
                    </Box>
                  </Flex>
                </Flex>
              }
            >
              <Icon color="navyblue-200" type="info" size="medium" verticalAlign="unset" ml={2} />
            </Tooltip>
          </Heading>
          <Flex spacing={2} as="ul" flexShrink={0} ml="auto">
            <Box as="li">
              <StatusBadge status={policy.complianceStatus} disabled={!policy.enabled} />
            </Box>
            <Box as="li">
              <SeverityBadge severity={policy.severity} />
            </Box>
            {policy.autoRemediationId && (
              <Tooltip
                content={
                  <Flex spacing={3}>
                    <Flex direction="column" spacing={2}>
                      <Box id="autoremediation-id-label">Auto Remediation ID</Box>
                      <Box id="autoremediation-parameters-label">Auto Remediation Parameters</Box>
                    </Flex>
                    <Flex direction="column" spacing={2} fontWeight="bold">
                      <Box aria-labelledby="autoremediation-id-label">
                        {policy.autoRemediationId}
                      </Box>
                      <Box aria-labelledby="autoremediation-parameters-label">
                        <JsonViewer data={JSON.parse(policy.autoRemediationParameters)} />
                      </Box>
                    </Flex>
                  </Flex>
                }
              >
                <Box as="li">
                  <Badge color="violet-400">
                    AUTO REMEDIATIATABLE
                    <Icon size="medium" type="check" my={-1} ml={2} p="2px" />
                  </Badge>
                </Box>
              </Tooltip>
            )}
          </Flex>
        </Flex>
      </Card>
    </React.Fragment>
  );
};

export default React.memo(PolicyDetailsInfo);

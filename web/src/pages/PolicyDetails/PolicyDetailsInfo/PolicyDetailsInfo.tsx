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
import { Link as RRLink } from 'react-router-dom';
import {
  Box,
  Button,
  Icon,
  SimpleGrid,
  Text,
  Link,
  Flex,
  Card,
  Heading,
  Badge,
  Tooltip,
} from 'pouncejs';
import { formatDatetime } from 'Helpers/utils';
import Linkify from 'Components/Linkify';
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
        <Flex as="header" align="center" mb={4} spacing={4}>
          <Heading fontWeight="bold" wordBreak="break-word" aria-describedby="policy-description">
            {policy.displayName || policy.id}
          </Heading>
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
            <Icon type="info" />
          </Tooltip>
        </Flex>
        <Flex spacing={4} as="ul" mb={6}>
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
                    <Box aria-labelledby="autoremediation-id-label">{policy.autoRemediationId}</Box>
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
        <Card variant="dark" as="section" p={4} mb={4}>
          <Text
            id="policy-description"
            fontStyle={!policy.description ? 'italic' : 'normal'}
            mb={6}
          >
            {policy.description || 'No description found for policy'}
          </Text>
          <SimpleGrid columns={2} spacing={5}>
            <Flex direction="column" spacing={2}>
              <Box
                color="navyblue-100"
                fontSize="small-medium"
                aria-describedby="runbook-description"
              >
                Runbook
              </Box>
              {policy.runbook ? (
                <Linkify id="runbook-description">{policy.runbook}</Linkify>
              ) : (
                <Box fontStyle="italic" color="navyblue-100" id="runbook-description">
                  No runbook specified
                </Box>
              )}
            </Flex>
            <Flex direction="column" spacing={2}>
              <Box
                color="navyblue-100"
                fontSize="small-medium"
                aria-describedby="reference-description"
              >
                Reference
              </Box>
              {policy.reference ? (
                <Linkify id="reference-description">{policy.reference}</Linkify>
              ) : (
                <Box fontStyle="italic" color="navyblue-100" id="reference-description">
                  No reference specified
                </Box>
              )}
            </Flex>
          </SimpleGrid>
        </Card>
        <Card variant="dark" as="section" p={4}>
          <SimpleGrid columns={2} spacing={5} fontSize="small-medium">
            <Box>
              <SimpleGrid gap={2} columns={8} spacing={2}>
                <Box gridColumn="1/3" color="navyblue-100" aria-describedby="tags-list">
                  Tags
                </Box>
                {policy.tags.length > 0 ? (
                  <Box gridColumn="3/8" id="tags-list">
                    {policy.tags.map((tag, index) => (
                      <Link
                        key={tag}
                        as={RRLink}
                        to={`${urls.compliance.policies.list()}?page=1&tags[]=${tag}`}
                      >
                        {tag}
                        {index !== policy.tags.length - 1 ? ', ' : null}
                      </Link>
                    ))}
                  </Box>
                ) : (
                  <Box fontStyle="italic" color="navyblue-100" gridColumn="3/8" id="tags-list">
                    This policy has no tags
                  </Box>
                )}

                <Box gridColumn="1/3" color="navyblue-100" aria-describedby="ignore-patterns-list">
                  Ignore Pattens
                </Box>
                {policy.suppressions.length > 0 ? (
                  <Box gridColumn="3/8" id="ignore-patterns-list">
                    {policy.suppressions?.length > 0 ? policy.suppressions.join(', ') : null}
                  </Box>
                ) : (
                  <Box gridColumn="3/8" id="ignore-patterns-list">
                    No particular resource is ignored for this policy
                  </Box>
                )}
              </SimpleGrid>
            </Box>
            <Box>
              <SimpleGrid gap={2} columns={8} spacing={2}>
                <Box gridColumn="1/3" color="navyblue-100" aria-describedby="created-at">
                  Created
                </Box>
                <Box gridColumn="3/8" id="created-at">
                  {formatDatetime(policy.createdAt)}
                </Box>

                <Box gridColumn="1/3" color="navyblue-100" aria-describedby="updated-at">
                  Modified
                </Box>
                <Box gridColumn="3/8" id="updated-at">
                  {formatDatetime(policy.lastModified)}
                </Box>
              </SimpleGrid>
            </Box>
          </SimpleGrid>
        </Card>
      </Card>
    </React.Fragment>
  );
};

export default React.memo(PolicyDetailsInfo);

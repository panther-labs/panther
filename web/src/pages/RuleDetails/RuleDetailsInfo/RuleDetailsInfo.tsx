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
import { Box, Button, Icon, Flex, Card, Heading, Tooltip } from 'pouncejs';
import { RuleDetails } from 'Generated/schema';
import urls from 'Source/urls';
import useModal from 'Hooks/useModal';
import { MODALS } from 'Components/utils/Modal';
import SeverityBadge from 'Components/badges/SeverityBadge';
import StatusBadge from 'Components/badges/StatusBadge';
import LinkButton from 'Components/buttons/LinkButton';
import Breadcrumbs from 'Components/Breadcrumbs';

interface ResourceDetailsInfoProps {
  rule?: RuleDetails;
}

const RuleDetailsInfo: React.FC<ResourceDetailsInfoProps> = ({ rule }) => {
  const { showModal } = useModal();

  return (
    <React.Fragment>
      <Breadcrumbs.Actions>
        <Flex spacing={4} justify="flex-end">
          <LinkButton
            icon="pencil"
            aria-label="Edit Rule"
            to={urls.logAnalysis.rules.edit(rule.id)}
          >
            Edit Rule
          </LinkButton>
          <Button
            icon="trash"
            variantColor="red"
            aria-label="Delete Rule"
            onClick={() =>
              showModal({
                modal: MODALS.DELETE_RULE,
                props: { rule },
              })
            }
          >
            Delete Rule
          </Button>
        </Flex>
      </Breadcrumbs.Actions>
      <Card as="article" p={6}>
        <Flex as="header" align="center">
          <Heading
            fontWeight="bold"
            wordBreak="break-word"
            aria-describedby="rule-description"
            flexShrink={1}
            display="flex"
            alignItems="center"
            mr={100}
          >
            {rule.displayName || rule.id}
            <Tooltip
              content={
                <Flex spacing={3}>
                  <Flex direction="column" spacing={2}>
                    <Box id="rule-id-label">Rule ID</Box>
                    <Box id="log-types-label">Log Types</Box>
                  </Flex>
                  <Flex direction="column" spacing={2} fontWeight="bold">
                    <Box aria-labelledby="rule-id-label">{rule.id}</Box>
                    <Box aria-labelledby="log-types-label">
                      {rule.logTypes.map(logType => (
                        <Box key={logType}>{logType}</Box>
                      ))}
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
              <StatusBadge status="ENABLED" disabled={!rule.enabled} />
            </Box>
            <Box as="li">
              <SeverityBadge severity={rule.severity} />
            </Box>
          </Flex>
        </Flex>
      </Card>
    </React.Fragment>
  );
};

export default React.memo(RuleDetailsInfo);

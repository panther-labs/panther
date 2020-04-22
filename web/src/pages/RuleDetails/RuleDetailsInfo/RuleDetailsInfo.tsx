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
import { Badge, Box, Button, Icon, Label, SimpleGrid, Text, Link } from 'pouncejs';
import { formatDatetime, minutesToString } from 'Helpers/utils';
import Panel from 'Components/Panel';
import Linkify from 'Components/Linkify';
import { RuleDetails } from 'Generated/schema';
import { SEVERITY_COLOR_MAP } from 'Source/constants';
import urls from 'Source/urls';
import useModal from 'Hooks/useModal';
import { MODALS } from 'Components/utils/Modal';

interface ResourceDetailsInfoProps {
  rule?: RuleDetails;
}

const RuleDetailsInfo: React.FC<ResourceDetailsInfoProps> = ({ rule }) => {
  const { showModal } = useModal();

  return (
    <Panel
      size="large"
      title="Rule Details"
      actions={
        <Box>
          <Button
            size="large"
            variant="default"
            mr={4}
            as={RRLink}
            to={urls.logAnalysis.rules.edit(rule.id)}
          >
            Edit
          </Button>
          <Button
            size="large"
            variant="default"
            color="red300"
            onClick={() =>
              showModal({
                modal: MODALS.DELETE_RULE,
                props: { rule },
              })
            }
          >
            Delete
          </Button>
        </Box>
      }
    >
      <SimpleGrid columns={3} spacing={6}>
        <Box my={1}>
          <Label mb={1} as="div" size="small" color="grey300">
            ID
          </Label>
          <Text size="medium" color="black">
            {rule.id}
          </Text>
        </Box>
        <Box my={1}>
          <Label mb={1} as="div" size="small" color="grey300">
            DISPLAY NAME
          </Label>
          <Text size="medium" color={rule.displayName ? 'black' : 'grey200'}>
            {rule.displayName || 'No display name found'}
          </Text>
        </Box>
        <Box my={1}>
          <Label mb={1} as="div" size="small" color="grey300">
            ENABLED
          </Label>
          {rule.enabled ? (
            <Icon type="check" color="green300" size="large" />
          ) : (
            <Icon type="close" color="red300" size="large" />
          )}
        </Box>
        <Box my={1}>
          <Label mb={1} as="div" size="small" color="grey300">
            REFERENCE
          </Label>
          {rule.reference ? (
            <Linkify>{rule.reference}</Linkify>
          ) : (
            <Text size="medium" color="grey200">
              No reference available
            </Text>
          )}
        </Box>
        <Box my={1}>
          <Label mb={1} as="div" size="small" color="grey300">
            LOG TYPES
          </Label>
          {rule.logTypes.length ? (
            rule.logTypes.map(logType => (
              <Text size="medium" color="black" key={logType}>
                {logType}
              </Text>
            ))
          ) : (
            <Text size="medium" color="black">
              All logs
            </Text>
          )}
        </Box>
        <Box my={1}>
          <Label mb={1} as="div" size="small" color="grey300">
            DESCRIPTION
          </Label>
          {rule.description ? (
            <Linkify>{rule.description}</Linkify>
          ) : (
            <Text size="medium" color="grey200">
              No description available
            </Text>
          )}
        </Box>
        <Box my={1}>
          <Label mb={1} as="div" size="small" color="grey300">
            RUNBOOK
          </Label>
          {rule.runbook ? (
            <Linkify>{rule.runbook}</Linkify>
          ) : (
            <Text size="medium" color="grey200">
              No runbook available
            </Text>
          )}
        </Box>
        <Box my={1}>
          <Label mb={1} as="div" size="small" color="grey300">
            SEVERITY
          </Label>
          <Badge color={SEVERITY_COLOR_MAP[rule.severity]}>{rule.severity}</Badge>
        </Box>
        <Box my={1}>
          <Label mb={1} as="div" size="small" color="grey300">
            TAGS
          </Label>
          {rule.tags.length ? (
            rule.tags.map((tag, index) => (
              <Link
                key={tag}
                fontSize={2}
                color="blue300"
                as={RRLink}
                to={`${urls.logAnalysis.rules.list()}?page=1&tags[]=${tag}`}
              >
                {tag}
                {index !== rule.tags.length - 1 ? ', ' : null}
              </Link>
            ))
          ) : (
            <Text size="medium" color="grey200">
              No tags assigned
            </Text>
          )}
        </Box>
        <Box my={1}>
          <Label mb={1} as="div" size="small" color="grey300">
            CREATED
          </Label>
          <Text size="medium" color="black">
            {formatDatetime(rule.createdAt)}
          </Text>
        </Box>
        <Box my={1}>
          <Label mb={1} as="div" size="small" color="grey300">
            LAST MODIFIED
          </Label>
          <Text size="medium" color="black">
            {formatDatetime(rule.lastModified)}
          </Text>
        </Box>
        <Box my={1}>
          <Label mb={1} as="div" size="small" color="grey300">
            DEDUPLICATION PERIOD TIME
          </Label>
          <Text size="medium" color={rule.displayName ? 'black' : 'grey200'}>
            {minutesToString(rule.dedupPeriodMinutes)}
          </Text>
        </Box>
      </SimpleGrid>
    </Panel>
  );
};

export default React.memo(RuleDetailsInfo);

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

import React from 'react';
import { Link } from 'react-router-dom';
import { Badge, Box, Button, Grid, Icon, Label, Text } from 'pouncejs';
import { formatDatetime } from 'Helpers/utils';
import Panel from 'Components/panel';
import { RuleDetails } from 'Generated/schema';
import { SEVERITY_COLOR_MAP, READONLY_ROLES_ARRAY } from 'Source/constants';
import { LinkifyProps } from 'linkifyjs/react';
import urls from 'Source/urls';
import useModal from 'Hooks/useModal';
import { MODALS } from 'Components/utils/modal-context';
import RoleRestrictedAccess from 'Components/role-restricted-access';

const Linkify = React.lazy(() =>
  import(/* webpackChunkName: "linkify" */ 'linkifyjs/react.js')
) as React.FC<LinkifyProps>;

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
        <RoleRestrictedAccess deniedRoles={READONLY_ROLES_ARRAY}>
          <Box>
            <Button
              size="large"
              variant="default"
              mr={4}
              is={Link}
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
        </RoleRestrictedAccess>
      }
    >
      <Grid gridTemplateColumns="repeat(3, 1fr)" gridGap={6}>
        <Box my={1}>
          <Label mb={1} is="div" size="small" color="grey300">
            ID
          </Label>
          <Text size="medium" color="black">
            {rule.id}
          </Text>
        </Box>
        <Box my={1}>
          <Label mb={1} is="div" size="small" color="grey300">
            DISPLAY NAME
          </Label>
          <Text size="medium" color={rule.displayName ? 'black' : 'grey200'}>
            {rule.displayName || 'No display name found'}
          </Text>
        </Box>
        <Box my={1}>
          <Label mb={1} is="div" size="small" color="grey300">
            ENABLED
          </Label>
          {rule.enabled ? (
            <Icon type="check" color="green300" size="large" />
          ) : (
            <Icon type="close" color="red300" size="large" />
          )}
        </Box>
        <Box my={1}>
          <Label mb={1} is="div" size="small" color="grey300">
            REFERENCE
          </Label>
          <Text size="medium" color={rule.reference ? 'blue300' : 'grey200'}>
            {rule.reference ? (
              <a href={rule.reference} target="_blank" rel="noopener noreferrer">
                {rule.reference}
              </a>
            ) : (
              'No reference found'
            )}
          </Text>
        </Box>
        <Box my={1}>
          <Label mb={1} is="div" size="small" color="grey300">
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
          <Label mb={1} is="div" size="small" color="grey300">
            DESCRIPTION
          </Label>
          <Text size="medium" color={rule.description ? 'black' : 'grey200'}>
            <React.Suspense fallback={<span>{rule.description}</span>}>
              <Linkify>{rule.description || 'No description available'}</Linkify>
            </React.Suspense>
          </Text>
        </Box>
        <Box my={1}>
          <Label mb={1} is="div" size="small" color="grey300">
            RUNBOOK
          </Label>
          <Text size="medium" color={rule.runbook ? 'black' : 'grey200'}>
            <React.Suspense fallback={<span>{rule.runbook}</span>}>
              <Linkify>{rule.runbook || 'No runbook available'}</Linkify>
            </React.Suspense>
          </Text>
        </Box>
        <Box my={1}>
          <Label mb={1} is="div" size="small" color="grey300">
            SEVERITY
          </Label>
          <Badge color={SEVERITY_COLOR_MAP[rule.severity]}>{rule.severity}</Badge>
        </Box>
        <Box my={1}>
          <Label mb={1} is="div" size="small" color="grey300">
            TAGS
          </Label>
          {rule.tags.length ? (
            rule.tags.map((tag, index) => (
              <Text size="medium" color="black" key={tag} is="span">
                {tag}
                {index !== rule.tags.length - 1 ? ', ' : null}
              </Text>
            ))
          ) : (
            <Text size="medium" color="grey200">
              No tags assigned
            </Text>
          )}
        </Box>
        <Box my={1}>
          <Label mb={1} is="div" size="small" color="grey300">
            CREATED
          </Label>
          <Text size="medium" color="black">
            {formatDatetime(rule.createdAt)}
          </Text>
        </Box>
        <Box my={1}>
          <Label mb={1} is="div" size="small" color="grey300">
            LAST MODIFIED
          </Label>
          <Text size="medium" color="black">
            {formatDatetime(rule.lastModified)}
          </Text>
        </Box>
      </Grid>
    </Panel>
  );
};

export default React.memo(RuleDetailsInfo);

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
import { render } from 'test-utils';
import logo from 'Assets/aws-minimal-logo.svg';
import { Box, Flex } from 'pouncejs';
import GenericItemCard from './index';

describe('GenericItemCard', () => {
  it('renders a step', () => {
    const { container } = render(
      <GenericItemCard>
        <GenericItemCard.Logo src={logo} />
        <GenericItemCard.Body>
          <GenericItemCard.ValuesGroup>
            <GenericItemCard.Value label="Test label" value="String value" />
            <GenericItemCard.Value label="Test label" value="Another value" />
            <GenericItemCard.LineBreak />
            <GenericItemCard.Value
              label="Test tailormade component"
              value={<Box>Cool right</Box>}
            />
            <Flex ml="auto" mr={0} align="flex-end">
              <Box>Test custom children</Box>
            </Flex>
            <GenericItemCard.Value value="without label" />
          </GenericItemCard.ValuesGroup>
        </GenericItemCard.Body>
      </GenericItemCard>
    );

    expect(container).toMatchSnapshot();
  });
});

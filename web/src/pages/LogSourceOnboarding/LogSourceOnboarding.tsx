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
import { Box, Card, FadeIn, Heading, Text } from 'pouncejs';
import urls from 'Source/urls';
import LogSourceCard from 'Components/LogSourceCard';
import s3Logo from 'Assets/s3-minimal-logo.svg';
import duoLogo from 'Assets/duo-minimal-logo.svg';
import eventBridgeLogo from 'Assets/eventbridge-minimal-logo.svg';
import oktaLogo from 'Assets/okta-minimal-logo.svg';
import withSEO from 'Hoc/withSEO';

const logSourcesConfig = [
  {
    logo: s3Logo,
    title: 'Amazon S3',
    type: 'S3',
  },
  {
    logo: eventBridgeLogo,
    title: 'Amazon EventBridge',
    type: 'eventbridge',
    disabled: true,
  },
  {
    logo: oktaLogo,
    title: 'Okta',
    type: 'okta',
    disabled: true,
  },
  {
    logo: duoLogo,
    title: 'Duo Security',
    type: 'duo',
    disabled: true,
  },
];
const LogSourceOnboarding: React.FC = () => {
  return (
    <FadeIn>
      <Card p={9} mb={6}>
        <Box width={600} m="auto" textAlign="center">
          <Heading mb={4}>Select a Source Type</Heading>
          <Text color="gray-300" mb={8}>
            Please select the source type you want to configure from the list below
          </Text>
          {logSourcesConfig.map(config => (
            <LogSourceCard
              key={config.title}
              logo={config.logo}
              title={config.title}
              disabled={config.disabled}
              to={`${urls.logAnalysis.sources.create(config.type)}`}
            />
          ))}
        </Box>
      </Card>
    </FadeIn>
  );
};

export default withSEO({ title: 'Create Log Source' })(LogSourceOnboarding);

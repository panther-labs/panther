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
import { Box, Card, FadeIn, SimpleGrid } from 'pouncejs';
import urls from 'Source/urls';
import s3Logo from 'Assets/s3-minimal-logo.svg';
import sqsLogo from 'Assets/sqs-minimal-logo.svg';
import duoLogo from 'Assets/duo-minimal-logo.svg';
import eventBridgeLogo from 'Assets/eventbridge-minimal-logo.svg';
import oktaLogo from 'Assets/okta-minimal-logo.svg';
import gsuiteLogo from 'Assets/gsuite-minimal-logo.svg';
import boxLogo from 'Assets/box-logo.svg';
import slackLogo from 'Assets/slack-minimal-logo.svg';
import crowdstrikeLogo from 'Assets/crowdstrike-minimal-logo.svg';
import withSEO from 'Hoc/withSEO';
import { WizardPanel } from 'Components/Wizard';
import LogSourceCard from './LogSourceCard';

const logSourcesConfig = [
  {
    logo: s3Logo,
    title: 'Amazon S3',
    type: 'S3',
  },
  {
    logo: sqsLogo,
    title: 'Amazon SQS',
    type: 'SQS',
  },
  {
    logo: eventBridgeLogo,
    title: 'EventBridge',
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
    logo: crowdstrikeLogo,
    title: 'Crowdstrike',
    type: 'crowdstrike',
    disabled: true,
  },
  {
    logo: gsuiteLogo,
    title: 'G Suite',
    type: 'gsuite',
    disabled: true,
  },
  {
    logo: slackLogo,
    title: 'Slack',
    type: 'slack',
    disabled: true,
  },
  {
    logo: duoLogo,
    title: 'Duo',
    type: 'duo',
    disabled: true,
  },
  {
    logo: boxLogo,
    title: 'Box',
    type: 'box',
    disabled: true,
  },
];
const LogSourceOnboarding: React.FC = () => {
  return (
    <FadeIn>
      <Card p={6} mb={6}>
        <WizardPanel>
          <WizardPanel.Heading
            title="Select a Source Type"
            subtitle="Please select the source type you want to configure from the list below"
          />
          <Box width={820} mx="auto">
            <SimpleGrid gap={4} columns={3} pb={6}>
              {logSourcesConfig.map(config => (
                <LogSourceCard
                  key={config.title}
                  logo={config.logo}
                  title={config.title}
                  disabled={config.disabled}
                  to={`${urls.integrations.logSources.create(config.type)}`}
                />
              ))}
            </SimpleGrid>
          </Box>
        </WizardPanel>
      </Card>
    </FadeIn>
  );
};

export default withSEO({ title: 'Create Log Source' })(LogSourceOnboarding);

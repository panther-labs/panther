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
import { Box, Card, Heading, Link, SimpleGrid, Text } from 'pouncejs';
import slackLogo from 'Assets/slack-minimal-logo.svg';
import pantherEnterpriseLogo from 'Assets/panther-enterprise-minimal-logo.svg';
import feedbackIcon from 'Assets/illustrations/feedback.svg';
import mailIcon from 'Assets/illustrations/mail.svg';
import withSEO from 'Hoc/withSEO';
import { PANTHER_DOCS_LINK } from 'Source/constants';
import useTrackPageView from 'Hooks/useTrackPageView';
import { PageViewEnum } from 'Helpers/analytics';
import SupportItemCard from './SupportItemCard';

export const supportLinks = {
  slack: 'https://slack.runpanther.io',
  email: 'support@runpanther.io',
  productBoard: 'https://portal.productboard.com/runpanther/1-product-portal/tabs/2-in-progress',
  demo: 'https://runpanther.io/request-a-demo/',
};

const SupportPage: React.FC = () => {
  useTrackPageView(PageViewEnum.Support);
  return (
    <Card p={9} as="article">
      <Box as="header" mb={10} textAlign="center">
        <Heading size="large" fontWeight="medium">
          Get the support you need
        </Heading>
        <Text fontSize="large" mt={2} color="gray-300">
          You can also visit{' '}
          <Link external href={PANTHER_DOCS_LINK}>
            {' '}
            our documentation
          </Link>{' '}
          if you are facing any problems
        </Text>
      </Box>
      <SimpleGrid columns={2} spacing={6} px={10}>
        <SupportItemCard
          title="Join our Community Slack"
          subtitle="We’re proud of our growing community in Slack. Join us in supporting each other!"
          imgSrc={slackLogo}
          cta={
            <Link external href={supportLinks.slack}>
              Join Now
            </Link>
          }
        />
        <SupportItemCard
          title="Send us Product Feedback"
          subtitle="If you found a bug, have an idea for a new feature or simply want to send us your thoughts, don’t hesitate!"
          imgSrc={feedbackIcon}
          cta={
            <Link external href={supportLinks.productBoard}>
              Send your Feedback
            </Link>
          }
        />
        <SupportItemCard
          title="Send us an E-mail"
          subtitle="If you have any question about our product or simply want to reach out to us, you can send us an e-mail."
          imgSrc={mailIcon}
          cta={
            <Link external href={`mailto:${supportLinks.email}`}>
              {supportLinks.email}
            </Link>
          }
        />
        <SupportItemCard
          title="Panther Enterprise"
          subtitle="Get a demo of our enterprise functionality. We'll answer your questions and prepare you for a trial."
          imgSrc={pantherEnterpriseLogo}
          cta={
            <Link external href={supportLinks.demo}>
              Request a demo
            </Link>
          }
        />
      </SimpleGrid>
    </Card>
  );
};

export default withSEO({ title: 'Support' })(SupportPage);

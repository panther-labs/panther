import React from 'react';
import { Box, Flex, Card, Grid, Icon, Text, Heading } from 'pouncejs';
import { Link } from 'react-router-dom';
import logo from 'Source/assets/panther-minimal-logo.svg';
import urls from 'Source/urls';
import { PANTHER_SCHEMA_DOCS_LINK } from 'Source/constants';

const LandingPage: React.FC = () => {
  return (
    <Box>
      <Box is="article">
        <Box my={60}>
          <Flex width={1} justifyContent="center">
            <img src={logo} alt="Panther logo" width="60" height="60" />
          </Flex>
          <Heading is="h1" size="large" textAlign="center" color="grey500" mb={2} mt={5}>
            Welcome!
          </Heading>
          <Heading is="h2" size="medium" textAlign="center" color="grey300">
            Let{"'"}s get you started with Panther
          </Heading>
        </Box>
        <Card mb={6} is="section">
          <Grid gridTemplateColumns="repeat(3, 1fr)" py={5}>
            <Flex flexDirection="column" alignItems="center" justifyContent="center" px={10} py={5}>
              <Icon color="grey300" type="user" mb={4} size="large" />
              <Text size="large" is="h4" color="grey500" mb={4}>
                Invite your team
              </Text>
              <Text size="medium" is="p" color="grey300" textAlign="center" maxWidth={250}>
                Create multiple users and get your team onboarded to Panther
              </Text>
              <Text color="blue300" p={4} is={Link} to={urls.settings.users()} size="large">
                Manage Users
              </Text>
            </Flex>
            <Flex flexDirection="column" justifyContent="center" alignItems="center" px={10} py={5}>
              <Icon color="grey300" type="infra-source" mb={4} size="large" />
              <Text size="large" is="h4" color="grey500" mb={4}>
                Setup Infrastructure Monitoring
              </Text>
              <Text size="medium" is="p" color="grey300" textAlign="center" maxWidth={250}>
                Connect AWS accounts, scan resources and detect misconfigurations
              </Text>
              <Text
                color="blue300"
                p={4}
                is={Link}
                to={urls.compliance.sources.create()}
                size="large"
              >
                Onboard an AWS account
              </Text>
            </Flex>
            <Flex flexDirection="column" justifyContent="center" alignItems="center" px={10} py={5}>
              <Icon color="grey300" type="log-source" mb={4} size="large" />
              <Text size="large" is="h4" color="grey500" mb={4}>
                Setup your Log Sources
              </Text>
              <Text size="medium" is="p" color="grey300" textAlign="center" maxWidth={250}>
                Connect your log buckets and analyze data with rules
              </Text>
              <Text
                color="blue300"
                p={4}
                is={Link}
                to={urls.logAnalysis.sources.create()}
                size="large"
              >
                Connect S3 Buckets
              </Text>
            </Flex>
          </Grid>
        </Card>

        <Card mb={6} is="section">
          <Grid gridTemplateColumns="repeat(3, 1fr)" py={5}>
            <Flex flexDirection="column" alignItems="center" justifyContent="center" px={10} py={5}>
              <Icon color="grey300" type="output" mb={4} size="large" />
              <Text size="large" is="h4" color="grey500" mb={4}>
                Setup an Alert Destination
              </Text>
              <Text size="medium" is="p" color="grey300" textAlign="center" maxWidth={250}>
                Add notification channels for suspicious activity or misconfiguration detection
              </Text>
              <Text color="blue300" p={4} is={Link} to={urls.settings.destinations()} size="large">
                Setup Destinations
              </Text>
            </Flex>

            <Flex flexDirection="column" alignItems="center" justifyContent="center" px={10} py={5}>
              <Icon color="grey300" type="policy" mb={4} size="large" />
              <Text size="large" is="h4" color="grey500" mb={4}>
                Write Infrastructure Policies
              </Text>
              <Text size="medium" is="p" color="grey300" textAlign="center" maxWidth={250}>
                Create policies that your AWS infrastructure must abide to
              </Text>
              <Text
                color="blue300"
                p={4}
                is={Link}
                to={urls.compliance.policies.create()}
                size="large"
              >
                Create a Policy
              </Text>
            </Flex>
            <Flex flexDirection="column" alignItems="center" justifyContent="center" px={10} py={5}>
              <Icon color="grey300" type="rule" mb={4} size="large" />
              <Text size="large" is="h4" color="grey500" mb={4}>
                Write Log Detection Rules
              </Text>
              <Text size="medium" is="p" color="grey300" textAlign="center" maxWidth={250}>
                Create rules to run against your logs and trigger alerts on suspicious activity
              </Text>
              <Text
                color="blue300"
                p={4}
                is={Link}
                to={urls.logAnalysis.rules.create()}
                size="large"
              >
                Create a Rule
              </Text>
            </Flex>
          </Grid>
        </Card>
        <Card mb={6} is="section">
          <Grid gridTemplateColumns="repeat(3, 1fr)" py={5}>
            <Flex flexDirection="column" alignItems="center" justifyContent="center" px={10} py={5}>
              <Icon color="grey300" type="alert" mb={4} size="large" />
              <Text size="large" is="h4" color="grey500" mb={4}>
                Triage Alerts
              </Text>
              <Text size="medium" is="p" color="grey300" textAlign="center" maxWidth={250}>
                View alerts about suspicious activity according to your Rules
              </Text>
              <Text
                color="blue300"
                p={4}
                is={Link}
                to={urls.logAnalysis.alerts.list()}
                size="large"
              >
                View Alerts
              </Text>
            </Flex>
            <Flex flexDirection="column" alignItems="center" justifyContent="center" px={10} py={5}>
              <Icon color="grey300" type="resource" mb={4} size="large" />
              <Text size="large" is="h4" color="grey500" mb={4}>
                Search through Resources
              </Text>
              <Text size="medium" is="p" color="grey300" textAlign="center" maxWidth={250}>
                View your connected AWS resources and monitor their health
              </Text>
              <Text
                color="blue300"
                p={4}
                is={Link}
                to={urls.compliance.resources.list()}
                size="large"
              >
                View Resources
              </Text>
            </Flex>
            <Flex flexDirection="column" alignItems="center" justifyContent="center" px={10} py={5}>
              <Icon color="grey300" type="search" mb={4} size="large" />
              <Text size="large" is="h4" color="grey500" mb={4}>
                Query Logs with Athena
              </Text>
              <Text size="medium" is="p" color="grey300" textAlign="center" maxWidth={250}>
                Use AWS Athena to write complex queries against formatted logs
              </Text>
              <Text
                color="blue300"
                p={4}
                is="a"
                target="_blank"
                rel="noopener noreferrer"
                href={`https://${process.env.AWS_REGION}.console.aws.amazon.com/athena/`}
                size="large"
              >
                Launch Athena
              </Text>
            </Flex>
          </Grid>
        </Card>
      </Box>
      <Box borderTop="1px solid" borderColor="grey100" my={60}>
        <Box is="header" my={10}>
          <Heading is="h1" size="large" textAlign="center" color="grey500" mb={4}>
            The following links may seem helpful
          </Heading>
          <Heading is="h2" size="medium" textAlign="center" color="grey300">
            We{"'"}ve got some things to make you stick around a little bit more.
          </Heading>
        </Box>
        <Grid gridTemplateColumns="repeat(3, 1fr)" py={5} gridGap={6}>
          <Card p={9} is="article">
            <Heading size="medium" color="grey500" is="h4" mb={3}>
              Our Blog
            </Heading>
            <Text size="medium" is="p" color="grey300" mb={3}>
              Learn tips and best practices on how to keep your account safe
            </Text>
            <Text
              color="blue300"
              py={4}
              is="a"
              href="http://blog.runpanther.io/"
              rel="noopener noreferrer"
              target="_blank"
              size="large"
            >
              Visit our blog
            </Text>
          </Card>
          <Card p={9} is="article">
            <Heading size="medium" color="grey500" is="h4" mb={3}>
              Panther Documentation
            </Heading>
            <Text size="medium" is="p" color="grey300" mb={3}>
              Learn more about Panther and how can you best harness its power to secure your
              business
            </Text>
            <Text
              color="blue300"
              py={4}
              is="a"
              href={PANTHER_SCHEMA_DOCS_LINK}
              size="large"
              target="_blank"
              rel="noopener noreferrer"
            >
              Discover Panther
            </Text>
          </Card>
          <Card p={9} is="article">
            <Heading size="medium" color="grey500" is="h4" mb={3}>
              Need support?
            </Heading>
            <Text size="medium" is="p" color="grey300" mb={3}>
              Facing issues or want to learn more about Panther? Get in touch with us!
            </Text>
            <Text
              color="blue300"
              py={4}
              is="a"
              size="large"
              target="_blank"
              rel="noopener noreferrer"
              href="mailto:contact@runpanther.io"
            >
              Contact us
            </Text>
          </Card>
        </Grid>
      </Box>
    </Box>
  );
};

export default LandingPage;

import React from 'react';
import { Box } from 'pouncejs';
import { LinkifyProps } from 'linkifyjs/react';
import { css } from '@emotion/core';

const OriginalReactLinkify = React.lazy(() =>
  import(/* webpackChunkName: "linkify" */ 'linkifyjs/react.js')
) as React.FC<LinkifyProps>;

const linkifyOptions = {
  attributes: {
    rel: 'noopener noreferrer',
  },
  className: '',
  defaultProtocol: 'https',
};

const Linkify: React.FC = ({ children }) => {
  return (
    <Box
      css={css`
        word-break: break-word;
      `}
    >
      <React.Suspense fallback={<div>{children}</div>}>
        <OriginalReactLinkify options={linkifyOptions}>{children}</OriginalReactLinkify>
      </React.Suspense>
    </Box>
  );
};

export default Linkify;

import React from 'react';
import { FadeIn, FadeInProps } from 'pouncejs';

type FadeInTrailProps = Omit<FadeInProps, 'delay'>;

const FadeInTrail: React.FC<FadeInTrailProps> = ({ children, ...rest }) => {
  return (
    <React.Fragment>
      {React.Children.map(children, (child, index) => (
        <FadeIn delay={50 * index} {...rest}>
          {child}
        </FadeIn>
      ))}
    </React.Fragment>
  );
};

export default FadeInTrail;

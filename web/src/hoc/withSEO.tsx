import React from 'react';
import { Helmet } from 'react-helmet';
import useRouter from 'Hooks/useRouter';
import { RouteComponentProps } from 'react-router';

interface Options {
  title: string | ((routerData: RouteComponentProps<any, undefined>) => string);
}

function withSEO<P>({ title }: Options) {
  return (Component: React.FC<P>) => {
    const ComponentWithSEO: React.FC<P> = props => {
      const routerData = useRouter();

      return (
        <React.Fragment>
          <Helmet titleTemplate="%s | Panther">
            <title>{typeof title === 'string' ? title : title(routerData)}</title>
          </Helmet>
          <Component {...props} />
        </React.Fragment>
      );
    };
    return ComponentWithSEO;
  };
}

export default withSEO;

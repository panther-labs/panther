import React from 'react';
import { Button, useSnackbar } from 'pouncejs';
import { useSQLShellContext } from 'Pages/SQLShell/SQLShellContext';
import { useGetLogQueryDownloadUrlLazyQuery } from './graphql/getLogQueryDownloadUrl.generated';

interface DownloadButtonProps {
  isQuerySuccessful: boolean;
}

const DownloadButton: React.FC<DownloadButtonProps> = ({ isQuerySuccessful }) => {
  const {
    state: { queryId },
  } = useSQLShellContext();
  const { pushSnackbar } = useSnackbar();
  const [getDownloadUrl, { loading }] = useGetLogQueryDownloadUrlLazyQuery({
    variables: {
      input: {
        queryId,
      },
    },
    onCompleted: data => {
      if (data.getLogQueryDownloadUrl.error) {
        pushSnackbar({
          variant: 'error',
          title: `Failed to download`,
          description: data.getLogQueryDownloadUrl.error.message,
          duration: 5000,
        });
      } else {
        window.location.href = data.getLogQueryDownloadUrl.url;
      }
    },
    onError: () => {
      pushSnackbar({
        variant: 'error',
        title: `Failed to download`,
      });
    },
  });
  return (
    <Button
      size="large"
      variant="primary"
      onClick={() => getDownloadUrl()}
      disabled={!isQuerySuccessful || loading}
    >
      {loading ? 'Requesting...' : 'Download CSV'}
    </Button>
  );
};

export default React.memo(DownloadButton);

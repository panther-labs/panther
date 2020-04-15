import React from 'react';
import useUrlParams from 'Hooks/useUrlParams';

type State = {
  selectedDatabase: string | null;
  selectedTable: string | null;
  selectedColumn: string | null;
  searchValue: string;
  globalErrorMessage: string;
  queryId?: string | null;
  queryStatus: 'provisioning' | 'errored' | 'running' | 'succeeded' | null;
};

type Action<T, P = never> = {
  type: T;
  payload?: P;
};

type SelectDatabaseAction = Action<'SELECT_DATABASE', { database: string }>;
type SelectTableAction = Action<'SELECT_TABLE', { table: string }>;
type SelectColumnAction = Action<'SELECT_COLUMN', { column: string }>;
type SearchAction = Action<'SEARCH_DATABASE', { searchValue: string }>;
type MarkQueryAsProvisioning = Action<'QUERY_PROVISIONING'>;
type MarkQueryAsErrored = Action<'QUERY_ERRORED', { message: string }>;
type MarkQueryAsRunning = Action<'QUERY_RUNNING', { queryId: string }>;
type MarkQueryAsCanceled = Action<'QUERY_CANCELED'>;
type MarkQueryAsSuccessful = Action<'QUERY_SUCCEEDED'>;

type Actions =
  | SelectDatabaseAction
  | SelectTableAction
  | SelectColumnAction
  | SearchAction
  | MarkQueryAsErrored
  | MarkQueryAsCanceled
  | MarkQueryAsProvisioning
  | MarkQueryAsRunning
  | MarkQueryAsSuccessful;

function reducer(state: State, action: Actions) {
  switch (action.type) {
    case 'SELECT_DATABASE':
      return {
        ...state,
        selectedDatabase: action.payload.database,
        selectedTable: null,
        selectedColumn: null,
        searchValue: '',
      };
    case 'SELECT_TABLE':
      return {
        ...state,
        selectedTable: action.payload.table,
        selectedColumn: null,
        searchValue: '',
      };
    case 'SELECT_COLUMN':
      return { ...state, selectedColumn: action.payload.column };
    case 'SEARCH_DATABASE':
      return { ...state, searchValue: action.payload.searchValue };
    case 'QUERY_ERRORED':
      return {
        ...state,
        globalErrorMessage: action.payload.message,
        queryStatus: 'errored' as const,
      };
    case 'QUERY_PROVISIONING':
      return { ...state, queryStatus: 'provisioning' as const };
    case 'QUERY_RUNNING':
      return {
        ...state,
        queryStatus: 'running' as const,
        queryId: action.payload.queryId,
        globalErrorMessage: '',
      };
    case 'QUERY_CANCELED':
      return { ...state, queryId: null, queryStatus: null };
    case 'QUERY_SUCCEEDED':
      return { ...state, queryStatus: 'succeeded' as const };
    default:
      throw new Error();
  }
}

const SQLShellContext = React.createContext<{
  state: State;
  dispatch: (action: Actions) => void;
}>(undefined);

export const SQLShellContextProvider: React.FC = ({ children }) => {
  const { urlParams, updateUrlParams } = useUrlParams<
    Pick<State, 'queryId' | 'selectedDatabase'>
  >();

  const initialState = React.useMemo(
    () => ({
      queryId: urlParams.queryId || null,
      selectedDatabase: urlParams.selectedDatabase || null,
      selectedTable: null,
      selectedColumn: null,
      searchValue: '',
      globalErrorMessage: '',
      queryStatus: null,
    }),
    []
  );

  const [state, dispatch] = React.useReducer<React.Reducer<State, Actions>>(reducer, initialState);

  React.useEffect(() => {
    updateUrlParams({ queryId: state.queryId, selectedDatabase: state.selectedDatabase });
  }, [state.queryId, state.selectedDatabase, updateUrlParams]);

  const contextValue = React.useMemo(() => ({ state, dispatch }), [state, dispatch]);

  return <SQLShellContext.Provider value={contextValue}>{children}</SQLShellContext.Provider>;
};

export const useSQLShellContext = () => React.useContext(SQLShellContext);

export const withSQLShellContext = (Component: React.FC) => props => (
  <SQLShellContextProvider>
    <Component {...props} />
  </SQLShellContextProvider>
);

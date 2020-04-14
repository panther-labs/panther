import React from 'react';

type State = {
  selectedDatabase: string | null;
  selectedTable: string | null;
  selectedColumn: string | null;
  searchValue: string;
  globalErrorMessage: string;
};

type Action<T, P = never> = {
  type: T;
  payload?: P;
};

type SelectDatabaseAction = Action<'SELECT_DATABASE', { database: string }>;
type SelectTableAction = Action<'SELECT_TABLE', { table: string }>;
type SelectColumnAction = Action<'SELECT_COLUMN', { column: string }>;
type SearchAction = Action<'SEARCH_DATABASE', { searchValue: string }>;
type SetGlobalErrorAction = Action<'SET_ERROR', { message: string }>;
type ResetGlobalErrorAction = Action<'RESET_ERROR'>;

type Actions =
  | SelectDatabaseAction
  | SelectTableAction
  | SelectColumnAction
  | SearchAction
  | SetGlobalErrorAction
  | ResetGlobalErrorAction;

const initialState = {
  selectedDatabase: null,
  selectedTable: null,
  selectedColumn: null,
  searchValue: '',
  globalErrorMessage: '',
};

function reducer(state: State = initialState, action: Actions) {
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
    case 'SET_ERROR':
      return { ...state, globalErrorMessage: action.payload.message };
    case 'RESET_ERROR':
      return { ...state, globalErrorMessage: '' };
    default:
      throw new Error();
  }
}

const SQLShellContext = React.createContext<{
  state: State;
  dispatch: (action: Actions) => void;
}>(undefined);

export const SQLShellContextProvider: React.FC = ({ children }) => {
  const [state, dispatch] = React.useReducer<React.Reducer<State, Actions>>(reducer, initialState);

  const contextValue = React.useMemo(() => ({ state, dispatch }), [state, dispatch]);

  return <SQLShellContext.Provider value={contextValue}>{children}</SQLShellContext.Provider>;
};

export const useSQLShellContext = () => React.useContext(SQLShellContext);

export const withSQLShellContext = (Component: React.FC) => props => (
  <SQLShellContextProvider>
    <Component {...props} />
  </SQLShellContextProvider>
);

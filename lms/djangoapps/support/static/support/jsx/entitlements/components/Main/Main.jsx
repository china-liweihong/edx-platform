import React from 'react';
import PropTypes from 'prop-types';

import SearchContainer from '../Search/SearchContainer';
import { StatusAlert } from '@edx/paragon';

const Main = (props) => (
  <div>
    <StatusAlert
      alertType="danger"
      dialog={ props.errorMessage }
      onClose={ props.dismissErrorMessage }
      open={ !!props.errorMessage }
    />
    <h2>
      Entitlement Support Page
    </h2>
    <SearchContainer/>
  </div>
);

Main.propTypes = {
  errorMessage: PropTypes.string.isRequired,
  dismissErrorMessage: PropTypes.func.isRequired,
};

export default Main;
